//! Owned policy routing for explicit Internet sharing. No host default-route edits.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use traffic_masq_netlink::{
    Ipv4RouteInfo, Ipv4RouteSpec, Ipv4RuleInfo, Ipv4RuleSpec, NetworkProvider,
};

use crate::RouterDataplaneDesired;

const PROTOCOL: u8 = traffic_masq_netlink::TRAFFIC_MASQ_SHARING_ROUTE_PROTOCOL;
const TABLE_PREFIX: u32 = 0x5400_0000;
const RETURN_PRIORITY: u32 = 5_000;
const OUTBOUND_PRIORITY: u32 = 5_001;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharingRoutingSnapshot {
    routes: Vec<Ipv4RouteInfo>,
    rules: Vec<Ipv4RuleInfo>,
    /// Bind saved routes by interface identity after a restored link changes index.
    interfaces: BTreeMap<u32, String>,
}

impl SharingRoutingSnapshot {
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.rules.is_empty()
    }

    fn canonicalize(&mut self) {
        self.routes
            .sort_by_key(|r| (r.table, r.gateway.is_some(), r.destination, r.metric));
        self.rules.sort_by_key(|r| {
            (
                r.priority,
                r.table,
                r.input_interface.clone(),
                r.source,
                r.destination,
            )
        });
    }
}

pub fn is_reserved_table(table: u32) -> bool {
    table & 0xff00_0000 == TABLE_PREFIX
}

fn table_for(rule: &crate::ForwardingConfig) -> u32 {
    // Stable across reordering/removal, unlike a vector index. Collisions are rejected.
    let mut hash = 2_166_136_261u32;
    for byte in format!(
        "{}\0{}\0{}",
        rule.from,
        rule.to,
        rule.source_subnet
            .map(|s| s.to_string())
            .unwrap_or_default()
    )
    .bytes()
    {
        hash = (hash ^ u32::from(byte)).wrapping_mul(16_777_619);
    }
    TABLE_PREFIX | (hash & 0x00ff_ffff)
}

fn owned_rule(rule: &Ipv4RuleInfo) -> bool {
    is_reserved_table(rule.table)
        && rule.protocol == Some(PROTOCOL)
        && matches!(rule.priority, Some(RETURN_PRIORITY | OUTBOUND_PRIORITY))
        && rule.input_interface.is_some()
        && rule.output_interface.is_none()
        && rule.fw_mark.is_none()
        && rule.fw_mask.is_none()
}

pub(crate) async fn observe(network: &impl NetworkProvider) -> Result<SharingRoutingSnapshot> {
    network
        .check_ipv4_policy_namespace(TABLE_PREFIX, 0xff00_0000, 0, PROTOCOL)
        .await?;
    let mut state = SharingRoutingSnapshot::default();
    for route in network.list_ipv4_routes().await? {
        if !is_reserved_table(route.table) {
            continue;
        }
        anyhow::ensure!(
            route.protocol == PROTOCOL,
            "foreign route occupies sharing table {}; refusing adoption or deletion",
            route.table
        );
        state.routes.push(route);
    }
    for rule in network.list_ipv4_rules().await? {
        if !is_reserved_table(rule.table)
            && !matches!(rule.priority, Some(RETURN_PRIORITY | OUTBOUND_PRIORITY))
        {
            continue;
        }
        anyhow::ensure!(
            owned_rule(&rule),
            "foreign rule conflicts with sharing routing namespace; inspect ip -4 rule show"
        );
        state.rules.push(rule);
    }
    let interfaces = network.list_interfaces().await?;
    for route in &state.routes {
        let index = route
            .output_interface_index
            .context("sharing route has no output interface")?;
        let name = interfaces
            .iter()
            .find(|i| i.index == index)
            .context("sharing route references an unavailable interface")?
            .name
            .clone();
        state.interfaces.insert(index, name);
    }
    state.canonicalize();
    Ok(state)
}

fn policy_rule(table: u32, priority: u32, ingress: &str) -> Ipv4RuleInfo {
    Ipv4RuleInfo {
        protocol: Some(PROTOCOL),
        source: None,
        destination: None,
        table,
        priority: Some(priority),
        fw_mark: None,
        fw_mask: None,
        input_interface: Some(ingress.into()),
        output_interface: None,
    }
}

pub(crate) async fn desired(
    network: &impl NetworkProvider,
    config: &RouterDataplaneDesired,
) -> Result<SharingRoutingSnapshot> {
    let mut state = SharingRoutingSnapshot::default();
    if config.forwarding_rules().is_empty() {
        return Ok(state);
    }
    network
        .check_ipv4_policy_namespace(TABLE_PREFIX, 0xff00_0000, OUTBOUND_PRIORITY, PROTOCOL)
        .await?;
    let interfaces = network.list_interfaces().await?;
    let observed = network.list_ipv4_routes().await?;
    let mut tables = BTreeSet::new();
    for rule in config.forwarding_rules() {
        let table = table_for(&rule);
        anyhow::ensure!(
            tables.insert(table),
            "sharing route-table identity collision; use distinct forwarding selectors"
        );
        let ingress = interfaces
            .iter()
            .find(|i| i.name == rule.from && i.is_up)
            .with_context(|| format!("sharing ingress {} is unavailable", rule.from))?;
        let egress = interfaces
            .iter()
            .find(|i| i.name == rule.to && i.is_up)
            .with_context(|| format!("sharing egress {} is unavailable", rule.to))?;
        state.interfaces.insert(ingress.index, ingress.name.clone());
        state.interfaces.insert(egress.index, egress.name.clone());
        let lan: Vec<_> = observed
            .iter()
            .filter(|r| {
                r.table == 254
                    && r.output_interface_index == Some(ingress.index)
                    && r.destination.prefix_len() != 0
            })
            .collect();
        anyhow::ensure!(
            !lan.is_empty(),
            "sharing ingress {} has no IPv4 route for replies",
            rule.from
        );
        let mut outgoing = policy_rule(table, OUTBOUND_PRIORITY, &rule.from);
        outgoing.source = rule.source_subnet.filter(|s| s.prefix_len() != 0);
        state.rules.push(outgoing);
        let destinations: BTreeSet<_> = lan
            .iter()
            .filter_map(|r| match rule.source_subnet {
                None => Some(r.destination),
                Some(source) if r.destination.contains(&source) => Some(source),
                Some(source) if source.contains(&r.destination) => Some(r.destination),
                _ => None,
            })
            .collect();
        anyhow::ensure!(
            !destinations.is_empty(),
            "sharing source subnet has no route back through {}",
            rule.from
        );
        for destination in destinations {
            for return_ingress in [rule.to.as_str(), "lo"] {
                let mut returning = policy_rule(table, RETURN_PRIORITY, return_ingress);
                returning.destination = Some(destination);
                anyhow::ensure!(
                    !state
                        .rules
                        .iter()
                        .any(|r| r.priority == Some(RETURN_PRIORITY)
                            && r.input_interface == returning.input_interface
                            && r.table != table
                            && r.destination
                                .is_some_and(|d| d.contains(&destination.addr())
                                    || destination.contains(&d.addr()))),
                    "overlapping sharing return paths on {return_ingress}"
                );
                state.rules.push(returning);
            }
        }
        // Prefer the selected interface's main-table routes. A tunnel may keep
        // its default in a separate VPN table. Never copy our own derived routes.
        let candidates: Vec<_> = observed
            .iter()
            .filter(|r| {
                r.table != 255
                    && !is_reserved_table(r.table)
                    && r.output_interface_index == Some(egress.index)
            })
            .collect();
        anyhow::ensure!(
            candidates.iter().any(|r| r.destination.prefix_len() == 0),
            "sharing Through {} has no IPv4 default route/gateway",
            rule.to
        );
        // Main is authoritative when it supplies the exit default. Otherwise
        // use one unambiguous tunnel table, preserving other policy scopes.
        let default_tables: BTreeSet<_> = candidates
            .iter()
            .filter(|r| r.destination.prefix_len() == 0)
            .map(|r| r.table)
            .collect();
        let source_table = if default_tables.contains(&254) {
            254
        } else {
            anyhow::ensure!(
                default_tables.len() == 1,
                "sharing Through {} has ambiguous default route tables",
                rule.to
            );
            *default_tables.first().expect("default route checked above")
        };
        let mut selected = BTreeMap::new();
        for route in candidates.into_iter().filter(|r| r.table == source_table) {
            let preference = (route.table != 254, route.metric.unwrap_or(0), route.table);
            let entry = selected
                .entry(route.destination)
                .or_insert((preference, route));
            if preference < entry.0 {
                *entry = (preference, route);
            }
        }
        for route in lan
            .into_iter()
            .chain(selected.into_values().map(|(_, r)| r))
        {
            let mut route = route.clone();
            route.table = table;
            route.protocol = PROTOCOL;
            // The netlink adapter creates gateway-less routes with link scope.
            route.scope = if route.gateway.is_some() { 0 } else { 253 };
            if !state.routes.contains(&route) {
                state.routes.push(route);
            }
        }
    }
    for (index, route) in state.routes.iter().enumerate() {
        anyhow::ensure!(
            !state.routes[..index]
                .iter()
                .any(|prior| prior.table == route.table
                    && prior.destination == route.destination
                    && prior.metric == route.metric
                    && prior != route),
            "sharing ingress and egress have conflicting routes for {}",
            route.destination
        );
    }
    state.canonicalize();
    Ok(state)
}

pub(crate) async fn current(
    network: &impl NetworkProvider,
    config: &RouterDataplaneDesired,
) -> Result<bool> {
    Ok(observe(network).await? == desired(network, config).await?)
}

/// Revalidate ownership on each pass, including compensation after a partial write.
/// Callers retain the router journal and the runtime reservation until completion.
pub(crate) async fn restore(
    network: &impl NetworkProvider,
    saved: &SharingRoutingSnapshot,
) -> Result<()> {
    let mut target = saved.clone();
    let links = network.list_interfaces().await?;
    for route in &mut target.routes {
        anyhow::ensure!(
            is_reserved_table(route.table) && route.protocol == PROTOCOL,
            "unsafe sharing route snapshot"
        );
        let old = route
            .output_interface_index
            .context("sharing snapshot route has no interface")?;
        let name = saved
            .interfaces
            .get(&old)
            .context("sharing snapshot has no interface identity")?;
        route.output_interface_index = Some(
            links
                .iter()
                .find(|i| &i.name == name)
                .with_context(|| {
                    format!("cannot restore sharing route: interface {name} is absent")
                })?
                .index,
        );
    }
    for rule in &target.rules {
        anyhow::ensure!(owned_rule(rule), "unsafe sharing rule snapshot");
    }
    for route in &target.routes {
        Ipv4RouteSpec {
            destination: route.destination,
            gateway: route.gateway,
            output_interface_index: route.output_interface_index,
            table: route.table,
            metric: route.metric,
            protocol: route.protocol,
        }
        .validate()?;
    }
    // Validate the complete snapshot before retiring any current object.
    for rule in &target.rules {
        Ipv4RuleSpec {
            protocol: rule.protocol,
            source: rule.source,
            destination: rule.destination,
            table: rule.table,
            priority: rule.priority,
            fw_mark: rule.fw_mark,
            fw_mask: rule.fw_mask,
            input_interface: rule.input_interface.clone(),
            output_interface: rule.output_interface.clone(),
        }
        .validate()?;
    }
    let existing = observe(network).await?;
    // Withdraw selectors before routes; publish selectors only after routes exist.
    for rule in &existing.rules {
        if !target.rules.contains(rule) {
            network.delete_ipv4_rule(rule).await?;
        }
    }
    let same_key = |a: &Ipv4RouteInfo, b: &Ipv4RouteInfo| {
        a.table == b.table && a.destination == b.destination && a.metric == b.metric
    };
    for route in existing.routes.iter().rev() {
        if !target.routes.iter().any(|next| same_key(route, next)) {
            network.delete_ipv4_route(route).await?;
        }
    }
    for route in &target.routes {
        if !existing.routes.contains(route) {
            let spec = Ipv4RouteSpec {
                destination: route.destination,
                gateway: route.gateway,
                output_interface_index: route.output_interface_index,
                table: route.table,
                metric: route.metric,
                protocol: PROTOCOL,
            };
            if existing.routes.iter().any(|old| same_key(old, route)) {
                network.replace_ipv4_route(&spec).await?;
            } else {
                network.add_ipv4_route(&spec).await?;
            }
        }
    }
    for rule in &target.rules {
        if !existing.rules.contains(rule) {
            network
                .add_ipv4_rule(&Ipv4RuleSpec {
                    protocol: rule.protocol,
                    source: rule.source,
                    destination: rule.destination,
                    table: rule.table,
                    priority: rule.priority,
                    fw_mark: None,
                    fw_mask: None,
                    input_interface: rule.input_interface.clone(),
                    output_interface: None,
                })
                .await?;
        }
    }
    // Read-back is required: an acknowledged netlink write is not proof of state.
    let actual = observe(network).await?;
    target.interfaces = actual.interfaces.clone();
    target.canonicalize();
    anyhow::ensure!(
        actual == target,
        "sharing routing read-back did not match the requested state"
    );
    Ok(())
}

pub(crate) async fn cleanup_removed(
    network: &impl NetworkProvider,
    retained: Option<&RouterDataplaneDesired>,
) -> Result<()> {
    let mut state = observe(network).await?;
    let tables: BTreeSet<_> = retained
        .into_iter()
        .flat_map(|d| d.forwarding_rules())
        .map(|r| table_for(&r))
        .collect();
    state.rules.retain(|r| tables.contains(&r.table));
    state.routes.retain(|r| tables.contains(&r.table));
    restore(network, &state).await
}

/// Share the existing nft operation reservation with routing workers. Dropping
/// an async caller cannot release it while an accepted netlink write is running.
#[derive(Debug)]
pub(crate) struct Backend<L> {
    network: std::sync::Arc<L>,
    operations: std::sync::Arc<tokio::sync::Mutex<()>>,
}

enum Update {
    Apply(RouterDataplaneDesired),
    Restore(SharingRoutingSnapshot),
    Retain(Option<RouterDataplaneDesired>),
}

impl<L: NetworkProvider + 'static> Backend<L> {
    pub(crate) fn new(
        network: std::sync::Arc<L>,
        operations: std::sync::Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            network,
            operations,
        }
    }

    pub(crate) async fn observe(&self) -> Result<SharingRoutingSnapshot> {
        let _reservation = self.operations.lock().await;
        observe(self.network.as_ref()).await
    }

    pub(crate) async fn current(&self, config: &RouterDataplaneDesired) -> Result<bool> {
        let _reservation = self.operations.lock().await;
        current(self.network.as_ref(), config).await
    }

    async fn update(self: &std::sync::Arc<Self>, update: Update) -> Result<()> {
        let reservation = self.operations.clone().lock_owned().await;
        let backend = self.clone();
        tokio::spawn(async move {
            let _reservation = reservation;
            match update {
                Update::Apply(config) => {
                    let state = desired(backend.network.as_ref(), &config).await?;
                    restore(backend.network.as_ref(), &state).await?;
                    anyhow::ensure!(
                        current(backend.network.as_ref(), &config).await?,
                        "sharing routing changed during apply"
                    );
                    Ok(())
                }
                Update::Restore(state) => restore(backend.network.as_ref(), &state).await,
                Update::Retain(config) => {
                    cleanup_removed(backend.network.as_ref(), config.as_ref()).await
                }
            }
        })
        .await?
    }

    pub(crate) async fn apply(
        self: &std::sync::Arc<Self>,
        config: &RouterDataplaneDesired,
    ) -> Result<()> {
        self.update(Update::Apply(config.clone())).await
    }
    pub(crate) async fn restore(
        self: &std::sync::Arc<Self>,
        state: &SharingRoutingSnapshot,
    ) -> Result<()> {
        self.update(Update::Restore(state.clone())).await
    }
    pub(crate) async fn cleanup_removed(
        self: &std::sync::Arc<Self>,
        config: Option<&RouterDataplaneDesired>,
    ) -> Result<()> {
        self.update(Update::Retain(config.cloned())).await
    }
}
