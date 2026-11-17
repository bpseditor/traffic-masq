//! Routing of encrypted hop traffic, separate from the exit's LAN policy.
//! Install the output guard before configuring a marked socket or WireGuard peer.
//! Keep the guard until the socket and interface have both been removed.

use anyhow::{ensure, Result};

use crate::core::vpn_policy::MAX_VPN_HOP_INDEX;
use crate::netlink::{Ipv4RouteSpec, Ipv4RuleSpec, TRAFFIC_MASQ_ROUTE_PROTOCOL};

/// Transport selectors must not match the 0x54/8 LAN policy namespace.
pub const TRANSPORT_MARK_BASE: u32 = 0x5500_0000;
const TRANSPORT_TABLE_BASE: u32 = 31_100;
const TRANSPORT_PRIORITY_BASE: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnTransportPlan {
    pub hop_index: u32,
    pub mark: u32,
    pub upstream: String,
    pub rule: Ipv4RuleSpec,
    pub route: Option<Ipv4RouteSpec>,
}

impl VpnTransportPlan {
    /// Hop zero uses the main routing table, preserving its gateway and DHCP
    /// changes. Later hops use a dedicated default through the previous tunnel.
    /// The output guard makes an empty table fail closed instead of allowing
    /// the policy-routing lookup to fall through to the physical uplink.
    pub fn new(hop_index: u32, upstream: &str, upstream_index: u32) -> Result<Self> {
        ensure!(hop_index <= MAX_VPN_HOP_INDEX, "unsupported VPN hop index");
        ensure!(upstream_index != 0, "upstream interface index is zero");
        ensure!(
            !upstream.is_empty()
                && upstream.len() <= 15
                && upstream
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            "unsafe VPN transport upstream interface"
        );
        let mark = TRANSPORT_MARK_BASE | (hop_index + 1);
        let table = if hop_index == 0 {
            254 // RT_TABLE_MAIN: do not invent a gateway-less uplink default.
        } else {
            TRANSPORT_TABLE_BASE + hop_index
        };
        Ok(Self {
            hop_index,
            mark,
            upstream: upstream.into(),
            rule: Ipv4RuleSpec {
                source: None,
                destination: None,
                table,
                priority: Some(TRANSPORT_PRIORITY_BASE + hop_index),
                fw_mark: Some(mark),
                fw_mask: Some(u32::MAX),
                input_interface: None,
                output_interface: None,
            },
            route: (hop_index != 0).then(|| Ipv4RouteSpec {
                destination: "0.0.0.0/0".parse().expect("constant IPv4 default"),
                gateway: None,
                output_interface_index: Some(upstream_index),
                table,
                metric: Some(50),
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
            }),
        })
    }

    /// Install the guard first. Failures deliberately retain it so partial
    /// installation cannot expose an already-running transport.
    pub async fn install(
        &self,
        network: &dyn crate::netlink::NetworkProvider,
        executor: std::sync::Arc<dyn crate::firewall::NftExecutor>,
    ) -> Result<()> {
        crate::core::vpn_transport_guard::apply_guard(executor, self.clone(), false).await?;
        let expected = self.rule_info();
        let rules = network.list_ipv4_rules().await?;
        for rule in &rules {
            let mark_overlap = rule
                .fw_mark
                .is_some_and(|mark| (mark ^ self.mark) & rule.fw_mask.unwrap_or(u32::MAX) == 0);
            ensure!(
                rule == &expected
                    || !(rule.priority == expected.priority
                        || mark_overlap
                        || (self.route.is_some() && rule.table == expected.table)),
                "foreign rule overlaps VPN transport selector"
            );
        }
        if let Some(route) = &self.route {
            let routes = network.list_ipv4_routes().await?;
            let existing: Vec<_> = routes.iter().filter(|r| r.table == route.table).collect();
            ensure!(
                existing
                    .iter()
                    .all(|r| r.protocol == TRAFFIC_MASQ_ROUTE_PROTOCOL),
                "foreign route in VPN transport table"
            );
            let matches = |r: &crate::netlink::Ipv4RouteInfo| {
                r.destination == route.destination
                    && r.gateway == route.gateway
                    && r.output_interface_index == route.output_interface_index
                    && r.metric == route.metric
                    && r.protocol == route.protocol
            };
            if existing.len() != 1 || !matches(existing[0]) {
                for old in existing {
                    network.delete_ipv4_route(old).await?;
                }
                network.add_ipv4_route(route).await?;
            }
        }
        if !rules.contains(&expected) {
            network.add_ipv4_rule(&self.rule).await?;
        }
        Ok(())
    }

    /// Read-only drift detection; never turn an unhealthy path into a healthy
    /// result by silently reinstalling its protection.
    pub async fn health(
        &self,
        network: &dyn crate::netlink::NetworkProvider,
        executor: std::sync::Arc<dyn crate::firewall::NftExecutor>,
    ) -> Result<()> {
        crate::core::vpn_transport_guard::health_guard(executor, self.clone()).await?;
        let expected = self.rule_info();
        let rules = network.list_ipv4_rules().await?;
        ensure!(
            rules.iter().filter(|rule| **rule == expected).count() == 1,
            "VPN transport rule missing or duplicated"
        );
        for rule in &rules {
            let overlaps = rule
                .fw_mark
                .is_some_and(|mark| (mark ^ self.mark) & rule.fw_mask.unwrap_or(u32::MAX) == 0);
            ensure!(
                rule == &expected
                    || !(rule.priority == expected.priority
                        || overlaps
                        || (self.route.is_some() && rule.table == expected.table)),
                "foreign rule overlaps VPN transport selector"
            );
        }
        if let Some(expected) = &self.route {
            let routes = network.list_ipv4_routes().await?;
            let routes: Vec<_> = routes
                .iter()
                .filter(|route| route.table == expected.table)
                .collect();
            ensure!(
                routes.len() == 1
                    && routes[0].destination == expected.destination
                    && routes[0].gateway == expected.gateway
                    && routes[0].output_interface_index == expected.output_interface_index
                    && routes[0].metric == expected.metric
                    && routes[0].protocol == expected.protocol,
                "VPN transport route drift"
            );
        }
        Ok(())
    }

    /// Caller must first prove that both WireGuard and its userspace transport
    /// have stopped. The guard is the last resource removed, and is retained
    /// on any route/rule cleanup failure.
    pub async fn remove_after_transport_stopped(
        &self,
        network: &dyn crate::netlink::NetworkProvider,
        executor: std::sync::Arc<dyn crate::firewall::NftExecutor>,
    ) -> Result<()> {
        let expected = self.rule_info();
        for rule in network.list_ipv4_rules().await? {
            if rule == expected {
                network.delete_ipv4_rule(&rule).await?;
            }
        }
        if let Some(route) = &self.route {
            for current in network.list_ipv4_routes().await? {
                if current.table == route.table {
                    ensure!(
                        current.protocol == TRAFFIC_MASQ_ROUTE_PROTOCOL,
                        "foreign route in VPN transport table"
                    );
                    network.delete_ipv4_route(&current).await?;
                }
            }
        }
        crate::core::vpn_transport_guard::apply_guard(executor, self.clone(), true).await
    }

    fn rule_info(&self) -> crate::netlink::Ipv4RuleInfo {
        crate::netlink::Ipv4RuleInfo {
            source: self.rule.source,
            destination: self.rule.destination,
            table: self.rule.table,
            priority: self.rule.priority,
            fw_mark: self.rule.fw_mark,
            fw_mask: self.rule.fw_mask,
            input_interface: self.rule.input_interface.clone(),
            output_interface: self.rule.output_interface.clone(),
        }
    }

    /// An inert guard for unrelated traffic. IPv6 transport is rejected until
    /// equivalent IPv6 policy routes are available. The loopback exception is
    /// required for WireGuard's local wgobfs proxy and cannot reach the uplink.
    /// This runs after output route/mangle chains have selected the final route.
    pub fn guard_table(&self) -> String {
        format!(
            "table inet traffic_masq_transport_{} {{\n  comment \"traffic-masq:transport:v1:{}\"\n  chain output {{\n    type filter hook output priority 10; policy accept;\n    meta mark {:#010x} oifname \"lo\" return\n    meta mark {:#010x} meta nfproto ipv6 drop\n    meta mark {:#010x} oifname != \"{}\" drop\n  }}\n}}\n",
            self.hop_index, self.hop_index, self.mark, self.mark, self.mark, self.upstream,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::vpn_policy::VpnPolicyReservedIds;

    #[test]
    fn transport_selectors_do_not_compete_with_each_other_or_lan() {
        let plans: Vec<_> = (0..=MAX_VPN_HOP_INDEX)
            .map(|hop| VpnTransportPlan::new(hop, "upstream", hop + 1).unwrap())
            .collect();
        for (i, plan) in plans.iter().enumerate() {
            for other in &plans[i + 1..] {
                assert_ne!(plan.mark, other.mark);
                assert_ne!(plan.rule.priority, other.rule.priority);
                assert_ne!(plan.rule.table, other.rule.table);
            }
            let lan = VpnPolicyReservedIds::for_hop(i as u32).unwrap();
            assert_ne!(plan.mark & lan.fw_mask.get(), lan.fw_mark.get());
            assert!(plan.rule.priority.unwrap() < lan.rule_priority_start.get());
            assert_eq!(plan.rule.fw_mask, Some(u32::MAX));
        }
    }

    #[test]
    fn first_hop_preserves_gateway_later_hops_use_previous_tunnel() {
        let first = VpnTransportPlan::new(0, "eth0", 2).unwrap();
        assert_eq!(first.rule.table, 254);
        assert!(first.route.is_none());
        let second = VpnTransportPlan::new(1, "tm-wg-0", 7).unwrap();
        let route = second.route.as_ref().unwrap();
        assert_eq!(route.output_interface_index, Some(7));
        assert_eq!(route.table, second.rule.table);
        assert_eq!(route.destination.prefix_len(), 0);
        assert!(second.guard_table().contains("oifname != \"tm-wg-0\" drop"));
        assert!(second.guard_table().contains("meta nfproto ipv6 drop"));
        assert!(VpnTransportPlan::new(1, "bad\"name", 7).is_err());
        assert!(VpnTransportPlan::new(MAX_VPN_HOP_INDEX + 1, "eth0", 2).is_err());
    }
    #[test]
    #[ignore = "requires root, unshare, ip, nft and python3"]
    fn transport_route_fallthrough_is_blocked_in_kernel() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let plan = VpnTransportPlan::new(1, "previous", 7).unwrap();
        let mut child = Command::new("unshare")
            .args(["-n", "--", "python3"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/core/vpn_transport_kernel_test.py"
            ))
            .arg(plan.mark.to_string())
            .arg(plan.rule.table.to_string())
            .arg(plan.rule.priority.unwrap().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(plan.guard_table().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let observed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        crate::core::vpn_transport_guard::verify_guard_structure(&observed, &plan).unwrap();
        for field in ["expr", "chain"] {
            let mut drifted = observed.clone();
            let rule = drifted["nftables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find_map(|entry| entry.get_mut("rule"))
                .unwrap();
            rule[field] = serde_json::Value::Null;
            assert!(
                crate::core::vpn_transport_guard::verify_guard_structure(&drifted, &plan).is_err()
            );
        }
    }
}
