//! Allowlisted diagnostics. Never serialize requests, responses, credentials or configs.
use std::future::Future;
use std::time::{Duration, Instant};

use crate::config::InterfaceConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Operation {
    pub id: String,
    pub source: &'static str,
    pub command: &'static str,
}

tokio::task_local! {
    pub(crate) static CURRENT: Operation;
    pub(crate) static STAGE: &'static str;
}

impl Operation {
    pub fn new(source: &'static str, command: &'static str) -> Self {
        Self {
            id: format!("{:032x}", rand::random::<u128>()),
            source,
            command,
        }
    }
    pub fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> {
        // Control dispatch futures are large. Do not copy them into another
        // nested async state machine merely to attach diagnostic metadata.
        CURRENT.scope(self.clone(), Box::pin(future))
    }
}

pub(crate) fn current() -> Option<Operation> {
    CURRENT.try_with(Clone::clone).ok()
}

/// Capture before spawning: Tokio task locals are not inherited by child tasks.
pub(crate) fn inherit<T>(future: impl Future<Output = T>) -> impl Future<Output = T> {
    let operation = current();
    async move {
        match operation {
            Some(operation) => operation.scope(future).await,
            None => future.await,
        }
    }
}

pub(crate) fn os_error(error: &anyhow::Error) -> Option<i32> {
    crate::netlink::netlink_os_error(error).or_else(|| {
        error.chain().find_map(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error)
        })
    })
}

pub(crate) async fn stage<T>(
    name: &'static str,
    budget: Option<Duration>,
    future: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    STAGE.scope(name, async {
        let started = Instant::now();
        let foreground = current().is_some_and(|operation| operation.source != "reconcile");
        if foreground { tracing::info!(stage = name, budget_ms = budget.map(|d| d.as_millis() as u64), "network stage started"); }
        else { tracing::debug!(stage = name, "network stage started"); }
        let result = future.await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match &result {
            Ok(_) if foreground => tracing::info!(stage = name, elapsed_ms, outcome = "completed", "network stage finished"),
            Ok(_) => tracing::debug!(stage = name, elapsed_ms, outcome = "completed", "network stage finished"),
            Err(error) => {
                let errno = os_error(error);
                if foreground {
                    tracing::warn!(stage = name, elapsed_ms, budget_ms = budget.map(|d| d.as_millis() as u64), errno,
                        outcome = "failed", error = %format!("{error:#}"), "network stage failed");
                } else {
                    tracing::debug!(stage = name, elapsed_ms, errno, error = %format!("{error:#}"), "network stage failed; convergence worker reports repeated failures");
                }
            }
        }
        result
    }).await
}

/// Explicit fields only: adding a config field never implicitly makes it loggable.
pub(crate) fn interface_summary(config: Option<&InterfaceConfig>) -> serde_json::Value {
    match config {
        None => serde_json::Value::Null,
        Some(config) => serde_json::json!({
            "managed": config.managed, "role": config.role,
            "ipv4": config.ipv4, "randomize_mac": config.randomize_mac,
            "mac_address": config.mac_address, "wifi_concurrent": config.wifi_concurrent,
            "wifi_client_present": config.wifi_client.is_some(),
            "wifi_ap_present": config.wifi.is_some(), "dhcp_server_present": config.dhcp.is_some(),
            "dhcp_enabled": config.dhcp_client.as_ref().map(|c| c.enabled),
            "dhcp_wifi_owned": config.dhcp_client.as_ref().map(|c| c.wifi_owned),
            "dhcp_route_metric": config.dhcp_client.as_ref().map(|c| c.route_metric),
        }),
    }
}

pub(crate) fn interface_diff(
    previous: Option<&InterfaceConfig>,
    target: &InterfaceConfig,
) -> serde_json::Value {
    let before = interface_summary(previous);
    let after = interface_summary(Some(target));
    let mut changes = serde_json::Map::new();
    for (key, value) in after.as_object().expect("summary object") {
        if before.get(key) != Some(value) {
            changes.insert(
                key.clone(),
                serde_json::json!({"before": before.get(key), "after": value}),
            );
        }
    }
    if previous.and_then(|c| c.wifi_client.as_ref()) != target.wifi_client.as_ref() {
        changes.insert("wifi_client_settings_changed".into(), true.into());
    }
    if previous.and_then(|c| c.wifi.as_ref()) != target.wifi.as_ref() {
        changes.insert("wifi_ap_settings_changed".into(), true.into());
    }
    changes.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_diff_excludes_network_names_hostnames_and_secret_paths() {
        let mut config: InterfaceConfig = serde_json::from_value(serde_json::json!({
            "role": "input", "managed": true,
            "wifi_client": {"ssid": "private-network", "security": "wpa2", "passphrase_file": "/secret/private-password"},
            "dhcp_client": {"enabled": true, "wifi_owned": false, "hostname": "private-host"}
        })).unwrap();
        let before = config.clone();
        config.wifi_client = None;
        let output = interface_diff(Some(&before), &config).to_string();
        for secret in ["private-network", "private-password", "private-host"] {
            assert!(!output.contains(secret));
            assert!(!interface_summary(Some(&before))
                .to_string()
                .contains(secret));
        }
        assert_eq!(
            interface_diff(Some(&before), &config)["wifi_client_present"]["after"],
            false
        );
        assert_eq!(interface_summary(Some(&config))["dhcp_wifi_owned"], false);
    }

    #[tokio::test]
    async fn inherited_context_survives_spawn_without_leaking_to_other_tasks() {
        let operation = Operation::new("api", "apply_interface");
        let expected = operation.clone();
        operation
            .scope(async {
                let child = tokio::spawn(inherit(async {
                    tokio::task::yield_now().await;
                    current()
                }));
                assert_eq!(child.await.unwrap(), Some(expected));
                assert!(tokio::spawn(async { current() }).await.unwrap().is_none());
            })
            .await;
        assert!(current().is_none());
    }
}
