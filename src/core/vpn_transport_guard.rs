//! Ownership-checked, atomic transport guard updates.
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use serde_json::Value;

use crate::core::vpn_transport::VpnTransportPlan;
use crate::firewall::NftExecutor;

/// Keep admission in the blocking worker even if its caller is cancelled.
pub async fn apply_guard(
    executor: Arc<dyn NftExecutor>,
    plan: VpnTransportPlan,
    remove: bool,
) -> Result<()> {
    let reservation = match executor.operation_gate() {
        Some(gate) => Some(gate.lock_owned().await),
        None => None,
    };
    tokio::task::spawn_blocking(move || {
        let _reservation = reservation;
        let name = format!("traffic_masq_transport_{}", plan.hop_index);
        let comment = format!("traffic-masq:transport:v1:{}", plan.hop_index);
        let output = executor.execute(&["--json", "list", "ruleset"], &[])?;
        let ruleset: Value = serde_json::from_slice(&output)?;
        let entries = ruleset["nftables"]
            .as_array()
            .context("missing nftables array")?;
        let mut exists = false;
        for entry in entries {
            let Some(table) = entry.get("table") else {
                continue;
            };
            if table["family"] != "inet" || table["name"] != name {
                continue;
            }
            ensure!(!exists, "duplicate transport table");
            exists = true;
            if let Some(actual) = table.get("comment") {
                ensure!(actual.as_str() == Some(&comment), "foreign transport table");
            } else {
                // nft 1.0.6 keeps table comments but omits them from JSON.
                let text = executor.execute(&["list", "table", "inet", &name], &[])?;
                verify_owner_text(&text, &name, &comment)?;
            }
        }
        if remove && !exists {
            return Ok(());
        }
        let mut batch = if exists {
            format!("delete table inet {name}\n")
        } else {
            String::new()
        };
        if !remove {
            batch.push_str(&plan.guard_table());
        }
        executor.execute(&["-f", "-"], batch.as_bytes())?;
        Ok(())
    })
    .await?
}

/// Observe without repairing: ownership alone does not prove leak protection.
pub async fn health_guard(executor: Arc<dyn NftExecutor>, plan: VpnTransportPlan) -> Result<()> {
    let reservation = match executor.operation_gate() {
        Some(gate) => Some(gate.lock_owned().await),
        None => None,
    };
    tokio::task::spawn_blocking(move || {
        let _reservation = reservation;
        let name = format!("traffic_masq_transport_{}", plan.hop_index);
        let comment = format!("traffic-masq:transport:v1:{}", plan.hop_index);
        let output = executor.execute(&["--json", "list", "table", "inet", &name], &[])?;
        let ruleset: Value = serde_json::from_slice(&output)?;
        verify_guard_structure(&ruleset, &plan)?;
        let table = ruleset["nftables"]
            .as_array()
            .context("missing nftables array")?
            .iter()
            .find_map(|entry| entry.get("table"))
            .context("missing guard table")?;
        if let Some(actual) = table.get("comment") {
            ensure!(actual.as_str() == Some(&comment), "foreign transport table");
        } else {
            let text = executor.execute(&["list", "table", "inet", &name], &[])?;
            verify_owner_text(&text, &name, &comment)?;
        }
        Ok(())
    })
    .await?
}

pub(super) fn verify_guard_structure(ruleset: &Value, plan: &VpnTransportPlan) -> Result<()> {
    use serde_json::json;
    let name = format!("traffic_masq_transport_{}", plan.hop_index);
    let entries = ruleset["nftables"]
        .as_array()
        .context("missing nftables array")?;
    let mut tables = 0;
    let mut chains = 0;
    let mut rules = Vec::new();
    for entry in entries {
        if entry.get("metainfo").is_some() {
            continue;
        }
        if let Some(table) = entry.get("table") {
            ensure!(
                table["family"] == "inet" && table["name"] == name,
                "unexpected guard table"
            );
            tables += 1;
        } else if let Some(chain) = entry.get("chain") {
            ensure!(
                chain["family"] == "inet"
                    && chain["table"] == name
                    && chain["name"] == "output"
                    && chain["type"] == "filter"
                    && chain["hook"] == "output"
                    && chain["prio"] == 10
                    && chain["policy"] == "accept",
                "transport guard chain drift"
            );
            chains += 1;
        } else if let Some(rule) = entry.get("rule") {
            ensure!(
                rule["family"] == "inet" && rule["table"] == name && rule["chain"] == "output",
                "unexpected guard rule"
            );
            rules.push(rule["expr"].clone());
        } else {
            anyhow::bail!("unexpected object in transport guard");
        }
    }
    let condition = |key: &str, op: &str, right: Value| json!({"match":{"op":op,"left":{"meta":{"key":key}},"right":right}});
    let mark = condition("mark", "==", json!(plan.mark));
    let expected = vec![
        json!([mark, condition("oifname", "==", json!("lo")), {"return":null}]),
        json!([mark, condition("nfproto", "==", json!("ipv6")), {"drop":null}]),
        json!([mark, condition("oifname", "!=", json!(plan.upstream)), {"drop":null}]),
    ];
    ensure!(
        tables == 1 && chains == 1 && rules == expected,
        "transport guard rules drift"
    );
    Ok(())
}

fn verify_owner_text(text: &[u8], name: &str, comment: &str) -> Result<()> {
    let text = std::str::from_utf8(text)?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    ensure!(
        lines.next() == Some(format!("table inet {name} {{").as_str())
            && lines.next() == Some(format!("comment \"{comment}\"").as_str()),
        "missing transport table ownership comment"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Executor {
        json: Vec<u8>,
        text: Vec<u8>,
        writes: Mutex<Vec<String>>,
    }
    impl NftExecutor for Executor {
        fn execute(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
            match args {
                ["--json", "list", "ruleset"] => Ok(self.json.clone()),
                ["list", "table", "inet", _] => Ok(self.text.clone()),
                ["-f", "-"] => {
                    self.writes
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(input.to_vec())?);
                    Ok(Vec::new())
                }
                _ => anyhow::bail!("unexpected nft invocation"),
            }
        }
    }

    #[tokio::test]
    async fn failed_route_install_retains_guard_and_cleanup_preserves_main_routes() {
        let network = crate::test_support::FakeNetworkProvider::default();
        let executor = Arc::new(Executor {
            json: br#"{"nftables":[]}"#.to_vec(),
            text: Vec::new(),
            writes: Mutex::new(Vec::new()),
        });
        let plan = VpnTransportPlan::new(1, "previous", 7).unwrap();
        *network.fail_next_add_route.lock().await = true;
        assert!(plan.install(&network, executor.clone()).await.is_err());
        assert_eq!(executor.writes.lock().unwrap().len(), 1);
        assert_eq!(executor.writes.lock().unwrap()[0], plan.guard_table());
        assert!(network.rules.lock().await.is_empty());
        plan.install(&network, executor.clone()).await.unwrap();
        assert_eq!(network.routes.lock().await.len(), 1);
        assert_eq!(network.rules.lock().await.len(), 1);
        plan.install(&network, executor.clone()).await.unwrap();
        assert_eq!(network.routes.lock().await.len(), 1);
        assert_eq!(network.rules.lock().await.len(), 1);
        let mut main = network.routes.lock().await[0].clone();
        main.table = 254;
        network.routes.lock().await.push(main.clone());
        plan.remove_after_transport_stopped(&network, executor.clone())
            .await
            .unwrap();
        assert!(network.rules.lock().await.is_empty());
        assert_eq!(*network.routes.lock().await, vec![main.clone()]);
        let first = VpnTransportPlan::new(0, "uplink", 2).unwrap();
        first.install(&network, executor.clone()).await.unwrap();
        first
            .remove_after_transport_stopped(&network, executor)
            .await
            .unwrap();
        assert_eq!(*network.routes.lock().await, vec![main]);
    }

    #[tokio::test]
    async fn foreign_tables_never_replaced_even_with_nested_matching_comment() {
        let plan = VpnTransportPlan::new(1, "previous", 7).unwrap();
        for comment in [Some("foreign"), None] {
            let mut table = serde_json::json!({"family":"inet","name":"traffic_masq_transport_1"});
            if let Some(comment) = comment {
                table["comment"] = comment.into();
            }
            let executor = Arc::new(Executor {
                json: serde_json::to_vec(&serde_json::json!({"nftables":[{"table":table}]})).unwrap(),
                text: b"table inet traffic_masq_transport_1 {\nchain nested {\ncomment \"traffic-masq:transport:v1:1\"\n}\n}".to_vec(),
                writes: Mutex::new(Vec::new()),
            });
            assert!(apply_guard(executor.clone(), plan.clone(), false)
                .await
                .is_err());
            assert!(apply_guard(executor.clone(), plan.clone(), true)
                .await
                .is_err());
            assert!(executor.writes.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn old_nft_ownership_allows_atomic_replace_and_cleanup() {
        let plan = VpnTransportPlan::new(1, "previous", 7).unwrap();
        let executor = Arc::new(Executor {
            json:
                br#"{"nftables":[{"table":{"family":"inet","name":"traffic_masq_transport_1"}}]}"#
                    .to_vec(),
            text:
                b"table inet traffic_masq_transport_1 {\ncomment \"traffic-masq:transport:v1:1\"\n}"
                    .to_vec(),
            writes: Mutex::new(Vec::new()),
        });
        apply_guard(executor.clone(), plan.clone(), false)
            .await
            .unwrap();
        apply_guard(executor.clone(), plan.clone(), true)
            .await
            .unwrap();
        let writes = executor.writes.lock().unwrap();
        assert_eq!(
            writes[0],
            format!(
                "delete table inet traffic_masq_transport_1\n{}",
                plan.guard_table()
            )
        );
        assert_eq!(writes[1], "delete table inet traffic_masq_transport_1\n");
    }
}
