//! Daemon-owned retry budget. All network changes use the control transaction gate.
use super::*;
use traffic_masq_protocol::VpnAutoconnectSettings;

#[derive(Default)]
pub(super) struct State {
    settings: Option<VpnAutoconnectSettings>,
    attempts: u8,
    pending: Option<String>,
    exhausted: bool,
}

impl ControlService {
    fn read_vpn_autoconnect(&self) -> Result<VpnAutoconnectSettings> {
        let path = self.config.runtime.state_dir.join("vpn-autoconnect.json");
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub(super) async fn get_vpn_autoconnect(&self) -> Response {
        match self.read_vpn_autoconnect() {
            Ok(settings) => Response::VpnAutoconnect { settings },
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        }
    }

    pub(super) async fn set_vpn_autoconnect(&self, settings: VpnAutoconnectSettings) -> Response {
        let result = (|| -> Result<()> {
            anyhow::ensure!(
                (1..=20).contains(&settings.attempts),
                "Attempts must be between 1 and 20"
            );
            if let Some(name) = &settings.profile {
                let store =
                    crate::vpn::WireGuardProfileStore::new(&self.config.vpn.wireguard_config_dir);
                store.read(&crate::vpn::WireGuardDriver, name)?;
            }
            let path = self.config.runtime.state_dir.join("vpn-autoconnect.json");
            crate::atomic_file::replace_preserving_on_error(
                &path,
                &serde_json::to_vec(&settings)?,
                0o600,
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => Response::VpnAutoconnect { settings },
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        }
    }

    async fn autoconnect_admitted_profile(&self, profile: &str, fallback: bool) -> bool {
        let Ok(settings) = self.read_vpn_autoconnect() else {
            return false;
        };
        let Ok(config) = self.effective_config().await else {
            return false;
        };
        if settings.profile.as_deref() != Some(profile)
            || (fallback && !settings.fallback_direct)
            || !config.vpn.enabled
            || !config.router.vpn_chain.is_empty()
        {
            return false;
        }
        let Some(vpn) = &self.vpn else { return false };
        match vpn.status().await {
            Ok(None) => true,
            Ok(Some(active)) => active.profile_name == profile,
            Err(_) => false,
        }
    }

    pub(super) async fn vpn_autoconnect_attempt(&self, profile: String) -> Response {
        if !self.autoconnect_admitted_profile(&profile, false).await {
            return Response::Error {
                message: "VPN autoconnect selection changed; attempt cancelled".into(),
            };
        }
        self.vpn_activate(profile).await
    }

    // Called through dispatch so recovery and mutation admission are identical
    // to operator-driven router transactions. Recheck intent under that gate.
    pub(super) async fn vpn_autoconnect_fallback(&self, profile: String) -> Response {
        if !self.autoconnect_admitted_profile(&profile, true).await {
            return Response::Error {
                message: "VPN autoconnect selection changed or direct fallback is disabled".into(),
            };
        }
        self.apply_standalone_vpn(true, None, Some(VpnPolicyMode::Direct))
            .await
    }

    pub(crate) async fn autoconnect_vpn_once(&self) -> Result<()> {
        let mut state = self.vpn_autoconnect.lock().await;
        // Timeout recovery or an operator may have already completed our
        // tentative transaction. Never retain or act on that stale token.
        if let Some(router) = &self.router {
            if state.pending.is_some() && router.pending_token().await != state.pending {
                state.pending = None;
            }
        }
        let settings = self.read_vpn_autoconnect()?;
        if state.settings.as_ref() != Some(&settings) {
            // Finish our own tentative attempt before accepting a new policy.
            if let Some(token) = state.pending.take() {
                let response = self
                    .dispatch(Request::RouterRollback {
                        token: token.clone(),
                    })
                    .await;
                if !matches!(response, Response::RouterRolledBack) {
                    state.pending = Some(token);
                    anyhow::bail!(
                        "Cannot replace autoconnect policy before rollback: {response:?}"
                    );
                }
            }
            *state = State {
                settings: Some(settings.clone()),
                ..Default::default()
            };
        }
        let Some(name) = &settings.profile else {
            return Ok(());
        };
        let effective = self.effective_config().await.map_err(anyhow::Error::msg)?;
        if !effective.vpn.enabled || !effective.router.vpn_chain.is_empty() {
            return Ok(());
        }
        let Some(vpn) = &self.vpn else { return Ok(()) };
        let active = vpn.status().await?;
        // Do not replace a profile explicitly selected by an operator.
        if active.as_ref().is_some_and(|a| a.profile_name != *name) {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let healthy = if let Some(active) = active.as_ref().filter(|a| a.up) {
            vpn.latest_handshake(&active.interface)
                .await?
                .is_some_and(|at| at <= now && now - at <= 180)
        } else {
            false
        };
        if healthy {
            if let Some(token) = state.pending.take() {
                let response = self.dispatch(Request::RouterCommit { token }).await;
                anyhow::ensure!(
                    matches!(response, Response::RouterCommitted { .. }),
                    "VPN autoconnect commit failed: {response:?}"
                );
            }
            state.attempts = 0;
            state.exhausted = false;
            return Ok(());
        }
        if let Some(token) = state.pending.take() {
            let response = self.dispatch(Request::RouterRollback { token }).await;
            anyhow::ensure!(
                matches!(response, Response::RouterRolledBack),
                "VPN autoconnect rollback failed: {response:?}"
            );
        }
        if state.exhausted {
            return Ok(());
        }
        if !self.transactions.pending().await.is_empty() || self.router.is_none() {
            return Ok(());
        }
        if let Some(router) = &self.router {
            if router.status().await != crate::core::router_transaction::CoordinatorStatus::Idle {
                return Ok(());
            }
        }
        if state.attempts >= settings.attempts {
            state.exhausted = true;
            if settings.fallback_direct {
                let response = self
                    .dispatch(Request::VpnAutoconnectFallback {
                        profile: name.clone(),
                    })
                    .await;
                match response {
                    Response::RouterTransactionPending { token, .. } => {
                        let result = self.dispatch(Request::RouterCommit { token }).await;
                        anyhow::ensure!(
                            matches!(result, Response::RouterCommitted { .. }),
                            "Direct fallback commit failed: {result:?}"
                        );
                    }
                    other => anyhow::bail!("Direct fallback failed: {other:?}"),
                }
            }
            tracing::warn!(attempts = state.attempts, "VPN autoconnect exhausted");
            return Ok(());
        }
        if let Some(active) = vpn.status().await? {
            let _admission = self.network_mutations.admit().await;
            let _execution = self.network_mutations.execute().await;
            self.overrides
                .recovery()
                .check_scope(&self.config.runtime.state_dir, None)?;
            if vpn
                .status()
                .await?
                .is_none_or(|current| current.profile_name != *name)
            {
                return Ok(());
            }
            vpn.enable_keepalive(&active.interface).await?;
        }
        state.attempts += 1;
        let response = self
            .dispatch(Request::VpnAutoconnectAttempt {
                profile: name.clone(),
            })
            .await;
        match response {
            Response::RouterTransactionPending { token, .. } => {
                state.pending = Some(token);
                let _admission = self.network_mutations.admit().await;
                let _execution = self.network_mutations.execute().await;
                vpn.enable_keepalive(crate::vpn::manager::OWNED_INTERFACE_NAME)
                    .await?;
            }
            Response::VpnError {
                detail: VpnErrorDetail::AlreadyActive,
            } => {}
            other => {
                tracing::warn!(attempt = state.attempts, response = ?other, "VPN autoconnect attempt failed")
            }
        }
        Ok(())
    }
}
