//! Admission and authorization policy shared by REST, control RPC and clients.
use crate::Request;

/// Execution discipline; interface transactions must leave convergence workers free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    ReadOnly,
    /// Persisted settings share the committed document and serialize with runtime writers.
    Settings,
    Direct,
    InterfaceTransaction,
    RouterTransaction,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestPolicy<'a> {
    pub administrator: bool,
    pub mutation: MutationKind,
    pub recovery_interface: Option<&'a str>,
    pub provisioning_recovery: bool,
    /// Reject overlapping direct/convenience writes while an interface change
    /// is pending. Scoped interface owners and router coordinator requests
    /// enforce their own transaction ownership instead.
    pub requires_idle_interfaces: bool,
    /// Preserve the longer deadline for writes, scans and dry-run plans.
    pub long_running: bool,
}

impl RequestPolicy<'_> {
    pub fn network_mutation(self) -> bool {
        matches!(
            self.mutation,
            MutationKind::Direct
                | MutationKind::InterfaceTransaction
                | MutationKind::RouterTransaction
        )
    }

    pub fn direct_network_mutation(self) -> bool {
        matches!(
            self.mutation,
            MutationKind::Direct | MutationKind::InterfaceTransaction
        )
    }

    /// Retain admission across convergence waits.
    pub fn needs_admission(self) -> bool {
        self.mutation != MutationKind::ReadOnly
    }

    /// Interface transactions leave execution free for their convergence workers.
    pub fn needs_execution(self) -> bool {
        matches!(
            self.mutation,
            MutationKind::Settings | MutationKind::Direct | MutationKind::RouterTransaction
        )
    }
}

impl<Interface, Proposal> Request<Interface, Proposal> {
    /// Stable command identity without inspecting or serializing payloads.
    pub fn command_name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::DaemonLogs { .. } => "daemon_logs",
            Self::GetApiHttpsConfig => "get_api_https_config",
            Self::ConfigureApiHttpsSettings { .. } => "configure_api_https_settings",
            Self::ResetApiHttpsSettings => "reset_api_https_settings",
            Self::GetDhcpDnsDefaults => "get_dhcp_dns_defaults",
            Self::ConfigureDhcpDnsDefaults { .. } => "configure_dhcp_dns_defaults",
            Self::GetSecurityConfig => "get_security_config",
            Self::ConfigureSecuritySettings { .. } => "configure_security_settings",
            Self::ResetSecuritySettings => "reset_security_settings",
            Self::ListInterfaces => "list_interfaces",
            Self::ListInterfaceInventory => "list_interface_inventory",
            Self::ListWifiInventory => "list_wifi_inventory",
            Self::SaveWifiClientProfile { .. } => "save_wifi_client_profile",
            Self::SaveWifiInterface { .. } => "save_wifi_interface",
            Self::SaveInterfaceConfig { .. } => "save_interface_config",
            Self::ForgetInterfaceConfig { .. } => "forget_interface_config",
            Self::ResetInterfaceOverride { .. } => "reset_interface_override",
            Self::GetInterfaceConfig { .. } => "get_interface_config",
            Self::DhcpStatus => "dhcp_status",
            Self::DhcpClientStatus => "dhcp_client_status",
            Self::GetDhcpClient { .. } => "get_dhcp_client",
            Self::ConfigureDhcpClient { .. } => "configure_dhcp_client",
            Self::DisableDhcpClient { .. } => "disable_dhcp_client",
            Self::RenewDhcpClient { .. } => "renew_dhcp_client",
            Self::ReleaseDhcpClient { .. } => "release_dhcp_client",
            Self::ConfigureDhcpSettings { .. } => "configure_dhcp_settings",
            Self::GetDhcpConfig { .. } => "get_dhcp_config",
            Self::ConfigureDhcp { .. } => "configure_dhcp",
            Self::DisableDhcp { .. } => "disable_dhcp",
            Self::ListLeases { .. } => "list_leases",
            Self::DryRunInterface { .. } => "dry_run_interface",
            Self::DryRunInterfaceEdit { .. } => "dry_run_interface_edit",
            Self::ApplyInterface { .. } => "apply_interface",
            Self::ApplyInterfaceEdit { .. } => "apply_interface_edit",
            Self::CommitNetworkChange { .. } => "commit_network_change",
            Self::RollbackNetworkChange { .. } => "rollback_network_change",
            Self::PendingNetworkChanges => "pending_network_changes",
            Self::RouterStatus => "router_status",
            Self::SharingDiagnostics { .. } => "sharing_diagnostics",
            Self::SaveRouterIntent { .. } => "save_router_intent",
            Self::RouterIntentPreview { .. } => "router_intent_preview",
            Self::RouterPlan { .. } => "router_plan",
            Self::RouterApply { .. } => "router_apply",
            Self::RouterCommit { .. } => "router_commit",
            Self::RouterRollback { .. } => "router_rollback",
            Self::RouterPendingTransaction => "router_pending_transaction",
            Self::ListRouteInventory { .. } => "list_route_inventory",
            Self::ListRoutes { .. } => "list_routes",
            Self::GetRouterConfig => "get_router_config",
            Self::RouterProvisioningPreview { .. } => "router_provisioning_preview",
            Self::RouterProvisioningApply { .. } => "router_provisioning_apply",
            Self::RouterProvisioningStatus => "router_provisioning_status",
            Self::RouterProvisioningRepair => "router_provisioning_repair",
            Self::VpnListSources => "vpn_list_sources",
            Self::VpnImportFromSource { .. } => "vpn_import_from_source",
            Self::VpnListProfiles => "vpn_list_profiles",
            Self::VpnImportProfile { .. } => "vpn_import_profile",
            Self::VpnDeleteProfile { .. } => "vpn_delete_profile",
            Self::GetVpnConfig => "get_vpn_config",
            Self::SetVpnEnabled { .. } => "set_vpn_enabled",
            Self::VpnStatus => "vpn_status",
            Self::VpnActivate { .. } => "vpn_activate",
            Self::VpnDeactivate => "vpn_deactivate",
            Self::VpnPolicyStatus => "vpn_policy_status",
            Self::VpnPolicySetMode { .. } => "vpn_policy_set_mode",
            Self::VpnPolicyClearMode => "vpn_policy_clear_mode",
            Self::WifiStatus => "wifi_status",
            Self::GetWifiConfig { .. } => "get_wifi_config",
            Self::ConfigureWifi { .. } => "configure_wifi",
            Self::ProvisionWifiAccessPoint { .. } => "provision_wifi_access_point",
            Self::DisableWifi { .. } => "disable_wifi",
            Self::WifiSetPassphrase { .. } => "wifi_set_passphrase",
            Self::ListWifiStations { .. } => "list_wifi_stations",
            Self::WifiDeauthStation { .. } => "wifi_deauth_station",
            Self::WifiReload { .. } => "wifi_reload",
            Self::WifiClientStatus => "wifi_client_status",
            Self::GetWifiClientConfig { .. } => "get_wifi_client_config",
            Self::ConfigureWifiClient { .. } => "configure_wifi_client",
            Self::DisableWifiClient { .. } => "disable_wifi_client",
            Self::WifiClientSetPassphrase { .. } => "wifi_client_set_passphrase",
            Self::WifiClientReconnect { .. } => "wifi_client_reconnect",
            Self::WifiClientScan { .. } => "wifi_client_scan",
            Self::ListWifiApProfiles => "list_wifi_ap_profiles",
            Self::SaveWifiApProfile { .. } => "save_wifi_ap_profile",
            Self::DeleteWifiApProfile { .. } => "delete_wifi_ap_profile",
            Self::ActivateWifiApProfile { .. } => "activate_wifi_ap_profile",
            Self::ListWifiClientProfiles => "list_wifi_client_profiles",
            Self::GetWifiClientProfile { .. } => "get_wifi_client_profile",
            Self::CreateWifiClientProfile { .. } => "create_wifi_client_profile",
            Self::UpdateWifiClientProfile { .. } => "update_wifi_client_profile",
            Self::DeleteWifiClientProfile { .. } => "delete_wifi_client_profile",
            Self::ProvisionWifiClient { .. } => "provision_wifi_client",
            Self::ActivateWifiClientProfile { .. } => "activate_wifi_client_profile",
            Self::DeactivateWifiClientProfile { .. } => "deactivate_wifi_client_profile",
        }
    }

    /// Exhaustive by design: adding a command requires an explicit policy.
    pub fn policy(&self) -> RequestPolicy<'_> {
        use MutationKind::*;
        use Request::*;
        match self {
            Ping
            | GetApiHttpsConfig
            | GetDhcpDnsDefaults
            | GetSecurityConfig
            | ListInterfaces
            | ListInterfaceInventory
            | ListWifiInventory
            | DhcpStatus
            | DhcpClientStatus
            | PendingNetworkChanges
            | RouterStatus
            | RouterPendingTransaction
            | ListRouteInventory { .. }
            | ListRoutes { .. }
            | GetRouterConfig
            | RouterProvisioningStatus
            | VpnListProfiles
            | GetVpnConfig
            | VpnStatus
            | VpnPolicyStatus
            | WifiStatus
            | WifiClientStatus
            | ListWifiApProfiles
            | ListWifiClientProfiles
            | GetWifiClientProfile { .. } => RequestPolicy {
                administrator: false,
                mutation: ReadOnly,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: false,
            },
            SharingDiagnostics { .. } => RequestPolicy {
                administrator: true,
                mutation: ReadOnly,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: true,
            },
            DaemonLogs { .. } | VpnListSources => RequestPolicy {
                administrator: true,
                mutation: ReadOnly,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: false,
            },
            ConfigureApiHttpsSettings { .. }
            | ResetApiHttpsSettings
            | ConfigureSecuritySettings { .. }
            | ConfigureDhcpDnsDefaults { .. }
            | ResetSecuritySettings => RequestPolicy {
                administrator: true,
                mutation: Settings,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: true,
            },
            SaveWifiClientProfile { interface, .. }
            | SaveWifiInterface { interface, .. }
            | SaveInterfaceConfig { interface, .. }
            | ForgetInterfaceConfig { interface, .. }
            | ResetInterfaceOverride { interface, .. }
            | RenewDhcpClient { interface, .. }
            | ReleaseDhcpClient { interface, .. }
            | WifiDeauthStation { interface, .. }
            | WifiReload { interface, .. }
            | WifiClientReconnect { interface, .. }
            | WifiClientScan { interface, .. } => RequestPolicy {
                administrator: true,
                mutation: Direct,
                recovery_interface: Some(interface),
                provisioning_recovery: false,
                requires_idle_interfaces: true,
                long_running: true,
            },
            GetInterfaceConfig { interface, .. }
            | GetDhcpClient { interface, .. }
            | GetDhcpConfig { interface, .. }
            | ListLeases { interface, .. }
            | GetWifiConfig { interface, .. }
            | ListWifiStations { interface, .. }
            | GetWifiClientConfig { interface, .. } => RequestPolicy {
                administrator: false,
                mutation: ReadOnly,
                recovery_interface: Some(interface),
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: false,
            },
            ConfigureDhcpClient { interface, .. }
            | DisableDhcpClient { interface, .. }
            | ConfigureDhcpSettings { interface, .. }
            | ConfigureDhcp { interface, .. }
            | DisableDhcp { interface, .. }
            | WifiSetPassphrase { interface, .. }
            | WifiClientSetPassphrase { interface, .. }
            | ConfigureWifi { interface, .. }
            | ProvisionWifiAccessPoint { interface, .. }
            | DisableWifi { interface, .. }
            | ConfigureWifiClient { interface, .. }
            | DisableWifiClient { interface, .. }
            | ActivateWifiApProfile { interface, .. }
            | ProvisionWifiClient { interface, .. }
            | ActivateWifiClientProfile { interface, .. }
            | DeactivateWifiClientProfile { interface, .. } => RequestPolicy {
                administrator: true,
                mutation: InterfaceTransaction,
                recovery_interface: Some(interface),
                provisioning_recovery: false,
                requires_idle_interfaces: true,
                long_running: true,
            },
            ApplyInterface { interface, .. } | ApplyInterfaceEdit { interface, .. } => {
                RequestPolicy {
                    administrator: true,
                    mutation: InterfaceTransaction,
                    recovery_interface: Some(interface),
                    provisioning_recovery: false,
                    requires_idle_interfaces: false,
                    long_running: true,
                }
            }
            DryRunInterface { interface, .. } | DryRunInterfaceEdit { interface, .. } => {
                RequestPolicy {
                    administrator: false,
                    mutation: ReadOnly,
                    recovery_interface: Some(interface),
                    provisioning_recovery: false,
                    requires_idle_interfaces: false,
                    long_running: true,
                }
            }
            CommitNetworkChange { .. } => RequestPolicy {
                administrator: true,
                mutation: InterfaceTransaction,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: true,
            },
            RollbackNetworkChange { .. } => RequestPolicy {
                administrator: true,
                mutation: InterfaceTransaction,
                recovery_interface: None,
                provisioning_recovery: true,
                requires_idle_interfaces: false,
                long_running: true,
            },
            SaveRouterIntent { .. }
            | VpnImportFromSource { .. }
            | VpnImportProfile { .. }
            | VpnDeleteProfile { .. }
            | SaveWifiApProfile { .. }
            | DeleteWifiApProfile { .. }
            | CreateWifiClientProfile { .. }
            | UpdateWifiClientProfile { .. }
            | DeleteWifiClientProfile { .. } => RequestPolicy {
                administrator: true,
                mutation: Direct,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: true,
                long_running: true,
            },
            RouterIntentPreview { .. } | RouterPlan { .. } | RouterProvisioningPreview { .. } => {
                RequestPolicy {
                    administrator: false,
                    mutation: ReadOnly,
                    recovery_interface: None,
                    provisioning_recovery: false,
                    requires_idle_interfaces: false,
                    long_running: true,
                }
            }
            RouterApply { .. }
            | RouterProvisioningApply { .. }
            | RouterProvisioningRepair
            | SetVpnEnabled { .. }
            | VpnActivate { .. }
            | VpnDeactivate
            | VpnPolicySetMode { .. }
            | VpnPolicyClearMode => RequestPolicy {
                administrator: true,
                mutation: RouterTransaction,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: true,
            },
            RouterCommit { .. } | RouterRollback { .. } => RequestPolicy {
                administrator: true,
                mutation: RouterTransaction,
                recovery_interface: None,
                provisioning_recovery: true,
                requires_idle_interfaces: false,
                long_running: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ControlRequest as Request;

    #[test]
    fn interface_convergence_can_run_while_other_writers_keep_execution_reserved() {
        let interface = Request::ApplyInterfaceEdit {
            interface: "wan0".into(),
            edit: crate::InterfaceEditRequest {
                wifi_concurrent: false,
                randomize_mac: false,
                mac_address: None,
                cidr: String::new(),
                role: crate::InterfaceRole::Input,
                managed: true,
                allow_management_change: false,
            },
        };
        assert!(interface.policy().needs_admission());
        assert!(!interface.policy().needs_execution());
        assert_eq!(interface.policy().recovery_interface, Some("wan0"));
        for writer in [
            Request::RouterApply {
                proposal: Default::default(),
            },
            Request::ResetSecuritySettings,
            Request::WifiClientScan {
                interface: "wan0".into(),
            },
        ] {
            assert!(writer.policy().needs_admission());
            assert!(writer.policy().needs_execution());
        }
        assert!(!Request::ResetSecuritySettings.policy().network_mutation());
    }

    #[test]
    fn recovery_and_administrative_reads_are_independent_of_mutation() {
        for request in [Request::DaemonLogs { limit: 1 }, Request::VpnListSources] {
            assert!(request.policy().administrator);
            assert!(!request.policy().needs_admission());
            assert!(!request.policy().long_running);
        }
        assert!(
            Request::RollbackNetworkChange { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
        assert!(
            !Request::CommitNetworkChange { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
        assert!(
            Request::RouterCommit { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
        assert!(
            Request::RouterRollback { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
    }
}

#[cfg(test)]
mod pending_change_tests {
    use crate::ControlRequest as Request;

    #[test]
    fn overlapping_writes_require_idle_but_reads_and_transaction_owners_remain_available() {
        for request in [
            Request::WifiReload {
                interface: "lan0".into(),
            },
            Request::DisableWifi {
                interface: "lan0".into(),
            },
            Request::DisableDhcpClient {
                interface: "wan0".into(),
            },
            Request::DeleteWifiClientProfile {
                id: "office".into(),
            },
        ] {
            let policy = request.policy();
            assert!(policy.network_mutation(), "{request:?}");
            assert!(policy.requires_idle_interfaces, "{request:?}");
        }
        for request in [
            Request::Ping,
            Request::VpnDeactivate,
            Request::PendingNetworkChanges,
            Request::CommitNetworkChange { token: "t".into() },
            Request::RollbackNetworkChange { token: "t".into() },
            Request::ApplyInterfaceEdit {
                interface: "lan0".into(),
                edit: crate::InterfaceEditRequest {
                    wifi_concurrent: false,
                    randomize_mac: false,
                    mac_address: None,
                    cidr: "192.0.2.1/24".into(),
                    role: crate::InterfaceRole::Output,
                    managed: true,
                    allow_management_change: true,
                },
            },
        ] {
            assert!(!request.policy().requires_idle_interfaces, "{request:?}");
        }
    }
}
