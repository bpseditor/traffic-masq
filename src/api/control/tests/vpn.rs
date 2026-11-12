use super::*;

#[tokio::test]
async fn vpn_import_accepts_config_and_native_forwarding_settings() {
    use std::os::unix::fs::PermissionsExt;
    let (service, directory) = vpn_enabled_service().await;
    let response = service
        .dispatch(Request::VpnImportProfile {
            name: "obfs.conf".into(),
            contents: valid_vpn_profile_contents(),
            forwarding: Some(traffic_masq_protocol::WgObfsForwarding {
                ip: "203.0.113.45".parse().unwrap(),
                port: 443,
                password: zeroize::Zeroizing::new("api-test-password".into()),
            }),
        })
        .await;
    assert!(matches!(response, Response::VpnProfileImported { .. }));
    let path = directory.path().join("wireguard/obfs.conf");
    let contents = std::fs::read(&path).unwrap();
    let profile = crate::vpn::WireGuardDriver
        .parse_named_profile("obfs.conf", &contents)
        .unwrap();
    assert_eq!(
        profile.wgobfs.unwrap().forward,
        "203.0.113.45:443".parse().unwrap()
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !format!("{:?}", service.dispatch(Request::VpnListProfiles).await)
            .contains("api-test-password")
    );
    let invalid = service
        .dispatch(Request::VpnImportProfile {
            name: "bad-obfs.conf".into(),
            contents: valid_vpn_profile_contents(),
            forwarding: Some(traffic_masq_protocol::WgObfsForwarding {
                ip: "203.0.113.45".parse().unwrap(),
                port: 0,
                password: zeroize::Zeroizing::new("invalid-secret".into()),
            }),
        })
        .await;
    assert!(matches!(
        invalid,
        Response::VpnError {
            detail: VpnErrorDetail::InvalidProfile { .. }
        }
    ));
    assert!(!format!("{invalid:?}").contains("invalid-secret"));
    assert!(!directory.path().join("wireguard/bad-obfs.conf").exists());
}

#[tokio::test]
async fn vpn_requests_are_rejected_when_vpn_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new_detached(config, network, dhcp, overrides);

    for request in [
        Request::VpnListProfiles,
        Request::VpnImportProfile {
            forwarding: None,
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        },
        Request::VpnDeleteProfile {
            name: "home.conf".to_string(),
        },
        Request::VpnStatus,
        Request::VpnActivate {
            name: "home.conf".to_string(),
        },
        Request::VpnDeactivate,
    ] {
        let response = service.dispatch(request).await;
        assert!(matches!(
            response,
            Response::VpnError {
                detail: VpnErrorDetail::VpnDisabled
            }
        ));
    }
}

#[tokio::test]
async fn vpn_import_list_delete_profile_round_trip_never_leaks_the_private_key() {
    let (service, _directory) = vpn_enabled_service().await;

    match service
        .dispatch(Request::VpnImportProfile {
            forwarding: None,
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await
    {
        Response::VpnProfileImported { name } => assert_eq!(name, "home.conf"),
        other => panic!("unexpected response: {other:?}"),
    }

    let profiles = match service.dispatch(Request::VpnListProfiles).await {
        Response::VpnProfiles { profiles } => profiles,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].name, "home.conf");
    assert!(profiles[0].size_bytes > 0);

    let debug = format!("{profiles:?}");
    assert!(!debug.contains(VALID_VPN_PRIVATE_KEY));
    let json = serde_json::to_string(&profiles).expect("serialize");
    assert!(!json.contains(VALID_VPN_PRIVATE_KEY));

    match service
        .dispatch(Request::VpnDeleteProfile {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnProfileDeleted { name } => assert_eq!(name, "home.conf"),
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::VpnListProfiles).await {
        Response::VpnProfiles { profiles } => assert!(profiles.is_empty()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_delete_missing_profile_returns_typed_not_found() {
    let (service, _directory) = vpn_enabled_service().await;

    match service
        .dispatch(Request::VpnDeleteProfile {
            name: "missing.conf".to_string(),
        })
        .await
    {
        Response::VpnError {
            detail: VpnErrorDetail::NotFound { name },
        } => assert_eq!(name, "missing.conf"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_activate_status_deactivate_workflow_dispatches_through_control_service() {
    let (service, _directory) = vpn_enabled_service().await;
    service
        .dispatch(Request::VpnImportProfile {
            forwarding: None,
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await;

    match service.dispatch(Request::VpnStatus).await {
        Response::VpnStatus { active } => assert!(active.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }

    commit_vpn_request(
        &service,
        Request::VpnActivate {
            name: "home.conf".into(),
        },
    )
    .await;

    match service.dispatch(Request::VpnStatus).await {
        Response::VpnStatus {
            active: Some(active),
        } => {
            assert_eq!(active.profile_name, "home.conf");
            assert!(active.up);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    commit_vpn_request(&service, Request::VpnDeactivate).await;

    match service.dispatch(Request::VpnStatus).await {
        Response::VpnStatus { active } => assert!(active.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_activate_conflict_with_foreign_interface_returns_typed_error() {
    let provider = FakeVpnProvider::default();
    provider.seed_foreign_link(
        crate::vpn::manager::OWNED_INTERFACE_NAME,
        OTHER_VPN_PRIVATE_KEY,
    );
    let (service, _directory) = vpn_enabled_service_with_provider(provider).await;
    service
        .dispatch(Request::VpnImportProfile {
            forwarding: None,
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await;

    match service
        .dispatch(Request::VpnActivate {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnError {
            detail: VpnErrorDetail::ForeignInterfaceConflict,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_activate_when_already_active_returns_typed_error() {
    let (service, _directory) = vpn_enabled_service().await;
    service
        .dispatch(Request::VpnImportProfile {
            forwarding: None,
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await;
    commit_vpn_request(
        &service,
        Request::VpnActivate {
            name: "home.conf".into(),
        },
    )
    .await;

    match service
        .dispatch(Request::VpnActivate {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnError {
            detail: VpnErrorDetail::AlreadyActive,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn unused_vpn_profile_storage_remains_available_with_execution_disabled() {
    let (service, _directory) = vpn_enabled_service().await;
    service.overrides.set_vpn_enabled(false).await.unwrap();
    assert!(matches!(
        service
            .dispatch(Request::VpnImportProfile {
                forwarding: None,
                name: "offline.conf".into(),
                contents: valid_vpn_profile_contents()
            })
            .await,
        Response::VpnProfileImported { .. }
    ));
    assert!(
        matches!(service.dispatch(Request::VpnListProfiles).await, Response::VpnProfiles { profiles } if profiles.len() == 1)
    );
    assert!(matches!(
        service
            .dispatch(Request::VpnDeleteProfile {
                name: "offline.conf".into()
            })
            .await,
        Response::VpnProfileDeleted { .. }
    ));
}

#[tokio::test]
async fn vpn_source_import_copies_profile_without_exposing_keys_or_changing_source() {
    let (service, directory) = vpn_enabled_service().await;
    let source = directory.path().join("sources");
    std::fs::create_dir(&source).unwrap();
    let contents =
        valid_vpn_profile_contents().replace("203.0.113.1:51820", "wg010.njalla.no:51820");
    std::fs::write(source.join("wg0.conf"), &contents).unwrap();
    let response = service.dispatch(Request::VpnListSources).await;
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains(VALID_VPN_PRIVATE_KEY));
    match response {
        Response::VpnSources {
            directory: path,
            profiles,
        } => {
            assert_eq!(path, source.display().to_string());
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].name, "wg0.conf");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        service
            .dispatch(Request::VpnImportFromSource {
                forwarding: None,
                name: "wg0.conf".into()
            })
            .await,
        Response::VpnProfileImported { .. }
    ));
    assert_eq!(
        std::fs::read_to_string(source.join("wg0.conf")).unwrap(),
        contents
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("wireguard/wg0.conf")).unwrap(),
        contents
    );
    assert!(matches!(
        service
            .dispatch(Request::VpnImportFromSource {
                forwarding: None,
                name: "../wg0.conf".into()
            })
            .await,
        Response::Error { .. }
    ));
}

#[tokio::test]
async fn standalone_vpn_is_tentative_rollback_then_commit_survives_reload() {
    let (service, directory) = vpn_enabled_service().await;
    service
        .dispatch(Request::VpnImportProfile {
            forwarding: None,
            name: "home.conf".into(),
            contents: valid_vpn_profile_contents(),
        })
        .await;
    let committed = service.overrides.snapshot().await;
    let response = service
        .dispatch(Request::VpnActivate {
            name: "home.conf".into(),
        })
        .await;
    let token = match response {
        Response::RouterTransactionPending { token, .. } => token,
        other => panic!("{other:?}"),
    };
    assert_eq!(service.overrides.snapshot().await, committed);
    assert!(service
        .vpn
        .as_ref()
        .unwrap()
        .status()
        .await
        .unwrap()
        .is_some());
    assert!(matches!(
        service.dispatch(Request::RouterRollback { token }).await,
        Response::RouterRolledBack
    ));
    assert!(service
        .vpn
        .as_ref()
        .unwrap()
        .status()
        .await
        .unwrap()
        .is_none());
    commit_vpn_request(
        &service,
        Request::VpnActivate {
            name: "home.conf".into(),
        },
    )
    .await;
    let reloaded = crate::state::overrides::RuntimeOverrideStore::in_state_dir(directory.path())
        .load()
        .await
        .unwrap();
    assert_eq!(
        reloaded.standalone_vpn.unwrap().profile.as_deref(),
        Some("home.conf")
    );
    assert!(reloaded.committed_router_transaction.is_some());
    assert_eq!(reloaded.revision, committed.revision + 1);
}

#[tokio::test]
async fn standalone_vpn_rollback_rebinds_owned_routes_after_tunnel_recreation() {
    let fixture = vpn_policy_fixture(true).await;
    commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
    )
    .await;
    fixture
        .service
        .dispatch(Request::VpnImportProfile {
            forwarding: None,
            name: "other.conf".into(),
            contents: valid_vpn_profile_contents(),
        })
        .await;
    let response = fixture
        .service
        .dispatch(Request::VpnActivate {
            name: "other.conf".into(),
        })
        .await;
    let token = match response {
        Response::RouterTransactionPending { token, .. } => token,
        other => panic!("{other:?}"),
    };
    fixture.network.interfaces.lock().unwrap()[0].index = 99;
    let response = fixture
        .service
        .dispatch(Request::RouterRollback { token })
        .await;
    assert!(
        matches!(response, Response::RouterRolledBack),
        "{response:?}"
    );
    assert_eq!(
        fixture
            .service
            .vpn
            .as_ref()
            .unwrap()
            .status()
            .await
            .unwrap()
            .unwrap()
            .profile_name,
        "home.conf"
    );
    assert!(fixture
        .network
        .routes
        .lock()
        .unwrap()
        .iter()
        .any(|route| route.output_interface_index == Some(99)));
    assert!(!fixture
        .network
        .routes
        .lock()
        .unwrap()
        .iter()
        .any(|route| route.output_interface_index == Some(42)));
}

#[tokio::test]
async fn standalone_failed_tunnel_restore_reinstates_protection_and_retains_recovery() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = vpn_policy_fixture(true).await;
    commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
    )
    .await;
    let committed = fixture.overrides.snapshot().await;
    let response = fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Direct,
        })
        .await;
    let token = match response {
        Response::RouterTransactionPending { token, .. } => token,
        other => panic!("{other:?}"),
    };
    let path = fixture
        .service
        .base_config
        .vpn
        .wireguard_config_dir
        .join("home.conf");
    let profile = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    fixture
        .provider
        .delete_link(OWNED_INTERFACE_NAME)
        .await
        .unwrap();
    let response = fixture
        .service
        .dispatch(Request::RouterRollback {
            token: token.clone(),
        })
        .await;
    assert!(
        matches!(response, Response::RouterError { .. }),
        "{response:?}"
    );
    let firewall = VpnPolicyFirewallBackend::new(fixture.executor.clone())
        .observe()
        .unwrap();
    assert!(
        firewall.desired.is_some(),
        "previous protection must precede tunnel restoration"
    );
    assert_eq!(fixture.overrides.snapshot().await, committed);
    assert!(fixture
        ._directory
        .path()
        .join("router-transaction.json")
        .exists());
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: token.clone()
            })
            .await,
        Response::RouterError { .. }
    ));
    std::fs::write(&path, profile).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let response = fixture
        .service
        .dispatch(Request::RouterRollback { token })
        .await;
    assert!(
        matches!(response, Response::RouterRolledBack),
        "{response:?}"
    );
    assert!(!fixture
        ._directory
        .path()
        .join("router-transaction.json")
        .exists());
    commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Direct,
        },
    )
    .await;
    assert_eq!(
        fixture.overrides.snapshot().await.revision,
        committed.revision + 1
    );
}

#[tokio::test]
async fn vpn_config_can_be_read_and_updated_without_exposing_debug_secrets() {
    let (service, _directory) = vpn_enabled_service().await;
    let original = valid_vpn_profile_contents();
    let name = "editable.conf".to_string();
    assert!(matches!(
        service
            .dispatch(Request::VpnImportProfile {
                name: name.clone(),
                contents: original.clone(),
                forwarding: None,
            })
            .await,
        Response::VpnProfileImported { .. }
    ));
    let response = service
        .dispatch(Request::VpnReadProfile { name: name.clone() })
        .await;
    assert!(!format!("{response:?}").contains("PrivateKey"));
    match response {
        Response::VpnProfileContents { contents, .. } => assert_eq!(&*contents.0, &original),
        other => panic!("unexpected response: {other:?}"),
    }
    let updated = format!("{original}\n# Edited configuration\n");
    assert!(matches!(
        service
            .dispatch(Request::VpnImportProfile {
                name: name.clone(),
                contents: updated.clone(),
                forwarding: None,
            })
            .await,
        Response::VpnProfileImported { .. }
    ));
    match service.dispatch(Request::VpnReadProfile { name }).await {
        Response::VpnProfileContents { contents, .. } => assert_eq!(&*contents.0, &updated),
        other => panic!("unexpected response: {other:?}"),
    }
    assert!(matches!(
        service
            .dispatch(Request::VpnReadProfile {
                name: "../escape.conf".into()
            })
            .await,
        Response::Error { .. }
    ));
}

#[tokio::test]
async fn vpn_autoconnect_settings_default_validate_and_persist() {
    let (service, _directory) = vpn_enabled_service().await;
    match service.dispatch(Request::GetVpnAutoconnect).await {
        Response::VpnAutoconnect { settings } => {
            assert_eq!(settings.attempts, 5);
            assert!(!settings.fallback_direct);
            assert!(settings.profile.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
    let settings = traffic_masq_protocol::VpnAutoconnectSettings {
        profile: None,
        attempts: 0,
        fallback_direct: true,
    };
    assert!(matches!(
        service
            .dispatch(Request::SetVpnAutoconnect { settings })
            .await,
        Response::Error { .. }
    ));
    let settings = traffic_masq_protocol::VpnAutoconnectSettings {
        profile: Some("missing.conf".into()),
        ..Default::default()
    };
    assert!(matches!(
        service
            .dispatch(Request::SetVpnAutoconnect { settings })
            .await,
        Response::Error { .. }
    ));
    let settings = traffic_masq_protocol::VpnAutoconnectSettings {
        attempts: 7,
        fallback_direct: true,
        ..Default::default()
    };
    assert!(matches!(
        service
            .dispatch(Request::SetVpnAutoconnect {
                settings: settings.clone()
            })
            .await,
        Response::VpnAutoconnect { .. }
    ));
    match service.dispatch(Request::GetVpnAutoconnect).await {
        Response::VpnAutoconnect { settings: actual } => assert_eq!(actual, settings),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_autoconnect_exhaustion_keeps_tunnel_by_default_and_disconnects_only_when_opted_in() {
    for fallback_direct in [false, true] {
        let (service, _directory) = vpn_enabled_service().await;
        let name = "retry.conf".to_string();
        assert!(matches!(
            service
                .dispatch(Request::VpnImportProfile {
                    name: name.clone(),
                    contents: valid_vpn_profile_contents(),
                    forwarding: None,
                })
                .await,
            Response::VpnProfileImported { .. }
        ));
        commit_vpn_request(&service, Request::VpnActivate { name: name.clone() }).await;
        let settings = traffic_masq_protocol::VpnAutoconnectSettings {
            profile: Some(name),
            fallback_direct,
            ..Default::default()
        };
        assert!(matches!(
            service
                .dispatch(Request::SetVpnAutoconnect { settings })
                .await,
            Response::VpnAutoconnect { .. }
        ));
        for _ in 0..5 {
            service.autoconnect_vpn_once().await.unwrap();
            assert!(service
                .vpn
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .is_some());
        }
        service.autoconnect_vpn_once().await.unwrap();
        assert_eq!(
            service
                .vpn
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .is_none(),
            fallback_direct
        );
        // Exhaustion must not silently restart the retry budget.
        service.autoconnect_vpn_once().await.unwrap();
        assert_eq!(
            service
                .vpn
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .is_none(),
            fallback_direct
        );
    }
}

#[tokio::test]
async fn vpn_autoconnect_commits_only_after_handshake_and_caps_failed_startup_attempts() {
    for healthy in [false, true] {
        let mut provider = FakeVpnProvider::default();
        provider.handshake = healthy.then(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        let (service, _directory) = vpn_enabled_service_with_provider(provider).await;
        service
            .dispatch(Request::VpnImportProfile {
                name: "auto.conf".into(),
                contents: valid_vpn_profile_contents(),
                forwarding: None,
            })
            .await;
        service
            .dispatch(Request::SetVpnAutoconnect {
                settings: traffic_masq_protocol::VpnAutoconnectSettings {
                    profile: Some("auto.conf".into()),
                    ..Default::default()
                },
            })
            .await;
        service.autoconnect_vpn_once().await.unwrap();
        assert_eq!(
            service.router.as_ref().unwrap().status().await,
            crate::core::router_transaction::CoordinatorStatus::Pending
        );
        if healthy {
            service.autoconnect_vpn_once().await.unwrap();
            assert_eq!(
                service.router.as_ref().unwrap().status().await,
                crate::core::router_transaction::CoordinatorStatus::Idle
            );
            assert!(service
                .vpn
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .is_some());
        } else {
            for _ in 1..5 {
                service.autoconnect_vpn_once().await.unwrap();
                assert_eq!(
                    service.router.as_ref().unwrap().status().await,
                    crate::core::router_transaction::CoordinatorStatus::Pending
                );
            }
            for _ in 0..2 {
                service.autoconnect_vpn_once().await.unwrap();
                assert_eq!(
                    service.router.as_ref().unwrap().status().await,
                    crate::core::router_transaction::CoordinatorStatus::Idle
                );
                assert!(service
                    .vpn
                    .as_ref()
                    .unwrap()
                    .status()
                    .await
                    .unwrap()
                    .is_none());
            }
        }
    }
}

#[tokio::test]
async fn vpn_autoconnect_never_replaces_a_new_manual_selection() {
    let (service, _directory) = vpn_enabled_service().await;
    for name in ["automatic.conf", "manual.conf"] {
        service
            .dispatch(Request::VpnImportProfile {
                name: name.into(),
                contents: valid_vpn_profile_contents(),
                forwarding: None,
            })
            .await;
    }
    service
        .dispatch(Request::SetVpnAutoconnect {
            settings: traffic_masq_protocol::VpnAutoconnectSettings {
                profile: Some("automatic.conf".into()),
                fallback_direct: true,
                ..Default::default()
            },
        })
        .await;
    commit_vpn_request(
        &service,
        Request::VpnActivate {
            name: "manual.conf".into(),
        },
    )
    .await;
    for request in [
        Request::VpnAutoconnectAttempt {
            profile: "automatic.conf".into(),
        },
        Request::VpnAutoconnectFallback {
            profile: "automatic.conf".into(),
        },
    ] {
        assert!(matches!(
            service.dispatch(request).await,
            Response::Error { .. }
        ));
        assert_eq!(
            service
                .vpn
                .as_ref()
                .unwrap()
                .status()
                .await
                .unwrap()
                .unwrap()
                .profile_name,
            "manual.conf"
        );
    }
}
