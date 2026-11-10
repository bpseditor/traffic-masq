use crate::vpn::{VpnDriver, VpnDriverError, VpnKind, VpnProvider};
use std::collections::BTreeMap;
use std::sync::Mutex;
use traffic_masq_wireguard::wgobfs::WgObfsClient;

pub use traffic_masq_wireguard::{
    validate_wireguard_profile_name, ProfileError, WireGuardDriver, WireGuardEndpoint,
    WireGuardInterfaceConfig, WireGuardKey, WireGuardPeerConfig, WireGuardProfile,
};

pub struct WireGuardVpnDriver {
    parser: WireGuardDriver,
    store: crate::vpn::store::WireGuardProfileStore,
    provider: std::sync::Arc<dyn VpnProvider>,
    transports: Mutex<BTreeMap<String, WgObfsClient>>,
}

impl WireGuardVpnDriver {
    pub fn new(
        provider: std::sync::Arc<dyn VpnProvider>,
        store: crate::vpn::store::WireGuardProfileStore,
    ) -> Self {
        Self {
            parser: WireGuardDriver,
            store,
            provider,
            transports: Mutex::new(BTreeMap::new()),
        }
    }

    async fn prepare_peers(
        &self,
        profile: &WireGuardProfile,
    ) -> Result<(Vec<WireGuardPeerConfig>, Option<WgObfsClient>), VpnDriverError> {
        let mut peers = profile.peers.clone();
        let transport = if let Some(config) = &profile.wgobfs {
            if peers.len() != 1 {
                return Err(VpnDriverError::Transport(
                    "rs-wgobfs forwarding requires exactly one WireGuard peer".into(),
                ));
            }
            let client = WgObfsClient::start(config)
                .await
                .map_err(|error| VpnDriverError::Transport(error.to_string()))?;
            peers[0].endpoint = Some(WireGuardEndpoint::Address(client.local_addr()));
            Some(client)
        } else {
            None
        };
        for peer in &mut peers {
            if let Some(endpoint) = &peer.endpoint {
                peer.endpoint = Some(WireGuardEndpoint::Address(
                    endpoint.resolve().await.map_err(|error| {
                        VpnDriverError::Transport(format!(
                            "WireGuard endpoint resolution failed: {error}"
                        ))
                    })?,
                ));
            }
        }
        Ok((peers, transport))
    }

    /// Replace loopback proxy destinations with the actual transport server.
    pub async fn transport_endpoints(
        &self,
        interface: &str,
    ) -> Result<Vec<std::net::SocketAddr>, VpnDriverError> {
        let mut endpoints = self.provider.peer_endpoints(interface).await?;
        if let Some(client) = self
            .transports
            .lock()
            .expect("transport mutex poisoned")
            .get(interface)
        {
            if !client.is_running() {
                return Err(VpnDriverError::Transport("rs-wgobfs client stopped".into()));
            }
            for address in &mut endpoints {
                if *address == client.local_addr() {
                    *address = client.forward_addr();
                }
            }
        }
        Ok(endpoints)
    }
}

#[async_trait::async_trait]
impl VpnDriver for WireGuardVpnDriver {
    type Profile = WireGuardProfile;
    type OwnershipProof = WireGuardKey;

    fn kind(&self) -> VpnKind {
        VpnKind::WireGuard
    }

    fn list_profiles(
        &self,
    ) -> Result<Vec<crate::vpn::store::WireGuardProfileSummary>, VpnDriverError> {
        Ok(self.store.list()?)
    }

    fn import_profile(&self, name: &str, raw: &[u8]) -> Result<Self::Profile, VpnDriverError> {
        Ok(self.store.import(&self.parser, name, raw)?)
    }

    fn delete_profile(&self, name: &str) -> Result<(), VpnDriverError> {
        Ok(self.store.delete(name)?)
    }

    fn read_profile(&self, name: &str) -> Result<Self::Profile, VpnDriverError> {
        Ok(self.store.read(&self.parser, name)?)
    }

    async fn link_exists(&self, interface: &str) -> Result<bool, VpnDriverError> {
        Ok(self.provider.link_exists(interface).await?)
    }

    async fn is_up(&self, interface: &str) -> Result<bool, VpnDriverError> {
        let up = self.provider.is_up(interface).await?;
        Ok(up
            && self
                .transports
                .lock()
                .expect("transport mutex poisoned")
                .get(interface)
                .is_none_or(WgObfsClient::is_running))
    }

    async fn read_ownership_proof(
        &self,
        interface: &str,
    ) -> Result<Option<Self::OwnershipProof>, VpnDriverError> {
        Ok(self.provider.public_key(interface).await?)
    }

    async fn delete_if_launch_marker(
        &self,
        interface: &str,
        launch_marker: &str,
    ) -> Result<bool, VpnDriverError> {
        let deleted = self
            .provider
            .delete_link_if_launch_marker(interface, launch_marker)
            .await?;
        if deleted {
            self.stop_runtime(interface).await?;
        }
        Ok(deleted)
    }

    async fn activate(
        &self,
        interface: &str,
        profile: &Self::Profile,
        launch_marker: &str,
    ) -> Result<Self::OwnershipProof, VpnDriverError> {
        let (peers, transport) = self.prepare_peers(profile).await?;
        self.provider
            .create_link(
                interface,
                &profile.interface.private_key,
                profile.interface.listen_port,
                launch_marker,
            )
            .await?;

        let activation = async {
            if let Some(mtu) = profile.interface.mtu {
                self.provider.set_mtu(interface, mtu).await?;
            }
            self.provider
                .set_addresses(interface, &profile.interface.addresses)
                .await?;
            self.provider.set_peers(interface, &peers).await?;
            self.provider.set_link_up(interface).await?;

            self.provider.public_key(interface).await?.ok_or_else(|| {
                tracing::error!(
                    interface,
                    "kernel reported no public key for the interface immediately after \
                     create_link/set_addresses/set_peers/set_link_up; refusing to report \
                     ownership (this means the interface has no private key configured, not \
                     that a foreign interface is present)"
                );
                VpnDriverError::NoOwnershipProof(interface.to_string())
            })
        }
        .await;

        match activation {
            Ok(proof) => {
                if let Some(client) = transport {
                    self.transports
                        .lock()
                        .expect("transport mutex poisoned")
                        .insert(interface.into(), client);
                }
                Ok(proof)
            }
            Err(error) => match self
                .provider
                .delete_link_if_launch_marker(interface, launch_marker)
                .await
            {
                Ok(true) => Err(error),
                Ok(false) => Err(VpnDriverError::ActivationCleanupFailed {
                    interface: interface.to_string(),
                    activation: error.to_string(),
                    cleanup: "launch marker no longer matches; refusing to delete the interface"
                        .to_string(),
                }),
                Err(cleanup) => Err(VpnDriverError::ActivationCleanupFailed {
                    interface: interface.to_string(),
                    activation: error.to_string(),
                    cleanup: cleanup.to_string(),
                }),
            },
        }
    }

    async fn deactivate(&self, interface: &str) -> Result<(), VpnDriverError> {
        self.provider.set_link_down(interface).await?;
        self.provider.delete_link(interface).await?;
        self.stop_runtime(interface).await?;
        Ok(())
    }

    async fn restore_runtime(
        &self,
        interface: &str,
        profile_name: &str,
    ) -> Result<(), VpnDriverError> {
        if self
            .transports
            .lock()
            .expect("transport mutex poisoned")
            .get(interface)
            .is_some_and(WgObfsClient::is_running)
        {
            return Ok(());
        }
        let profile = self.read_profile(profile_name)?;
        if profile.wgobfs.is_none() {
            return Ok(());
        }
        let (peers, transport) = self.prepare_peers(&profile).await?;
        self.provider.set_peers(interface, &peers).await?;
        if let Some(client) = transport {
            self.transports
                .lock()
                .expect("transport mutex poisoned")
                .insert(interface.into(), client);
        }
        Ok(())
    }

    async fn stop_runtime(&self, interface: &str) -> Result<(), VpnDriverError> {
        self.transports
            .lock()
            .expect("transport mutex poisoned")
            .remove(interface);
        Ok(())
    }

    fn encode_ownership_proof(&self, proof: &Self::OwnershipProof) -> Vec<u8> {
        proof.0.to_vec()
    }

    fn decode_ownership_proof(&self, raw: &[u8]) -> Result<Self::OwnershipProof, VpnDriverError> {
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| VpnDriverError::InvalidOwnershipProof)?;
        Ok(WireGuardKey(bytes))
    }
}
