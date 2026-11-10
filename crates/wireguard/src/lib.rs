//! WireGuard profile parsing and Linux netlink operations.

mod provider;
pub mod wgobfs;
mod wireguard;

pub use provider::{LazyNetlinkVpnProvider, NetlinkVpnProvider, ProviderError, VpnProvider};
pub use wireguard::{
    validate_wireguard_profile_name, ProfileError, WireGuardDriver, WireGuardEndpoint,
    WireGuardInterfaceConfig, WireGuardKey, WireGuardPeerConfig, WireGuardProfile,
};
