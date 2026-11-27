//! Driver-specific AP setup policy. Ownership and recovery stay in `concurrent`.
use anyhow::{ensure, Context, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Profile {
    Standard,
    Brcmfmac,
}

impl Profile {
    fn for_driver(driver: &std::ffi::OsStr) -> Self {
        if driver == "brcmfmac" {
            Self::Brcmfmac
        } else {
            Self::Standard
        }
    }
}

pub(super) async fn detect(parent: &str) -> Result<Profile> {
    crate::config::validate_interface_name(parent)?;
    let driver = tokio::fs::read_link(
        Path::new("/sys/class/net")
            .join(parent)
            .join("device/driver"),
    )
    .await
    .context("cannot identify Wi-Fi driver before virtual AP creation")?;
    Ok(Profile::for_driver(
        driver.file_name().context("invalid Wi-Fi driver link")?,
    ))
}

/// brcmfmac ignores NEW_INTERFACE's MAC but accepts RTM_NEWLINK while DOWN.
/// The caller must durably record and revalidate the creation receipt first.
pub(super) async fn set_created_ap_mac(
    network: &dyn crate::netlink::NetworkProvider,
    name: &str,
    mac: [u8; 6],
) -> Result<()> {
    let interfaces = network.list_interfaces().await?;
    let interface = interfaces
        .iter()
        .find(|link| link.name == name)
        .context("created AP disappeared before MAC correction")?;
    ensure!(
        !interface.is_up,
        "created AP is already UP; refusing driver MAC correction"
    );
    network.set_mac_address(name, mac).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_brcmfmac_driver_selects_workaround() {
        for name in ["brcmfmac_pcie", "brcmsmac", "ath9k", "", "BR C M"] {
            assert_eq!(Profile::for_driver(name.as_ref()), Profile::Standard);
        }
        assert_eq!(Profile::for_driver("brcmfmac".as_ref()), Profile::Brcmfmac);
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::*;
    #[tokio::test]
    async fn correction_requires_present_down_and_observable_link() {
        let network = crate::test_support::FakeNetworkProvider::default();
        let mac = [2, 1, 2, 3, 4, 5];
        assert!(set_created_ap_mac(&network, "ap0", mac).await.is_err());
        network.add_interface("ap0", 4).await;
        assert!(set_created_ap_mac(&network, "ap0", mac).await.is_err());
        assert!(network.macs.lock().await.is_empty());
        network
            .add_interface_with_state("ap0", 4, false, vec![])
            .await;
        *network.fail_interface_observation.lock().await = true;
        assert!(set_created_ap_mac(&network, "ap0", mac).await.is_err());
        assert!(network.macs.lock().await.is_empty());
        *network.fail_interface_observation.lock().await = false;
        set_created_ap_mac(&network, "ap0", mac).await.unwrap();
        assert_eq!(network.macs.lock().await["ap0"], mac);
    }
}
