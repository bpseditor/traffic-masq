//! Opt-in live test. Secrets are read from private files, never embedded here.
//! The WG UDP socket and native proxy live in the host namespace. The WG
//! interface is then moved into a private namespace, preserving its socket's
//! birth namespace. Only that namespace receives a default route.

use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use traffic_masq::vpn::{VpnDriver, WireGuardDriver, WireGuardProfileStore, WireGuardVpnDriver};
use traffic_masq_protocol::WgObfsForwarding;

mod support;
use support::namespace::{require_command, require_root, run, unique_suffix};

struct TestNetwork {
    namespace: String,
    interface: String,
    created: bool,
    moved: bool,
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        if self.created && !self.moved {
            let _ = Command::new("ip")
                .args(["link", "del", &self.interface])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = Command::new("ip")
            .args(["netns", "del", &self.namespace])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[tokio::test]
#[ignore = "requires root and explicit TRAFFIC_MASQ_WG_CONFIG / TRAFFIC_MASQ_WGOBFS_FORWARDING secret-file paths"]
async fn native_wgobfs_live_handshake_and_ping_in_private_namespace() -> Result<()> {
    require_root()?;
    require_command("ip", &["-V"])?;
    require_command("wg", &["--version"])?;
    let raw = zeroize::Zeroizing::new(std::fs::read(std::env::var("TRAFFIC_MASQ_WG_CONFIG")?)?);
    let forwarding_bytes = zeroize::Zeroizing::new(std::fs::read(std::env::var(
        "TRAFFIC_MASQ_WGOBFS_FORWARDING",
    )?)?);
    let settings: WgObfsForwarding = serde_json::from_slice(&forwarding_bytes)?;
    let config = traffic_masq_wireguard::wgobfs::WgObfsConfig::new(
        std::net::SocketAddr::new(settings.ip, settings.port),
        &settings.password,
    )?;
    let contents = WireGuardDriver.with_wgobfs("live.conf", &raw, &config)?;
    let profile = WireGuardDriver.parse_named_profile("live.conf", contents.as_bytes())?;
    let temp = tempfile::tempdir()?;
    let provider = std::sync::Arc::new(traffic_masq::vpn::NetlinkVpnProvider::connect()?);
    let driver = WireGuardVpnDriver::new(provider, WireGuardProfileStore::new(temp.path()));
    let suffix = unique_suffix();
    let namespace = format!("tm-obfs-live-{suffix}");
    let interface = format!("tmobl{suffix}");
    run("ip", &["netns", "add", &namespace])?;
    let mut network = TestNetwork {
        namespace,
        interface,
        created: false,
        moved: false,
    };
    driver
        .activate(
            &network.interface,
            &profile,
            "traffic-masq:live-wgobfs-test",
        )
        .await?;
    network.created = true;
    run(
        "ip",
        &[
            "link",
            "set",
            &network.interface,
            "netns",
            &network.namespace,
        ],
    )?;
    network.moved = true;
    run(
        "ip",
        &[
            "-n",
            &network.namespace,
            "link",
            "set",
            &network.interface,
            "up",
        ],
    )?;
    run("ip", &["-n", &network.namespace, "link", "set", "lo", "up"])?;
    run(
        "ip",
        &[
            "-n",
            &network.namespace,
            "route",
            "add",
            "default",
            "dev",
            &network.interface,
        ],
    )?;
    let target = std::env::var("TRAFFIC_MASQ_WG_TEST_IP").unwrap_or_else(|_| "10.66.66.1".into());
    let target = target
        .parse::<std::net::Ipv4Addr>()
        .context("invalid live test target")?
        .to_string();
    let namespace_copy = network.namespace.clone();
    let status = tokio::task::spawn_blocking(move || {
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespace_copy,
                "ping",
                "-c",
                "5",
                "-W",
                "3",
                &target,
            ])
            .status()
    })
    .await??;
    let observed = Command::new("ip")
        .args([
            "netns",
            "exec",
            &network.namespace,
            "wg",
            "show",
            &network.interface,
            "latest-handshakes",
        ])
        .output()?;
    anyhow::ensure!(
        observed.status.success(),
        "failed to observe the WireGuard handshake"
    );
    let handshakes = String::from_utf8(observed.stdout)?;
    anyhow::ensure!(
        handshakes.lines().any(|line| line
            .split_whitespace()
            .last()
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > 0)),
        "native rs-wgobfs did not establish a WireGuard handshake"
    );
    if !status.success() {
        bail!("WireGuard handshake succeeded, but the live target did not answer ping");
    }
    println!(
        "Native rs-wgobfs: live WireGuard handshake and ping succeeded; host routes untouched"
    );
    drop(network);
    drop(driver);
    Ok(())
}
