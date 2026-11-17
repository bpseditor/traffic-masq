// Explicit opt-in. The parent always reexecutes inside a fresh network namespace.
#[test]
#[ignore = "requires root, unshare, ip, nft and kernel WireGuard"]
fn transport_marks_kernel() {
    if std::env::var_os("TRAFFIC_MASQ_MARK_TEST_CHILD").is_none() {
        let result = std::process::Command::new("unshare")
            .args(["-n", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "transport_marks_kernel", "--ignored"])
            .env("TRAFFIC_MASQ_MARK_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(result.success());
        return;
    }
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "refusing to mutate the host network"
    );
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        use traffic_masq_wireguard::{NetlinkVpnProvider, VpnProvider, WireGuardKey};
        use traffic_masq_wireguard::wgobfs::{WgObfsClient, WgObfsConfig};
        use tokio::net::UdpSocket;
        use std::time::Duration;

        let provider = NetlinkVpnProvider::connect().unwrap();
        provider.create_link("mark-test", &WireGuardKey([7; 32]), None, "mark-test")
            .await.unwrap();
        provider.set_fwmark("mark-test", 0x2101).await.unwrap();
        assert_eq!(provider.fwmark("mark-test").await.unwrap(), Some(0x2101));
        provider.set_fwmark("mark-test", 0x2102).await.unwrap();
        assert_eq!(provider.fwmark("mark-test").await.unwrap(), Some(0x2102));
        provider.delete_link("mark-test").await.unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = WgObfsConfig::new(server.local_addr().unwrap(), "mark-test").unwrap();
        let rules = format!(
            "table inet mark_test {{ chain output {{ type filter hook output priority 0; policy accept; udp dport {} meta mark 0x2101 counter drop; }}; }}",
            server.local_addr().unwrap().port()
        );
        assert!(std::process::Command::new("nft").arg(rules).status().unwrap().success());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = [0u8; 148];
        packet[0] = 1;
        let marked = WgObfsClient::start_marked(&config, Some(0x2101)).await.unwrap();
        client.send_to(&packet, marked.local_addr()).await.unwrap();
        let mut received = [0u8; 512];
        assert!(tokio::time::timeout(Duration::from_millis(300), server.recv(&mut received)).await.is_err());
        let counters = std::process::Command::new("nft")
            .args(["list", "table", "inet", "mark_test"]).output().unwrap();
        assert!(counters.status.success());
        assert!(String::from_utf8(counters.stdout).unwrap().contains("counter packets 1 "));
        let plain = WgObfsClient::start(&config).await.unwrap();
        client.send_to(&packet, plain.local_addr()).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), server.recv(&mut received)).await.unwrap().unwrap() > 0);
    });
}
