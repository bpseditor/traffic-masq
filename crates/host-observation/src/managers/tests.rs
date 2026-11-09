use super::*;

#[tokio::test]
async fn scan_canonicalizes_aliases_and_ignores_unavailable_or_supervised_processes() {
    let root = tempfile::tempdir().unwrap();
    for (pid, comm) in [
        ("1", "systemd-network"),
        ("2", "systemd-networkd"),
        ("3", "connmand"),
        ("4", "connman"),
        ("5", "hostapd"),
        ("6", "wpa_supplicant"),
        ("7", "NetworkManager"),
        ("non-pid", "iwd"),
    ] {
        let path = root.path().join(pid);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("comm"), format!("{comm}\n")).unwrap();
    }
    // A process can disappear after readdir but before its comm is read.
    std::fs::create_dir(root.path().join("8")).unwrap();
    assert_eq!(
        find_competing_network_managers_at(root.path()).await,
        ["NetworkManager", "connman", "systemd-networkd"],
    );
}
