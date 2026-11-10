use super::*;
use std::time::Duration;

fn packet(kind: u8, size: usize) -> Vec<u8> {
    let mut bytes: Vec<_> = (0..size).map(|i| (i * 17 + 3) as u8).collect();
    bytes[..4].copy_from_slice(&[kind, 0, 0, 0]);
    if kind == 1 {
        bytes[132..148].fill(0);
    }
    if kind == 2 {
        bytes[76..92].fill(0);
    }
    bytes
}

#[test]
fn chacha6_reference_vector() {
    // rs-wgobfs 0.6.2 chacha_glue::test_chacha6.
    let key = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8,
    ];
    let input = [0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0];
    assert_eq!(
        hash(&input, &key),
        [
            0xc5, 0x92, 0x55, 0x87, 0xca, 0x38, 0xaa, 0xc4, 0x31, 0xe7, 0x2e, 0xed, 0x19, 0x72,
            0x31, 0x93, 0x51, 0x13, 0x96, 0xee, 0x67, 0xea, 0x08, 0x43, 0xd7, 0x3c, 0x9e, 0xa3,
            0x96, 0xd4, 0x83, 0x1f
        ]
    );
}

#[test]
fn packet_types_roundtrip_and_malformed_datagrams_are_rejected() {
    for (kind, size) in [
        (1, 148),
        (2, 92),
        (3, 64),
        (4, 64),
        (4, 1440),
        (4, 1452),
        (4, 1412),
        (4, 64000),
    ] {
        let original = packet(kind, size);
        let mut bytes = original.clone();
        bytes.resize(size + 32, 0);
        let encoded = obfuscate(&mut bytes, size, &[7; 32]).unwrap();
        assert_ne!(&bytes[..16], &original[..16]);
        let decoded = unobfuscate(&mut bytes, encoded, &[7; 32]).unwrap();
        assert_eq!(&bytes[..decoded], original);
    }
    for size in 0..300 {
        let mut bytes = vec![0; size];
        assert_eq!(unobfuscate(&mut bytes, size, &[7; 32]), None);
        assert_eq!(obfuscate(&mut bytes, size, &[7; 32]), None);
    }
    // A forged handshake marker on a short packet used to panic in the
    // reference implementation's MAC2 restoration. Exercise all input lengths.
    for size in 32..160 {
        let mut bytes = vec![0; size + 32];
        bytes[0] = 0x11;
        let _ = unobfuscate(&mut bytes, size, &[3; 32]);
    }
}

#[test]
fn password_bytes_follow_rs_wgobfs_repetition_rules() {
    let config = WgObfsConfig::new("127.0.0.1:443".parse().unwrap(), "abc").unwrap();
    assert_eq!(&config.key.0, b"abcabcabcabcabcabcabcabcabcabcab");
    assert!(!format!("{config:?}").contains("abc"));
    assert!(WgObfsConfig::new(config.forward, "").is_err());
}

#[test]
fn keepalives_follow_reference_drop_rules_and_retained_packets_roundtrip() {
    let mut retained = 0;
    for seed in 0..=255 {
        let mut original = packet(4, 32);
        original[16] = seed;
        let mut bytes = original.clone();
        bytes.resize(64, 0);
        if let Some(encoded) = obfuscate(&mut bytes, 32, &[9; 32]) {
            retained += 1;
            assert_eq!(unobfuscate(&mut bytes, encoded, &[9; 32]), Some(32));
            assert_eq!(&bytes[..32], original);
        }
    }
    assert!(retained > 0 && retained < 256);
}

#[tokio::test]
async fn native_client_forwards_both_directions_and_releases_its_socket() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = WgObfsConfig::new(server.local_addr().unwrap(), "native test password").unwrap();
    let client = WgObfsClient::start(&config).await.unwrap();
    let local_address = client.local_addr();
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // A full MTU-1420 payload produces a 1452-byte WireGuard datagram;
    // padding is clamped to the MTU instead of rounded up to 16 bytes.
    for (request_kind, request_size, response_kind, response_size) in
        [(1, 148, 2, 92), (4, 1452, 4, 1412)]
    {
        let request = packet(request_kind, request_size);
        wg.send_to(&request, local_address).await.unwrap();
        let mut buf = vec![0; 65568];
        let (size, source) =
            tokio::time::timeout(Duration::from_secs(3), server.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let decoded = unobfuscate(&mut buf, size, &config.key.0).unwrap();
        assert_eq!(&buf[..decoded], request);
        let response = packet(response_kind, response_size);
        buf[..response_size].copy_from_slice(&response);
        let encoded = obfuscate(&mut buf, response_size, &config.key.0).unwrap();
        server.send_to(&buf[..encoded], source).await.unwrap();
        let (size, from) = tokio::time::timeout(Duration::from_secs(3), wg.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, local_address);
        assert_eq!(&buf[..size], response);
    }
    drop(client);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if UdpSocket::bind(local_address).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_client_recovers_when_the_remote_server_starts_later() {
    let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let config = WgObfsConfig::new(address, "server-restart-test").unwrap();
    let client = WgObfsClient::start(&config).await.unwrap();
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = packet(1, 148);
    wg.send_to(&request, client.local_addr()).await.unwrap();
    // Let the worker receive the ICMP port-unreachable response.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(client.is_running());
    let server = UdpSocket::bind(address).await.unwrap();
    let mut buf = vec![0; 65568];
    let (size, source) = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            wg.send_to(&request, client.local_addr()).await.unwrap();
            if let Ok(result) =
                tokio::time::timeout(Duration::from_millis(100), server.recv_from(&mut buf)).await
            {
                break result.unwrap();
            }
        }
    })
    .await
    .unwrap();
    let decoded = unobfuscate(&mut buf, size, &config.key.0).unwrap();
    assert_eq!(&buf[..decoded], request);
    let response = packet(2, 92);
    buf[..92].copy_from_slice(&response);
    let encoded = obfuscate(&mut buf, 92, &config.key.0).unwrap();
    server.send_to(&buf[..encoded], source).await.unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), wg.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], response);
}

/// Independent wire compatibility, using the unmodified upstream executable.
#[tokio::test]
#[ignore = "set RS_WGOBFS_BINARY to a reference rs-wgobfs executable"]
async fn native_client_interoperates_with_rs_wgobfs() {
    use std::process::Stdio;
    let binary = std::env::var("RS_WGOBFS_BINARY").expect("RS_WGOBFS_BINARY");
    let plain = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut process = tokio::process::Command::new(binary)
        .args([
            "-l",
            &address.to_string(),
            "-f",
            &plain.local_addr().unwrap().to_string(),
            "-k",
            "compatibility password",
            "-m",
            "unobfs",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let config = WgObfsConfig::new(address, "compatibility password").unwrap();
    let client = WgObfsClient::start(&config).await.unwrap();
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0; 65568];
    for (kind, size) in [(1, 148), (2, 92), (3, 64), (4, 64), (4, 1440)] {
        let request = packet(kind, size);
        let received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                wg.send_to(&request, client.local_addr()).await.unwrap();
                if let Ok(result) =
                    tokio::time::timeout(Duration::from_millis(100), plain.recv_from(&mut buf))
                        .await
                {
                    break result.unwrap();
                }
                assert!(
                    process.try_wait().unwrap().is_none(),
                    "reference process exited"
                );
            }
        })
        .await
        .unwrap();
        assert_eq!(&buf[..received.0], request);
        plain.send_to(&request, received.1).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), wg.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], request);
    }
    process.kill().await.unwrap();
}
