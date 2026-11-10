//! Native client for the rs-wgobfs / xt_wgobfs wire format.
//!
//! Wire-format reference: https://github.com/infinet/rs-wgobfs (0.6.2).
//! WireGuard still provides authentication and encryption; this layer only
//! disguises its datagrams. No external executable or command-line secret.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::wireguard::WireGuardKey;

#[derive(Debug, Clone)]
pub struct WgObfsConfig {
    pub forward: SocketAddr,
    pub key: WireGuardKey,
}

impl WgObfsConfig {
    /// rs-wgobfs repeats/truncates the UTF-8 password bytes to 32 bytes.
    pub fn new(forward: SocketAddr, password: &str) -> io::Result<Self> {
        if forward.port() == 0
            || forward.ip().is_unspecified()
            || forward.ip().is_multicast()
            || password.is_empty()
            || password.contains('\0')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid rs-wgobfs forwarding address or empty password",
            ));
        }
        let mut key = [0; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = password.as_bytes()[i % password.len()];
        }
        Ok(Self {
            forward,
            key: WireGuardKey(key),
        })
    }
}

pub struct WgObfsClient {
    local: SocketAddr,
    forward: SocketAddr,
    task: JoinHandle<io::Result<()>>,
}

impl WgObfsClient {
    pub async fn start(config: &WgObfsConfig) -> io::Result<Self> {
        let local = UdpSocket::bind("127.0.0.1:0").await?;
        let remote = UdpSocket::bind(if config.forward.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        remote.connect(config.forward).await?;
        let address = local.local_addr()?;
        let key = config.key.clone();
        let task = tokio::spawn(async move { forward(local, remote, key).await });
        Ok(Self {
            local: address,
            forward: config.forward,
            task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn forward_addr(&self) -> SocketAddr {
        self.forward
    }
    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }
}

impl Drop for WgObfsClient {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward(local: UdpSocket, remote: UdpSocket, key: WireGuardKey) -> io::Result<()> {
    // Reuse initialized buffers and one task per tunnel. A connected remote
    // socket rejects datagrams from sources other than the configured server.
    let mut outbound = vec![0; 65536 + 32];
    let mut inbound = vec![0; 65536];
    let mut client = None;
    loop {
        tokio::select! {
            received = local.recv_from(&mut outbound[..65536]) => {
                let (len, source) = received?;
                if !source.ip().is_loopback() || client.is_some_and(|known| known != source) { continue; }
                if let Some(size) = obfuscate(&mut outbound, len, &key.0) {
                    client = Some(source);
                    // A full socket or transient network error must not kill the transport.
                    let _ = remote.send(&outbound[..size]).await;
                }
            }
            received = remote.recv(&mut inbound) => {
                match received {
                    Ok(len) => {
                        if let (Some(destination), Some(size)) = (client, unobfuscate(&mut inbound, len, &key.0)) {
                            let _ = local.send_to(&inbound[..size], destination).await;
                        }
                    }
                    // Connected UDP may report an ICMP error while the server
                    // is offline. Keep listening so a later handshake can work.
                    Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

fn valid_packet(packet: &[u8]) -> bool {
    packet.len() >= 32
        && packet[1..4] == [0; 3]
        && match packet[0] {
            1 => packet.len() == 148,
            2 => packet.len() == 92,
            3 => packet.len() == 64,
            // WireGuard clamps padding to the MTU, which need not be a
            // multiple of 16. The minimum size is checked above.
            4 => true,
            _ => false,
        }
}

fn obfuscate(buf: &mut [u8], len: usize, key: &[u8; 32]) -> Option<usize> {
    if len.checked_add(32)? > buf.len() || !valid_packet(&buf[..len]) {
        return None;
    }
    let mut input: [u8; 16] = buf[16..32].try_into().ok()?;
    input[0] = input[0].wrapping_add(42);
    if buf[0] == 4 && len == 32 {
        input[0] = input[0].wrapping_add(1);
        if hash(&input, key)[0] > 50 {
            return None;
        }
    }
    let mac2 = match (buf[0], len) {
        (1, 148) => Some(132),
        (2, 92) => Some(76),
        _ => None,
    };
    if let Some(offset) = mac2 {
        if buf[offset..offset + 4] == [0; 4] {
            input[0] = input[0].wrapping_add(1);
            buf[offset..offset + 16].copy_from_slice(&hash(&input, key)[..16]);
            buf[0] |= 0x10;
        }
    }
    let max = if len > 200 { 8 } else { 32 };
    let (padding, count) = loop {
        input[0] = input[0].wrapping_add(1);
        let random = hash(&input, key);
        if let Some(count) = random.iter().find(|&&v| (4..=max).contains(&v)) {
            let count = *count as usize;
            break (random, count);
        }
    };
    buf[len..len + count].copy_from_slice(&padding[..count]);
    let mask = hash(buf[16..32].try_into().ok()?, key);
    buf[len + count - 1] = count as u8 ^ mask[16];
    for i in 0..16 {
        buf[i] ^= mask[i];
    }
    Some(len + count)
}

fn unobfuscate(buf: &mut [u8], len: usize, key: &[u8; 32]) -> Option<usize> {
    if len < 36 || len > buf.len() {
        return None;
    }
    let mask = hash(buf[16..32].try_into().ok()?, key);
    let padding = (buf[len - 1] ^ mask[16]) as usize;
    if !(4..=32).contains(&padding) || len < padding + 32 {
        return None;
    }
    let size = len - padding;
    for i in 0..16 {
        buf[i] ^= mask[i];
    }
    match (buf[0], size) {
        (0x11, 148) => {
            buf[132..148].fill(0);
            buf[0] = 1;
        }
        (0x12, 92) => {
            buf[76..92].fill(0);
            buf[0] = 2;
        }
        _ => {}
    }
    valid_packet(&buf[..size]).then_some(size)
}

// Six ChaCha rounds, with all 16 nonce/counter bytes supplied by the packet.
// The first 32 bytes of the first block are the rs-wgobfs PRN.
fn hash(input: &[u8; 16], key: &[u8; 32]) -> [u8; 32] {
    let mut initial = Zeroizing::new([0u32; 16]);
    initial[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (i, bytes) in key.chunks_exact(4).chain(input.chunks_exact(4)).enumerate() {
        initial[4 + i] = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    let mut state = Zeroizing::new(*initial);
    for _ in 0..3 {
        for [a, b, c, d] in [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15],
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ] {
            state[a] = state[a].wrapping_add(state[b]);
            state[d] = (state[d] ^ state[a]).rotate_left(16);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_left(12);
            state[a] = state[a].wrapping_add(state[b]);
            state[d] = (state[d] ^ state[a]).rotate_left(8);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_left(7);
        }
    }
    let mut out = [0; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].wrapping_add(initial[i]).to_le_bytes());
    }
    initial.zeroize();
    out
}

#[cfg(test)]
mod tests;
