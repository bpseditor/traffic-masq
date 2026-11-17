use std::collections::HashMap;
use std::fmt;
use std::io::IsTerminal;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

mod chacha;
mod chacha_glue;
mod guts;
mod wgobfs;

use crate::wgobfs::MAX_RND_LEN;
use crate::wgobfs::{obfs_udp_payload, unobfs_udp_payload, ForwardState};

const HELP: &str = "\
USAGE:
  rs-wgobfs [OPTIONS]

OPTIONS:
  -h, --help                          Print help information
  -l or --listen <IP:Port>            Listen address:port
  -f or --forward <IP|Hostname:Port>  Peer's address:port
  -6                                  (Optional) Prefer IPv6 when connecting
                                      to the forward Peer
  -v, --verbose                       Log every forwarded and dropped packet

  -k or --key                         Shared secret (will be repeated or
                                      truncated to 32 characters)

  -m or --mode <obfs|unobfs>          Mode, either obfs or unobfs
";

#[derive(Copy, Clone, Debug)]
enum OPMode {
    Obfs,
    UnObfs,
}

impl fmt::Display for OPMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Obfs => write!(f, "obfs"),
            Self::UnObfs => write!(f, "unobfs"),
        }
    }
}

struct AppArgs {
    local_addr: SocketAddr,
    fwd_addr: SocketAddr,
    key: [u8; 32],
    obfs_mode: OPMode,
    verbose: bool,
}

static STARTED_AT: OnceLock<Instant> = OnceLock::new();

fn log_event(level: &str, symbol: &str, message: fmt::Arguments<'_>) {
    let elapsed = STARTED_AT.get_or_init(Instant::now).elapsed().as_secs_f32();
    let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let (level_color, reset) = if color {
        let value = match level {
            "ERROR" => "\x1b[31m",
            "WARN " => "\x1b[33m",
            "FLOW " => "\x1b[36m",
            _ => "\x1b[32m",
        };
        (value, "\x1b[0m")
    } else {
        ("", "")
    };
    eprintln!("[{elapsed:>9.3}s] {level_color}{level}{reset} {symbol} {message}");
}

macro_rules! info {
    ($symbol:expr, $($arg:tt)*) => { log_event("INFO ", $symbol, format_args!($($arg)*)) };
}
macro_rules! warn {
    ($symbol:expr, $($arg:tt)*) => { log_event("WARN ", $symbol, format_args!($($arg)*)) };
}
macro_rules! error {
    ($symbol:expr, $($arg:tt)*) => { log_event("ERROR", $symbol, format_args!($($arg)*)) };
}

#[derive(Default)]
struct ClientStats {
    to_peer: AtomicU64,
    to_client: AtomicU64,
    dropped: AtomicU64,
}

fn log_packet(verbose: bool, count: u64, direction: &str, bytes: usize, client: SocketAddr) {
    if verbose || count == 1 || count.is_multiple_of(1000) {
        log_event(
            "FLOW ",
            direction,
            format_args!("client={client} bytes={bytes} packet=#{count}"),
        );
    }
}

fn parse_socket_addr(s: &str, prefer_v6: bool) -> Option<SocketAddr> {
    // without DNS
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }

    // use DNS
    let mut v4: Option<SocketAddr> = None;
    let mut v6: Option<SocketAddr> = None;
    let addrs = s.to_socket_addrs().ok()?;
    for addr in addrs {
        match addr {
            SocketAddr::V4(_) if v4.is_none() => v4 = Some(addr),
            SocketAddr::V6(_) if v6.is_none() => v6 = Some(addr),
            _ => {}
        }
    }

    if prefer_v6 && v6.is_some() {
        return v6;
    } else if v4.is_some() {
        return v4;
    } else if v6.is_some() {
        return v6;
    } else {
        return None;
    }
}

async fn create_dual_stack_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    // create a raw socket2 Socket
    let socket: Socket;
    if addr.is_ipv4() {
        socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    } else {
        socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        // disable "IPv6 Only" to allow IPv4 traffic on the same socket
        socket.set_only_v6(false)?;
    }

    // Increase socket buffer to 1MB
    // Default sizes in Windows/Linux/BSDs are not big enough on Gigabit
    // network. There are many retries when testing the tunnel with iperf3.
    //
    // OpenBSD 7.8 defaults:
    //   net.inet.udp.recvspace=41600
    //   net.inet.udp.sendspace=9216
    socket.set_recv_buffer_size(1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024)?;

    socket.bind(&addr.into())?;
    // convert to Tokio UdpSocket
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn repeat_string_to_bytes(s: &str, len: usize) -> Vec<u8> {
    let v = s.as_bytes().to_vec();
    let repeat_count = (len + v.len() - 1) / v.len();
    let repeated = v.repeat(repeat_count);
    repeated.into_iter().take(len).collect()
}

fn parse_args() -> Result<AppArgs, Box<dyn std::error::Error>> {
    let mut pargs = pico_args::Arguments::from_env();

    if pargs.contains(["-h", "--help"]) {
        print!("{}", HELP);
        std::process::exit(0);
    }

    let local_str: String = pargs
        .value_from_str("--listen")
        .or_else(|_| pargs.value_from_str("-l"))?;
    let remote_str: String = pargs
        .value_from_str("--forward")
        .or_else(|_| pargs.value_from_str("-f"))?;

    let mode: String = pargs
        .value_from_str("--mode")
        .or_else(|_| pargs.value_from_str("-m"))?;

    let key: String = pargs
        .value_from_str("--key")
        .or_else(|_| pargs.value_from_str("-k"))?;

    if key.is_empty() {
        return Err("shared secret must not be empty".into());
    }

    let key32 = repeat_string_to_bytes(&key, 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key32);

    let prefer_v6: bool = pargs.contains("-6");
    let verbose = pargs.contains(["-v", "--verbose"]);
    let args = AppArgs {
        local_addr: parse_socket_addr(&local_str, false)
            .ok_or_else(|| format!("invalid listening address: {local_str}"))?,
        fwd_addr: parse_socket_addr(&remote_str, prefer_v6)
            .ok_or_else(|| format!("cannot resolve peer address: {remote_str}"))?,
        key: key_arr,
        obfs_mode: match mode.as_str() {
            "obfs" => OPMode::Obfs,
            "unobfs" => OPMode::UnObfs,
            _ => return Err(format!("invalid --mode '{mode}'; expected obfs or unobfs").into()),
        },
        verbose,
    };

    let remaining = pargs.finish();
    if !remaining.is_empty() {
        return Err(format!("unknown arguments: {remaining:?}").into());
    }

    Ok(args)
}

type ClientMap = Arc<RwLock<HashMap<SocketAddr, Client>>>;

struct Client {
    socket: Arc<UdpSocket>,
    handle: JoinHandle<()>,
    last_seen: AtomicU64,
    stats: Arc<ClientStats>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // tell the spawned task to stop
        self.handle.abort();
    }
}

struct ClientWorker {
    listen_socket: Arc<UdpSocket>,
    recv_socket: Arc<UdpSocket>,
    stats: Arc<ClientStats>,
    verbose: bool,
}

impl ClientWorker {
    async fn run(self, client_addr: SocketAddr, key: [u8; 32], obfs_mode: OPMode) {
        let mut buf = [0u8; 65535 + MAX_RND_LEN];
        loop {
            let n = match self.recv_socket.recv(&mut buf).await {
                Ok(n) => n,
                Err(err) => {
                    error!(
                        "✗",
                        "receive from peer failed for client {client_addr}: {err}"
                    );
                    break;
                }
            };
            // unobfs and forward response back to the original client
            let mut rnd_len: usize = 0;
            match obfs_mode {
                OPMode::Obfs => {
                    if let ForwardState::XTContinue =
                        unobfs_udp_payload(&mut buf, n, &key, &mut rnd_len)
                    {
                        match self
                            .listen_socket
                            .send_to(&buf[..n - rnd_len], client_addr)
                            .await
                        {
                            Ok(bytes) => {
                                let count =
                                    self.stats.to_client.fetch_add(1, Ordering::Relaxed) + 1;
                                log_packet(self.verbose, count, "←", bytes, client_addr);
                            }
                            Err(err) => error!("✗", "send to client {client_addr} failed: {err}"),
                        }
                    } else {
                        let count = self.stats.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                        if self.verbose || count == 1 || count.is_multiple_of(100) {
                            warn!("↓", "dropped invalid peer packet: client={client_addr} bytes={n} dropped=#{count}");
                        }
                    }
                }

                OPMode::UnObfs => {
                    if let ForwardState::XTContinue =
                        obfs_udp_payload(&mut buf, n, &key, &mut rnd_len)
                    {
                        match self
                            .listen_socket
                            .send_to(&buf[..n + rnd_len], client_addr)
                            .await
                        {
                            Ok(bytes) => {
                                let count =
                                    self.stats.to_client.fetch_add(1, Ordering::Relaxed) + 1;
                                log_packet(self.verbose, count, "←", bytes, client_addr);
                            }
                            Err(err) => error!("✗", "send to client {client_addr} failed: {err}"),
                        }
                    } else {
                        let count = self.stats.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                        if self.verbose || count == 1 || count.is_multiple_of(100) {
                            warn!("↓", "dropped peer keepalive/invalid packet: client={client_addr} bytes={n} dropped=#{count}");
                        }
                    }
                }
            }
        }
    }
}

struct ForwardWorker {
    fwd_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    stats: Arc<ClientStats>,
    verbose: bool,
}

impl ForwardWorker {
    async fn run(self, mut buf: BytesMut, len: usize, key: [u8; 32], obfs_mode: OPMode) {
        let mut rnd_len: usize = 0;
        match obfs_mode {
            OPMode::Obfs => {
                if let ForwardState::XTContinue =
                    obfs_udp_payload(&mut buf, len, &key, &mut rnd_len)
                {
                    self.send_and_log(&buf[..len + rnd_len]).await;
                } else {
                    self.log_drop(len, "keepalive/invalid local packet");
                }
            }
            OPMode::UnObfs => {
                if let ForwardState::XTContinue =
                    unobfs_udp_payload(&mut buf, len, &key, &mut rnd_len)
                {
                    self.send_and_log(&buf[..len - rnd_len]).await;
                } else {
                    self.log_drop(len, "invalid obfuscated local packet");
                }
            }
        }
    }

    async fn send_and_log(&self, buf: &[u8]) {
        match self.fwd_socket.send(buf).await {
            Ok(bytes) => {
                let count = self.stats.to_peer.fetch_add(1, Ordering::Relaxed) + 1;
                log_packet(self.verbose, count, "→", bytes, self.client_addr);
            }
            Err(err) => error!(
                "✗",
                "send to peer failed for client {}: {err}", self.client_addr
            ),
        }
    }

    fn log_drop(&self, bytes: usize, reason: &str) {
        let count = self.stats.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if self.verbose || count == 1 || count.is_multiple_of(100) {
            warn!(
                "↓",
                "dropped {reason}: client={} bytes={bytes} dropped=#{count}", self.client_addr
            );
        }
    }
}

#[inline]
fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn clean_inactive_client(registry: ClientMap, timeout: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(120));
    loop {
        interval.tick().await;
        let mut map_write = registry.write().expect("Write-lock failed");
        // retain() removes items where the closure returns false
        map_write.retain(|addr, client| {
            let last_seen = client.last_seen.load(Ordering::Relaxed);
            let is_alive = epoch_now().saturating_sub(last_seen) < timeout;
            if !is_alive {
                info!("○", "client expired: {addr} (idle timeout {timeout}s, sent={}, received={}, dropped={})",
                    client.stats.to_peer.load(Ordering::Relaxed),
                    client.stats.to_client.load(Ordering::Relaxed),
                    client.stats.dropped.load(Ordering::Relaxed));
                client.handle.abort();
            }
            is_alive
        });
    }
}

const SLAB_SIZE: usize = 1024 * 256;

// Use single thread.
//
// - Multi thread works poorly on openbsd, async socket stops working after
//   sending at high speed for few seconds.
//
// - On Linux, single thread has higher throughput, likely due to better cache
//   locality. With a 7th gen i7, one thread is fast enough to almost saturate
//   Gigabit network.
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let args = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            error!("✗", "invalid arguments: {e}");
            std::process::exit(1);
        }
    };

    let listener = match create_dual_stack_socket(args.local_addr).await {
        Ok(socket) => Arc::new(socket),
        Err(err) => {
            error!("✗", "cannot listen on {}: {err}", args.local_addr);
            return Err(err);
        }
    };
    info!("✓", "rs-wgobfs started");
    info!("●", "listening on {}", args.local_addr);
    info!(
        "⇄",
        "mode={} peer={} verbose={}", args.obfs_mode, args.fwd_addr, args.verbose
    );
    info!("…", "waiting for UDP traffic");

    let mut global_buf = BytesMut::zeroed(SLAB_SIZE);

    let client_map: ClientMap = Arc::new(RwLock::new(HashMap::new()));
    let timeout: u64 = 600;
    tokio::spawn(clean_inactive_client(Arc::clone(&client_map), timeout));
    loop {
        if global_buf.len() < 2048 {
            global_buf = BytesMut::zeroed(SLAB_SIZE);
        }

        // Reserve room for obfuscation padding and the 256-byte slab alignment.
        let receive_capacity = global_buf.len() - MAX_RND_LEN - 255;
        let (len, client_addr) = match listener.recv_from(&mut global_buf[..receive_capacity]).await {
            Ok(packet) => packet,
            Err(err) => {
                error!("✗", "receive on {} failed: {err}", args.local_addr);
                continue;
            }
        };
        // only split_to multiple of 256
        let aligned_len = (len + MAX_RND_LEN + 255) & !255;
        let buf = global_buf.split_to(aligned_len);

        // read lock only lives inside scope
        let mut fwd_socket = {
            let map_read = client_map.read().expect("Read-lock failed");
            match map_read.get(&client_addr) {
                Some(client) => {
                    client.last_seen.store(epoch_now(), Ordering::Relaxed);
                    Some(client.socket.clone())
                }
                None => None,
            }
        };

        // write lock only lives inside scope
        if fwd_socket.is_none() {
            // create a dedicated socket to WG peer for the new client
            let bind_addr = match args.fwd_addr {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };
            let s = match UdpSocket::bind(bind_addr).await {
                Ok(socket) => Arc::new(socket),
                Err(err) => {
                    error!(
                        "✗",
                        "cannot create upstream socket for client {client_addr}: {err}"
                    );
                    continue;
                }
            };
            if let Err(err) = s.connect(args.fwd_addr).await {
                error!(
                    "✗",
                    "cannot connect client {client_addr} to peer {}: {err}", args.fwd_addr
                );
                continue;
            }
            let upstream_addr = s.local_addr().ok();
            info!(
                "+",
                "client connected: {client_addr} → {} (upstream={})",
                args.fwd_addr,
                upstream_addr.map_or_else(|| "unknown".to_string(), |addr| addr.to_string())
            );
            let stats = Arc::new(ClientStats::default());
            // listen for return traffic from the server to THIS client
            let client_worker = ClientWorker {
                recv_socket: s.clone(),
                listen_socket: listener.clone(),
                stats: Arc::clone(&stats),
                verbose: args.verbose,
            };

            // use handle to abort inactive clients
            let handle = tokio::spawn(client_worker.run(client_addr, args.key, args.obfs_mode));

            let client = Client {
                socket: s.clone(),
                handle,
                last_seen: AtomicU64::new(epoch_now()), // for cleanup
                stats,
            };

            let mut map_write = client_map.write().expect("Write-lock failed");
            map_write.insert(client_addr, client);
            fwd_socket = Some(s);
        };

        let Some(fwd_socket) = fwd_socket else {
            error!(
                "✗",
                "internal error: no upstream socket for client {client_addr}"
            );
            continue;
        };
        let stats = {
            let map_read = client_map.read().expect("Read-lock failed");
            Arc::clone(
                &map_read
                    .get(&client_addr)
                    .expect("Client disappeared")
                    .stats,
            )
        };
        let fwd_worker = ForwardWorker {
            fwd_socket,
            client_addr,
            stats,
            verbose: args.verbose,
        };
        tokio::spawn(fwd_worker.run(buf, len, args.key, args.obfs_mode));
    }
}
