use crate::config::ResolvedConfig;
use crate::agent::SshAgent;
use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::msg;
use ssh_core::transport::*;
use ssh_core::auth::*;
use ssh_core::channel::*;
use ssh_core::known_hosts::*;
use ssh_core::hostkey::*;
use ssh_core::kex::{KexExchange, KexAlgorithm};
use std::collections::{VecDeque, HashMap};
use std::pin::Pin;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, mpsc};

pub trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> IoStream for T {}
pub type BoxedStream = Pin<Box<dyn IoStream>>;

#[cfg(unix)]
fn terminal_size() -> std::io::Result<(u32, u32)> {
    
    let winsize: libc::winsize = unsafe { std::mem::zeroed() };
    let mut ws = winsize;
    let r = unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if ws.ws_col == 0 || ws.ws_row == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "no tty size"));
    }
    Ok((ws.ws_col as u32, ws.ws_row as u32))
}

/// Saves terminal state and puts it in raw mode. Restores on Drop.
#[cfg(unix)]
pub struct TerminalGuard {
    saved_termios: Option<libc::termios>,
    tty_active: bool,
}

#[cfg(unix)]
impl TerminalGuard {
    pub fn new() -> Self {
        if !atty::is(atty::Stream::Stdin) {
            return TerminalGuard { saved_termios: None, tty_active: false };
        }
        unsafe {
            let mut termios = std::mem::zeroed::<libc::termios>();
            if libc::tcgetattr(1, &mut termios) == 0 {
                // Save original settings
                let mut raw = termios;
                raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
                raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
                raw.c_oflag &= !libc::OPOST;
                raw.c_cflag &= !(libc::CSIZE | libc::PARENB);
                raw.c_cflag |= libc::CS8;
                raw.c_cc[libc::VMIN] = 1;
                raw.c_cc[libc::VTIME] = 0;
                if libc::tcsetattr(1, libc::TCSADRAIN, &raw) == 0 {
                    return TerminalGuard {
                        saved_termios: Some(termios),
                        tty_active: true,
                    };
                }
            }
        }
        TerminalGuard { saved_termios: None, tty_active: false }
    }
}

#[cfg(unix)]
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.tty_active {
            if let Some(ref termios) = self.saved_termios {
                unsafe {
                    libc::tcsetattr(1, libc::TCSADRAIN, termios);
                }
            }
        }
    }
}

#[cfg(not(unix))]
pub struct TerminalGuard;
#[cfg(not(unix))]
impl TerminalGuard {
    pub fn new() -> Self { TerminalGuard }
}

#[cfg(not(unix))]
fn terminal_size() -> std::io::Result<(u32, u32)> {
    Err(std::io::Error::new(std::io::ErrorKind::Other, "no tty size"))
}

fn env_pattern_match(name: &str, pattern: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    if !name.starts_with(first) {
        return false;
    }
    let mut rest = name[first.len()..].to_string();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        match rest.find(part) {
            Some(idx) => {
                rest = rest[idx + part.len()..].to_string();
            }
            None => return false,
        }
    }
    true
}

/// Expand a leading `~` in a path to the user's home directory.
fn expand_tilde(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::PathBuf;
    let s = path.to_string_lossy();
    if s == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
    } else if let Some(rest) = s.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest)
    } else if let Some(rest) = s.strip_prefix('~') {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest)
    } else {
        path.to_path_buf()
    }
}

/// Map an SSH signal name (without "SIG" prefix) to its numeric value.
fn signal_number(name: &str) -> Option<i32> {
    match name.to_ascii_uppercase().as_str() {
        "HUP" => Some(1),
        "INT" => Some(2),
        "QUIT" => Some(3),
        "ILL" => Some(4),
        "ABRT" => Some(6),
        "FPE" => Some(8),
        "KILL" => Some(9),
        "USR1" => Some(10),
        "SEGV" => Some(11),
        "USR2" => Some(12),
        "PIPE" => Some(13),
        "ALRM" => Some(14),
        "TERM" => Some(15),
        "CHLD" => Some(17),
        "CONT" => Some(18),
        "STOP" => Some(19),
        "TSTP" => Some(20),
        "WINCH" => Some(28),
        _ => None,
    }
}

/// Filter resolved addresses per `AddressFamily`/`-4`/`-6` preference.
fn filter_addrs_for_family(
    addrs: Vec<std::net::SocketAddr>,
    prefer_ipv4: bool,
    prefer_ipv6: bool,
) -> Vec<std::net::SocketAddr> {
    let mut out: Vec<std::net::SocketAddr> = addrs
        .into_iter()
        .filter(|a| {
            if prefer_ipv4 && !prefer_ipv6 {
                a.is_ipv4()
            } else if prefer_ipv6 && !prefer_ipv4 {
                a.is_ipv6()
            } else {
                true
            }
        })
        .collect();
    // OpenSSH tries IPv4 before IPv6 by default (any family).
    out.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
    out
}

/// Resolve the (user, global) known_hosts file paths, honoring the config and
/// falling back to OpenSSH's defaults.
fn known_hosts_paths(config: &ResolvedConfig) -> (std::path::PathBuf, std::path::PathBuf) {
    let user = config
        .user_known_hosts_file
        .clone()
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(KnownHosts::default_client_path);
    let global = config
        .global_known_hosts_file
        .clone()
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(KnownHosts::default_server_path);
    (user, global)
}

/// Hostname used for host-key verification (Honors HostKeyAlias).
fn host_key_lookup_name(config: &ResolvedConfig) -> String {
    config.host_key_alias.clone().unwrap_or_else(|| config.hostname.clone())
}

/// True if `host` refers to the local machine (OpenSSH's `localhost` check for
/// `NoHostAuthenticationForLocalhost`). Matches the literal name and loopback
/// addresses 127.0.0.1/::1.
fn is_localhost_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "localhost"
        || h == "127.0.0.1"
        || h == "::1"
        || h == "::ffff:127.0.0.1"
}

/// Combined user-then-global known_hosts check for a single host.
fn check_host_status(
    user_kh: &KnownHosts,
    global_kh: &KnownHosts,
    host: &str,
    port: u16,
    key_type: &str,
    key_blob: &[u8],
) -> HostKeyStatus {
    let user_status = user_kh.check(host, port, key_type, key_blob);
    match user_status {
        HostKeyStatus::Known => HostKeyStatus::Known,
        HostKeyStatus::Changed => HostKeyStatus::Changed,
        HostKeyStatus::Unknown => {
            if global_kh.check(host, port, key_type, key_blob) == HostKeyStatus::Known {
                HostKeyStatus::Known
            } else {
                HostKeyStatus::Unknown
            }
        }
    }
}

/// Format an OpenSSH-style host key fingerprint: `SHA256:...` (default) or
/// `MD5:aa:bb:...` when FingerprintHash=md5.
fn format_fingerprint(key_blob: &[u8], hash: &str) -> String {
    use sha2::{Sha256, Digest};
    if hash.eq_ignore_ascii_case("md5") {
        use md5::{Digest as _, Md5};
        let digest = Md5::digest(key_blob);
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        let colon = hex
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join(":");
        format!("MD5:{}", colon)
    } else {
        let digest = Sha256::digest(key_blob);
        let fp = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &digest,
        );
        format!("SHA256:{}", fp.trim_end_matches('='))
    }
}

/// OpenSSH-style randomart (VisualHostKey): a deterministic 17x9 grid walk.
/// Uses SHA256 over the key blob to drive a bounded random walk.
fn randomart(key_blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const W: usize = 17;
    const H: usize = 9;
    const CHARS: &[u8] = b" .o+=*BOX@%&#/^";
    let mut grid = vec![0u8; W * H];
    let digest = Sha256::digest(key_blob);
    let mut x = W / 2;
    let mut y = H / 2;
    for b in digest.iter() {
        x = (x + (*b & 0x0f) as usize) % W;
        y = (y + (*b >> 4) as usize) % H;
        grid[y * W + x] = grid[y * W + x].saturating_add(1);
    }
    // Start (S) and end (E) positions; OpenSSH marks them explicitly.
    let sx = W / 2;
    let sy = H / 2;
    grid[sy * W + sx] = 0; // will be 'S'
    // Recompute the final drift position for 'E'.
    let mut ex = W / 2;
    let mut ey = H / 2;
    for b in digest.iter() {
        ex = (ex + (*b & 0x0f) as usize) % W;
        ey = (ey + (*b >> 4) as usize) % H;
    }
    let mut out = String::new();
    for row in 0..H {
        let mut line = String::new();
        for col in 0..W {
            let idx = row * W + col;
            if idx == sy * W + sx {
                line.push('S');
            } else if idx == ey * W + ex {
                line.push('E');
            } else {
                let v = grid[idx] as usize;
                line.push(CHARS[v.min(CHARS.len() - 1)] as char);
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Prompt the user to accept an unknown host key (StrictHostKeyChecking=ask).
fn prompt_accept_host_key(hostname: &str, key_type: &str, key_blob: &[u8], fingerprint_hash: &str) -> bool {
    let fp = format_fingerprint(key_blob, fingerprint_hash);
    eprintln!("The authenticity of host '{}' can't be established.", hostname);
    eprintln!("{} key fingerprint is {}.", key_type, fp);
    eprint!("Are you sure you want to continue connecting (yes/no)? ");
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let answer = line.trim().to_ascii_lowercase();
    answer == "yes" || answer == "y"
}

/// OpenSSH escape-sequence state for interactive sessions (`~.`, `~C`, ...).
#[derive(Default)]
struct EscapeState {
    at_line_start: bool,
    escape_pending: bool,
}

impl EscapeState {
    fn new() -> Self {
        EscapeState { at_line_start: true, escape_pending: false }
    }

    /// Process a chunk of stdin bytes. `escape_char` is the configured escape
    /// character (default '~'). Returns bytes to forward and whether to exit.
    fn process(&mut self, data: &[u8], escape_char: char) -> (Vec<u8>, bool) {
        let esc = escape_char as u8;
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            if self.escape_pending {
                self.escape_pending = false;
                match b {
                    // `~.` terminates the connection.
                    b'.' => return (out, true),
                    // `~C` opens the OpenSSH command line (unsupported here).
                    b'C' => {
                        eprintln!("(escape command line not supported by ns-ssh)");
                        self.at_line_start = true;
                        continue;
                    }
                    // `~Z` suspend, `~&` background: unsupported, ignore.
                    b'Z' | b'&' => {
                        self.at_line_start = true;
                        continue;
                    }
                    // Not a recognized escape: forward the escape char + byte.
                    _ => {
                        out.push(esc);
                        out.push(b);
                        self.at_line_start = false;
                    }
                }
                continue;
            }
            if self.at_line_start && b == esc {
                self.escape_pending = true;
                continue;
            }
            if b == b'\n' || b == b'\r' {
                self.at_line_start = true;
            } else {
                self.at_line_start = false;
            }
            out.push(b);
        }
        (out, false)
    }
}

/// Display an SSH_MSG_USERAUTH_BANNER message on stderr (OpenSSH behavior).
fn display_auth_banner(pkt: &[u8]) {
    let mut r = &pkt[1..];
    if let Ok(text) = SshString::decode(&mut r) {
        if let Ok(s) = text.as_str() {
            eprint!("{}", s);
            use std::io::Write;
            let _ = std::io::stderr().flush();
        }
    }
}

/// Verify a host key against SSHFP DNS records (`VerifyHostKeyDNS`).
/// Returns `Some(true)` on a match, `Some(false)` if records exist but none
/// match (hard failure), and `None` if there are no SSHFP records (fall back).
async fn check_host_key_dns(lookup_host: &str, key_type: &str, key_blob: &[u8]) -> Option<bool> {
    use sha2::{Digest, Sha256};
    // The lookup is synchronous std::net code with a per-server timeout. Run it
    // on a blocking thread so a slow resolver cannot stall the async runtime
    // (this previously froze every concurrent connection in the integration
    // tests).
    let host = lookup_host.to_string();
    let records = tokio::task::spawn_blocking(move || crate::dns_sshfp::lookup_sshfp(&host))
        .await
        .unwrap_or_default();
    if records.is_empty() {
        return None;
    }
    // Map the key type to an SSHFP algorithm number (RFC 4255/6594).
    let algo = match key_type {
        "ssh-ed25519" => 4,
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => 3,
        "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => 2,
        "ssh-dss" => 1,
        _ => 0,
    };
    for r in &records {
        if algo != 0 && r.algorithm != algo {
            continue;
        }
        let fp: Vec<u8> = match r.fingerprint_type {
            1 => {
                use sha1::{Digest as _, Sha1};
                Sha1::digest(key_blob).to_vec()
            }
            2 => Sha256::digest(key_blob).to_vec(),
            _ => continue,
        };
        if fp == r.fingerprint {
            return Some(true);
        }
    }
    Some(false)
}

/// Decode an SSH_MSG_DEBUG payload (boolean always-display, string message,
/// string language) and return the message text.
fn decode_debug_message(pkt: &[u8]) -> Option<String> {
    let mut r = &pkt[1..];
    let _always_display = bool::decode(&mut r).ok()?;
    let msg = SshString::decode(&mut r).ok()?.as_str().ok()?.to_string();
    Some(msg)
}

/// Receive a packet during authentication, silently skipping IGNORE/DEBUG and
/// displaying any USERAUTH_BANNER. Returns the first meaningful packet.
async fn read_auth_packet(
    stream: &mut BoxedStream,
    transport: &mut SshTransport,
    aead: bool,
) -> Result<Vec<u8>> {
    loop {
        let pkt = receive_encrypted_packet(stream, transport, false, aead).await?;
        match pkt.first() {
            Some(&msg::SSH_MSG_IGNORE) | Some(&msg::SSH_MSG_DEBUG) => continue,
            Some(&msg::SSH_MSG_USERAUTH_BANNER) => {
                display_auth_banner(&pkt);
                continue;
            }
            _ => return Ok(pkt),
        }
    }
}

pub struct SshClient {
    pub config: ResolvedConfig,
    pub stream: Option<BoxedStream>,
    pub transport: SshTransport,
    pub session_id: Option<Vec<u8>>,
    pub server_sig_algs: Vec<String>,
    agent: SshAgent,
    loaded_signers: Vec<Box<dyn HostKeySigner>>,
    pub channel_manager: ChannelManager,
    pending_open: HashMap<ChannelId, oneshot::Sender<Result<(ChannelId, u32, u32)>>>,
    pending_global: VecDeque<oneshot::Sender<Result<Option<Vec<u8>>>>>,
    pub captured_host_key: Option<(String, Vec<u8>)>,
    /// ControlMaster: instant when the last multiplexed session closed.
    pub control_idle_since: Option<std::time::Instant>,
    /// Peer IP of the TCP connection (used for CheckHostIP host-key checks).
    pub peer_ip: Option<String>,
    /// Inbound channel data buffered by the SCP/SFTP flow-control pump,
    /// keyed by local channel id.
    pump_in: VecDeque<(ChannelId, Vec<u8>)>,
    /// Outbound encrypted packets buffered by the pump when the socket would block.
    pump_write: VecDeque<Vec<u8>>,
    /// Set when the pump observes SSH_MSG_CHANNEL_EOF or SSH_MSG_CHANNEL_CLOSE.
    pump_closed: bool,
    /// Inbound packets read while a rekey was in progress that are not part of
    /// the key exchange (e.g. a CHANNEL_SUCCESS for a pre-rekey request). They
    /// are replayed by `recv_packet` after the rekey completes.
    deferred_packets: VecDeque<Vec<u8>>,
}

impl SshClient {
    pub fn new(config: ResolvedConfig) -> Self {
        let mut transport = SshTransport::new();
        // Apply RekeyLimit so rekeying follows the configured thresholds.
        transport.rekey_bytes = config.rekey_limit_bytes;
        transport.rekey_seconds = config.rekey_limit_time;
        // Compression yes/no: controls whether zlib is advertised and preferred.
        transport.compression_enabled = config.compression;
        // Read IdentityAgent before moving `config` into the struct.
        let identity_agent_path = config.identity_agent.clone();
        SshClient {
            config,
            stream: None,
            transport,
            session_id: None,
            server_sig_algs: Vec::new(),
            agent: SshAgent::new_with_path(identity_agent_path.as_deref()),
            loaded_signers: Vec::new(),
            channel_manager: ChannelManager::new(),
            pending_open: HashMap::new(),
            pending_global: VecDeque::new(),
            captured_host_key: None,
            control_idle_since: None,
            peer_ip: None,
            pump_in: VecDeque::new(),
            pump_write: VecDeque::new(),
            pump_closed: false,
            deferred_packets: VecDeque::new(),
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let target_host = self.config.hostname.clone();
        let target_port = self.config.port;
        let connect_timeout = self.config.connect_timeout;

        if let Some(ref pc) = self.config.proxy_command.clone() {
            if !pc.is_empty() && pc != "none" {
                let stream = connect_proxy_command(&self.config, pc, &target_host, target_port)?;
                self.stream = Some(stream);
                return Ok(());
            }
        }

        if let Some(ref proxy_spec) = self.config.proxy_jump.clone() {
            if !proxy_spec.is_empty() && proxy_spec != "none" {
                let stream = connect_via_proxy_jump(
                    proxy_spec,
                    &target_host,
                    target_port,
                    self.config.clone(),
                ).await?;
                self.stream = Some(stream);
                return Ok(());
            }
        }

        // ConnectionAttempts: retry the TCP connect before giving up (default 1).
        let attempts = self.config.connection_attempts.max(1);
        let mut last_err: Option<SshError> = None;
        for _ in 0..attempts {
            match self.connect_direct(connect_timeout).await {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            SshError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection failed"))
        }))
    }

    async fn connect_direct(&mut self, connect_timeout: Option<u32>) -> Result<()> {
        let target_host = self.config.hostname.clone();
        let target_port = self.config.port;
        let addr = format!("{}:{}", target_host, target_port);
        let connect_dur = connect_timeout.map(|s| std::time::Duration::from_secs(s as u64));

        // Resolve with AddressFamily (`-4`/`-6`/AddressFamily) constraint.
        let mut addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(addr.as_str()).await
            .map_err(SshError::Io)?
            .collect();
        addrs = filter_addrs_for_family(addrs, self.config.prefer_ipv4, self.config.prefer_ipv6);
        if addrs.is_empty() {
            return Err(SshError::Protocol("cannot resolve target (no address matching AddressFamily)".into()));
        }

        let stream = if let Some(bind) = self.config.bind_address.clone() {
            let bind_addr = format!("{}:0", bind);
            let bind_addr: std::net::SocketAddr = bind_addr.parse().map_err(|_| SshError::Protocol("invalid BindAddress".into()))?;
            let mut last_err: Option<SshError> = None;
            let mut connected = None;
            for target_addr in addrs {
                let socket = if target_addr.is_ipv6() {
                    tokio::net::TcpSocket::new_v6().map_err(SshError::Io)?
                } else {
                    tokio::net::TcpSocket::new_v4().map_err(SshError::Io)?
                };
                if socket.bind(bind_addr).is_err() { continue; }
                let res = if let Some(timeout) = connect_dur {
                    tokio::time::timeout(timeout, socket.connect(target_addr))
                        .await
                        .map_err(|_| SshError::Timeout)
                        .and_then(|r| r.map_err(SshError::Io))
                } else {
                    socket.connect(target_addr).await.map_err(SshError::Io)
                };
                match res {
                    Ok(s) => { connected = Some(s); break; }
                    Err(e) => last_err = Some(e),
                }
            }
            connected.ok_or_else(|| last_err.unwrap_or_else(|| {
                SshError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "all connection attempts failed"))
            }))?
        } else {
            let mut last_err: Option<SshError> = None;
            let mut connected = None;
            for target_addr in addrs {
                let res = if let Some(timeout) = connect_dur {
                    tokio::time::timeout(timeout, TcpStream::connect(target_addr))
                        .await
                        .map_err(|_| SshError::Timeout)
                        .and_then(|r| r.map_err(SshError::Io))
                } else {
                    TcpStream::connect(target_addr).await.map_err(SshError::Io)
                };
                match res {
                    Ok(s) => { connected = Some(s); break; }
                    Err(e) => last_err = Some(e),
                }
            }
            connected.ok_or_else(|| last_err.unwrap_or_else(|| {
                SshError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "all connection attempts failed"))
            }))?
        };

        // Apply TCP-level keepalive if configured
        if self.config.tcp_keep_alive {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = stream.as_raw_fd();
                let val: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE,
                                     &val as *const libc::c_int as *const libc::c_void,
                                     std::mem::size_of::<libc::c_int>() as libc::socklen_t);
                }
            }
        }

        self.peer_ip = stream.peer_addr().ok().map(|a| a.ip().to_string());
        self.stream = Some(Box::pin(stream));
        Ok(())
    }

    pub async fn handshake(&mut self) -> Result<()> {
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;

        send_version_string(stream, msg::SSH_VERSION.as_bytes()).await?;
        self.transport.client_version = msg::SSH_VERSION.as_bytes().to_vec();

        let server_version = read_version_string(stream).await?;
        self.transport.server_version = server_version;

        let kex_init = self.transport.build_kex_init(
            self.config.host_key_algorithms.as_deref(),
            self.config.kex_algorithms.as_deref(),
            self.config.ciphers.as_deref(),
            self.config.macs.as_deref(),
            false,
        );
        send_raw_packet(stream, &kex_init).await?;
        self.transport.outgoing_seq += 1; // seq counts every packet (RFC 4253 §6.4)
        self.transport.state = KexState::KexInitSent;

        let server_kex = receive_raw_packet(stream).await?;
        self.transport.incoming_seq += 1;
        self.transport.server_kex_init = server_kex.clone();
        self.transport.state = KexState::KexInitReceived;

        let negotiation = SshTransport::negotiate_algorithms(
            &self.transport.client_kex_init,
            &self.transport.server_kex_init,
        )?;
        self.transport.strict_kex = negotiation.strict_kex;
        self.transport.strict_kex_peer_kexinit = negotiation.strict_kex;

        let mut kex = SshTransport::create_kex_algorithm(&negotiation.kex_algorithm)?;

        let (server_host_key_blob, _server_public_key, server_signature_blob, shared_secret, exchange_hash, kex_hash_name) = if negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange") {
            // RFC 4419 §3: min = 2048, preferred = 3072, max = 8192 (the same
            // range OpenSSH requests).
            let (min, nbits, max) = (2048u32, 3072u32, 8192u32);
            // RFC 4419 §3: clients send SSH_MSG_KEX_DH_GEX_REQUEST (34) with
            // min/n/max. The legacy 30 (REQUEST_OLD) carries only min/n and is
            // rejected by modern servers, so always use 34.
            let mut req = Vec::new();
            req.push(msg::SSH_MSG_KEX_DH_GEX_REQUEST);
            min.encode(&mut req)?;
            nbits.encode(&mut req)?;
            max.encode(&mut req)?;
            send_raw_packet(stream, &req).await?;
            self.transport.outgoing_seq += 1;

            let group_msg = receive_raw_packet(stream).await?;
            self.transport.incoming_seq += 1;
            if group_msg.first() != Some(&msg::SSH_MSG_KEX_DH_GEX_GROUP) {
                return Err(SshError::Protocol("expected SSH_MSG_KEX_DH_GEX_GROUP".into()));
            }
            let mut r = &group_msg[1..];
            let p_mp = SshMpInt::decode(&mut r)?.0;
            let g_mp = SshMpInt::decode(&mut r)?.0;
            let p_bytes = p_mp.clone();
            let g_bytes = g_mp.clone();
            let p_bu = num_bigint::BigUint::from_bytes_be(&p_mp);
            let g_bu = num_bigint::BigUint::from_bytes_be(&g_mp);
            // Validate the server-selected group before using it: the size must
            // fall inside the range we requested and g must be a valid
            // generator in (1, p-1).
            let p_bits = p_bu.bits();
            if p_bits < u64::from(min) || p_bits > u64::from(max) {
                return Err(SshError::Protocol(format!(
                    "group-exchange modulus is {} bits, outside requested [{}, {}]",
                    p_bits, min, max
                )));
            }
            if g_bu <= num_bigint::BigUint::from(1u32) || g_bu >= &p_bu - num_bigint::BigUint::from(1u32) {
                return Err(SshError::Protocol("group-exchange generator out of range".into()));
            }
            let exp_bytes = if negotiation.kex_algorithm.contains("sha256") { 512 } else { 256 };
            let gex_name: &'static str = if negotiation.kex_algorithm.contains("sha256") {
                "diffie-hellman-group-exchange-sha256"
            } else {
                "diffie-hellman-group-exchange-sha1"
            };
            let gex_hash: &'static str = if negotiation.kex_algorithm.contains("sha256") { "sha256" } else { "sha1" };
            let mut real_modp = ssh_core::kex::ModpKex::with_params(gex_name, gex_hash, p_bu.clone(), g_bu.clone(), exp_bytes);
            real_modp.generate_keypair()?;
            let client_pub = real_modp.public_key_bytes();

            let mut init_msg = Vec::new();
            init_msg.push(msg::SSH_MSG_KEX_DH_GEX_INIT);
            SshMpInt(client_pub.clone()).encode(&mut init_msg)?;
            send_raw_packet(stream, &init_msg).await?;
            self.transport.outgoing_seq += 1;

            let reply = receive_raw_packet(stream).await?;
            self.transport.incoming_seq += 1;
            if reply.first() != Some(&msg::SSH_MSG_KEX_DH_GEX_REPLY) {
                return Err(SshError::Protocol("expected SSH_MSG_KEX_DH_GEX_REPLY".into()));
            }
            let mut r = &reply[1..];
            let host_key_blob = SshBytes::decode(&mut r)?.0;
            let f_bytes = SshMpInt::decode(&mut r)?.0;
            let sig_blob = SshBytes::decode(&mut r)?.0;

            let shared = real_modp.compute_shared_secret(&f_bytes)?;
            let exchange = KexExchange {
                client_version: self.transport.client_version.clone(),
                server_version: self.transport.server_version.clone(),
                client_kex_init: self.transport.client_kex_init.clone(),
                server_kex_init: self.transport.server_kex_init.clone(),
            };
            let exch_hash = ssh_core::kex::compute_gex_exchange_hash(
                real_modp.hash_name(),
                &exchange,
                min, nbits, max,
                &p_bytes, &g_bytes,
                &host_key_blob,
                &client_pub,
                &f_bytes,
                &shared,
            );
            // Override trait object kex so later we can save it back into transport
            kex = Box::new(real_modp);
            (host_key_blob, f_bytes, sig_blob, shared, exch_hash, gex_hash.to_string())
        } else {
            kex.generate_keypair()?;
            let mut dh_payload = Vec::new();
            dh_payload.push(msg::SSH_MSG_KEXDH_INIT);
            // Finite-field DH sends e as an mpint (0x00 sign byte when the
            // high bit is set); ECDH/curve25519 send the ephemeral public key
            // as a plain byte string, where an extra byte would make peers
            // reject an over-long key.
            if negotiation.kex_algorithm.starts_with("diffie-hellman-group") {
                SshMpInt(kex.public_key_bytes()).encode(&mut dh_payload)?;
            } else {
                SshBytes(kex.public_key_bytes()).encode(&mut dh_payload)?;
            }
            send_raw_packet(stream, &dh_payload).await?;
            self.transport.outgoing_seq += 1;
            self.transport.state = KexState::KexDhInitSent;

            let reply = receive_raw_packet(stream).await?;
            self.transport.incoming_seq += 1;
            self.transport.state = KexState::KexDhReplyReceived;

            let mut r = &reply[1..];
            let host_key_blob = SshBytes::decode(&mut r)?.0;
            let srv_pub = SshBytes::decode(&mut r)?.0;
            let sig_blob = SshBytes::decode(&mut r)?.0;

            let shared = kex.compute_shared_secret(&srv_pub)?;
            let hash_name = kex.hash_name().to_string();

            let exchange = KexExchange {
                client_version: self.transport.client_version.clone(),
                server_version: self.transport.server_version.clone(),
                client_kex_init: self.transport.client_kex_init.clone(),
                server_kex_init: self.transport.server_kex_init.clone(),
            };

            let exch_hash = ssh_core::kex::compute_exchange_hash(
                &hash_name,
                &exchange,
                &host_key_blob,
                &kex.public_key_bytes(),
                &srv_pub,
                &shared,
                // Finite-field DH hashes e/f as mpints; ECDH/curve25519 as
                // byte strings.
                negotiation.kex_algorithm.starts_with("diffie-hellman-group"),
            );
            (host_key_blob, srv_pub, sig_blob, shared, exch_hash, hash_name)
        };

        self.transport.state = KexState::KexDhReplyReceived;
        let hash_name = kex_hash_name.as_str();

        let mut r2 = &server_host_key_blob[..];
        let host_key_type = SshString::decode(&mut r2)?.as_str()?.to_string();
        let host_key_bytes = if host_key_type.starts_with("ecdsa-") {
            let _curve = SshString::decode(&mut r2)?;
            SshBytes::decode(&mut r2)?.0
        } else if host_key_type == "ssh-rsa" || host_key_type.starts_with("rsa-sha2-") {
            // RSA keys carry two fields (e, n); keep both instead of decoding
            // a single string (reading only `e` made verification fail with an
            // end-of-buffer error).
            r2.to_vec()
        } else {
            SshBytes::decode(&mut r2)?.0
        };

        // ssh-keyscan: capture the host key without verifying known_hosts.
        if self.config.ssh_keyscan {
            self.captured_host_key = Some((host_key_type.clone(), server_host_key_blob.clone()));
        } else {
            // Honor UserKnownHostsFile/GlobalKnownHostsFile (OpenSSH behavior):
            // the user file is consulted first and is where new keys are added;
            // the global file is read-only.
            let (user_kh_path, global_kh_path) = known_hosts_paths(&self.config);
            let user_kh = KnownHosts::new(user_kh_path.clone());
            let global_kh = KnownHosts::new(global_kh_path.clone());

            // HostKeyAlias: use the alias (not the real hostname) for verification.
            let lookup_host = host_key_lookup_name(&self.config);
            // NoHostAuthenticationForLocalhost: skip host-key verification for
            // loopback connections (OpenSSH behavior). This bypasses the strict
            // host-key check entirely for localhost.
            if self.config.no_host_authentication_for_localhost
                && is_localhost_host(&lookup_host)
            {
                tracing::debug!("skipping host-key verification for localhost");
            } else {
            let mut status = check_host_status(
                &user_kh, &global_kh,
                &lookup_host, self.config.port,
                &host_key_type, &server_host_key_blob,
            );

            // VerifyHostKeyDNS: verify the host key against SSHFP records.
            // OpenSSH semantics: a match accepts the key; a mismatch is fatal
            // only for "yes", while "ask" only warns and falls through to the
            // normal known_hosts handling. "no" (the default) disables the
            // lookup entirely.
            if self.config.verify_host_key_dns != "no" {
                match check_host_key_dns(&lookup_host, &host_key_type, &server_host_key_blob).await {
                    Some(true) => status = HostKeyStatus::Known,
                    Some(false) => {
                        if self.config.verify_host_key_dns == "yes" {
                            eprintln!("Warning: host key verification failed: SSHFP DNS records do not match.");
                            return Err(SshError::HostKeyVerificationFailed);
                        }
                        eprintln!("Warning: no matching SSHFP DNS record found for {}.", lookup_host);
                    }
                    None => {}
                }
            }

            // CheckHostIP: additionally verify the server's IP in known_hosts
            // (OpenSSH checks the IP too when it differs from the hostname).
            if self.config.check_host_ip {
                if let Some(ip) = &self.peer_ip {
                    if ip != &lookup_host {
                        let ip_status = check_host_status(
                            &user_kh, &global_kh,
                            ip, self.config.port,
                            &host_key_type, &server_host_key_blob,
                        );
                        match (status, ip_status) {
                            (HostKeyStatus::Unknown, HostKeyStatus::Known) => {
                                status = HostKeyStatus::Known;
                            }
                            (HostKeyStatus::Unknown, HostKeyStatus::Changed) => {
                                status = HostKeyStatus::Changed;
                            }
                            (HostKeyStatus::Known, HostKeyStatus::Changed) => {
                                eprintln!("Warning: the IP address {} is listed in known_hosts with a different key.", ip);
                            }
                            _ => {}
                        }
                    }
                }
            }

            match status {
                HostKeyStatus::Known => {
                    // VisualHostKey: print ASCII randomart of the host key.
                    if self.config.visual_host_key {
                        eprintln!("+---[{}]-----+", host_key_type);
                        eprint!("{}", randomart(&server_host_key_blob));
                        eprintln!("+---[{}]-----+", host_key_type);
                    }
                }
                HostKeyStatus::Unknown => {
                    if self.config.strict_host_key_checking.is_strict() {
                        return Err(SshError::HostKeyVerificationFailed);
                    }
                    // In `ask` mode, prompt the user like OpenSSH does.
                    if self.config.strict_host_key_checking.is_ask()
                        && !prompt_accept_host_key(&lookup_host, &host_key_type, &server_host_key_blob, &self.config.fingerprint_hash)
                    {
                        return Err(SshError::HostKeyVerificationFailed);
                    }
                    eprintln!("Warning: Permanently added '{}' ({}) to the list of known hosts.",
                        lookup_host, host_key_type);
                    let mut kh = KnownHosts::new(user_kh_path);
                    kh.add_host_hashed(
                        &lookup_host,
                        self.config.port,
                        &host_key_type,
                        &server_host_key_blob,
                        self.config.hash_known_hosts,
                    )?;
                }
                HostKeyStatus::Changed => {
                    eprintln!("WARNING: Remote host identification has changed!");
                    if self.config.strict_host_key_checking.is_strict() {
                        return Err(SshError::HostKeyVerificationFailed);
                    }
                    // In `ask` mode, a changed key is always rejected (OpenSSH
                    // refuses to auto-accept a changed key even with ask).
                    if self.config.strict_host_key_checking.is_ask() {
                        return Err(SshError::HostKeyVerificationFailed);
                    }
                }
            }
            }
        }

        let sig_ok = match host_key_type.as_str() {
            "ssh-ed25519" => {
                let pk_bytes: [u8; 32] = host_key_bytes.as_slice().try_into()
                    .map_err(|_| SshError::InvalidKey("ed25519 pubkey length".into()))?;
                let verifier = Ed25519HostKey::from_public_bytes(&pk_bytes)?;
                HostKeyVerifier::verify(&verifier, &exchange_hash, &server_signature_blob)?
            }
            "ecdsa-sha2-nistp256" => {
                let verifier = EcdsaP256HostKey::from_public_bytes(&host_key_bytes)?;
                HostKeyVerifier::verify(&verifier, &exchange_hash, &server_signature_blob)?
            }
            "ecdsa-sha2-nistp384" => {
                let verifier = EcdsaP384HostKey::from_public_bytes(&host_key_bytes)?;
                HostKeyVerifier::verify(&verifier, &exchange_hash, &server_signature_blob)?
            }
            "ecdsa-sha2-nistp521" => {
                let verifier = EcdsaP521HostKey::from_public_bytes(&host_key_bytes)?;
                HostKeyVerifier::verify(&verifier, &exchange_hash, &server_signature_blob)?
            }
            "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => {
                let verifier = RsaHostKey::from_public_bytes(&host_key_bytes)?;
                if verifier.bits() < self.config.required_rsa_size as usize {
                    return Err(SshError::HostKeyVerificationFailed);
                }
                let sig_alg = {
                    let mut r = &server_signature_blob[..];
                    let got = SshString::decode(&mut r).ok();
                    got.and_then(|s| s.as_str().ok().map(|s| s.to_string()))
                        .unwrap_or_else(|| host_key_type.clone())
                };
                HostKeyVerifier::verify_with(&verifier, &sig_alg, &exchange_hash, &server_signature_blob)?
            }
            other => {
                eprintln!("Warning: unsupported host key type {} for signature verification", other);
                true
            }
        };
        if !sig_ok {
            return Err(SshError::HostKeyVerificationFailed);
        }

        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;

        // RFC 4253 §7.1: SSH_MSG_NEWKEYS is sent with the current (old) keys.
        // Neither side has installed the new keys yet, so this is a plaintext
        // packet; both sides switch to the new keys only after the exchange.
        let newkeys_msg = vec![msg::SSH_MSG_NEWKEYS];
        send_encrypted_packet(stream, &newkeys_msg, &mut self.transport, true, aead).await?;
        self.transport.state = KexState::NewKeysSent;

        let newkeys_response = receive_encrypted_packet(stream, &mut self.transport, true, aead).await?;
        if newkeys_response.first() != Some(&msg::SSH_MSG_NEWKEYS) {
            return Err(SshError::Protocol("expected NEWKEYS".into()));
        }
        self.transport.state = KexState::NewKeysReceived;
        // Strict KEX restarts both sequence numbers at zero after NEWKEYS.
        self.transport.reset_sequences_after_newkeys();

        // Only now is it safe to install and use the new keys.
        self.transport.install_new_keys(
            &negotiation,
            hash_name,
            &shared_secret,
            &exchange_hash,
            &exchange_hash,
        )?;

        self.session_id = Some(exchange_hash);
        self.transport.kex_algorithm = Some(kex);
        self.transport.state = KexState::Established;
        // The RekeyLimit byte counter starts after the initial key exchange.
        self.transport.last_rekey_bytes = self.transport.total_bytes();
        self.transport.last_rekey_instant = std::time::Instant::now();

        Ok(())
    }

    pub async fn authenticate(&mut self) -> Result<()> {
        let session_id = self.session_id.clone().ok_or_else(|| SshError::Protocol("no session id".into()))?;
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;

        let mut svc_request = vec![msg::SSH_MSG_SERVICE_REQUEST];
        SshString::new(msg::SSH_SERVICE_NAME_USERAUTH).encode(&mut svc_request)?;
        send_encrypted_packet(stream, &svc_request, &mut self.transport, false, aead).await?;

        let svc_accept = loop {
            let pkt = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
            match pkt.first() {
                Some(&msg::SSH_MSG_SERVICE_ACCEPT) => break pkt,
                Some(&msg::SSH_EXT_INFO_S) => {
                    let mut r = &pkt[1..];
                    if let Ok(nr_ext) = u32::decode(&mut r) {
                        for _ in 0..nr_ext {
                            if let (Ok(ext_name), Ok(ext_value)) = (SshString::decode(&mut r), SshBytes::decode(&mut r)) {
                                if let Ok(name) = ext_name.as_str() {
                                    if name == "server-sig-algs" {
                                        let algs_str = String::from_utf8_lossy(&ext_value.0);
                                        self.server_sig_algs = algs_str
                                            .split(',')
                                            .map(|s| s.trim().to_string())
                                            .filter(|s| !s.is_empty())
                                            .collect();
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                Some(&msg::SSH_MSG_IGNORE) => continue,
                Some(&msg::SSH_MSG_DEBUG) => continue,
                Some(&msg::SSH_MSG_USERAUTH_BANNER) => {
                    display_auth_banner(&pkt);
                    continue;
                }
                _ => break pkt,
            }
        };
        if svc_accept.first() != Some(&msg::SSH_MSG_SERVICE_ACCEPT) {
            return Err(SshError::AuthFailed("service not accepted".into()));
        }

        let username = self.config.user.clone();
        let mut auth_succeeded = false;

        let mut method_order: Vec<String> = Vec::new();
        if let Some(pref) = &self.config.preferred_authentications {
            for m in pref {
                let ok = match m.as_str() {
                    "publickey" => self.config.pubkey_authentication,
                    "keyboard-interactive" => self.config.kbd_interactive_authentication,
                    "password" => self.config.password_authentication,
                    _ => false,
                };
                if ok && !method_order.contains(m) {
                    method_order.push(m.clone());
                }
            }
            if method_order.is_empty() {
                return Err(SshError::AuthFailed("no authentication methods enabled".into()));
            }
        } else {
            if self.config.pubkey_authentication { method_order.push("publickey".into()); }
            if self.config.kbd_interactive_authentication { method_order.push("keyboard-interactive".into()); }
            if self.config.password_authentication { method_order.push("password".into()); }
        }

        let mut identity_files: Vec<std::path::PathBuf> = Vec::new();
        if let Some(id) = &self.config.identity_file {
            identity_files.push(id.clone());
        }
        if !self.config.identities_only {
            identity_files.extend(crate::agent::get_identity_files());
        }
        for key_path in &identity_files {
            match crate::agent::load_private_key(key_path) {
                Ok(signer) => {
                    self.loaded_signers.push(signer);
                }
                Err(_) => continue,
            }
        }

        let has_sig_algs = !self.server_sig_algs.is_empty();

        for method in &method_order {
            match method.as_str() {
                "publickey" => {
                    for i in 0..self.loaded_signers.len() {
                        let alg = self.loaded_signers[i].algorithm_name().to_string();
                        if has_sig_algs && !self.server_sig_algs.iter().any(|a| a == &alg) {
                            continue;
                        }
                        if let Some(ref accepted) = self.config.pubkey_accepted_algorithms {
                            if !crate::config::pubkey_alg_accepted(&alg, accepted) {
                                continue;
                            }
                        }
                        let method = AuthMethod::PublicKey(self.loaded_signers[i].clone());
                        let auth_msg = build_userauth_request_with_session(
                            &username,
                            msg::SSH_SERVICE_NAME_CONNECTION,
                            &method,
                            &session_id,
                        );
                        send_encrypted_packet(stream, &auth_msg, &mut self.transport, false, aead).await?;

                        let response = read_auth_packet(stream, &mut self.transport, aead).await?;
                        match response.first() {
                            Some(&msg::SSH_MSG_USERAUTH_SUCCESS) => {
                                auth_succeeded = true;
                                break;
                            }
                            Some(&msg::SSH_MSG_USERAUTH_PK_OK) => {
                                let method2 = AuthMethod::PublicKey(self.loaded_signers[i].clone());
                                let auth_msg2 = build_userauth_request_with_session(
                                    &username,
                                    msg::SSH_SERVICE_NAME_CONNECTION,
                                    &method2,
                                    &session_id,
                                );
                                send_encrypted_packet(stream, &auth_msg2, &mut self.transport, false, aead).await?;
                                let resp = read_auth_packet(stream, &mut self.transport, aead).await?;
                                if resp.first() == Some(&msg::SSH_MSG_USERAUTH_SUCCESS) {
                                    auth_succeeded = true;
                                    break;
                                }
                            }
                            _ => continue,
                        }
                    }
                    // Fall back to keys held by an SSH agent (OpenSSH behavior:
                    // `ssh-agent` keys are tried alongside identity files).
                    if !auth_succeeded && self.agent.is_available() {
                        if let Ok(ids) = self.agent.request_identities().await {
                            for (_comment, blob) in ids {
                                let alg = crate::agent::blob_algorithm(&blob).unwrap_or_default();
                                if alg.is_empty() { continue; }
                                if has_sig_algs && !self.server_sig_algs.iter().any(|a| a == &alg) {
                                    continue;
                                }
                                if let Some(ref accepted) = self.config.pubkey_accepted_algorithms {
                                    if !crate::config::pubkey_alg_accepted(&alg, accepted) {
                                        continue;
                                    }
                                }
                                // Probe with an unsigned request first.
                                let query = build_userauth_pubkey_query(
                                    &username,
                                    msg::SSH_SERVICE_NAME_CONNECTION,
                                    &alg,
                                    &blob,
                                );
                                send_encrypted_packet(stream, &query, &mut self.transport, false, aead).await?;
                                let resp = read_auth_packet(stream, &mut self.transport, aead).await?;
                                if resp.first() != Some(&msg::SSH_MSG_USERAUTH_PK_OK) {
                                    continue;
                                }
                                let sign_data = build_sign_data_for_agent(
                                    &username,
                                    msg::SSH_SERVICE_NAME_CONNECTION,
                                    &alg,
                                    &blob,
                                    &session_id,
                                );
                                match self.agent.sign_request(&blob, &sign_data, 0).await {
                                    Ok(sig) => {
                                        let signed = build_userauth_pubkey_signed(
                                            &username,
                                            msg::SSH_SERVICE_NAME_CONNECTION,
                                            &alg,
                                            &blob,
                                            &sig,
                                        );
                                        send_encrypted_packet(stream, &signed, &mut self.transport, false, aead).await?;
                                        let resp2 = read_auth_packet(stream, &mut self.transport, aead).await?;
                                        if resp2.first() == Some(&msg::SSH_MSG_USERAUTH_SUCCESS) {
                                            auth_succeeded = true;
                                            break;
                                        }
                                    }
                                    Err(_) => continue,
                                }
                            }
                        }
                    }
                    if auth_succeeded { break; }
                }
                "keyboard-interactive" => {
                    if self.config.batch_mode {
                        continue;
                    }
                    let kbd_method = AuthMethod::KeyboardInteractive(Vec::new());
                    let kbd_msg = build_userauth_request_with_session(
                        &username,
                        msg::SSH_SERVICE_NAME_CONNECTION,
                        &kbd_method,
                        &session_id,
                    );
                    send_encrypted_packet(stream, &kbd_msg, &mut self.transport, false, aead).await?;

                    let mut kbd_tries = 0;
                    while kbd_tries < 3 {
                        let kbd_resp = read_auth_packet(stream, &mut self.transport, aead).await?;
                        match kbd_resp.first() {
                            Some(&msg::SSH_MSG_USERAUTH_SUCCESS) => {
                                auth_succeeded = true;
                                break;
                            }
                            Some(&msg::SSH_MSG_USERAUTH_FAILURE) => {
                                break;
                            }
                            Some(&msg::SSH_MSG_USERAUTH_INFO_REQUEST) => {
                                let prompts = parse_userauth_info_request(&kbd_resp)?;
                                let mut answers: Vec<String> = Vec::with_capacity(prompts.len());
                                for (prompt, _ans, echo, _) in prompts {
                                    eprint!("{}", prompt);
                                    use std::io::Write;
                                    let _ = std::io::stderr().flush();
                                    let mut line = String::new();
                                    std::io::stdin().read_line(&mut line)
                                        .map_err(|e| SshError::Io(e))?;
                                    let line = line.trim_end_matches('\n').trim_end_matches('\r').to_string();
                                    let _ = echo;
                                    answers.push(line);
                                }
                                let resp_msg = build_userauth_info_response(&answers);
                                send_encrypted_packet(stream, &resp_msg, &mut self.transport, false, aead).await?;
                            }
                            _ => break,
                        }
                        kbd_tries += 1;
                    }
                    if auth_succeeded { break; }
                }
                "password" => {
                    if self.config.batch_mode {
                        continue;
                    }
                    // NumberOfPasswordPrompts: limit interactive password attempts (default 3).
                    let max_tries = self.config.number_of_password_prompts.max(1);
                    for attempt in 0..max_tries {
                        eprint!("{}@{}'s password: ", self.config.user, self.config.hostname);
                        use std::io::Write;
                        let _ = std::io::stderr().flush();
                        let mut password = String::new();
                        std::io::stdin().read_line(&mut password)
                            .map_err(|e| SshError::Io(e))?;
                        let password = password.trim_end().to_string();

                        let pwd_method = AuthMethod::Password(password);
                        let pwd_msg = build_userauth_request_with_session(
                            &username,
                            msg::SSH_SERVICE_NAME_CONNECTION,
                            &pwd_method,
                            &session_id,
                        );
                        send_encrypted_packet(stream, &pwd_msg, &mut self.transport, false, aead).await?;

                        let pwd_resp = read_auth_packet(stream, &mut self.transport, aead).await?;
                        if pwd_resp.first() == Some(&msg::SSH_MSG_USERAUTH_SUCCESS) {
                            auth_succeeded = true;
                            break;
                        }
                        if attempt + 1 < max_tries {
                            eprintln!("Permission denied, please try again.");
                        }
                    }
                    if auth_succeeded { break; }
                }
                _ => {}
            }
        }

        if !auth_succeeded {
            return Err(SshError::AuthFailed("authentication failed".into()));
        }

        if self.transport.client_to_server_compression == "zlib@openssh.com"
            || self.transport.client_to_server_compression == "zlib"
        {
            self.transport.compression_active_c2s = true;
        }
        if self.transport.server_to_client_compression == "zlib@openssh.com"
            || self.transport.server_to_client_compression == "zlib"
        {
            self.transport.compression_active_s2c = true;
        }

        Ok(())
    }

    pub async fn request_session(
        &mut self,
        command: Option<&str>,
        pty: bool,
        term: &str,
        width: u32,
        height: u32,
    ) -> Result<ChannelId> {
        let local_id = self.channel_manager.alloc_channel(
            msg::SSH_CHANNEL_TYPE_SESSION,
            msg::CHANNEL_PACKET_WINDOW_SIZE,
            msg::CHANNEL_MAX_PACKET_SIZE,
        );

        let open_msg = build_channel_open(
            msg::SSH_CHANNEL_TYPE_SESSION,
            local_id,
            msg::CHANNEL_PACKET_WINDOW_SIZE,
            msg::CHANNEL_MAX_PACKET_SIZE,
        );
        self.send_packet(&open_msg, false).await?;

        let open_resp = self.recv_packet().await?;
        if std::env::var("NS_DEBUG_PKT").is_ok() {
            let hex: String = open_resp.iter().map(|b| format!("{:02x}", b)).collect();
            eprintln!("CHANNEL_OPEN_RESP type={} len={} seq={} hex={}", open_resp.first().copied().unwrap_or(0), open_resp.len(), self.transport.incoming_seq.saturating_sub(1), hex);
        }
        match open_resp.first() {
            Some(&msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                let (recipient, sender, w, _m) = parse_channel_open_confirmation(&open_resp)?;
                if recipient != local_id {
                    return Err(SshError::Protocol("unexpected recipient in open confirmation".into()));
                }
                self.channel_manager.set_remote_id(local_id, sender);
                self.channel_manager.set_peer_window(local_id, w);
            }
            Some(&msg::SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                let (_, reason, message) = parse_channel_open_failure(&open_resp)?;
                return Err(SshError::Channel(format!("session open failed: {} ({})", message, reason)));
            }
            _ => return Err(SshError::Protocol("unexpected response to channel open".into())),
        }

        if self.config.forward_agent {
            let req = build_channel_request(local_id, msg::SSH_REQUEST_AUTH_AGENT, false, None);
            self.send_packet(&req, false).await?;
        }

        if pty {
            let pty_data = build_pty_request(term, width, height, width * 8, height * 16, &[]);
            let pty_msg = build_channel_request(local_id, msg::SSH_REQUEST_PTY, true, Some(&pty_data));
            self.send_packet(&pty_msg, false).await?;
            let _resp = self.recv_packet().await?;
        }

        if self.config.forward_x11 {
            let mut cookie = [0u8; 16];
            let mut seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            for b in cookie.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *b = (seed >> 33) as u8;
            }
            let cookie_hex: String = cookie.iter().map(|b| format!("{:02x}", b)).collect();
            let x11_data = build_x11_request(false, "MIT-MAGIC-COOKIE-1", &cookie_hex, 0);
            let x11_msg = build_channel_request(local_id, msg::SSH_REQUEST_X11, true, Some(&x11_data));
            self.send_packet(&x11_msg, false).await?;
            let _resp = self.recv_packet().await?;
        }

        for (name, value) in &self.config.set_env.clone() {
            let env_data = build_env_request(name, value);
            let env_msg = build_channel_request(local_id, msg::SSH_REQUEST_ENV, false, Some(&env_data));
            self.send_packet(&env_msg, false).await?;
        }
        if !self.config.send_env.is_empty() {
            let envs: Vec<(String, String)> = std::env::vars().collect();
            for pattern in &self.config.send_env.clone() {
                for (name, value) in &envs {
                    if env_pattern_match(name, pattern) {
                        let env_data = build_env_request(name, value);
                        let env_msg = build_channel_request(local_id, msg::SSH_REQUEST_ENV, false, Some(&env_data));
                        self.send_packet(&env_msg, false).await?;
                    }
                }
            }
        }

        if let Some(cmd) = command {
            let exec_data = build_exec_request(cmd);
            let exec_msg = build_channel_request(local_id, msg::SSH_REQUEST_EXEC, true, Some(&exec_data));
            self.send_packet(&exec_msg, false).await?;
            let _resp = self.recv_packet().await?;
        } else {
            let shell_msg = build_channel_request(local_id, msg::SSH_REQUEST_SHELL, true, None);
            self.send_packet(&shell_msg, false).await?;
            let _resp = self.recv_packet().await?;
        }

        Ok(local_id)
    }

    pub async fn request_session_subsystem(&mut self, subsystem: &str) -> Result<ChannelId> {
        let local_id = self.channel_manager.alloc_channel(
            msg::SSH_CHANNEL_TYPE_SESSION,
            msg::CHANNEL_PACKET_WINDOW_SIZE,
            msg::CHANNEL_MAX_PACKET_SIZE,
        );
        let open_msg = build_channel_open(
            msg::SSH_CHANNEL_TYPE_SESSION,
            local_id,
            msg::CHANNEL_PACKET_WINDOW_SIZE,
            msg::CHANNEL_MAX_PACKET_SIZE,
        );
        self.send_packet(&open_msg, false).await?;
        let open_resp = self.recv_packet().await?;
        match open_resp.first() {
            Some(&msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                let (recipient, sender, w, _m) = parse_channel_open_confirmation(&open_resp)?;
                if recipient != local_id {
                    return Err(SshError::Protocol("unexpected recipient in open confirmation".into()));
                }
                self.channel_manager.set_remote_id(local_id, sender);
                self.channel_manager.set_peer_window(local_id, w);
            }
            Some(&msg::SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                let (_, reason, message) = parse_channel_open_failure(&open_resp)?;
                return Err(SshError::Channel(format!("session open failed: {} ({})", message, reason)));
            }
            _ => return Err(SshError::Protocol("unexpected response to channel open".into())),
        }
        let remote_id = self.channel_manager.get_channel(local_id)
            .and_then(|c| c.remote_id)
            .unwrap_or(local_id);
        let sub_data = build_subsystem_request(subsystem);
        let sub_msg = build_channel_request(remote_id, msg::SSH_REQUEST_SUBSYSTEM, true, Some(&sub_data));
        self.send_packet(&sub_msg, false).await?;
        let resp = self.recv_packet().await?;
        match resp.first() {
            Some(&msg::SSH_MSG_CHANNEL_SUCCESS) => {}
            Some(&msg::SSH_MSG_CHANNEL_FAILURE) => {
                return Err(SshError::Channel(format!("subsystem '{}' refused", subsystem)))
            }
            _ => return Err(SshError::Protocol("unexpected subsystem response".into())),
        }
        Ok(local_id)
    }

    pub async fn run_event_loop(
        &mut self,
        session_id: Option<ChannelId>,
    ) -> Result<i32> {
        use tokio::net::TcpListener;
        let aead = self.is_aead();
        let mut exit_code: i32 = 0;
        let mut should_exit = false;
        let mut stdin_active = true;

        // OpenSSH-style escape characters are processed only when stdin is a
        // terminal (interactive session), matching `ssh` behavior. Setting
        // `EscapeChar none` disables escape-sequence processing entirely.
        let escape_char = if self.config.escape_char.eq_ignore_ascii_case("none") {
            '\0'
        } else {
            self.config.escape_char.chars().next().unwrap_or('~')
        };
        let escape_enabled = atty::is(atty::Stream::Stdin) && escape_char != '\0';
        let mut escape_state = EscapeState::new();

        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            loop {
                let n = tokio::task::spawn_blocking(move || {
                    use std::io::Read;
                    let mut buf = [0u8; 4096];
                    match std::io::stdin().read(&mut buf) {
                        Ok(n) => (n, buf),
                        Err(_) => (0, [0u8; 4096]),
                    }
                }).await.unwrap_or((0, [0u8; 4096]));
                if n.0 == 0 { break; }
                if stdin_tx.send(n.1[..n.0].to_vec()).is_err() { break; }
            }
        });

        let (to_ssh_tx, mut to_ssh_rx) = mpsc::unbounded_channel::<(ChannelId, Vec<u8>)>();

        enum AcceptEvent {
            Local(usize, tokio::net::TcpStream),
            Dynamic(tokio::net::TcpStream),
            StreamLocal(usize, tokio::net::UnixStream),
        }
        let (accept_tx, mut accept_rx) = mpsc::unbounded_channel::<AcceptEvent>();

        // Bind all local forwards to a hostname honoring `-g`/GatewayPorts and
        // the configured bind address (OpenSSH default is loopback).
        let local_bind_host = if self.config.gateway_ports {
            self.config.bind_address.clone().unwrap_or_else(|| "0.0.0.0".to_string())
        } else {
            self.config.bind_address.clone().unwrap_or_else(|| "127.0.0.1".to_string())
        };

        let mut local_meta: Vec<(String, u16, u16)> = Vec::new();
        let mut forward_failed = false;
        for (i, (fbind, bind_port, host, connect_port)) in self.config.local_forwards.clone().into_iter().enumerate() {
            // Per-forward bind address (`-L bind:port:host:hostport`) overrides
            // the global BindAddress / GatewayPorts policy.
            let bind_host = if fbind.is_empty() { local_bind_host.clone() } else { fbind };
            let bind_addr = format!("{}:{}", bind_host, bind_port);
            match TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    tracing::info!("Local forwarding listening on {} -> {}:{}", bind_addr, host, connect_port);
                    local_meta.push((host, connect_port, bind_port));
                    let tx = accept_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((s, _)) => {
                                    if tx.send(AcceptEvent::Local(i, s)).is_err() { break; }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(_) => {
                    eprintln!("ns-ssh: cannot listen on {}", bind_addr);
                    forward_failed = true;
                }
            }
        }

        for socks_port in self.config.dynamic_forwards.clone() {
            let bind_addr = format!("{}:{}", local_bind_host, socks_port);
            match TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    tracing::info!("Dynamic forwarding (SOCKS5) listening on {}", bind_addr);
                    let tx = accept_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((s, _)) => {
                                    if tx.send(AcceptEvent::Dynamic(s)).is_err() { break; }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(_) => {
                    eprintln!("ns-ssh: cannot listen on {}", bind_addr);
                    forward_failed = true;
                }
            }
        }
        // StreamLocal `-L local_socket:remote_socket` forwards (Unix sockets).
        let mut local_streamlocal_meta: Vec<String> = Vec::new();
        for (i, (local_socket, remote_socket)) in self.config.local_streamlocal.clone().into_iter().enumerate() {
            let _ = std::fs::remove_file(&local_socket);
            match tokio::net::UnixListener::bind(&local_socket) {
                Ok(listener) => {
                    tracing::info!("StreamLocal forwarding listening on {} -> {}", local_socket, remote_socket);
                    local_streamlocal_meta.push(remote_socket.clone());
                    let tx = accept_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((s, _)) => {
                                    if tx.send(AcceptEvent::StreamLocal(i, s)).is_err() { break; }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(_) => {
                    eprintln!("ns-ssh: cannot listen on streamlocal {}", local_socket);
                    forward_failed = true;
                }
            }
        }
        drop(accept_tx);

        // `ExitOnForwardFailure yes`: exit with an error if a forward could not
        // be set up (OpenSSH behavior).
        if forward_failed && self.config.exit_on_forward_failure {
            eprintln!("ns-ssh: forwarding setup failed; exiting (ExitOnForwardFailure)");
            return Err(SshError::Channel("forward setup failed".into()));
        }

        let mut remote_forward_map: HashMap<u16, (String, u16)> = HashMap::new();
        for (bind_addr, remote_port, ref local_host, local_port) in self.config.remote_forwards.clone() {
            // An empty bind address makes the server apply its GatewayPorts
            // policy (OpenSSH: `-R` defaults to loopback unless GatewayPorts);
            // an explicit `-R bind:port:host:hostport` bind address is honored.
            let req = build_global_request_tcpip_forward(true, &bind_addr, remote_port as u32);
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
            remote_forward_map.insert(remote_port, (local_host.clone(), local_port));
        }

        // StreamLocal `-R remote_socket:local_socket` forwards (Unix sockets).
        let mut remote_streamlocal_map: HashMap<String, String> = HashMap::new();
        for (remote_socket, local_socket) in self.config.remote_streamlocal.clone() {
            let req = build_global_request_streamlocal_forward(true, &remote_socket);
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
            remote_streamlocal_map.insert(remote_socket, local_socket);
        }

        let mut session_data_rx = None;
        let mut session_ext_rx = None;
        if let Some(sid) = session_id {
            session_data_rx = self.channel_manager.take_data_rx(sid);
            session_ext_rx = self.channel_manager.take_ext_data_rx(sid);
        }

        // For -W: send direct-tcpip open now, handle confirmation in event loop
        let mut stdio_forward_channel_id: Option<ChannelId> = None;
        let mut stdio_forward_remote_id: Option<u32> = None;
        let mut stdio_forward_pending_data: Vec<Vec<u8>> = Vec::new();
        let mut stdio_forward_eof_pending = false;
        if session_id.is_none() {
            if let Some((ref host, port)) = self.config.stdio_forward {
                let host = host.clone();
                let aead = self.is_aead();
                let local_id = self.channel_manager.alloc_channel(
                    msg::SSH_CHANNEL_TYPE_DIRECT_TCPIP,
                    msg::CHANNEL_PACKET_WINDOW_SIZE,
                    msg::CHANNEL_MAX_PACKET_SIZE,
                );
                let msg_bytes = build_direct_tcpip_open(
                    local_id,
                    msg::CHANNEL_PACKET_WINDOW_SIZE,
                    msg::CHANNEL_MAX_PACKET_SIZE,
                    &host,
                    port as u32,
                    "127.0.0.1",
                    0,
                );
                let (tx, _rx) = oneshot::channel();
                self.pending_open.insert(local_id, tx);
                let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
                send_encrypted_packet(stream, &msg_bytes, &mut self.transport, false, aead).await?;
                stdio_forward_channel_id = Some(local_id);
            }
        }

        let alive_interval_ms = self.config.server_alive_interval.unwrap_or(0) as u64 * 1000;
        let alive_max = self.config.server_alive_count_max.unwrap_or(3).max(1) as u32;
        let mut alive_sleep = if alive_interval_ms > 0 {
            Some(Box::pin(tokio::time::sleep(tokio::time::Duration::from_millis(alive_interval_ms))))
        } else {
            None
        };
        let mut last_any_packet = std::time::Instant::now();
        // Track outstanding keepalive requests and count missed responses so the
        // server-alive mechanism enforces ServerAliveInterval/ServerAliveCountMax
        // per keepalive (OpenSSH behavior) rather than only via last-any-packet.
        let mut missed_alive: u32 = 0;
        let mut keepalive_outstanding: Option<std::time::Instant> = None;
        let mut pending_forward_sockets: HashMap<ChannelId, TcpStream> = HashMap::new();
        let mut pending_streamlocal_sockets: HashMap<ChannelId, tokio::net::UnixStream> = HashMap::new();
        // Forward-channel data deferred because the peer's receive window was 0.
        // Flushed when the server sends SSH_MSG_CHANNEL_WINDOW_ADJUST.
        let mut pending_window_data: VecDeque<(ChannelId, Vec<u8>)> = VecDeque::new();
        // Encrypted packets queued because the socket would block (peer receive
        // buffer full). Flushed non-blockingly at the top of the loop so incoming
        // packets are never starved by a blocked socket write (avoids the
        // bidirectional TCP deadlock on large simultaneous transfers).
        let mut pending_write: VecDeque<Vec<u8>> = VecDeque::new();
        // Channel EOF deferred until window-deferred data is flushed. Without
        // this, a large upload whose tail is window-gated would send SSH_MSG_
        // CHANNEL_EOF before the deferred bytes, truncating the transfer.
        let mut session_eof_pending = false;

        #[cfg(unix)]
        let mut winch_sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .ok();
        #[cfg(not(unix))]
        let winch_sig: Option<tokio::signal::unix::Signal> = None;

        // Forward local SIGINT/SIGTERM to the remote process (OpenSSH behavior).
        #[cfg(unix)]
        let mut sigint_sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .ok();
        #[cfg(not(unix))]
        let sigint_sig: Option<tokio::signal::unix::Signal> = None;
        #[cfg(unix)]
        let mut sigterm_sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .ok();
        #[cfg(not(unix))]
        let sigterm_sig: Option<tokio::signal::unix::Signal> = None;

        loop {
            if should_exit { break; }

            // Flush packets deferred because the socket would block. This is
            // non-blocking so incoming packets are processed promptly and a
            // blocked socket write never starves the receive path.
            self.flush_pending_write(&mut pending_write);

            {
                let tb = self.transport.total_bytes();
                let el = self.transport.last_rekey_instant.elapsed().as_secs();
                if self.transport.needs_rekey(tb, el) {
                    match self.perform_rekey().await {
                        Ok(deferred) => {
                            for d in deferred {
                                self.deferred_packets.push_back(d);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("rekey failed (continuing): {:?}", e);
                        }
                    }
                }
            }

            tokio::select! {
                biased;

                to_ssh = to_ssh_rx.recv() => {
                    if let Some((remote_id, data)) = to_ssh {
                        // Respect the peer's advertised receive window; defer
                        // when it is exhausted (flushed on WINDOW_ADJUST).
                        self.send_channel_data_gated(remote_id, data, &mut pending_window_data, &mut pending_write, aead).await;
                    }
                }

                _ = async {
                    if let Some(ref mut s) = alive_sleep { s.as_mut().await; } else { std::future::pending().await }
                }, if alive_interval_ms > 0 => {
                    let interval_secs = (alive_interval_ms as u32 / 1000).max(1);
                    // A previously-sent keepalive that got no response within the
                    // interval counts as a missed keepalive.
                    if keepalive_outstanding.is_some_and(|t| {
                        t.elapsed().as_secs() as u32 >= interval_secs
                    }) {
                        missed_alive += 1;
                        keepalive_outstanding = None;
                        tracing::debug!("server keepalive response missed ({}/{})", missed_alive, alive_max);
                    }
                    if missed_alive >= alive_max
                        || last_any_packet.elapsed().as_secs() as u32 >= interval_secs * alive_max
                    {
                        tracing::warn!("ServerAliveCountMax exceeded, disconnecting");
                        should_exit = true;
                    } else {
                        let _ = self.send_keepalive().await;
                        keepalive_outstanding = Some(std::time::Instant::now());
                    }
                    alive_sleep = Some(Box::pin(tokio::time::sleep(tokio::time::Duration::from_millis(alive_interval_ms))));
                }

                _ = async {
                    if let Some(ref mut s) = winch_sig { let _ = s.recv().await; } else { std::future::pending().await }
                }, if winch_sig.is_some() => {
                    if let Some(sid) = session_id {
                        if let Ok((w, h)) = terminal_size() {
                            let _ = self.send_window_change(sid, w, h).await;
                        }
                    }
                }

                _ = async {
                    if let Some(ref mut s) = sigint_sig { let _ = s.recv().await; } else { std::future::pending().await }
                }, if sigint_sig.is_some() && session_id.is_some() => {
                    if let Some(sid) = session_id {
                        let _ = self.send_signal(sid, "INT").await;
                    }
                }

                _ = async {
                    if let Some(ref mut s) = sigterm_sig { let _ = s.recv().await; } else { std::future::pending().await }
                }, if sigterm_sig.is_some() && session_id.is_some() => {
                    if let Some(sid) = session_id {
                        let _ = self.send_signal(sid, "TERM").await;
                    }
                }

                ev = accept_rx.recv(), if self.config.local_forwards.len() + self.config.dynamic_forwards.len() + self.config.local_streamlocal.len() > 0 => {
                    match ev {
                        Some(AcceptEvent::Local(idx, local_stream)) => {
                            if idx >= local_meta.len() { continue; }
                            let (ref host, connect_port, bind_port) = local_meta[idx];
                            let _ = self.open_direct_tcpip_queued(
                                &mut pending_forward_sockets,
                                host, connect_port as u32, "127.0.0.1", bind_port as u32,
                                local_stream, to_ssh_tx.clone(),
                            ).await;
                        }
                        Some(AcceptEvent::StreamLocal(idx, unix_stream)) => {
                            if idx >= local_streamlocal_meta.len() { continue; }
                            let remote_socket = local_streamlocal_meta[idx].clone();
                            let _ = self.open_direct_streamlocal_queued(
                                &mut pending_streamlocal_sockets,
                                &remote_socket, unix_stream, to_ssh_tx.clone(),
                            ).await;
                        }
                        Some(AcceptEvent::Dynamic(mut local_stream)) => {
                            let mut handshake = [0u8; 2];
                            if local_stream.read_exact(&mut handshake).await.is_err() { continue; }
                            if handshake[0] != 5 { continue; }
                            let nmethods = handshake[1] as usize;
                            let mut methods = vec![0u8; nmethods];
                            if local_stream.read_exact(&mut methods).await.is_err() { continue; }
                            let _ = local_stream.write_all(&[5, 0]).await;

                            let mut req_hdr = [0u8; 4];
                            if local_stream.read_exact(&mut req_hdr).await.is_err() { continue; }
                            if req_hdr[0] != 5 || req_hdr[1] != 1 {
                                let _ = local_stream.write_all(&[5, 8, 0, 1, 0,0,0,0, 0,0]).await;
                                continue;
                            }
                            let atyp = req_hdr[3];
                            let (host, port) = match atyp {
                                1 => {
                                    let mut ip = [0u8; 4];
                                    if local_stream.read_exact(&mut ip).await.is_err() { continue; }
                                    let mut p = [0u8; 2];
                                    if local_stream.read_exact(&mut p).await.is_err() { continue; }
                                    (format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), u16::from_be_bytes(p))
                                }
                                3 => {
                                    let mut len = [0u8; 1];
                                    if local_stream.read_exact(&mut len).await.is_err() { continue; }
                                    let mut hostbuf = vec![0u8; len[0] as usize];
                                    if local_stream.read_exact(&mut hostbuf).await.is_err() { continue; }
                                    let mut p = [0u8; 2];
                                    if local_stream.read_exact(&mut p).await.is_err() { continue; }
                                    (String::from_utf8_lossy(&hostbuf).to_string(), u16::from_be_bytes(p))
                                }
                                4 => {
                                    let mut ip = [0u8; 16];
                                    if local_stream.read_exact(&mut ip).await.is_err() { continue; }
                                    let mut p = [0u8; 2];
                                    if local_stream.read_exact(&mut p).await.is_err() { continue; }
                                    (std::net::Ipv6Addr::from(ip).to_string(), u16::from_be_bytes(p))
                                }
                                _ => { let _ = local_stream.write_all(&[5, 8, 0, 1, 0,0,0,0, 0,0]).await; continue; }
                            };
                            let reply = [5, 0, 0, 1, 0,0,0,0, 0,0];
                            let _ = local_stream.write_all(&reply).await;
                            tracing::info!("SOCKS5: connect {}:{}", host, port);
                            let _ = self.open_direct_tcpip_queued(
                                &mut pending_forward_sockets,
                                &host, port as u32, "127.0.0.1", 0,
                                local_stream, to_ssh_tx.clone(),
                            ).await;
                        }
                        None => {}
                    }
                }

                stdin_data = stdin_rx.recv(), if stdin_active => {
                    match stdin_data {
                        Some(data) => {
                            let (forward_data, exit_now) = if escape_enabled {
                                escape_state.process(&data, escape_char)
                            } else {
                                (data, false)
                            };
                            if exit_now {
                                eprintln!("Connection to {} closed.", self.config.hostname);
                                should_exit = true;
                            } else if !forward_data.is_empty() {
                                if let Some(rid) = stdio_forward_remote_id {
                                    self.send_channel_data_gated(rid, forward_data, &mut pending_window_data, &mut pending_write, aead).await;
                                } else if self.config.stdio_forward.is_some() {
                                    stdio_forward_pending_data.push(forward_data);
                                } else if let Some(sid) = session_id {
                                    if let Some(remote_id) = self.channel_manager.get_channel(sid).and_then(|c| c.remote_id) {
                                        self.send_channel_data_gated(remote_id, forward_data, &mut pending_window_data, &mut pending_write, aead).await;
                                    }
                                }
                            }
                        }
                        None => {
                            stdin_active = false;
                            // `ssh -N host` with no session channel and no port
                            // forwards has nothing left to do once stdin closes;
                            // exit like OpenSSH instead of waiting forever.
                            let no_forwards = self.config.local_forwards.is_empty()
                                && self.config.remote_forwards.is_empty()
                                && self.config.dynamic_forwards.is_empty()
                                && self.config.local_streamlocal.is_empty()
                                && self.config.remote_streamlocal.is_empty()
                                && self.config.stdio_forward.is_none();
                            if session_id.is_none() && no_forwards {
                                should_exit = true;
                            }
                            if let Some(rid) = stdio_forward_remote_id {
                                let eof = build_channel_eof(rid);
                                let _ = self.queue_send(&eof, &mut pending_write);
                            } else if self.config.stdio_forward.is_some() {
                                stdio_forward_eof_pending = true;
                            } else if let Some(sid) = session_id {
                                if let Some(ch) = self.channel_manager.get_channel(sid) {
                                    if let Some(remote_id) = ch.remote_id {
                                        // Only send EOF once all window-gated data
                                        // has actually been sent to the peer; otherwise
                                        // the transfer would be truncated.
                                        let has_pending = pending_window_data.iter().any(|(rid, _)| *rid == remote_id);
                                        if has_pending {
                                            session_eof_pending = true;
                                        } else {
                                            let eof = build_channel_eof(remote_id);
                                            let _ = self.queue_send(&eof, &mut pending_write);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                sdata = async {
                    if let Some(ref mut rx) = session_data_rx { rx.recv().await } else { std::future::pending().await }
                } => {
                    if let Some(data) = sdata {
                        use std::io::Write;
                        let _ = std::io::stdout().write_all(&data);
                        let _ = std::io::stdout().flush();
                    }
                }

                sext = async {
                    if let Some(ref mut rx) = session_ext_rx { rx.recv().await } else { std::future::pending().await }
                } => {
                    if let Some((_dt, data)) = sext {
                        use std::io::Write;
                        let _ = std::io::stderr().write_all(&data);
                        let _ = std::io::stderr().flush();
                    }
                }

                packet = self.recv_packet_impl(false) => {
                    last_any_packet = std::time::Instant::now();
                    match packet {
                        Ok(payload) if !payload.is_empty() => {
                            match payload[0] {
                                msg::SSH_MSG_CHANNEL_DATA => {
                                    if let Ok((recipient, data)) = parse_channel_data(&payload) {
                                        let data_len = data.len() as u32;
                                        // Inbound recipient is our local id; the
                                        // window-adjust reply must use the peer's
                                        // id for that channel (RFC 4254 §5.2).
                                        let channel = self.channel_manager.get_channel(recipient);
                                        let reply_id = self.channel_manager.reply_recipient(recipient).unwrap_or(recipient);
                                        if stdio_forward_channel_id == Some(recipient) {
                                            use std::io::Write;
                                            let _ = std::io::stdout().write_all(&data);
                                            let _ = std::io::stdout().flush();
                                            // Replenish the server's send window for this channel.
                                            let adj = build_channel_window_adjust(reply_id, data_len);
                                            let _ = self.queue_send(&adj, &mut pending_write);
                                            continue;
                                        }
                                        if let Some(local_id) = channel.map(|c| c.local_id) {
                                            if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                                if let Some(tx) = &ch.data_tx { let _ = tx.try_send(data); }
                                            }
                                        }
                                        // Replenish the server's send window so large
                                        // server->client transfers do not stall once the
                                        // advertised window is exhausted.
                                        let adj = build_channel_window_adjust(reply_id, data_len);
                                        let _ = self.queue_send(&adj, &mut pending_write);
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                                    let mut r = &payload[1..];
                                    let recipient = u32::decode(&mut r)?;
                                    let dt = u32::decode(&mut r)?;
                                    let data = SshBytes::decode(&mut r)?.0;
                                    let data_len = data.len() as u32;
                                    let reply_id = self.channel_manager.reply_recipient(recipient)
                                        .unwrap_or(recipient);
                                    if let Some(local_id) = self.channel_manager.get_channel(recipient).map(|c| c.local_id) {
                                        if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                            if let Some(ref ext_tx) = ch.ext_data_tx {
                                                let _ = ext_tx.try_send((dt, data));
                                            }
                                        }
                                    }
                                    // Replenish the server's send window for stderr too.
                                    let adj = build_channel_window_adjust(reply_id, data_len);
                                    let _ = self.queue_send(&adj, &mut pending_write);
                                }
                                msg::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                                    let mut r = &payload[1..];
                                    let recipient = u32::decode(&mut r)?;
                                    let amount = u32::decode(&mut r)?;
                                    if let Some(local_id) = self.channel_manager.get_channel(recipient).map(|c| c.local_id) {
                                        self.channel_manager.add_window(local_id, amount);
                                    }
                                    // Flush forward-channel data deferred when the
                                    // peer's receive window was exhausted.
                                    self.flush_pending_window_data(&mut pending_window_data, &mut pending_write, aead).await;
                                    // If stdin closed but the tail of the upload was
                                    // window-gated, send the deferred channel EOF now
                                    // that the deferred data has been flushed.
                                    if session_eof_pending {
                                        let all_flushed = pending_window_data.is_empty()
                                            || session_id.and_then(|sid| self.channel_manager.get_channel(sid).and_then(|c| c.remote_id))
                                                .map(|rid| !pending_window_data.iter().any(|(r, _)| *r == rid))
                                                .unwrap_or(true);
                                        if all_flushed {
                                            if let Some(sid) = session_id {
                                                if let Some(remote_id) = self.channel_manager.get_channel(sid).and_then(|c| c.remote_id) {
                                                    let eof = build_channel_eof(remote_id);
                                                    let _ = self.queue_send(&eof, &mut pending_write);
                                                }
                                            }
                                            session_eof_pending = false;
                                        }
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_REQUEST => {
                                    if let Ok((recipient, req_type, want_reply)) = parse_channel_request(&payload) {
                                        let local_id = self.channel_manager.get_channel(recipient).map(|c| c.local_id);
                                        if req_type == "exit-status" {
                                            let mut r = &payload[10 + req_type.len()..];
                                            if let Ok(code) = u32::decode(&mut r) {
                                                exit_code = code as i32;
                                            }
                                        } else if req_type == "exit-signal" {
                                            // string signal, boolean core-dumped,
                                            // string error-message, string language
                                            let mut r = &payload[10 + req_type.len()..];
                                            if let Ok(sig) = SshString::decode(&mut r) {
                                                if let Ok(name) = sig.as_str() {
                                                    eprintln!("Killed by signal {}.", name);
                                                    exit_code = 128 + signal_number(name).unwrap_or(1);
                                                }
                                            }
                                        }
                                        if want_reply {
                                            if let Some(lid) = local_id {
                                                if let Some(ch) = self.channel_manager.get_channel(lid) {
                                                    if let Some(rid) = ch.remote_id {
                                                        let reply = build_channel_success(rid);
                                                        let _ = self.queue_send(&reply, &mut pending_write);
                                                    }
                                                }
                                            }
                                        }
                                        // Do NOT stop on exit-status/exit-signal: OpenSSH
                                        // senders may follow it with the tail of the
                                        // channel output before CHANNEL_CLOSE. Record the
                                        // status and let the CLOSE/EOF handler end the
                                        // session, otherwise the last data chunk is lost.
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                                    if let Ok((recipient, sender, w, m)) = parse_channel_open_confirmation(&payload) {
                                        if let Some(tx) = self.pending_open.remove(&recipient) {
                                            self.channel_manager.set_remote_id(recipient, sender);
                                            self.channel_manager.set_peer_window(recipient, w);
                                            let _ = tx.send(Ok((sender, w, m)));
                                        }
                                        // Handle -W stdio forward confirmation
                                        if stdio_forward_channel_id == Some(recipient) {
                                            stdio_forward_remote_id = Some(sender);
                                            for data in stdio_forward_pending_data.drain(..) {
                                                self.send_channel_data_gated(sender, data, &mut pending_window_data, &mut pending_write, aead).await;
                                            }
                                            if stdio_forward_eof_pending {
                                                let eof = build_channel_eof(sender);
                                                let _ = self.queue_send(&eof, &mut pending_write);
                                            }
                                        }
                                        if let Some(sock) = pending_forward_sockets.remove(&recipient) {
                                            if let Some(rx) = self.channel_manager.take_data_rx(recipient) {
                                                pump_socket_with_channel(sock, rx, sender, to_ssh_tx.clone());
                                            }
                                        }
                                        if let Some(sock) = pending_streamlocal_sockets.remove(&recipient) {
                                            if let Some(rx) = self.channel_manager.take_data_rx(recipient) {
                                                pump_socket_with_channel(sock, rx, sender, to_ssh_tx.clone());
                                            }
                                        }
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                                    if let Ok((recipient, reason, message)) = parse_channel_open_failure(&payload) {
                                        pending_forward_sockets.remove(&recipient);
                                        if let Some(tx) = self.pending_open.remove(&recipient) {
                                            let _ = tx.send(Err(SshError::Channel(format!("open failed: {} ({})", message, reason))));
                                        }
                                        if stdio_forward_channel_id == Some(recipient) {
                                            eprintln!("ns-ssh: -W direct-tcpip open failed: {} ({})", message, reason);
                                            should_exit = true;
                                        }
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_OPEN => {
                                    let (channel_type, sender_channel, _win, _max) = match parse_channel_open(&payload) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                    if channel_type == msg::SSH_CHANNEL_TYPE_FORWARDED_TCPIP {
                                        let (s, _w, _m, _addr, p, _orig_ip, _orig_port) = match parse_forwarded_tcpip_open(&payload) {
                                            Ok(v) => v,
                                            Err(_) => continue,
                                        };
                                        let bind_port = p as u16;
                                        let local_target = remote_forward_map.get(&bind_port).cloned();
                                        if let Some((lh, lp)) = local_target {
                                            // PermitRemoteOpen: refuse targets outside the
                                            // configured whitelist before connecting.
                                            if !crate::config::permit_remote_open_allows(
                                                &self.config.permit_remote_open, &lh, lp,
                                            ) {
                                                tracing::warn!(
                                                    "refusing remote forward to {}:{} (PermitRemoteOpen)",
                                                    lh, lp,
                                                );
                                                let fail = build_channel_open_failure(
                                                    sender_channel, 1, "remote open not permitted",
                                                );
                                                let _ = self.queue_send(&fail, &mut pending_write);
                                                continue;
                                            }
                                            let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_FORWARDED_TCPIP, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                            self.channel_manager.set_remote_id(local_id, sender_channel);
                                            let confirm = build_channel_open_confirmation(s, local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                            let _ = self.queue_send(&confirm, &mut pending_write);
                                            match tokio::net::TcpStream::connect(format!("{}:{}", lh, lp)).await {
                                                Ok(socket) => {
                                                    let rx = self.channel_manager.take_data_rx(local_id).unwrap();
                                                    pump_socket_with_channel(socket, rx, sender_channel, to_ssh_tx.clone());
                                                }
                                                Err(_) => {
                                                    if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                                        if let Some(rid) = ch.remote_id {
                                                            let close = build_channel_close(rid);
                                                            let _ = self.queue_send(&close, &mut pending_write);
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            let fail = build_channel_open_failure(sender_channel, 1, "forward not allowed");
                                            let _ = self.queue_send(&fail, &mut pending_write);
                                        }
                                    } else if channel_type == msg::SSH_CHANNEL_TYPE_FORWARDED_STREAMLOCAL {
                                        // Server opened a forwarded streamlocal channel: connect to
                                        // the local Unix socket mapped to the remote socket path.
                                        let (_s, _w, _m, sock_path) = match parse_forwarded_streamlocal_open(&payload) {
                                            Ok(v) => v,
                                            Err(_) => continue,
                                        };
                                        let local_socket = remote_streamlocal_map.get(&sock_path).cloned();
                                        if let Some(local_socket) = local_socket {
                                            let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_FORWARDED_STREAMLOCAL, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                            self.channel_manager.set_remote_id(local_id, sender_channel);
                                            let confirm = build_channel_open_confirmation(sender_channel, local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                            let _ = self.queue_send(&confirm, &mut pending_write);
                                            match tokio::net::UnixStream::connect(&local_socket).await {
                                                Ok(socket) => {
                                                    let rx = self.channel_manager.take_data_rx(local_id).unwrap();
                                                    pump_socket_with_channel(socket, rx, sender_channel, to_ssh_tx.clone());
                                                }
                                                Err(_) => {
                                                    if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                                        if let Some(rid) = ch.remote_id {
                                                            let close = build_channel_close(rid);
                                                            let _ = self.queue_send(&close, &mut pending_write);
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            let fail = build_channel_open_failure(sender_channel, 1, "streamlocal forward not allowed");
                                            let _ = self.queue_send(&fail, &mut pending_write);
                                        }
                                    } else if channel_type == msg::SSH_CHANNEL_TYPE_AUTH_AGENT && self.config.forward_agent {
                                        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_AUTH_AGENT, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        self.channel_manager.set_remote_id(local_id, sender_channel);
                                        let confirm = build_channel_open_confirmation(sender_channel, local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        let _ = self.queue_send(&confirm, &mut pending_write);
                                        if let Ok(sock) = connect_agent_socket(self.config.identity_agent.as_deref()).await {
                                            let rx = self.channel_manager.take_data_rx(local_id).unwrap();
                                            pump_socket_with_channel(sock, rx, sender_channel, to_ssh_tx.clone());
                                        }
                                    } else if channel_type == msg::SSH_CHANNEL_TYPE_X11 && self.config.forward_x11 {
                                        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_X11, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        self.channel_manager.set_remote_id(local_id, sender_channel);
                                        let confirm = build_channel_open_confirmation(sender_channel, local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        let _ = self.queue_send(&confirm, &mut pending_write);
                                        let display = std::env::var("DISPLAY").unwrap_or_default();
                                        match connect_x11_display(&display).await {
                                            Ok(socket) => {
                                                let rx = self.channel_manager.take_data_rx(local_id).unwrap();
                                                pump_socket_with_channel(socket, rx, sender_channel, to_ssh_tx.clone());
                                            }
                                            Err(_) => {
                                                if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                                    if let Some(rid) = ch.remote_id {
                                                        let close = build_channel_close(rid);
                                                        let _ = self.queue_send(&close, &mut pending_write);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        let fail = build_channel_open_failure(sender_channel, 1, "channel type not supported");
                                        let _ = self.queue_send(&fail, &mut pending_write);
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_EOF | msg::SSH_MSG_CHANNEL_CLOSE => {
                                    let mut r = &payload[1..];
                                    if let Ok(recipient) = u32::decode(&mut r) {
                                        // The recipient is our local channel id.
                                        if session_id == Some(recipient)
                                            || stdio_forward_channel_id == Some(recipient)
                                        {
                                            should_exit = true;
                                        }
                                    }
                                }
                                msg::SSH_MSG_DISCONNECT => {
                                    should_exit = true;
                                }
                                msg::SSH_MSG_REQUEST_SUCCESS => {
                                    // A response (e.g. to keepalive@openssh.com) resets
                                    // the missed-alive counter.
                                    missed_alive = 0;
                                    keepalive_outstanding = None;
                                    if let Some(tx) = self.pending_global.pop_front() {
                                        let extra = if payload.len() > 1 { Some(payload[1..].to_vec()) } else { None };
                                        let _ = tx.send(Ok(extra));
                                    }
                                }
                                msg::SSH_MSG_REQUEST_FAILURE => {
                                    missed_alive = 0;
                                    keepalive_outstanding = None;
                                    if let Some(tx) = self.pending_global.pop_front() {
                                        let _ = tx.send(Err(SshError::Channel("request failure".into())));
                                    }
                                }
                                msg::SSH_MSG_UNIMPLEMENTED => {
                                    if let Some(tx) = self.pending_global.pop_front() {
                                        let _ = tx.send(Err(SshError::Channel("unimplemented".into())));
                                    }
                                    tracing::debug!("server returned SSH_MSG_UNIMPLEMENTED");
                                }
                                msg::SSH_MSG_GLOBAL_REQUEST => {
                                    if let Ok((_name, want_reply, _)) = parse_global_request(&payload) {
                                        if want_reply {
                                            let resp = build_request_failure();
                                            let _ = self.queue_send(&resp, &mut pending_write);
                                        }
                                    }
                                }
                                msg::SSH_MSG_IGNORE => {}
                                msg::SSH_MSG_DEBUG => {
                                    // Display server debug messages at `-vv` (OpenSSH
                                    // prints debug1: ... when verbosity >= 2).
                                    if self.config.verbosity >= 2 {
                                        if let Some(m) = decode_debug_message(&payload) {
                                            eprintln!("debug1: {}", m);
                                        }
                                    }
                                }
                                msg::SSH_MSG_KEXINIT => {
                                    // Server-initiated rekey: it already sent its
                                    // KEXINIT; continue the exchange with it.
                                    match self.perform_rekey_with_kex(payload.clone()).await {
                                        Ok(deferred) => {
                                            for d in deferred {
                                                self.deferred_packets.push_back(d);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("rekey failed (continuing): {:?}", e);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Ok(_) => {}
                        Err(_) => { should_exit = true; }
                    }
                }
            }
        }

        // The loop can stop on CHANNEL_CLOSE/DISCONNECT while bytes decoded from
        // earlier CHANNEL_DATA packets are still queued in the forwarding
        // channels (the select! only moves one item per iteration). Flush them
        // before exiting, otherwise the tail of the command's output is dropped.
        {
            use std::io::Write;
            if let Some(mut rx) = session_data_rx.take() {
                while let Ok(data) = rx.try_recv() {
                    let _ = std::io::stdout().write_all(&data);
                }
                let _ = std::io::stdout().flush();
            }
            if let Some(mut rx) = session_ext_rx.take() {
                while let Ok((_dt, data)) = rx.try_recv() {
                    let _ = std::io::stderr().write_all(&data);
                }
                let _ = std::io::stderr().flush();
            }
        }

        if let Some(sid) = session_id {
            let _ = self.send_channel_close(sid).await;
        }

        let _ = self.send_disconnect().await;

        Ok(exit_code)
    }

    /// Run as a ControlMaster: keep the SSH connection alive and serve slave
    /// connections over a Unix socket at `control_path`.
    pub async fn run_control_master(
        &mut self,
        control_path: &str,
        persist_seconds: Option<u32>,
    ) -> Result<i32> {
        use ssh_core::channel::*;
        use std::collections::VecDeque;

        // Remove any stale socket and bind a fresh one.
        let _ = std::fs::remove_file(control_path);
        let listener = tokio::net::UnixListener::bind(control_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(control_path, std::fs::Permissions::from_mode(0o600));
        }
        eprintln!("ControlMaster listening on {}", control_path);

        let aead = self.is_aead();

        #[derive(Clone)]
        enum MasterEvent {
            NewConn {
                conn_id: u64,
                resp_tx: tokio::sync::mpsc::UnboundedSender<crate::control::ControlResponse>,
            },
            Request {
                conn_id: u64,
                req: crate::control::ControlRequest,
            },
            ConnClosed {
                conn_id: u64,
            },
        }

        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<MasterEvent>();
        let mut next_conn_id: u64 = 1;

        // Accept task: spawn a reader + writer task per slave connection.
        {
            let accept_listener = listener;
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                loop {
                    match accept_listener.accept().await {
                        Ok((sock, _)) => {
                            let tx = event_tx.clone();
                            let conn_id = next_conn_id;
                            next_conn_id += 1;
                            let (rd, wr) = sock.into_split();
                            let (resp_tx, mut resp_rx) =
                                tokio::sync::mpsc::unbounded_channel::<crate::control::ControlResponse>();
                            // Writer task: forwards responses to this slave.
                            let writer = tokio::spawn(async move {
                                let mut wr = wr;
                                while let Some(resp) = resp_rx.recv().await {
                                    if let Ok(frame) = crate::control::encode_response(&resp) {
                                        if crate::control::write_frame(&mut wr, &frame).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            });
                            let _ = writer;
                            // Reader task: forwards requests to the master.
                            tokio::spawn(async move {
                                let _ = tx.send(MasterEvent::NewConn { conn_id, resp_tx });
                                let mut rd = rd;
                                loop {
                                    match crate::control::read_frame(&mut rd).await {
                                        Ok(Some(frame)) => {
                                            if let Ok(req) = crate::control::decode_request(&frame) {
                                                if tx.send(MasterEvent::Request { conn_id, req }).is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                        _ => break,
                                    }
                                }
                                let _ = tx.send(MasterEvent::ConnClosed { conn_id });
                            });
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        // request_id -> (conn_id, local_id, remote_id) for open sessions.
        let mut channels: std::collections::HashMap<u32, (u64, u32, u32)> =
            std::collections::HashMap::new();
        let mut resp_by_conn: std::collections::HashMap<u64, tokio::sync::mpsc::UnboundedSender<crate::control::ControlResponse>> =
            std::collections::HashMap::new();
        // Per-connection agent/X11 forwarding socket paths (from the slave).
        let mut conn_forwards: std::collections::HashMap<u64, (Option<String>, Option<String>)> =
            std::collections::HashMap::new();
        // Pumps for forwarded agent/X11 channels send socket data to the master
        // over this channel; the main loop drains it into the SSH transport.
        let (mux_tx, mut mux_rx) =
            tokio::sync::mpsc::unbounded_channel::<(u32, Vec<u8>)>();
        let mut pending_send: VecDeque<Vec<u8>> = VecDeque::new();
        let mut pending_events: VecDeque<MasterEvent> = VecDeque::new();
        // Forwarded agent/X11 channel data deferred because the server's receive
        // window was exhausted. Flushed on SSH_MSG_CHANNEL_WINDOW_ADJUST.
        let mut pending_master_window_data: VecDeque<(ChannelId, Vec<u8>)> = VecDeque::new();
        // Encrypted packets queued because the socket would block; flushed
        // non-blockingly at the top of the loop.
        let mut pending_master_write: VecDeque<Vec<u8>> = VecDeque::new();
        // Raw SSH packets from the server are queued here and processed at the
        // top of the loop (where `self` is freely borrowable for forwarding
        // channel pumps), avoiding borrow conflicts with the select futures.
        let mut pending_packets: VecDeque<Vec<u8>> = VecDeque::new();
        // Set when a slave sends `-O exit` / `-O stop`; the master loop breaks.
        let mut master_exit_requested = false;

        // Persist: track when the last session closed.
        let persist_start: Option<std::time::Instant> = None;
        let _ = persist_start;

        loop {
            // Flush pending outbound SSH packets (no select borrow here).
            while let Some(msg) = pending_send.pop_front() {
                if let Some(stream) = self.stream.as_mut() {
                    let _ = send_encrypted_packet(stream, &msg, &mut self.transport, false, aead).await;
                }
            }

            // Drain forwarded agent/X11 socket data into the SSH transport,
            // gated on the server's advertised receive window.
            while let Ok((remote_id, data)) = mux_rx.try_recv() {
                self.send_channel_data_gated(remote_id, data, &mut pending_master_window_data, &mut pending_master_write, aead).await;
            }

            // Process queued SSH packets from the server. Session channels are
            // routed to their slave; forwarded agent/X11 channels are routed to
            // the local socket pumps (needs `&mut self`, so done here rather
            // than inside the select arm).
            while let Some(payload) = pending_packets.pop_front() {
                match payload.first() {
                    Some(&msg::SSH_MSG_CHANNEL_DATA) => {
                        if let Ok((local_id, data)) = parse_channel_data(&payload) {
                            let mut handled = false;
                            for (&req_id, &(conn_id, lid, _)) in channels.iter() {
                                if lid == local_id {
                                    if let Some(resp) = resp_by_conn.get(&conn_id) {
                                        let _ = resp.send(crate::control::ControlResponse::Data { request_id: req_id, data: data.clone() });
                                    }
                                    handled = true;
                                }
                            }
                            if !handled {
                                // Forwarded agent/X11 channel: feed the local socket pump.
                                if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                    if let Some(tx) = &ch.data_tx {
                                        let _ = tx.try_send(data);
                                    }
                                }
                            }
                        }
                    }
                    Some(&msg::SSH_MSG_CHANNEL_OPEN) => {
                        // Server opened a forwarded agent/X11 channel for a
                        // multiplexed session: connect the local socket and pump.
                        let _ = self.master_handle_forwarded_channel_open(
                            &payload, &conn_forwards, &mux_tx,
                        ).await;
                    }
                    Some(&msg::SSH_MSG_CHANNEL_EXTENDED_DATA) => {
                        let mut r = &payload[1..];
                        if let Ok(local_id) = u32::decode(&mut r) {
                            let dt = u32::decode(&mut r).unwrap_or(0);
                            let data = SshBytes::decode(&mut r).map(|s| s.0).unwrap_or_default();
                            for (&req_id, &(conn_id, lid, _)) in channels.iter() {
                                if lid == local_id {
                                    if let Some(resp) = resp_by_conn.get(&conn_id) {
                                        let _ = resp.send(crate::control::ControlResponse::ExtendedData { request_id: req_id, dtype: dt, data: data.clone() });
                                    }
                                }
                            }
                        }
                    }
                    Some(&msg::SSH_MSG_CHANNEL_REQUEST) => {
                        if let Ok((local_id, req_type, _want_reply)) = parse_channel_request(&payload) {
                            if req_type == "exit-status" {
                                let mut r = &payload[10 + req_type.len()..];
                                if let Ok(code) = u32::decode(&mut r) {
                                    for (&req_id, &(conn_id, lid, _)) in channels.iter() {
                                        if lid == local_id {
                                            if let Some(resp) = resp_by_conn.get(&conn_id) {
                                                let _ = resp.send(crate::control::ControlResponse::ExitStatus { request_id: req_id, code });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(&msg::SSH_MSG_CHANNEL_EOF) | Some(&msg::SSH_MSG_CHANNEL_CLOSE) => {
                        let mut r = &payload[1..];
                        if let Ok(local_id) = u32::decode(&mut r) {
                            let req_ids: Vec<u32> = channels.iter()
                                .filter(|(_, &(_, lid, _))| lid == local_id)
                                .map(|(&req_id, _)| req_id)
                                .collect();
                            for req_id in req_ids {
                                if let Some((conn_id, _, _)) = channels.remove(&req_id) {
                                    if let Some(resp) = resp_by_conn.get(&conn_id) {
                                        let _ = resp.send(crate::control::ControlResponse::Close { request_id: req_id });
                                    }
                                }
                            }
                            // If it was a forwarded agent/X11 channel (not a
                            // session), drop it so the socket pump winds down.
                            if self.channel_manager.get_channel(local_id)
                                .map(|c| c.channel_type != msg::SSH_CHANNEL_TYPE_SESSION)
                                .unwrap_or(false)
                            {
                                self.channel_manager.close_channel(local_id);
                            }
                        }
                    }
                    Some(&msg::SSH_MSG_CHANNEL_WINDOW_ADJUST) => {
                        // Track the channel's peer window so multiplexed session
                        // and forwarded agent/X11 channels stay protocol-correct.
                        // The recipient field is our local channel id.
                        let mut r = &payload[1..];
                        if let Ok(recipient) = u32::decode(&mut r) {
                            if let Ok(amount) = u32::decode(&mut r) {
                                let local_id = self.channel_manager.get_channel(recipient)
                                    .map(|c| c.local_id)
                                    .unwrap_or(recipient);
                                self.channel_manager.add_window(local_id, amount);
                                // Flush forwarded agent/X11 data deferred when the
                                // server's receive window was exhausted.
                                self.flush_pending_window_data(&mut pending_master_window_data, &mut pending_master_write, aead).await;
                            }
                        }
                    }
                    Some(&msg::SSH_MSG_DISCONNECT) => {
                        return Ok(0);
                    }
                    _ => {}
                }
            }

            // Handle queued control events (may block to open a session).
            while let Some(ev) = pending_events.pop_front() {
                match ev {
                    MasterEvent::NewConn { conn_id, resp_tx } => {
                        resp_by_conn.insert(conn_id, resp_tx);
                    }
                    MasterEvent::ConnClosed { conn_id } => {
                        resp_by_conn.remove(&conn_id);
                        conn_forwards.remove(&conn_id);
                    }
                    MasterEvent::Request { conn_id, req } => {
                        let resp_tx = resp_by_conn.get(&conn_id).cloned();
                        match req {
                            crate::control::ControlRequest::OpenSession(s) => {
                                if let Some(resp) = &resp_tx {
                                    let _ = self.master_open_session(s, conn_id, resp, &mut channels, &mut conn_forwards).await;
                                }
                            }
                            crate::control::ControlRequest::Data { request_id, data } => {
                                if let Some(&(_, _, remote_id)) = channels.get(&request_id) {
                                    self.send_channel_data_gated(remote_id, data, &mut pending_master_window_data, &mut pending_master_write, aead).await;
                                }
                            }
                            crate::control::ControlRequest::Eof { request_id } => {
                                if let Some(&(_, _, remote_id)) = channels.get(&request_id) {
                                    pending_send.push_back(build_channel_eof(remote_id));
                                }
                            }
                            crate::control::ControlRequest::Close { request_id } => {
                                if let Some(&(_, _, remote_id)) = channels.get(&request_id) {
                                    pending_send.push_back(build_channel_close(remote_id));
                                }
                            }
                            crate::control::ControlRequest::WindowChange { request_id, width, height } => {
                                if let Some(&(_, _, remote_id)) = channels.get(&request_id) {
                                    let wc = build_window_change(width, height, width * 8, height * 16);
                                    let req = build_channel_request(remote_id, "window-change", false, Some(&wc));
                                    pending_send.push_back(req);
                                }
                            }
                            crate::control::ControlRequest::Check => {
                                if let Some(resp) = &resp_tx {
                                    let _ = resp.send(crate::control::ControlResponse::Ok(std::process::id()));
                                }
                            }
                            crate::control::ControlRequest::Exit => {
                                if let Some(resp) = &resp_tx {
                                    let _ = resp.send(crate::control::ControlResponse::Ok(std::process::id()));
                                }
                                master_exit_requested = true;
                            }
                        }
                    }
                }
            }

            // Persist: exit after idle timeout when no session is active.
            if let Some(persist) = persist_seconds {
                if channels.is_empty() {
                    if let Some(start) = self.control_idle_since {
                        if start.elapsed().as_secs() >= persist as u64 {
                            break;
                        }
                    } else {
                        self.control_idle_since = Some(std::time::Instant::now());
                    }
                } else {
                    self.control_idle_since = None;
                }
            }

            tokio::select! {
                packet = async {
                    let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
                    receive_encrypted_packet(stream, &mut self.transport, false, aead).await
                } => {
                    match packet {
                        Ok(payload) if !payload.is_empty() => {
                            pending_packets.push_back(payload);
                        }
                        Ok(_) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                ev = event_rx.recv() => {
                    match ev {
                        Some(ev) => {
                            pending_events.push_back(ev)
                        },
                        None => return Ok(0),
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)), if persist_seconds.is_some() => {
                    // Wake up periodically to evaluate ControlPersist timeout.
                }
            }

            if master_exit_requested {
                break;
            }
        }

        eprintln!("ControlMaster: exiting");
        let _ = self.send_disconnect().await;
        Ok(0)
    }

    /// Open a session channel on behalf of a slave (blocking, waits for
    /// confirmation from the server).
    async fn master_open_session(
        &mut self,
        req: crate::control::OpenSessionRequest,
        conn_id: u64,
        resp_tx: &tokio::sync::mpsc::UnboundedSender<crate::control::ControlResponse>,
        channels: &mut std::collections::HashMap<u32, (u64, u32, u32)>,
        conn_forwards: &mut std::collections::HashMap<u64, (Option<String>, Option<String>)>,
    ) -> Result<()> {
        use ssh_core::channel::*;
        let aead = self.is_aead();
        let request_id = req.request_id;

        let local_id = self.channel_manager.alloc_channel(
            msg::SSH_CHANNEL_TYPE_SESSION,
            msg::CHANNEL_PACKET_WINDOW_SIZE,
            msg::CHANNEL_MAX_PACKET_SIZE,
        );

        let open_msg = build_channel_open(
            msg::SSH_CHANNEL_TYPE_SESSION,
            local_id,
            msg::CHANNEL_PACKET_WINDOW_SIZE,
            msg::CHANNEL_MAX_PACKET_SIZE,
        );
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        send_encrypted_packet(stream, &open_msg, &mut self.transport, false, aead).await?;

        // Wait for open confirmation (handle intermediate packets).
        let remote_id = loop {
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            let pkt = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
            match pkt.first() {
                Some(&msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                    let (recipient, sender, w, _m) = parse_channel_open_confirmation(&pkt)?;
                    if recipient != local_id {
                        continue;
                    }
                    self.channel_manager.set_remote_id(local_id, sender);
                    self.channel_manager.set_peer_window(local_id, w);
                    break sender;
                }
                Some(&msg::SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                    let (_, reason, message) = parse_channel_open_failure(&pkt)?;
                    let _ = resp_tx.send(crate::control::ControlResponse::OpenFailure {
                        request_id,
                        reason: format!("open failed: {} ({})", message, reason),
                    });
                    self.channel_manager.close_channel(local_id);
                    return Ok(());
                }
                _ => {}
            }
        };

        // Record agent/X11 forwarding paths for this connection so the master
        // can serve forwarded channels opened by the server later.
        if req.want_agent || req.want_x11 {
            conn_forwards.insert(conn_id, (req.agent_socket.clone(), req.x11_display.clone()));
        }

        // Agent forwarding request (auth-agent-req@openssh.com).
        if req.want_agent {
            let agent_req = build_channel_request(local_id, msg::SSH_REQUEST_AUTH_AGENT, false, None);
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &agent_req, &mut self.transport, false, aead).await?;
        }

        // PTY request.
        if req.pty {
            let pty_data = build_pty_request(&req.term, req.width, req.height, req.width * 8, req.height * 16, &[]);
            let pty_msg = build_channel_request(local_id, msg::SSH_REQUEST_PTY, true, Some(&pty_data));
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &pty_msg, &mut self.transport, false, aead).await?;
            let _ = self.await_request_reply().await;
        }

        // X11 forwarding request (x11-req) with a random MIT-MAGIC-COOKIE.
        if req.want_x11 {
            let mut cookie = [0u8; 16];
            let mut seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            for b in cookie.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *b = (seed >> 33) as u8;
            }
            let cookie_hex: String = cookie.iter().map(|b| format!("{:02x}", b)).collect();
            let x11_data = build_x11_request(false, "MIT-MAGIC-COOKIE-1", &cookie_hex, 0);
            let x11_msg = build_channel_request(local_id, msg::SSH_REQUEST_X11, true, Some(&x11_data));
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &x11_msg, &mut self.transport, false, aead).await?;
            let _ = self.await_request_reply().await;
        }

        // Environment variables.
        for (name, value) in &req.envs {
            let env_data = build_env_request(name, value);
            let env_msg = build_channel_request(local_id, msg::SSH_REQUEST_ENV, false, Some(&env_data));
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &env_msg, &mut self.transport, false, aead).await?;
        }

        // Exec or shell.
        let (exec_msg, is_exec) = match &req.command {
            Some(cmd) => (build_channel_request(local_id, msg::SSH_REQUEST_EXEC, true, Some(&build_exec_request(cmd))), true),
            None => (build_channel_request(local_id, msg::SSH_REQUEST_SHELL, true, None), false),
        };
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        send_encrypted_packet(stream, &exec_msg, &mut self.transport, false, aead).await?;
        if is_exec {
            let _ = self.await_request_reply().await;
        } else {
            let _ = self.await_request_reply().await;
        }

        // Confirm to the slave and start data pumps.
        let _ = resp_tx.send(crate::control::ControlResponse::OpenConfirm {
            request_id,
            remote_id,
        });
        channels.insert(request_id, (conn_id, local_id, remote_id));

        // Channel -> slave data pump.
        if let Some(mut data_rx) = self.channel_manager.take_data_rx(local_id) {
            let resp = resp_tx.clone();
            let req_id = request_id;
            tokio::spawn(async move {
                while let Some(data) = data_rx.recv().await {
                    if resp.send(crate::control::ControlResponse::Data { request_id: req_id, data }).is_err() {
                        break;
                    }
                }
            });
        }
        if let Some(mut ext_rx) = self.channel_manager.take_ext_data_rx(local_id) {
            let resp = resp_tx.clone();
            let req_id = request_id;
            tokio::spawn(async move {
                while let Some((dt, data)) = ext_rx.recv().await {
                    if resp.send(crate::control::ControlResponse::ExtendedData { request_id: req_id, dtype: dt, data }).is_err() {
                        break;
                    }
                }
            });
        }

        Ok(())
    }

    /// Handle a forwarded `auth-agent@openssh.com` or `x11` channel opened by
    /// the server on behalf of a multiplexed (ControlMaster) session. The
    /// master connects to the slave-provided agent socket / X11 display and
    /// pumps data between them and the SSH channel.
    async fn master_handle_forwarded_channel_open(
        &mut self,
        payload: &[u8],
        conn_forwards: &std::collections::HashMap<u64, (Option<String>, Option<String>)>,
        mux_tx: &tokio::sync::mpsc::UnboundedSender<(u32, Vec<u8>)>,
    ) -> Result<()> {
        use ssh_core::channel::*;
        let aead = self.is_aead();
        let (channel_type, sender_channel, peer_win, _max) = match parse_channel_open(payload) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        // Find the socket path for the most recent connection that requested
        // this kind of forwarding.
        let (path, is_x11) = if channel_type == msg::SSH_CHANNEL_TYPE_AUTH_AGENT {
            let p = conn_forwards.values().filter_map(|(a, _)| a.clone()).last();
            (p, false)
        } else if channel_type == msg::SSH_CHANNEL_TYPE_X11 {
            let p = conn_forwards.values().filter_map(|(_, x)| x.clone()).last();
            (p, true)
        } else {
            return Ok(());
        };

        let Some(path) = path else {
            let fail = build_channel_open_failure(sender_channel, 1, "forwarding not requested");
            if let Some(stream) = self.stream.as_mut() {
                let _ = send_encrypted_packet(stream, &fail, &mut self.transport, false, aead).await;
            }
            return Ok(());
        };

        // Connect to the local agent socket or X11 display.
        let sock: Result<LocalStream> =
            if is_x11 {
                match connect_x11_display(&path).await {
                    Ok(s) => Ok(LocalStream::Tcp(s)),
                    Err(e) => Err(SshError::Io(e)),
                }
            } else {
                match tokio::net::UnixStream::connect(&path).await {
                    Ok(s) => Ok(LocalStream::Unix(s)),
                    Err(e) => Err(SshError::Io(e)),
                }
            };

        match sock {
            Ok(sock) => {
                let local_id = self.channel_manager.alloc_channel(
                    &channel_type,
                    msg::CHANNEL_PACKET_WINDOW_SIZE,
                    msg::CHANNEL_MAX_PACKET_SIZE,
                );
                self.channel_manager.set_remote_id(local_id, sender_channel);
                self.channel_manager.set_peer_window(local_id, peer_win);
                let confirm = build_channel_open_confirmation(
                    sender_channel, local_id,
                    msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE,
                );
                if let Some(stream) = self.stream.as_mut() {
                    let _ = send_encrypted_packet(stream, &confirm, &mut self.transport, false, aead).await;
                }
                if let Some(rx) = self.channel_manager.take_data_rx(local_id) {
                    pump_socket_with_channel(sock, rx, sender_channel, mux_tx.clone());
                }
            }
            Err(_) => {
                let fail = build_channel_open_failure(sender_channel, 1, "connect failed");
                if let Some(stream) = self.stream.as_mut() {
                    let _ = send_encrypted_packet(stream, &fail, &mut self.transport, false, aead).await;
                }
            }
        }
        Ok(())
    }

    /// Wait for a single SSH_MSG_CHANNEL_SUCCESS / FAILURE packet.
    async fn await_request_reply(&mut self) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        loop {
            let pkt = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
            match pkt.first() {
                Some(&msg::SSH_MSG_CHANNEL_SUCCESS) | Some(&msg::SSH_MSG_CHANNEL_FAILURE) => return Ok(()),
                _ => {}
            }
        }
    }

    pub async fn open_direct_tcpip(&mut self, host: &str, port: u32, orig_ip: &str, orig_port: u32) -> Result<ChannelId> {
        let aead = self.is_aead();
        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_DIRECT_TCPIP, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
        let msg_bytes = build_direct_tcpip_open(local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE, host, port, orig_ip, orig_port);
        {
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &msg_bytes, &mut self.transport, false, aead).await?;
        }
        // Read packets inline until this channel's open confirmation/failure
        // arrives. ProxyJump calls this before any event loop is running, so the
        // confirmation cannot be delivered via `pending_open` (which the event
        // loop resolves); block here instead.
        loop {
            let pkt = {
                let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
                receive_encrypted_packet(stream, &mut self.transport, false, aead).await?
            };
            match pkt.first() {
                Some(&msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                    if let Ok((recipient, sender, w, _m)) = parse_channel_open_confirmation(&pkt) {
                        if recipient == local_id {
                            self.channel_manager.set_remote_id(recipient, sender);
                            self.channel_manager.set_peer_window(recipient, w);
                            return Ok(recipient);
                        }
                    }
                }
                Some(&msg::SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                    if let Ok((recipient, reason, message)) = parse_channel_open_failure(&pkt) {
                        if recipient == local_id {
                            self.channel_manager.close_channel(recipient);
                            return Err(SshError::Channel(format!("open failed: {} ({})", message, reason)));
                        }
                    }
                }
                Some(&msg::SSH_MSG_DISCONNECT) => {
                    self.channel_manager.close_channel(local_id);
                    return Err(SshError::Protocol("connection closed during direct-tcpip open".into()));
                }
                _ => {}
            }
        }
    }

    async fn open_direct_tcpip_queued(
        &mut self,
        pending_forward_sockets: &mut HashMap<ChannelId, TcpStream>,
        host: &str,
        port: u32,
        orig_ip: &str,
        orig_port: u32,
        socket: TcpStream,
        to_ssh_tx: tokio::sync::mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
    ) -> Result<ChannelId> {
        let aead = self.is_aead();
        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_DIRECT_TCPIP, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
        let msg_bytes = build_direct_tcpip_open(local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE, host, port, orig_ip, orig_port);
        let (tx, _rx) = oneshot::channel();
        self.pending_open.insert(local_id, tx);
        pending_forward_sockets.insert(local_id, socket);
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        send_encrypted_packet(stream, &msg_bytes, &mut self.transport, false, aead).await?;
        let _ = to_ssh_tx;
        Ok(local_id)
    }

    /// Open a `direct-streamlocal@openssh.com` channel (client -> server Unix
    /// socket forward). Queues the accepted socket until the channel opens.
    async fn open_direct_streamlocal_queued(
        &mut self,
        pending: &mut HashMap<ChannelId, tokio::net::UnixStream>,
        socket_path: &str,
        socket: tokio::net::UnixStream,
        to_ssh_tx: tokio::sync::mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
    ) -> Result<ChannelId> {
        let aead = self.is_aead();
        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_DIRECT_STREAMLOCAL, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
        let msg_bytes = build_direct_streamlocal_open(local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE, socket_path);
        let (tx, _rx) = oneshot::channel();
        self.pending_open.insert(local_id, tx);
        pending.insert(local_id, socket);
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        send_encrypted_packet(stream, &msg_bytes, &mut self.transport, false, aead).await?;
        let _ = to_ssh_tx;
        Ok(local_id)
    }

    fn is_aead(&self) -> bool {
        self.transport.client_to_server_cipher.as_ref()
            .map(|c| c.is_aead())
            .unwrap_or(false)
    }

    /// Send one encrypted packet. The rekey byte counter is not checked here;
    /// callers trigger client-initiated rekey from the main loop / setup.
    async fn send_packet(&mut self, payload: &[u8], is_new_keys: bool) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        send_encrypted_packet(stream, payload, &mut self.transport, is_new_keys, aead).await
    }

    /// Receive one encrypted packet. If the peer initiates a rekey (KEXINIT
    /// arrives unexpectedly), complete the rekey inline and continue reading,
    /// so synchronous setup paths (channel open / exec) transparently survive
    /// a server-initiated rekey.
    async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        // Setup paths expect the *next* reply and cannot treat a flow-control
        // packet as one, so they let recv_packet fold WINDOW_ADJUST into the
        // channel state and keep reading. The event loop needs those packets
        // returned so it can also flush data deferred on an exhausted window;
        // consuming them here would deadlock a window-gated upload when the
        // peer sends no further data packets.
        self.recv_packet_impl(true).await
    }

    async fn recv_packet_impl(&mut self, skip_window_adjust: bool) -> Result<Vec<u8>> {
        loop {
            if let Some(p) = self.deferred_packets.pop_front() {
                return Ok(p);
            }
            let aead = self.is_aead();
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            let p = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
            if p.first() == Some(&msg::SSH_MSG_KEXINIT) {
                let deferred = self.perform_rekey_with_kex(p).await?;
                for d in deferred {
                    self.deferred_packets.push_back(d);
                }
                continue;
            }
            // OpenSSH's server sends hostkeys-prove-00@openssh.com (and other
            // server-initiated GLOBAL_REQUESTs) unprompted; skip them and
            // honour want_reply so synchronous setup paths see the next packet.
            if p.first() == Some(&msg::SSH_MSG_GLOBAL_REQUEST) {
                if let Ok((_name, want_reply, _)) = parse_global_request(&p) {
                    if want_reply {
                        let resp = build_request_failure();
                        self.send_packet(&resp, false).await?;
                    }
                }
                continue;
            }
            // Flow-control changes may arrive while waiting for an unrelated
            // reply. OpenSSH confirms a session channel with a zero window and
            // immediately follows up with SSH_MSG_CHANNEL_WINDOW_ADJUST; if the
            // setup path consumed that packet as "the reply" the channel stayed
            // at window 0 and every write blocked forever.
            if skip_window_adjust && p.first() == Some(&msg::SSH_MSG_CHANNEL_WINDOW_ADJUST) {
                let mut r = &p[1..];
                if let (Ok(recipient), Ok(amount)) =
                    (u32::decode(&mut r), u32::decode(&mut r))
                {
                    let local_id = self.channel_manager
                        .get_channel(recipient)
                        .map(|c| c.local_id)
                        .unwrap_or(recipient);
                    self.channel_manager.add_window(local_id, amount);
                }
                continue;
            }
            // SSH_MSG_DEBUG / SSH_MSG_IGNORE may arrive at any time (OpenSSH
            // sends DEBUG after auth with key options); skip them so the setup
            // path sees the real response.
            if p.first() == Some(&msg::SSH_MSG_DEBUG) || p.first() == Some(&msg::SSH_MSG_IGNORE) {
                continue;
            }
            return Ok(p);
        }
    }

    pub async fn perform_rekey(&mut self) -> Result<Vec<Vec<u8>>> {
        self.perform_rekey_inner(None).await
    }

    /// Handle a server-initiated rekey: the server has already sent its
    /// KEXINIT (received by the main loop as `server_kex`). Use it directly
    /// instead of waiting for a second one.
    pub async fn perform_rekey_with_kex(&mut self, server_kex: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        self.perform_rekey_inner(Some(server_kex)).await
    }

    async fn perform_rekey_inner(&mut self, pre_server_kex: Option<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        use ssh_core::transport::KexState;
        if self.transport.state != KexState::Established {
            return Ok(Vec::new());
        }
        self.transport.state = KexState::RekeyInProgress;
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;

        // Non-kex packets (e.g. a CHANNEL_SUCCESS for a pre-rekey request)
        // that arrive while waiting for the KEXDH_REPLY. They are replayed by
        // the caller after the rekey completes.
        let mut deferred: Vec<Vec<u8>> = Vec::new();

        let client_kex_init = self.transport.prepare_rekey(false);
        send_encrypted_packet(stream, &client_kex_init, &mut self.transport, false, aead).await?;

        let server_kex = if let Some(k) = pre_server_kex {
            k
        } else {
            // Data packets sent by the peer before it processed our KEXINIT may
            // still be in flight and arrive ahead of its KEXINIT. RFC 4253 §7
            // allows this; they are deferred and replayed after the rekey.
            loop {
                let p = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
                if p.first() == Some(&msg::SSH_MSG_DISCONNECT) {
                    return Err(SshError::ConnectionClosed);
                }
                if p.first() == Some(&msg::SSH_MSG_KEXINIT) {
                    break p;
                }
                deferred.push(p);
            }
        };
        if server_kex.first() != Some(&msg::SSH_MSG_KEXINIT) {
            return Err(SshError::KexFailed("expected KEXINIT during rekey".into()));
        }
        self.transport.server_kex_init = server_kex.clone();

        let negotiation = SshTransport::negotiate_algorithms(
            &self.transport.client_kex_init,
            &self.transport.server_kex_init,
        )?;
        self.transport.strict_kex = negotiation.strict_kex;
        self.transport.strict_kex_peer_kexinit = negotiation.strict_kex;

        let mut kex = SshTransport::create_kex_algorithm(&negotiation.kex_algorithm)?;

        let (_server_host_key_blob, _server_pub_key, _server_sig_blob, shared_secret, exchange_hash, kex_hash_name) =
            if negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange") {
                // RFC 4419 §3: modern servers reject the legacy REQUEST_OLD
                // (30) form, so rekey must use the same REQUEST (34) message
                // as the initial exchange.
                let (min, nbits, max) = (2048u32, 3072u32, 8192u32);
                let mut req = Vec::new();
                req.push(msg::SSH_MSG_KEX_DH_GEX_REQUEST);
                min.encode(&mut req)?;
                nbits.encode(&mut req)?;
                max.encode(&mut req)?;
                send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;

                let group_msg = loop {
                    let p = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
                    if p.first() == Some(&msg::SSH_MSG_KEX_DH_GEX_GROUP) {
                        break p;
                    }
                    deferred.push(p);
                };
                if group_msg.first() != Some(&msg::SSH_MSG_KEX_DH_GEX_GROUP) {
                    return Err(SshError::Protocol("expected SSH_MSG_KEX_DH_GEX_GROUP".into()));
                }
                let mut r = &group_msg[1..];
                let p_mp = SshMpInt::decode(&mut r)?.0;
                let g_mp = SshMpInt::decode(&mut r)?.0;
                let p_bytes = p_mp.clone();
                let g_bytes = g_mp.clone();
                let p_bu = num_bigint::BigUint::from_bytes_be(&p_mp);
                let g_bu = num_bigint::BigUint::from_bytes_be(&g_mp);
                let p_bits = p_bu.bits();
                if p_bits < u64::from(min) || p_bits > u64::from(max) {
                    return Err(SshError::Protocol(format!(
                        "group-exchange modulus is {} bits, outside requested [{}, {}]",
                        p_bits, min, max
                    )));
                }
                if g_bu <= num_bigint::BigUint::from(1u32)
                    || g_bu >= &p_bu - num_bigint::BigUint::from(1u32)
                {
                    return Err(SshError::Protocol(
                        "group-exchange generator out of range".into(),
                    ));
                }
                let exp_bytes = if negotiation.kex_algorithm.contains("sha256") { 512 } else { 256 };
                let gex_name: &'static str = if negotiation.kex_algorithm.contains("sha256") {
                    "diffie-hellman-group-exchange-sha256"
                } else {
                    "diffie-hellman-group-exchange-sha1"
                };
                let gex_hash: &'static str = if negotiation.kex_algorithm.contains("sha256") { "sha256" } else { "sha1" };
                let mut real_modp = ssh_core::kex::ModpKex::with_params(gex_name, gex_hash, p_bu.clone(), g_bu.clone(), exp_bytes);
                real_modp.generate_keypair()?;
                let client_pub = real_modp.public_key_bytes();

                let mut init_msg = Vec::new();
                init_msg.push(msg::SSH_MSG_KEX_DH_GEX_INIT);
                SshMpInt(client_pub.clone()).encode(&mut init_msg)?;
                send_encrypted_packet(stream, &init_msg, &mut self.transport, false, aead).await?;

                let reply = loop {
                    let p = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
                    if p.first() == Some(&msg::SSH_MSG_KEX_DH_GEX_REPLY) {
                        break p;
                    }
                    deferred.push(p);
                };
                if reply.first() != Some(&msg::SSH_MSG_KEX_DH_GEX_REPLY) {
                    return Err(SshError::Protocol("expected SSH_MSG_KEX_DH_GEX_REPLY".into()));
                }
                let mut r = &reply[1..];
                let host_key_blob = SshBytes::decode(&mut r)?.0;
                let f_bytes = SshMpInt::decode(&mut r)?.0;
                let sig_blob = SshBytes::decode(&mut r)?.0;

                let shared = real_modp.compute_shared_secret(&f_bytes)?;
                let exchange = KexExchange {
                    client_version: self.transport.client_version.clone(),
                    server_version: self.transport.server_version.clone(),
                    client_kex_init: self.transport.client_kex_init.clone(),
                    server_kex_init: self.transport.server_kex_init.clone(),
                };
                let exch_hash = ssh_core::kex::compute_gex_exchange_hash(
                    real_modp.hash_name(),
                    &exchange,
                    min, nbits, max,
                    &p_bytes, &g_bytes,
                    &host_key_blob,
                    &client_pub,
                    &f_bytes,
                    &shared,
                );
                kex = Box::new(real_modp);
                (host_key_blob, f_bytes, sig_blob, shared, exch_hash, gex_hash.to_string())
            } else {
                kex.generate_keypair()?;
                let mut dh_payload = Vec::new();
                dh_payload.push(msg::SSH_MSG_KEXDH_INIT);
                if negotiation.kex_algorithm.starts_with("diffie-hellman-group") {
                    SshMpInt(kex.public_key_bytes()).encode(&mut dh_payload)?;
                } else {
                    SshBytes(kex.public_key_bytes()).encode(&mut dh_payload)?;
                }
                send_encrypted_packet(stream, &dh_payload, &mut self.transport, false, aead).await?;

                let reply = loop {
                    let p = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
                    if p.first() == Some(&msg::SSH_MSG_KEXDH_REPLY) {
                        break p;
                    }
                    // Not part of the key exchange: a response to a pre-rekey
                    // request. Replay it after the rekey completes.
                    deferred.push(p);
                };
                let mut r = &reply[1..];
                let host_key_blob = SshBytes::decode(&mut r)?.0;
                let srv_pub = SshBytes::decode(&mut r)?.0;
                let sig_blob = SshBytes::decode(&mut r)?.0;

                let shared = kex.compute_shared_secret(&srv_pub)?;
                let hash_name = kex.hash_name().to_string();
                let exchange = KexExchange {
                    client_version: self.transport.client_version.clone(),
                    server_version: self.transport.server_version.clone(),
                    client_kex_init: self.transport.client_kex_init.clone(),
                    server_kex_init: self.transport.server_kex_init.clone(),
                };
                let exch_hash = ssh_core::kex::compute_exchange_hash(
                    &hash_name,
                    &exchange,
                    &host_key_blob,
                    &kex.public_key_bytes(),
                    &srv_pub,
                    &shared,
                    negotiation.kex_algorithm.starts_with("diffie-hellman-group"),
                );
                (host_key_blob, srv_pub, sig_blob, shared, exch_hash, hash_name)
            };

        let session_id = self.session_id.clone().unwrap_or_default();

        // RFC 4253 §7.3: NEWKEYS is exchanged under the OLD keys; installing the
        // new keys first makes the peer fail to parse our NEWKEYS (it still
        // decrypts with the old keys). Install only after both NEWKEYS crossed.
        let newkeys_msg = vec![msg::SSH_MSG_NEWKEYS];
        send_encrypted_packet(stream, &newkeys_msg, &mut self.transport, true, aead).await?;
        self.transport.state = KexState::NewKeysSent;

        let newkeys_response = loop {
            let p = receive_encrypted_packet(stream, &mut self.transport, true, aead).await?;
            if p.first() == Some(&msg::SSH_MSG_DISCONNECT) {
                return Err(SshError::ConnectionClosed);
            }
            if p.first() == Some(&msg::SSH_MSG_NEWKEYS) {
                break p;
            }
            deferred.push(p);
        };
        if newkeys_response.first() != Some(&msg::SSH_MSG_NEWKEYS) {
            return Err(SshError::Protocol("expected NEWKEYS during rekey".into()));
        }
        self.transport.state = KexState::NewKeysReceived;
        self.transport.reset_sequences_after_newkeys();

        self.transport.install_new_keys(
            &negotiation,
            &kex_hash_name,
            &shared_secret,
            &exchange_hash,
            &session_id,
        )?;

        self.transport.kex_algorithm = Some(kex);
        self.transport.state = KexState::Established;
        self.transport.last_rekey_bytes = self.transport.total_bytes();
        self.transport.last_rekey_instant = std::time::Instant::now();
        Ok(deferred)
    }
}

/// A forward channel's local endpoint: either an agent Unix socket or an X11
/// TCP connection. Implements AsyncRead + AsyncWrite by delegation so it can be
/// passed to the generic `pump_socket_with_channel`.
enum LocalStream {
    Unix(tokio::net::UnixStream),
    Tcp(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for LocalStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for LocalStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            LocalStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            LocalStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

fn pump_socket_with_channel<S>(
    socket: S,
    channel_rx: mpsc::Receiver<Vec<u8>>,
    remote_id: ChannelId,
    to_ssh_tx: mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut sock_read, mut sock_write) = tokio::io::split(socket);
    let mut rx = channel_rx;

    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(data) => {
                    if sock_write.write_all(&data).await.is_err() { break; }
                }
                None => break,
            }
        }
        let _ = sock_write.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = [0u8; 32768];
        loop {
            match sock_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if to_ssh_tx.send((remote_id, buf[..n].to_vec())).is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });
}

async fn connect_agent_socket(override_path: Option<&str>) -> Result<tokio::net::UnixStream> {
    let path = if let Some(p) = override_path {
        p.to_string()
    } else {
        std::env::var("SSH_AUTH_SOCK").map_err(|_| SshError::Protocol("SSH_AUTH_SOCK not set".into()))?
    };
    tokio::net::UnixStream::connect(path).await.map_err(SshError::Io)
}

async fn connect_x11_display(display: &str) -> std::io::Result<tokio::net::TcpStream> {
    let (host, num) = if display.is_empty() {
        ("localhost".to_string(), 0)
    } else if let Some(rest) = display.strip_prefix("unix:") {
        let n: u16 = rest.parse().unwrap_or(0);
        return tokio::net::TcpStream::connect(format!("127.0.0.1:{}", 6000 + n)).await;
    } else {
        let (h, n) = match display.rsplit_once(':') {
            Some((h, n)) => (h.to_string(), n.split('.').next().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0)),
            None => (display.to_string(), 0),
        };
        let host = if h.is_empty() { "localhost".to_string() } else { h };
        (host, n)
    };
    tokio::net::TcpStream::connect(format!("{}:{}", host, 6000 + num)).await
}

fn parse_jump_spec(spec: &str) -> Result<(Option<String>, String, u16)> {
    let rest = spec.trim();
    if rest.is_empty() || rest == "-" {
        return Err(SshError::Protocol("invalid ProxyJump spec".into()));
    }

    let (user_part, host_part) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, rest.to_string()),
    };

    let (host, port) = if host_part.starts_with('[') {
        match host_part.find(']') {
            Some(i) => {
                let host = host_part[1..i].to_string();
                let after = &host_part[i+1..];
                let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(22);
                (host, port)
            }
            None => (host_part, 22),
        }
    } else {
        match host_part.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h.to_string(), p),
                Err(_) => (host_part, 22),
            },
            None => (host_part, 22),
        }
    };

    Ok((user_part, host, port))
}

async fn connect_via_proxy_jump(
    proxy_spec: &str,
    target_host: &str,
    target_port: u16,
    base_config: ResolvedConfig,
) -> Result<BoxedStream> {
    // Handle comma-separated multi-hop by recursing on first segment,
    // reducing it each hop: spec = "A,B,C" → first A then via A go to B then via B go to C, final connect to target
    let specs: Vec<&str> = proxy_spec.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if specs.is_empty() {
        return Err(SshError::Protocol("empty ProxyJump".into()));
    }

    // For each hop (except last): tunnel to next hop's SSH port (22 default) as the "target" connection
    // After last hop: tunnel to real target_host:target_port
    let mut stream: Option<BoxedStream> = None;

    for (i, spec) in specs.iter().enumerate() {
        let is_last = i + 1 == specs.len();
        let (jump_user_opt, jump_host, jump_port) = parse_jump_spec(spec)?;

        let mut jump_config = base_config.clone();
        jump_config.hostname = jump_host.clone();
        jump_config.port = jump_port;
        if let Some(u) = jump_user_opt {
            jump_config.user = u;
        }
        jump_config.proxy_jump = None;
        jump_config.no_remote_command = true;
        jump_config.local_forwards.clear();
        jump_config.remote_forwards.clear();
        jump_config.dynamic_forwards.clear();

        let mut jump_client = SshClient::new(jump_config);
        if let Some(prev) = stream.take() {
            jump_client.stream = Some(prev);
        } else {
            jump_client.connect_direct(jump_client.config.connect_timeout).await?;
        }
        jump_client.handshake().await?;
        jump_client.authenticate().await?;
        // OpenSSH does not use a SSH_MSG_SERVICE_REQUEST for "ssh-connection":
        // after userauth success the client opens a direct-tcpip channel directly.

        let (next_host, next_port): (&str, u32) = if is_last {
            (target_host, target_port as u32)
        } else {
            let (_, nh, np) = parse_jump_spec(specs[i+1])?;
            let leaked: &'static str = Box::leak(nh.into_boxed_str());
            (leaked, np as u32)
        };

        let channel_id = jump_client.open_direct_tcpip(
            next_host,
            next_port,
            "127.0.0.1",
            22,
        ).await?;

        stream = Some(spawn_proxy_tunnel_forwarder(
            jump_client,
            channel_id,
        ));
    }

    stream.ok_or_else(|| SshError::Protocol("no proxy hop produced tunnel".into()))
}

fn spawn_proxy_tunnel_forwarder(
    jump_client: SshClient,
    channel_id: ChannelId,
) -> BoxedStream {
    use ssh_core::channel::build_channel_data;
    use ssh_core::channel::build_channel_window_adjust;

    let SshClient {
        mut stream,
        mut transport,
        channel_manager,
        ..
    } = jump_client;

    let (remote_id, _window_size_init, _max_pkt) = match channel_manager.get_channel(channel_id) {
        Some(ch) => (
            ch.remote_id.unwrap_or(0),
            ch.window_size,
            ch.max_packet_size,
        ),
        None => (0, 2u32 << 20, 32768),
    };

    let mut remote_window = channel_manager.get_channel(channel_id)
        .map(|ch| ch.peer_window)
        .unwrap_or(2u32 << 20);

    let mut local_window = 2u32 << 20;

    let aead = transport.client_to_server_cipher.as_ref()
        .map(|c| c.is_aead())
        .unwrap_or(false);

    let stream = stream.take().unwrap();
    let (r, w) = tokio::io::split(stream);
    let (mut duplex_rd, outer_wr) = tokio::io::duplex(1 << 20);
    let (outer_rd, mut duplex_wr) = tokio::io::duplex(1 << 20);

    // Combine halves back into one stream to pass into existing functions
    let mut combined = CombinedStream::new(r, w);

    let window_threshold = 64 * 1024;

    tokio::spawn(async move {
        let mut recv_buf: Vec<u8> = Vec::with_capacity(4096);

        loop {
            tokio::select! {
                // 1) Read packets from jump server
                pkt = receive_encrypted_packet(&mut combined, &mut transport, false, aead) => {
                    let payload = match pkt {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    if payload.is_empty() { continue; }
                    let msg_type = payload[0];
                    match msg_type {
                        msg::SSH_MSG_CHANNEL_DATA | msg::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                            let mut rdr = &payload[1..];
                            let recipient = match u32::decode(&mut rdr) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            if recipient != remote_id && recipient != channel_id as u32 {
                                continue;
                            }
                            if msg_type == msg::SSH_MSG_CHANNEL_EXTENDED_DATA {
                                let _datatype = u32::decode(&mut rdr).ok();
                            }
                            let data = match SshBytes::decode(&mut rdr) {
                                Ok(b) => b.0,
                                Err(_) => continue,
                            };
                            let consumed = data.len() as u32;
                            local_window = local_window.saturating_sub(consumed);
                            if local_window < window_threshold {
                                let target = 2u32 << 20;
                                let delta = target.saturating_sub(local_window);
                                if delta > 0 {
                                    let adj = build_channel_window_adjust(remote_id, delta);
                                    if send_encrypted_packet(&mut combined, &adj, &mut transport, false, aead).await.is_err() {
                                        break;
                                    }
                                    local_window += delta;
                                }
                            }
                            if duplex_wr.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        msg::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                            let mut rdr = &payload[1..];
                            let Ok(recipient) = u32::decode(&mut rdr) else { continue };
                            if recipient != remote_id && recipient != channel_id as u32 { continue; }
                            let Ok(delta) = u32::decode(&mut rdr) else { continue };
                            remote_window = remote_window.saturating_add(delta);
                        }
                        msg::SSH_MSG_CHANNEL_CLOSE | msg::SSH_MSG_CHANNEL_EOF => {
                            let mut rdr = &payload[1..];
                            let Ok(_rcpt) = u32::decode(&mut rdr) else { break };
                            if msg_type == msg::SSH_MSG_CHANNEL_CLOSE {
                                let close = build_channel_close(remote_id);
                                let _ = send_encrypted_packet(&mut combined, &close, &mut transport, false, aead).await;
                            }
                            let _ = duplex_wr.shutdown().await;
                            break;
                        }
                        msg::SSH_MSG_DISCONNECT => {
                            break;
                        }
                        msg::SSH_MSG_GLOBAL_REQUEST => {
                            if let Ok((_name, want_reply, _rest)) = parse_global_request(&payload) {
                                if want_reply {
                                    let fail = build_request_failure();
                                    let _ = send_encrypted_packet(&mut combined, &fail, &mut transport, false, aead).await;
                                }
                            }
                        }
                        msg::SSH_MSG_IGNORE | msg::SSH_MSG_DEBUG => {}
                        _ => {}
                    }
                }

                // 2) Read bytes from outer side (target SSH transport will write them there = "to server via direct-tcpip")
                n = read_into_buf(&mut duplex_rd, &mut recv_buf) => {
                    match n {
                        Ok(0) => {
                            let eof = build_channel_eof(remote_id);
                            let _ = send_encrypted_packet(&mut combined, &eof, &mut transport, false, aead).await;
                            let close = build_channel_close(remote_id);
                            let _ = send_encrypted_packet(&mut combined, &close, &mut transport, false, aead).await;
                            break;
                        }
                        Ok(n) => {
                            let data: Vec<u8> = recv_buf.drain(..n).collect();
                            let mut remaining = data.as_slice();
                            while !remaining.is_empty() {
                                while remote_window == 0 {
                                    let pkt = match receive_encrypted_packet(&mut combined, &mut transport, false, aead).await {
                                        Ok(p) => p,
                                        Err(_) => return,
                                    };
                                    if !pkt.is_empty() && pkt[0] == msg::SSH_MSG_CHANNEL_WINDOW_ADJUST {
                                        let mut rdr = &pkt[1..];
                                        if let Ok(rcpt) = u32::decode(&mut rdr) {
                                            if rcpt == remote_id || rcpt == channel_id as u32 {
                                                if let Ok(delta) = u32::decode(&mut rdr) {
                                                    remote_window = remote_window.saturating_add(delta);
                                                }
                                            }
                                        }
                                    }
                                }
                                let can_send = (remaining.len() as u32).min(remote_window).min(32768) as usize;
                                let chunk = &remaining[..can_send];
                                remote_window -= can_send as u32;
                                let pkt = build_channel_data(remote_id, chunk);
                                if send_encrypted_packet(&mut combined, &pkt, &mut transport, false, aead).await.is_err() {
                                    return;
                                }
                                remaining = &remaining[can_send..];
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = duplex_wr.shutdown().await;
    });

    Box::pin(CombinedStream::new(outer_rd, outer_wr))
}

async fn read_into_buf<R: tokio::io::AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> std::result::Result<usize, std::io::Error> {
    use tokio::io::AsyncReadExt;
    let mut tmp = [0u8; 32768];
    match r.read(&mut tmp).await {
        Ok(0) => Ok(0),
        Ok(n) => {
            buf.extend_from_slice(&tmp[..n]);
            Ok(n)
        }
        Err(e) => Err(e),
    }
}

fn build_channel_data(remote_id: u32, data: &[u8]) -> Vec<u8> {
    use ssh_core::encoding::SshEncode;
    let mut out = Vec::new();
    out.push(msg::SSH_MSG_CHANNEL_DATA);
    let _ = remote_id.encode(&mut out);
    let _ = (data.len() as u32).encode(&mut out);
    out.extend_from_slice(data);
    out
}

fn build_channel_window_adjust(remote_id: u32, delta: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg::SSH_MSG_CHANNEL_WINDOW_ADJUST);
    let _ = remote_id.encode(&mut out);
    let _ = delta.encode(&mut out);
    out
}

fn build_channel_close(remote_id: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg::SSH_MSG_CHANNEL_CLOSE);
    let _ = remote_id.encode(&mut out);
    out
}

fn build_channel_eof(remote_id: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg::SSH_MSG_CHANNEL_EOF);
    let _ = remote_id.encode(&mut out);
    out
}

fn build_request_failure() -> Vec<u8> {
    vec![msg::SSH_MSG_REQUEST_FAILURE]
}

struct CombinedStream<R, W> {
    r: R,
    w: W,
}

impl<R, W> CombinedStream<R, W> {
    fn new(r: R, w: W) -> Self {
        CombinedStream { r, w }
    }
}

struct ProxyStream {
    // Kept alive so the proxy command's child is not dropped while the
    // stream is in use.
    _child: tokio::process::Child,
    stdout: tokio::process::ChildStdout,
    stdin: tokio::process::ChildStdin,
}

impl tokio::io::AsyncRead for ProxyStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.stdout), cx, buf)
    }
}

impl tokio::io::AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.stdin), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.stdin), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.stdin), cx)
    }
}

fn split_command(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '\\' => {
                    if let Some(&n) = chars.peek() {
                        cur.push(n);
                        chars.next();
                    }
                }
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        args.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(c),
            },
        }
    }
    if !cur.is_empty() {
        args.push(cur);
    }
    args
}

fn connect_proxy_command(config: &ResolvedConfig, cmd: &str, target_host: &str, target_port: u16) -> Result<BoxedStream> {
    use tokio::process::Command;
    use std::process::Stdio;
    let expanded = cmd
        .replace("%%", "\u{0}")
        .replace("%h", target_host)
        .replace("%p", &target_port.to_string())
        .replace("%r", &config.user)
        .replace("%n", target_host)
        .replace("%u", &config.user)
        .replace('\u{0}', "%");
    let argv = split_command(&expanded);
    if argv.is_empty() {
        return Err(SshError::Protocol("empty ProxyCommand".into()));
    }
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| SshError::Io(e))?;
    let stdout = child.stdout.take().ok_or_else(|| SshError::Protocol("proxy stdout not captured".into()))?;
    let stdin = child.stdin.take().ok_or_else(|| SshError::Protocol("proxy stdin not captured".into()))?;
    Ok(Box::pin(ProxyStream { _child: child, stdout, stdin }))
}

impl<R: tokio::io::AsyncRead + Unpin, W: Unpin> tokio::io::AsyncRead for CombinedStream<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.r), cx, buf)
    }
}

impl<R: Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CombinedStream<R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.w), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.w), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.w), cx)
    }
}

fn parse_global_request(payload: &[u8]) -> Result<(String, bool, Vec<u8>)> {
    use ssh_core::encoding::SshDecode;
    if payload.is_empty() || payload[0] != msg::SSH_MSG_GLOBAL_REQUEST {
        return Err(SshError::InvalidPacket("not global request".into()));
    }
    let mut r = &payload[1..];
    let name_bytes = <SshString as SshDecode>::decode(&mut r)?;
    let name = String::from_utf8_lossy(&name_bytes.0).into_owned();
    let want_reply = <bool as SshDecode>::decode(&mut r)?;
    Ok((name, want_reply, r.to_vec()))
}

async fn send_raw_packet(stream: &mut (impl AsyncWrite + Unpin + ?Sized), payload: &[u8]) -> Result<()> {
    let base = 1 + payload.len();
    let padding_len = ssh_core::transport::compute_packet_padding(base, 8, true);
    // RFC 4253 §6: packet_length is the body length (padding_length + payload +
    // padding), NOT including the 4-byte packet_length field itself.
    let packet_len_field = (base + padding_len) as u32;
    let mut packet = Vec::with_capacity(4 + (base + padding_len) as usize);
    packet.extend_from_slice(&packet_len_field.to_be_bytes());
    packet.push(padding_len as u8);
    packet.extend_from_slice(payload);
    let mut padding = vec![0u8; padding_len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
    packet.extend_from_slice(&padding);
    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

async fn receive_raw_packet(stream: &mut (impl AsyncRead + Unpin + ?Sized)) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;
    if total_len < 5 || total_len > 256 * 1024 {
        return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
    }
    let body_len = total_len;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;

    let padding_len = body[0] as usize;
    if padding_len >= body_len {
        return Err(SshError::InvalidPacket("invalid padding".into()));
    }
    let payload_len = body_len - 1 - padding_len;
    if payload_len == 0 {
        return Err(SshError::InvalidPacket("empty payload".into()));
    }
    Ok(body[1..1 + payload_len].to_vec())
}

/// Build an encrypted (and MAC'd) SSH packet from a payload, without writing it.
/// Advances `transport.outgoing_seq` (the packet is logically sent once built).
fn build_encrypted_packet(
    transport: &mut SshTransport,
    payload: &[u8],
    aead: bool,
) -> Result<Vec<u8>> {
    // Packet padding is always aligned to the cipher's block size. AES-GCM
    // reports 16 (it is an AEAD, but the *padding* rule is still
    // packet_length % 16 == 0); chacha20-poly1305 reports 8; before any cipher
    // exists (KEX/NEWKEYS) fall back to the RFC 4253 minimum of 8.
    let block_size = transport.client_to_server_cipher.as_ref()
        .map(|c| c.block_size())
        .unwrap_or(8);

    let has_cipher = transport.client_to_server_cipher.is_some();
    let etm = transport.client_to_server_mac.as_ref()
        .map(|m| m.is_etm()).unwrap_or(false);
    let chachapoly = transport.client_to_server_cipher.as_ref()
        .map(|c| c.is_chachapoly()).unwrap_or(false);
    // RFC 4253 §6.4 / RFC 6668: a non-ETM MAC (or the pre-key "none" cipher)
    // encrypts packet_length as part of the first cipher block; ETM and AEAD
    // ciphers leave packet_length in the clear (authenticated as AAD). OpenSSH's
    // chacha20-poly1305@openssh.com is the exception: it encrypts packet_length
    // with a separate header key (still authenticated by Poly1305).
    //
    // OpenSSH computes aadlen = (mac && etm) || authlen ? 4 : 0. For chacha and
    // other AEAD ciphers authlen != 0, so aadlen=4 regardless: the *padding*
    // rule is packet_length % block_size == 0 (same as ETM). But chacha still
    // *encrypts* the 4-byte length field on the wire with the header key.
    let length_encrypted_on_wire = chachapoly || !has_cipher || (!aead && !etm);
    // aadlen is only meaningful once a cipher/MAC is in place. Raw packets
    // (NEWKEYS, KEX before the key exchange) use aadlen=0, so packet_length
    // must satisfy (4 + packet_length) % block_size == 0.
    let padding_uses_aadlen = has_cipher && (aead || (etm && has_cipher) || chachapoly);

    let base = 1 + payload.len();
    let padding_len = ssh_core::transport::compute_packet_padding(base, block_size, !padding_uses_aadlen);
    let body_len = base + padding_len;
    // RFC 4253 §6: packet_length excludes its own 4-byte field.
    let packet_len_field = body_len as u32;

    let mut packet = Vec::with_capacity(4 + body_len);
    packet.extend_from_slice(&packet_len_field.to_be_bytes());
    packet.push(padding_len as u8);
    packet.extend_from_slice(payload);
    let mut padding = vec![0u8; padding_len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
    packet.extend_from_slice(&padding);

    let seq = transport.outgoing_seq;

    if std::env::var("NS_DEBUG_PKT").is_ok() {
        eprintln!("CLIENT send type={} seq={} body_len={} block={} aead={} etm={} pktlen_field={}", payload.first().copied().unwrap_or(0), seq, body_len, block_size, aead, etm, packet_len_field);
        if payload.first() == Some(&5u8) {
            let hex: String = packet.iter().map(|b| format!("{:02x}", b)).collect();
            eprintln!("CLIENT SERVICE packet(decrypted view) hex={}", hex);
        }
    }

    // Non-ETM MAC covers the plaintext packet (RFC 4253 §6.4):
    // H(seq || packet_length || padding_length || payload || padding).
    // Compute it before encrypting.
    let mut non_etm_tag = None;
    if !aead && !etm {
        if let Some(ref mac) = transport.client_to_server_mac {
            if mac.tag_len() > 0 {
                non_etm_tag = Some(mac.compute_tag(seq, &packet)?);
            }
        }
    }

    if let Some(ref mut cipher) = transport.client_to_server_cipher {
        if length_encrypted_on_wire {
            // Non-ETM / chacha: encrypt the entire packet (packet_length
            // included). For chacha, encrypt() returns ciphertext || tag.
            let ciphertext = cipher.encrypt(seq, &packet)?;
            packet = ciphertext;
        } else {
            // ETM/AEAD: keep packet_length plaintext, encrypt the body only.
            // AES-GCM authenticates the cleartext length as AAD (OpenSSH
            // cipher-gcm.c uses aadlen=4); ETM MACs are handled separately.
            let plaintext = packet[4..].to_vec();
            let ciphertext = if cipher.is_aead() && !cipher.is_chachapoly() {
                cipher.encrypt_with_aad(seq, &packet[..4], &plaintext)?
            } else {
                cipher.encrypt(seq, &plaintext)?
            };
            packet.truncate(4);
            packet.extend_from_slice(&ciphertext);
        }
    }

    if let Some(ref mac) = transport.client_to_server_mac {
        if mac.tag_len() > 0 {
            if etm {
                // ETM: MAC over seq || packet_length || ciphertext (RFC 6668).
                let tag = mac.compute_tag(seq, &packet)?;
                packet.extend_from_slice(&tag);
            } else if !aead {
                // Non-ETM: append the MAC computed over the plaintext packet.
                if let Some(t) = non_etm_tag {
                    packet.extend_from_slice(&t);
                }
            }
        }
    }

    if std::env::var("NS_DEBUG_PKT").is_ok() {
        if payload.first() == Some(&5u8) {
            let hex: String = packet.iter().map(|b| format!("{:02x}", b)).collect();
            eprintln!("CLIENT SERVICE wire hex={} (len={})", hex, packet.len());
        }
    }

    transport.bytes_out += packet.len() as u64;
    transport.outgoing_seq += 1;
    Ok(packet)
}

/// A no-op waker used only to probe `poll_write` synchronously without ever
/// registering a persistent wake-up (we retry in the loop instead).
fn noop_waker() -> std::task::Waker {
    use std::sync::Arc;
    struct Noop;
    impl std::task::Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    std::task::Waker::from(Arc::new(Noop))
}

/// Attempt a single non-blocking write of `buf` on `stream`. Returns the number
/// of bytes written, or `WouldBlock` if the socket's send buffer is full. Never
/// registers a persistent waker (we poll again on the next loop iteration).
fn nonblocking_write(stream: &mut BoxedStream, buf: &[u8]) -> std::io::Result<usize> {
    use std::task::{Context, Poll};
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    match stream.as_mut().poll_write(&mut cx, buf) {
        Poll::Ready(r) => r,
        Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
    }
}

async fn send_encrypted_packet(
    stream: &mut (impl AsyncWrite + Unpin + ?Sized),
    payload: &[u8],
    transport: &mut SshTransport,
    _is_new_keys: bool,
    aead: bool,
) -> Result<()> {
    let packet = build_encrypted_packet(transport, payload, aead)?;
    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

async fn receive_encrypted_packet(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    transport: &mut SshTransport,
    _is_new_keys: bool,
    aead: bool,
) -> Result<Vec<u8>> {
    let seq = transport.incoming_seq;

    let etm = transport.server_to_client_mac.as_ref()
        .map(|m| m.is_etm()).unwrap_or(false);
    let chachapoly = transport.server_to_client_cipher.as_ref()
        .map(|c| c.is_chachapoly()).unwrap_or(false);
    // RFC 4253 §6.4 / RFC 6668: a non-ETM MAC (or pre-key "none") encrypts the
    // 4-byte packet_length field as part of the first cipher block; ETM and
    // AEAD ciphers leave it in the clear (authenticated as AAD). OpenSSH's
    // chacha20-poly1305@openssh.com encrypts it with a separate header key.
    let packet_length_encrypted = !aead && !etm;

    let block_size = transport.server_to_client_cipher.as_ref()
        .map(|c| c.block_size())
        .unwrap_or(8)
        .max(8);

    let wire_len: usize;

    let body: Vec<u8> = if chachapoly {
        // chacha20-poly1305@openssh.com: the 4-byte packet_length is encrypted
        // with the header key; read it and decrypt_length to learn the body
        // length. The Poly1305 tag is appended after the ciphertext and is
        // verified by `cipher.decrypt` (which expects ciphertext || tag).
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let plen = if let Some(ref cipher) = transport.server_to_client_cipher {
            cipher.decrypt_length(seq, &len_buf)?
        } else {
            u32::from_be_bytes(len_buf)
        } as usize;
        if plen > 256 * 1024 || plen < 5 || plen % block_size != 0 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", plen)));
        }
        let mut ct = len_buf.to_vec();
        let mut body_ct = vec![0u8; plen];
        stream.read_exact(&mut body_ct).await?;
        ct.extend_from_slice(&body_ct);
        if let Some(ref mut cipher) = transport.server_to_client_cipher {
            let tlen = cipher.tag_len();
            if tlen > 0 {
                let mut tag = vec![0u8; tlen];
                stream.read_exact(&mut tag).await?;
                ct.extend_from_slice(&tag);
            }
        }
        let plain = if let Some(ref mut cipher) = transport.server_to_client_cipher {
            cipher.decrypt(seq, &ct)?
        } else {
            ct.clone()
        };
        // packet_length(4) + body + tag, all consumed from the wire.
        wire_len = ct.len();
        // Strip the leading 4-byte packet_length (now decrypted).
        if plain.len() < 4 {
            return Err(SshError::Protocol("chacha packet too short".into()));
        }
        plain[4..].to_vec()
    } else if packet_length_encrypted {
        // Read the first cipher block, decrypt it to learn packet_length.
        let mut first_block = vec![0u8; block_size];
        stream.read_exact(&mut first_block).await?;
        let plain_first = if let Some(ref mut cipher) = transport.server_to_client_cipher {
            cipher.decrypt(seq, &first_block)?
        } else {
            first_block.clone()
        };
        let plen = u32::from_be_bytes([plain_first[0], plain_first[1], plain_first[2], plain_first[3]]) as usize;
        if plen > 256 * 1024 || plen < 5 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", plen)));
        }
        // Read the remainder of the encrypted body: the cipher stream covers
        // packet_length plus the body, i.e. `4 + plen` bytes. Reject a payload
        // that is shorter than one cipher block (or misaligned) before
        // subtracting, otherwise `4 + plen - block_size` underflows for a
        // maliciously tiny packet_length.
        if 4 + plen < block_size || (4 + plen) % block_size != 0 {
            return Err(SshError::InvalidPacket(format!(
                "invalid non-ETM packet size: {} (block size {})",
                plen, block_size
            )));
        }
        let rest_len = 4 + plen - block_size;
        let mut rest = vec![0u8; rest_len];
        stream.read_exact(&mut rest).await?;
        // block_size + rest_len (+ non-ETM MAC tag) covers the whole packet.
        wire_len = 4 + plen
            + transport.server_to_client_mac.as_ref().map(|m| m.tag_len()).unwrap_or(0);
        // Decrypt the remainder (cipher state continues from the first block).
        let mut plain_body = if let Some(ref mut cipher) = transport.server_to_client_cipher {
            cipher.decrypt(seq, &rest)?
        } else {
            rest.clone()
        };
        let mut full = plain_first.clone();
        full.append(&mut plain_body);
        // Non-ETM MAC is verified over seq || packet_length || padding_length ||
        // payload || padding (RFC 4253 §6.4) — i.e. seq || full plaintext packet.
        if let Some(ref mac) = transport.server_to_client_mac {
            if mac.tag_len() > 0 && !mac.is_etm() {
                let mut tag_buf = vec![0u8; mac.tag_len()];
                stream.read_exact(&mut tag_buf).await?;
                if !mac.verify_tag(seq, &full, &tag_buf)? {
                    return Err(SshError::DecryptionFailed);
                }
            }
        }
        // Strip the leading 4-byte packet_length: the remaining bytes are the
        // plaintext body (padding_len || payload || padding).
        full[4..].to_vec()
    } else {
        // ETM / AEAD: packet_length is plaintext.
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let plen = u32::from_be_bytes(len_buf) as usize;
        // ETM and AEAD both use aadlen=4, so packet_length must be block-aligned.
        if plen > 256 * 1024 || plen < 5 || plen % block_size != 0 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", plen)));
        }
        let mut body = vec![0u8; plen];
        stream.read_exact(&mut body).await?;
        // packet_length(4) + body + (AEAD or ETM/MAC tag).
        let mut tag_bytes = 0usize;

        // AEAD ciphers append the auth tag to the ciphertext; the tag is not
        // counted in packet_length, so read it here and append it so
        // `cipher.decrypt` (which expects ciphertext || tag) works.
        if aead {
            if let Some(ref mut cipher) = transport.server_to_client_cipher {
                let tlen = cipher.tag_len();
                if tlen > 0 {
                    let mut tag = vec![0u8; tlen];
                    stream.read_exact(&mut tag).await?;
                    body.extend_from_slice(&tag);
                    tag_bytes += tlen;
                }
            }
        }

        // ETM MAC is verified over seq || packet_length || ciphertext (RFC 6668),
        // before decryption; the plaintext is not available yet.
        if let Some(ref mac) = transport.server_to_client_mac {
            if mac.tag_len() > 0 && mac.is_etm() {
                let mut tag_buf = vec![0u8; mac.tag_len()];
                stream.read_exact(&mut tag_buf).await?;
                tag_bytes += mac.tag_len();
                let mut etm_input = Vec::with_capacity(4 + body.len());
                etm_input.extend_from_slice(&len_buf);
                etm_input.extend_from_slice(&body);
                if !mac.verify_tag(seq, &etm_input, &tag_buf)? {
                    return Err(SshError::DecryptionFailed);
                }
            }
        }

        let body_plain = if let Some(ref mut cipher) = transport.server_to_client_cipher {
            if aead {
                // AES-GCM authenticates the cleartext packet_length as AAD.
                cipher.decrypt_with_aad(seq, &len_buf, &body)?
            } else {
                cipher.decrypt(seq, &body)?
            }
        } else {
            body.clone()
        };

        // Non-ETM MAC is verified over seq || packet_length || padding_length ||
        // payload || padding (RFC 4253 §6.4), after decryption.
        if let Some(ref mac) = transport.server_to_client_mac {
            if mac.tag_len() > 0 && !mac.is_etm() {
                let mut tag_buf = vec![0u8; mac.tag_len()];
                stream.read_exact(&mut tag_buf).await?;
                tag_bytes += mac.tag_len();
                let mut plain_input = Vec::with_capacity(4 + body_plain.len());
                plain_input.extend_from_slice(&len_buf);
                plain_input.extend_from_slice(&body_plain);
                if !mac.verify_tag(seq, &plain_input, &tag_buf)? {
                    return Err(SshError::DecryptionFailed);
                }
            }
        }

        // packet_length(4) + body + auth tag.
        wire_len = 4 + plen + tag_bytes;
        body_plain
    };

    transport.bytes_in += wire_len as u64;
    transport.incoming_seq += 1;

    if body.is_empty() {
        return Err(SshError::Protocol("empty packet".into()));
    }

    let payload = unpack_packet_body(&body)?;
    // Strict KEX rejects generic transport packets between KEXINIT and NEWKEYS.
    transport.check_strict_kex_packet(&payload)?;
    Ok(payload)
}

impl SshClient {
    /// Queue a payload for sending without ever blocking on the socket. Builds
    /// the encrypted packet and attempts a non-blocking `try_write`; if the
    /// socket would block (peer's receive buffer full), the packet is buffered
    /// in `pending_write` and flushed later. Ordering is preserved: once
    /// `pending_write` is non-empty, new packets are appended behind it so a
    /// partially-written packet is never interleaved with a new one.
    fn queue_send(&mut self, payload: &[u8], pending_write: &mut VecDeque<Vec<u8>>) -> Result<()> {
        let aead = self.is_aead();
        let packet = build_encrypted_packet(&mut self.transport, payload, aead)?;
        if !pending_write.is_empty() {
            // Preserve packet ordering: buffer behind any pending bytes.
            pending_write.push_back(packet);
            return Ok(());
        }
        if let Some(stream) = self.stream.as_mut() {
            match nonblocking_write(stream, &packet) {
                Ok(n) if n == packet.len() => {}
                Ok(n) => pending_write.push_back(packet[n..].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => pending_write.push_back(packet),
                Err(e) => return Err(SshError::Io(e)),
            }
        }
        Ok(())
    }

    /// Flush buffered outbound packets (from `queue_send`) using non-blocking
    /// writes. Returns as soon as the socket would block, leaving the rest for
    /// the next loop iteration so incoming packets are never starved.
    /// Returns `true` if every buffered packet was fully written, `false` if the
    /// socket would block (the caller should read to drain the peer's send
    /// window before retrying).
    fn flush_pending_write(&mut self, pending_write: &mut VecDeque<Vec<u8>>) -> bool {
        while let Some(packet) = pending_write.front() {
            let Some(stream) = self.stream.as_mut() else { break };
            match nonblocking_write(stream, packet) {
                Ok(0) => break,
                Ok(n) if n == packet.len() => { pending_write.pop_front(); }
                Ok(n) => {
                    let rem = packet[n..].to_vec();
                    pending_write[0] = rem;
                    break;
                }
                Err(_) => break,
            }
        }
        pending_write.is_empty()
    }

    /// Send channel data to the peer, respecting the peer's advertised receive
    /// window. If the window is exhausted, the remainder is queued in `pending`
    /// for later flushing on SSH_MSG_CHANNEL_WINDOW_ADJUST.
    async fn send_channel_data_gated(
        &mut self,
        remote_id: ChannelId,
        data: Vec<u8>,
        pending: &mut VecDeque<(ChannelId, Vec<u8>)>,
        pending_write: &mut VecDeque<Vec<u8>>,
        _aead: bool,
    ) {
        let local_id = self.channel_manager.find_by_remote_id(remote_id).map(|c| c.local_id);
        let window = local_id.map(|l| self.channel_manager.peer_window(l)).unwrap_or(u32::MAX);
        if window == 0 {
            pending.push_back((remote_id, data));
            return;
        }
        let can_send = (data.len() as u32).min(window) as usize;
        let msg = build_channel_data(remote_id, &data[..can_send]);
        let _ = self.queue_send(&msg, pending_write);
        if let Some(l) = local_id {
            self.channel_manager.sub_window(l, can_send as u32);
        }
        if can_send < data.len() {
            pending.push_back((remote_id, data[can_send..].to_vec()));
        }
    }

    /// Flush data that was deferred because the peer's window was 0.
    async fn flush_pending_window_data(
        &mut self,
        pending: &mut VecDeque<(ChannelId, Vec<u8>)>,
        pending_write: &mut VecDeque<Vec<u8>>,
        _aead: bool,
    ) {
        let mut still_pending: VecDeque<(ChannelId, Vec<u8>)> = VecDeque::new();
        while let Some((remote_id, data)) = pending.pop_front() {
            let local_id = self.channel_manager.find_by_remote_id(remote_id).map(|c| c.local_id);
            let window = local_id.map(|l| self.channel_manager.peer_window(l)).unwrap_or(u32::MAX);
            if window == 0 {
                still_pending.push_back((remote_id, data));
                continue;
            }
            let can_send = (data.len() as u32).min(window) as usize;
            let msg = build_channel_data(remote_id, &data[..can_send]);
            let _ = self.queue_send(&msg, pending_write);
            if let Some(l) = local_id {
                self.channel_manager.sub_window(l, can_send as u32);
            }
            if can_send < data.len() {
                still_pending.push_back((remote_id, data[can_send..].to_vec()));
            }
        }
        *pending = still_pending;
    }

    /// Send channel data, respecting the peer's advertised receive window and
    /// cooperatively pumping inbound packets so a full socket (or an exhausted
    /// window) never deadlocks the transfer. SCP/SFTP run their send and
    /// receive paths in a single task, so this method alternates between
    /// writing and reading instead of blocking on `write_all`.
    pub async fn send_channel_data(&mut self, session_local_id: ChannelId, data: &[u8]) -> Result<()> {
        if self.pump_closed {
            return Err(SshError::Protocol("channel closed during transfer".into()));
        }
        let remote_id = self.channel_manager.get_channel(session_local_id)
            .and_then(|c| c.remote_id)
            .unwrap_or(session_local_id);
        // Take the shared outbound buffer so it is not borrowed alongside `self`.
        let mut pump_write = std::mem::take(&mut self.pump_write);
        let result = self.send_channel_data_pump(session_local_id, data, remote_id, &mut pump_write).await;
        self.pump_write = pump_write;
        result
    }

    async fn send_channel_data_pump(
        &mut self,
        session_local_id: ChannelId,
        data: &[u8],
        remote_id: ChannelId,
        pump_write: &mut VecDeque<Vec<u8>>,
    ) -> Result<()> {
        // Respect the peer's advertised max packet size so a large caller buffer
        // (e.g. an SFTP write) is split into legal CHANNEL_DATA packets.
        let max_pkt = self.channel_manager.get_channel(session_local_id)
            .map(|c| c.max_packet_size)
            .filter(|m| *m > 0)
            .unwrap_or(msg::CHANNEL_MAX_PACKET_SIZE);
        let mut offset = 0;
        while offset < data.len() {
            let window = self.channel_manager.peer_window(session_local_id);
            if window == 0 {
                // Peer's receive window exhausted: read packets to collect the
                // WINDOW_ADJUST that replenishes it.
                self.pump_packet(pump_write).await?;
                if self.pump_closed {
                    return Err(SshError::Protocol("channel closed during transfer".into()));
                }
                continue;
            }
            let can_send = ((data.len() - offset) as u32).min(window).min(max_pkt) as usize;
            let msg = build_channel_data(remote_id, &data[offset..offset + can_send]);
            self.queue_send(&msg, pump_write)?;
            self.channel_manager.sub_window(session_local_id, can_send as u32);
            offset += can_send;
            if !self.flush_pending_write(pump_write) {
                // Socket send buffer full: read packets to drain the peer's
                // WINDOW_ADJUST (and buffer any inbound data) so the write can
                // make progress.
                self.pump_packet(pump_write).await?;
                if self.pump_closed {
                    return Err(SshError::Protocol("channel closed during transfer".into()));
                }
            }
        }
        // Flush any bytes still buffered before returning so the caller's next
        // read (e.g. the SCP ack byte) sees all data already on the wire.
        while !pump_write.is_empty() {
            if self.flush_pending_write(pump_write) { break; }
            self.pump_packet(pump_write).await?;
            if self.pump_closed {
                return Err(SshError::Protocol("channel closed during transfer".into()));
            }
        }
        Ok(())
    }

    /// Read one SSH packet and fold it into the flow-control pump state:
    /// - CHANNEL_DATA / CHANNEL_EXTENDED_DATA are buffered in `pump_in` and a
    ///   WINDOW_ADJUST is queued to replenish the peer's send window.
    /// - WINDOW_ADJUST grows the peer's window (allowing more outbound data).
    /// - EOF / CLOSE set `pump_closed`.
    async fn pump_packet(&mut self, pump_write: &mut VecDeque<Vec<u8>>) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        let packet = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        if packet.is_empty() { return Ok(()); }
        match packet[0] {
            msg::SSH_MSG_CHANNEL_DATA | msg::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let mut r = &packet[1..];
                let cid = u32::decode(&mut r)?;
                let data = if packet[0] == msg::SSH_MSG_CHANNEL_DATA {
                    SshBytes::decode(&mut r)?.0
                } else {
                    let _dt = u32::decode(&mut r)?;
                    SshBytes::decode(&mut r)?.0
                };
                // RFC 4254 §5.2: an inbound recipient is our local id. Map it
                // to the channel and answer on the peer's id for that channel.
                let channel = self.channel_manager.get_channel(cid);
                let local_id = channel.map(|c| c.local_id).unwrap_or(cid);
                let reply_id = channel.and_then(|c| c.remote_id).unwrap_or(cid);
                self.pump_in.push_back((local_id, data.clone()));
                // Replenish the peer's send window for the data we consumed so
                // large downloads do not stall.
                let adj = build_channel_window_adjust(reply_id, data.len() as u32);
                let _ = self.queue_send(&adj, pump_write);
            }
            msg::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                let mut r = &packet[1..];
                let recipient = u32::decode(&mut r)?;
                let amount = u32::decode(&mut r)?;
                let local_id = self.channel_manager.get_channel(recipient)
                    .map(|c| c.local_id)
                    .unwrap_or(recipient);
                self.channel_manager.add_window(local_id, amount);
            }
            msg::SSH_MSG_CHANNEL_EOF | msg::SSH_MSG_CHANNEL_CLOSE => {
                self.pump_closed = true;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn send_window_change(&mut self, local_id: ChannelId, width: u32, height: u32) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        let remote_id = self.channel_manager.get_channel(local_id)
            .and_then(|c| c.remote_id)
            .unwrap_or(0);
        let data = build_window_change(width, height, width * 8, height * 16);
        let req = build_channel_request(remote_id, msg::SSH_REQUEST_WINDOW_CHANGE, false, Some(&data));
        send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
        Ok(())
    }

    /// `AddKeysToAgent yes`: add the successfully-used identity files to the
    /// running ssh-agent (OpenSSH behavior).
    pub async fn add_loaded_keys_to_agent(&self) {
        if !self.agent.is_available() {
            return;
        }
        for signer in &self.loaded_signers {
            if let Err(e) = self.agent.add_identity(signer.as_ref()).await {
                tracing::debug!("failed to add identity to agent: {}", e);
            }
        }
    }

    /// Forward a signal (e.g. SIGINT) to the remote process via a `signal`
    /// channel request (OpenSSH behavior).
    pub async fn send_signal(&mut self, local_id: ChannelId, signal_name: &str) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        let remote_id = self.channel_manager.get_channel(local_id)
            .and_then(|c| c.remote_id)
            .unwrap_or(0);
        let data = build_signal_request(signal_name);
        let req = build_channel_request(remote_id, msg::SSH_REQUEST_SIGNAL, false, Some(&data));
        send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
        Ok(())
    }

    pub async fn send_keepalive(&mut self) -> Result<()> {
        let aead = self.is_aead();
        if let Some(stream) = self.stream.as_mut() {
            let mut req = vec![msg::SSH_MSG_GLOBAL_REQUEST];
            SshString::new("keepalive@openssh.com").encode(&mut req)?;
            true.encode(&mut req)?;
            send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
        }
        Ok(())
    }

    pub async fn send_channel_close(&mut self, local_id: ChannelId) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        if let Some(rid) = self.channel_manager.get_channel(local_id).and_then(|c| c.remote_id) {
            let close = build_channel_close(rid);
            send_encrypted_packet(stream, &close, &mut self.transport, false, aead).await?;
        }
        Ok(())
    }

    pub async fn send_disconnect(&mut self) -> Result<()> {
        let aead = self.is_aead();
        if let Some(stream) = self.stream.as_mut() {
            let mut disconnect = vec![msg::SSH_MSG_DISCONNECT];
            (1u32).encode(&mut disconnect)?; // SSH_DISCONNECT_BY_APPLICATION
            SshString::new("client exiting").encode(&mut disconnect)?;
            SshString::new("").encode(&mut disconnect)?;
            send_encrypted_packet(stream, &disconnect, &mut self.transport, false, aead).await?;
        }
        Ok(())
    }

    /// Receive the next channel data for `local_id`, cooperatively pumping
    /// inbound packets so queued WINDOW_ADJUSTs are flushed and the peer never
    /// stalls on its send window. Returns `Ok(None)` when the peer sends EOF
    /// or CLOSE. Buffered data (from a send-side pump) is drained first.
    pub async fn recv_channel_data(&mut self, local_id: ChannelId) -> Result<Option<Vec<u8>>> {
        // Take the shared outbound buffer so it is not borrowed alongside `self`.
        let mut pump_write = std::mem::take(&mut self.pump_write);
        let result = self.recv_channel_data_pump(local_id, &mut pump_write).await;
        self.pump_write = pump_write;
        result
    }

    async fn recv_channel_data_pump(
        &mut self,
        local_id: ChannelId,
        pump_write: &mut VecDeque<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>> {
        loop {
            // Return data the pump already buffered for this channel.
            if let Some(pos) = self.pump_in.iter().position(|(cid, _)| *cid == local_id) {
                let (_, data) = self.pump_in.remove(pos).unwrap();
                // Flush the WINDOW_ADJUST queued for the data we just consumed.
                let _ = self.flush_pending_write(pump_write);
                return Ok(Some(data));
            }
            if self.pump_closed {
                return Ok(None);
            }
            // Flush queued WINDOW_ADJUSTs before blocking on a read so the peer
            // is never left waiting on a window it cannot replenish.
            let _ = self.flush_pending_write(pump_write);
            self.pump_packet(pump_write).await?;
        }
    }
}

pub fn run_client(config: crate::config::ResolvedConfig, cmd: Option<String>, force_tty: bool) -> i32 {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut client = SshClient::new(config.clone());
        tracing::info!("connecting to {}:{} as {}", config.hostname, config.port, config.user);

        // ControlMaster: try to attach as a slave to an existing master socket.
        if config.control_master && config.control_path.is_some() {
            let path = config.control_path.clone().unwrap();
            if config.control_master_auto {
                if let Ok(sock) = tokio::net::UnixStream::connect(&path).await {
                    eprintln!("ControlMaster: reusing connection at {}", path);
                    let use_pty = config.request_tty || force_tty
                        || (cmd.is_none() && atty::is(atty::Stream::Stdout));
                    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
                    let req = crate::control::OpenSessionRequest {
                        request_id: 1,
                        command: config.remote_command.clone().or(cmd),
                        pty: use_pty,
                        term,
                        width: 80,
                        height: 24,
                        envs: config.set_env.clone(),
                        want_agent: config.forward_agent,
                        want_x11: config.forward_x11,
                        agent_socket: if config.forward_agent {
                            std::env::var("SSH_AUTH_SOCK").ok()
                        } else {
                            None
                        },
                        x11_display: if config.forward_x11 {
                            std::env::var("DISPLAY").ok()
                        } else {
                            None
                        },
                    };
                    return crate::control::run_control_slave(sock, req, config.batch_mode).await.unwrap_or(255);
                }
            }
            // Become the master: establish a connection, then serve.
            if client.connect().await.is_err() {
                eprintln!("ns-ssh: connect to {}:{} failed", config.hostname, config.port);
                return 255;
            }
            if client.handshake().await.is_err() {
                eprintln!("ns-ssh: handshake failed");
                return 255;
            }
            if client.authenticate().await.is_err() {
                eprintln!("ns-ssh: authentication failed");
                return 255;
            }
            if config.add_keys_to_agent {
                client.add_loaded_keys_to_agent().await;
            }
            return client.run_control_master(&path, config.control_persist).await.unwrap_or(255);
        }

        if client.connect().await.is_err() {
            eprintln!("ns-ssh: connect to {}:{} failed", config.hostname, config.port);
            return 255;
        }
        if let Err(e) = client.handshake().await {
            eprintln!("ns-ssh: handshake failed: {}", e);
            return 255;
        }
        if client.authenticate().await.is_err() {
            eprintln!("ns-ssh: authentication failed");
            return 255;
        }
        if config.add_keys_to_agent {
            client.add_loaded_keys_to_agent().await;
        }

        // LocalCommand: run on the local machine after the connection is established.
        if config.permit_local_command {
            if let Some(ref cmd) = config.local_command {
                let _ = std::process::Command::new("/bin/sh")
                    .arg("-c")
                    .arg(cmd)
                    .spawn();
            }
        }

        let use_pty = config.request_tty || force_tty || (cmd.is_none() && atty::is(atty::Stream::Stdout));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
        let final_cmd = config.remote_command.clone().or(cmd);

        let has_session = !config.no_remote_command && config.stdio_forward.is_none();

        // Set up terminal raw mode for interactive sessions
        let _term_guard = if use_pty && has_session {
            Some(TerminalGuard::new())
        } else {
            None
        };

        // -s subsystem request
        if let Some(ref sub) = config.subsystem {
            let sid = match client.request_session_subsystem(sub).await {
                Ok(sid) => sid,
                Err(e) => { eprintln!("ns-ssh: subsystem request failed: {}", e); return 255; }
            };
            return client.run_event_loop(Some(sid)).await.unwrap_or(255);
        }

        // -W host:port stdio forwarding
        // Handled inside run_event_loop

        let session_id = if has_session {
            match client.request_session(final_cmd.as_deref(), use_pty, &term, 80, 24).await {
                Ok(sid) => {
                    Some(sid)
                }
                Err(e) => {
                    eprintln!("ns-ssh: session request failed: {}", e);
                    return 255;
                }
            }
        } else {
            None
        };

        client.run_event_loop(session_id).await.unwrap_or(255)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_state_disconnect() {
        let mut s = EscapeState::new();
        // "echo hi\n" passes through; then "~." terminates.
        let (out, exit) = s.process(b"echo hi\n", '~');
        assert_eq!(out, b"echo hi\n".to_vec());
        assert!(!exit);
        let (out, exit) = s.process(b"~.", '~');
        assert!(exit);
        assert!(out.is_empty());
    }

    #[test]
    fn escape_state_midline_tilde_passthrough() {
        let mut s = EscapeState::new();
        // A '~' mid-line (not at line start) is forwarded verbatim.
        let (out, exit) = s.process(b"a~b\n", '~');
        assert_eq!(out, b"a~b\n".to_vec());
        assert!(!exit);
    }

    #[test]
    fn escape_state_unknown_escape() {
        let mut s = EscapeState::new();
        let (out, exit) = s.process(b"~x", '~');
        assert!(!exit);
        assert_eq!(out, b"~x".to_vec());
    }

    #[test]
    fn escape_state_spanning_chunks() {
        let mut s = EscapeState::new();
        // '~' at end of chunk, '.' at start of next chunk => disconnect.
        let (out, exit) = s.process(b"~", '~');
        assert!(!exit);
        assert!(out.is_empty());
        let (out, exit) = s.process(b".", '~');
        assert!(exit);
        assert!(out.is_empty());
    }

    #[test]
    fn signal_number_mapping() {
        assert_eq!(signal_number("INT"), Some(2));
        assert_eq!(signal_number("TERM"), Some(15));
        assert_eq!(signal_number("HUP"), Some(1));
        assert_eq!(signal_number("KILL"), Some(9));
        assert_eq!(signal_number("NOTASIGNAL"), None);
        // Case-insensitive.
        assert_eq!(signal_number("term"), Some(15));
    }

    #[test]
    fn filter_addrs_family() {
        let addrs: Vec<std::net::SocketAddr> = vec![
            "192.168.1.1:22".parse().unwrap(),
            "[::1]:22".parse().unwrap(),
        ];
        // -4 keeps IPv4 only.
        let v4 = filter_addrs_for_family(addrs.clone(), true, false);
        assert_eq!(v4.len(), 1);
        assert!(v4[0].is_ipv4());
        // -6 keeps IPv6 only.
        let v6 = filter_addrs_for_family(addrs.clone(), false, true);
        assert_eq!(v6.len(), 1);
        assert!(v6[0].is_ipv6());
        // Default keeps both, IPv4 first.
        let any = filter_addrs_for_family(addrs.clone(), false, false);
        assert_eq!(any.len(), 2);
        assert!(any[0].is_ipv4());
        assert!(any[1].is_ipv6());
    }

    #[test]
    fn fingerprint_sha256_default() {
        let blob = b"ssh-ed25519 some-key-bytes";
        let fp = format_fingerprint(blob, "sha256");
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), 7 + 43); // "SHA256:" + 43 base64 chars
        // Deterministic.
        assert_eq!(fp, format_fingerprint(blob, "sha256"));
    }

    #[test]
    fn fingerprint_md5_colons() {
        let blob = b"ssh-ed25519 some-key-bytes";
        let fp = format_fingerprint(blob, "md5");
        assert!(fp.starts_with("MD5:"));
        // 32 hex chars -> 32/2 = 16 colon-separated groups.
        assert_eq!(fp.len(), 4 + 16 * 3 - 1);
    }

    #[test]
    fn randomart_deterministic_and_bounded() {
        let blob = b"ssh-ed25519 some-key-bytes";
        let art1 = randomart(blob);
        let art2 = randomart(blob);
        assert_eq!(art1, art2);
        // 9 rows, each 17 chars + newline.
        let lines: Vec<&str> = art1.lines().collect();
        assert_eq!(lines.len(), 9);
        assert!(lines.iter().all(|l| l.len() == 17));
        // Start/end markers present.
        assert!(art1.contains('S'));
        assert!(art1.contains('E'));
        // Different key -> different art.
        assert_ne!(art1, randomart(b"ssh-ed25519 other"));
    }

    #[test]
    fn host_key_lookup_uses_alias() {
        let mut cfg = ResolvedConfig::default_for_user("alice");
        cfg.hostname = "real.example.com".to_string();
        cfg.host_key_alias = None;
        assert_eq!(host_key_lookup_name(&cfg), "real.example.com");
        cfg.host_key_alias = Some("alias.example.com".to_string());
        assert_eq!(host_key_lookup_name(&cfg), "alias.example.com");
    }

    #[test]
    fn localhost_detection_for_nohostauth() {
        assert!(is_localhost_host("localhost"));
        assert!(is_localhost_host("LOCALHOST"));
        assert!(is_localhost_host("127.0.0.1"));
        assert!(is_localhost_host("::1"));
        assert!(is_localhost_host("::ffff:127.0.0.1"));
        assert!(!is_localhost_host("example.com"));
        assert!(!is_localhost_host("192.168.1.5"));
    }

    /// Regression: a non-ETM peer sends `packet_length = 5` with a 16-byte
    /// cipher block. The old `4 + plen - block_size` subtracted 16 from 9 and
    /// panicked (debug) / wrapped (release). It must now be a clean
    /// `InvalidPacket` error.
    #[tokio::test]
    async fn non_etm_packet_length_shorter_than_block_is_rejected() {
        fn configured_cipher() -> Box<dyn ssh_core::cipher::SshCipher> {
            let mut c = ssh_core::cipher::create_cipher("aes128-ctr").unwrap();
            c.set_key(&[0x42u8; 16]).unwrap();
            c.set_iv(&[0x24u8; 16]).unwrap();
            c
        }

        // First cipher block whose plaintext begins with packet_length = 5.
        let mut block = vec![0u8; 16];
        block[3] = 5;
        let wire = configured_cipher().encrypt(0, &block).unwrap();

        let mut transport = SshTransport::new();
        // Fresh cipher state for the receiving side (the encryptor's IV moved).
        transport.server_to_client_cipher = Some(configured_cipher());

        let mut reader: &[u8] = &wire;
        let err = receive_encrypted_packet(&mut reader, &mut transport, false, false)
            .await
            .unwrap_err();
        assert!(matches!(err, SshError::InvalidPacket(_)), "got {:?}", err);
    }
}
