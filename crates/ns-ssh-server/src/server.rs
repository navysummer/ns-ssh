use crate::config::{x11_display_name, x11_listen_addr, ServerConfig};
use crate::hostkey::HostKeyManager;
use crate::auth::ServerAuth;
use crate::session::SessionManager;
use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::msg;
use ssh_core::transport::*;
use ssh_core::channel::*;
use ssh_core::kex::{KexExchange, KexAlgorithm};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::io::{AsyncRead, AsyncWrite};

trait StreamBox: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> StreamBox for T {}
type BoxStream = Box<dyn StreamBox + Send + Unpin>;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub struct SshServer {
    config: ServerConfig,
    host_keys: Arc<Mutex<HostKeyManager>>,
    auth: Arc<Mutex<ServerAuth>>,
}

impl SshServer {
    pub fn new(config: ServerConfig) -> Self {
        SshServer {
            config,
            host_keys: Arc::new(Mutex::new(HostKeyManager::new())),
            auth: Arc::new(Mutex::new(ServerAuth::new())),
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        let key_files = self.config.get_host_key_files();
        self.host_keys.lock().await.load_or_generate(&key_files)?;

        let auth_files = self.config.get_authorized_keys_files();
        self.auth.lock().await.load_authorized_keys(&auth_files)?;
        self.auth.lock().await.set_authorized_keys_patterns(self.config.authorized_keys_files.clone());
        self.auth.lock().await.set_authorized_keys_command(
            self.config.authorized_keys_command.clone(),
            self.config.authorized_keys_command_user.clone(),
        );
        self.auth.lock().await.set_strict_modes(self.config.strict_modes);
        self.auth.lock().await.set_required_rsa_size(self.config.required_rsa_size);

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_address, self.config.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| SshError::Io(e))?;

        tracing::info!("ns-ssh-server listening on {}", addr);

        let pending_auth = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_startups = MaxStartups::parse(&self.config.max_startups);

        loop {
            let (stream, peer_addr) = listener.accept().await
                .map_err(|e| SshError::Io(e))?;

            if let Some(ms) = &max_startups {
                let count = pending_auth.load(std::sync::atomic::Ordering::Relaxed);
                if !ms.allowed(count) {
                    drop(stream);
                    tracing::debug!(
                        "dropping connection from {}: MaxStartups ({} unauthenticated)",
                        peer_addr, count,
                    );
                    continue;
                }
            }

            // Enable TCP keepalive on accepted connections so dead peers are detected.
            #[cfg(unix)]
            if self.config.tcp_keep_alive {
                use std::os::unix::io::AsRawFd;
                let fd = stream.as_raw_fd();
                let val: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_KEEPALIVE,
                        &val as *const libc::c_int as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            let config = self.config.clone();
            let host_keys = self.host_keys.clone();
            let auth = self.auth.clone();
            let pending_guard = pending_auth.clone();
            pending_guard.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            tokio::spawn(async move {
                struct Guard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                let _guard = Guard(pending_guard);
                match handle_connection(
                    stream,
                    config,
                    host_keys,
                    auth,
                ).await {
                    Ok(()) => {}
                    // A peer that disconnects (RFC 4253 §11.1) is a normal end
                    // of connection, not an error worth alarming about.
                    Err(SshError::ConnectionClosed) => {
                        tracing::debug!("connection from {} closed", peer_addr);
                    }
                    Err(e) => {
                        tracing::error!("Connection error from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    config: ServerConfig,
    host_keys: Arc<Mutex<HostKeyManager>>,
    auth: Arc<Mutex<ServerAuth>>,
) -> Result<()> {
    let base_config = config;

    // Evaluate `Match` blocks: Host/Address/All are known at connection time;
    // User/Group are re-evaluated once the username is known (after auth request).
    let peer_ip = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let local_ip = stream.local_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let host_name = std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| local_ip.clone());
    let match_host = host_name;
    let match_addr = peer_ip.clone();

    let config = base_config.resolve_for_match("", &[], &match_host, &match_addr);

    let mut transport = SshTransport::new();
    // Apply RekeyLimit so server-initiated rekeying follows the configured thresholds.
    transport.rekey_bytes = config.rekey_limit_bytes;
    transport.rekey_seconds = config.rekey_limit_time;
    // Compression yes/no: controls whether zlib is advertised and preferred.
    transport.compression_enabled = config.compression;
    let client_version = read_version_string(&mut stream).await?;
    transport.client_version = client_version;

    if config.use_dns {
        if let Ok(peer) = stream.peer_addr() {
            if let Some(host) = reverse_dns(peer.ip()) {
                tracing::info!("connection from {} ({})", peer.ip(), host);
            } else {
                tracing::info!("connection from {} (no PTR record)", peer.ip());
            }
        }
    }

    send_version_string(&mut stream, msg::SSH_SERVER_VERSION.as_bytes()).await?;
    transport.server_version = msg::SSH_SERVER_VERSION.as_bytes().to_vec();

    let client_kex = receive_raw_packet(&mut stream).await?;
    transport.incoming_seq += 1;
    transport.client_kex_init = client_kex.clone();

    let mut host_key_algs: Vec<String> = {
        let hk = host_keys.lock().await;
        let mut algs = Vec::new();
        for k in hk.get_all_keys() {
            // An RSA key backs both SHA-2 signature variants. OpenSSH offers
            // rsa-sha2-512 before rsa-sha2-256 and leaves the SHA-1 `ssh-rsa`
            // variant out of its default host key list.
            if k.key_type() == "ssh-rsa" {
                for alg in ["rsa-sha2-512", "rsa-sha2-256"] {
                    if !algs.contains(&alg.to_string()) {
                        algs.push(alg.to_string());
                    }
                }
            } else {
                let alg = k.algorithm_name().to_string();
                if !algs.contains(&alg) {
                    algs.push(alg);
                }
            }
        }
        algs
    };
    if let Some(configured) = config.host_key_algorithms.as_ref() {
        let allowed: Vec<String> = configured
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        host_key_algs.retain(|a| allowed.iter().any(|x| x == a));
        // Honor the configured preference order.
        host_key_algs.sort_by_key(|a| allowed.iter().position(|x| x == a).unwrap_or(usize::MAX));
    }
    let kex_algs: Option<Vec<String>> = config.kex_algorithms.as_ref().map(|s| {
        s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
    });
    let cipher_algs: Option<Vec<String>> = config.ciphers.as_ref().map(|s| {
        s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
    });
    let mac_algs: Option<Vec<String>> = config.macs.as_ref().map(|s| {
        s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
    });
    let kex_init = transport.build_kex_init(
        Some(&host_key_algs),
        kex_algs.as_deref(),
        cipher_algs.as_deref(),
        mac_algs.as_deref(),
        true,
    );
    send_raw_packet(&mut stream, &kex_init).await?;
    transport.outgoing_seq += 1;
    transport.server_kex_init = kex_init.clone();
    transport.client_kex_init = client_kex;

    use tokio::io::AsyncWriteExt;
    if let Err(e) = stream.flush().await {
        return Err(e.into());
    }

    let negotiation_res = SshTransport::negotiate_algorithms(
        &transport.client_kex_init,
        &transport.server_kex_init,
    );
    let negotiation = match negotiation_res {
        Ok(n) => n,
        Err(e) => {
            return Err(e);
        }
    };
    // Terrapin mitigation: enable the strict KEX rules only when both the
    // client's `-c-` and our `-s-` pseudo algorithms were advertised. We have
    // the client's KEXINIT at this point, so the peer-side rule is active.
    transport.strict_kex = negotiation.strict_kex;
    transport.strict_kex_peer_kexinit = negotiation.strict_kex;

    let mut kex = SshTransport::create_kex_algorithm(&negotiation.kex_algorithm)?;

    let (host_key_blob, server_signature, shared_secret, exchange_hash, kex_hash) = {
        let hk = host_keys.lock().await;
        let selected_host_key = hk.get_key_for_algorithm(&negotiation.host_key_algorithm)
            .ok_or_else(|| SshError::Protocol("no matching host key".into()))?;

        let host_key_blob = selected_host_key.public_key_bytes();

        let (client_public_key, min, nbits, max, p_bytes, g_bytes, actual_modp) =
            if negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange") {
                let req_msg = receive_raw_packet(&mut stream).await?;
                transport.incoming_seq += 1;
                let (min, nbits, max) = match req_msg.first() {
                    Some(&msg::SSH_MSG_KEX_DH_GEX_REQUEST_OLD) => {
                        // RFC 4419 §3: the legacy 30 message carries only
                        // min and n; there is no explicit maximum.
                        let mut r = &req_msg[1..];
                        let mn = u32::decode(&mut r)?;
                        let nb = u32::decode(&mut r)?;
                        (mn, nb, u32::MAX)
                    }
                    Some(&msg::SSH_MSG_KEX_DH_GEX_REQUEST) => {
                        let mut r = &req_msg[1..];
                        let mn = u32::decode(&mut r)?;
                        let nb = u32::decode(&mut r)?;
                        let mx = u32::decode(&mut r)?;
                        (mn, nb, mx)
                    }
                    _ => return Err(SshError::Protocol("expected gex request".into())),
                };
                // RFC 4419 §3: answer with a group inside [min, max], closest
                // to the client's preferred size. Our supported groups are the
                // RFC 3526 2048/4096/8192-bit safe primes.
                let group = ssh_core::kex::select_gex_group(min, nbits, max)
                    .ok_or_else(|| SshError::KexFailed(format!(
                        "no supported group-exchange modulus in requested range [{}, {}]",
                        min, max
                    )))?;
                let p_bytes = group.p.to_bytes_be();
                let g_bytes = group.g.to_bytes_be();
                let p = group.p.clone();
                let g = group.g.clone();
                let exp_bytes = group.exp_bytes;
                let gex_hash: &'static str = if negotiation.kex_algorithm.contains("sha256") { "sha256" } else { "sha1" };
                let gex_name: &'static str = if negotiation.kex_algorithm.contains("sha256") {
                    "diffie-hellman-group-exchange-sha256"
                } else {
                    "diffie-hellman-group-exchange-sha1"
                };
                let mut group_msg = Vec::new();
                group_msg.push(msg::SSH_MSG_KEX_DH_GEX_GROUP);
                use ssh_core::encoding::SshMpInt;
                SshMpInt(p_bytes.clone()).encode(&mut group_msg)?;
                SshMpInt(g_bytes.clone()).encode(&mut group_msg)?;
                send_raw_packet(&mut stream, &group_msg).await?;
                transport.outgoing_seq += 1;

                let init_msg = receive_raw_packet(&mut stream).await?;
                transport.incoming_seq += 1;
                if init_msg.first() != Some(&msg::SSH_MSG_KEX_DH_GEX_INIT) {
                    return Err(SshError::Protocol("expected SSH_MSG_KEX_DH_GEX_INIT".into()));
                }
                let mut r = &init_msg[1..];
                let e_bytes = SshMpInt::decode(&mut r)?.0;

                let mut real_modp = ssh_core::kex::ModpKex::with_params(gex_name, gex_hash, p, g, exp_bytes);
                real_modp.generate_keypair()?;
                (e_bytes, Some(min), Some(nbits), Some(max), Some(p_bytes), Some(g_bytes), Some(real_modp))
            } else {
                kex.generate_keypair()?;
                let client_dh_init = receive_raw_packet(&mut stream).await?;
                transport.incoming_seq += 1;
                let mut r = &client_dh_init[1..];
                let client_pub = SshMpInt::decode(&mut r)?.0;
                (client_pub, None, None, None, None, None, None)
            };

        let (shared_secret, hash_name, client_pub_for_hash, server_pub_for_hash) = if let Some(mut am) = actual_modp {
            let shared = am.compute_shared_secret(&client_public_key)?;
            let hash_name = am.hash_name().to_string();
            let client_pub = client_public_key.clone();
            let server_pub = am.public_key_bytes();
            kex = Box::new(am);
            (shared, hash_name, client_pub, server_pub)
        } else {
            let shared = kex.compute_shared_secret(&client_public_key)?;
            let hash_name = kex.hash_name().to_string();
            let client_pub = client_public_key.clone();
            let server_pub = kex.public_key_bytes();
            (shared, hash_name, client_pub, server_pub)
        };

        let exchange = KexExchange {
            client_version: transport.client_version.clone(),
            server_version: transport.server_version.clone(),
            client_kex_init: transport.client_kex_init.clone(),
            server_kex_init: transport.server_kex_init.clone(),
        };

        let exchange_hash = if let (Some(mn), Some(nb), Some(mx), Some(pb), Some(gb)) = (min, nbits, max, p_bytes, g_bytes) {
            ssh_core::kex::compute_gex_exchange_hash(
                &hash_name,
                &exchange,
                mn, nb, mx,
                &pb, &gb,
                &host_key_blob,
                &client_pub_for_hash,
                &server_pub_for_hash,
                &shared_secret,
            )
        } else {
            ssh_core::kex::compute_exchange_hash(
                &hash_name,
                &exchange,
                &host_key_blob,
                &client_pub_for_hash,
                &server_pub_for_hash,
                &shared_secret,
                negotiation.kex_algorithm.starts_with("diffie-hellman-group"),
            )
        };

        let server_signature = selected_host_key.sign_with(&negotiation.host_key_algorithm, &exchange_hash)?;
        (host_key_blob, server_signature, shared_secret, exchange_hash, hash_name)
    };

    let mut dh_reply = Vec::new();
    let use_gex_msg = negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange");
    dh_reply.push(if use_gex_msg { msg::SSH_MSG_KEX_DH_GEX_REPLY } else { msg::SSH_MSG_KEXDH_REPLY });
    SshBytes(host_key_blob.clone()).encode(&mut dh_reply)?;
    if use_gex_msg {
        use ssh_core::encoding::SshMpInt;
        SshMpInt(kex.public_key_bytes()).encode(&mut dh_reply)?;
    } else if negotiation.kex_algorithm.starts_with("diffie-hellman-group") {
        // f is an mpint: values with the high bit set must carry a leading
        // 0x00 byte, otherwise peers read it as a negative bignum.
        SshMpInt(kex.public_key_bytes()).encode(&mut dh_reply)?;
    } else {
        // ECDH/curve25519 public keys are byte strings, not mpints; adding a
        // sign byte would make the peer reject an over-long key.
        SshBytes(kex.public_key_bytes()).encode(&mut dh_reply)?;
    }
    SshBytes(server_signature).encode(&mut dh_reply)?;
    send_raw_packet(&mut stream, &dh_reply).await?;
    transport.outgoing_seq += 1;

    let aead = negotiation.server_to_client_cipher.contains("gcm")
        || negotiation.server_to_client_cipher.contains("chacha20");

    // RFC 4253 §7.1: SSH_MSG_NEWKEYS is exchanged with the current (old) keys.
    // Neither side has installed the new keys yet, so both NEWKEYS packets are
    // plaintext; only after the exchange do we switch to the new keys.
    let newkeys_client = receive_encrypted_packet_server(&mut stream, &mut transport, true, aead).await?;
    if newkeys_client.first() != Some(&msg::SSH_MSG_NEWKEYS) {
        return Err(SshError::Protocol("expected NEWKEYS from client".into()));
    }

    let newkeys_msg = vec![msg::SSH_MSG_NEWKEYS];
    send_encrypted_packet_server(&mut stream, &newkeys_msg, &mut transport, true, aead).await?;
    // Strict KEX restarts both sequence numbers at zero after NEWKEYS.
    transport.reset_sequences_after_newkeys();

    // Only now is it safe to install and use the new keys.
    transport.install_new_keys(
        &negotiation,
        &kex_hash,
        &shared_secret,
        &exchange_hash,
        &exchange_hash,
    )?;

    transport.session_id = Some(exchange_hash.clone());

    transport.state = KexState::Established;
    // The RekeyLimit byte counter starts after the initial key exchange.
    transport.last_rekey_bytes = transport.total_bytes();
    transport.last_rekey_instant = std::time::Instant::now();

    {
        let mut ext_info = vec![msg::SSH_EXT_INFO_S];
        1u32.encode(&mut ext_info)?;
        SshString::new("server-sig-algs").encode(&mut ext_info)?;
        let mut sig_algs = Vec::new();
        let algs = [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ssh-rsa",
        ];
        for (i, a) in algs.iter().enumerate() {
            if i > 0 { sig_algs.push(b','); }
            sig_algs.extend_from_slice(a.as_bytes());
        }
        SshBytes(sig_algs).encode(&mut ext_info)?;
        let _ = send_encrypted_packet_server(&mut stream, &ext_info, &mut transport, false, aead).await;
    }

    handle_authenticated_session(
        stream,
        transport,
        config,
        base_config,
        match_host,
        match_addr,
        host_keys.clone(),
        auth.clone(),
        &exchange_hash,
    ).await?;

    Ok(())
}

/// Outcome of evaluating `AuthenticationMethods` against the methods already
/// completed on this connection.
enum AuthStep {
    /// No chain is configured, or the current chain is fully satisfied.
    Complete,
    /// The client must still complete one of these methods next.
    Continue(Vec<String>),
    /// The completed sequence matches none of the configured chains.
    Invalid,
}

/// Advance the authentication state machine. `required` holds the alternative
/// chains from `AuthenticationMethods` (empty = enforcement disabled), and
/// `done` the methods that have already succeeded in order.
fn next_auth_step(required: &[Vec<String>], done: &[String]) -> AuthStep {
    if required.is_empty() {
        return AuthStep::Complete;
    }
    if done.is_empty() {
        // Every chain is still reachable; the client may pick any first step.
        let mut firsts: Vec<String> = Vec::new();
        for chain in required {
            if let Some(first) = chain.first() {
                if !firsts.contains(first) {
                    firsts.push(first.clone());
                }
            }
        }
        return AuthStep::Continue(firsts);
    }
    for chain in required {
        if done.len() <= chain.len() && done.iter().zip(chain.iter()).all(|(a, b)| a == b) {
            return if done.len() == chain.len() {
                AuthStep::Complete
            } else {
                AuthStep::Continue(vec![chain[done.len()].clone()])
            };
        }
    }
    AuthStep::Invalid
}

/// Methods this server has enabled, in the order OpenSSH advertises them.
fn enabled_auth_methods(config: &ServerConfig) -> Vec<String> {
    let mut methods = Vec::new();
    if config.pubkey_auth { methods.push("publickey".to_string()); }
    if config.password_auth { methods.push("password".to_string()); }
    if config.kbd_interactive_auth { methods.push("keyboard-interactive".to_string()); }
    methods
}

/// Build the method list and `partial success` flag for a USERAUTH_FAILURE
/// response. With `AuthenticationMethods` configured only the next required
/// step is advertised; `partial` is set once a step has already completed.
fn failure_methods(
    config: &ServerConfig,
    completed: &[String],
    default_methods: Vec<String>,
) -> (Vec<String>, bool) {
    if config.authentication_methods.is_empty() {
        return (default_methods, false);
    }
    match next_auth_step(&config.authentication_methods, completed) {
        AuthStep::Continue(methods) => (methods, !completed.is_empty()),
        _ => (Vec::new(), false),
    }
}

async fn send_auth_failure(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    aead: bool,
    methods: Vec<String>,
    partial: bool,
) -> Result<()> {
    let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
    SshNameList(methods).encode(&mut failure)?;
    // RFC 4252 §5.1: TRUE means the previous request partially succeeded.
    failure.push(if partial { 1 } else { 0 });
    send_encrypted_packet_server(stream, &failure, transport, false, aead).await?;
    Ok(())
}

/// Record a successful authentication step and reply to the client: either
/// USERAUTH_SUCCESS when the configured chain is complete, or a partial
/// success failure naming the next required step. Returns `true` when the
/// user is fully authenticated.
async fn complete_auth_step(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    aead: bool,
    config: &ServerConfig,
    completed: &mut Vec<String>,
    method: &str,
) -> Result<bool> {
    completed.push(method.to_string());
    match next_auth_step(&config.authentication_methods, completed) {
        AuthStep::Complete => {
            let success = vec![msg::SSH_MSG_USERAUTH_SUCCESS];
            send_encrypted_packet_server(stream, &success, transport, false, aead).await?;
            Ok(true)
        }
        AuthStep::Continue(remaining) => {
            send_auth_failure(stream, transport, aead, remaining, true).await?;
            Ok(false)
        }
        AuthStep::Invalid => {
            // The method succeeded but breaks every configured chain.
            send_auth_failure(stream, transport, aead, Vec::new(), false).await?;
            Ok(false)
        }
    }
}

async fn handle_authenticated_session(
    mut stream: TcpStream,
    mut transport: SshTransport,
    config: ServerConfig,
    base_config: ServerConfig,
    match_host: String,
    match_addr: String,
    host_keys: Arc<Mutex<HostKeyManager>>,
    auth: Arc<Mutex<ServerAuth>>,
    session_id: &[u8],
) -> Result<()> {
    let mut config = config;
    let aead = transport.client_to_server_cipher.as_ref()
        .map(|c| c.is_aead())
        .unwrap_or(false);

    let svc_request = receive_encrypted_packet_server(&mut stream, &mut transport, false, aead).await?;
    if svc_request.first() != Some(&msg::SSH_MSG_SERVICE_REQUEST) {
        return Err(SshError::Protocol("expected service request".into()));
    }

    let mut r = &svc_request[1..];
    let service_name = SshString::decode(&mut r)?.as_str()?.to_string();

    if service_name != msg::SSH_SERVICE_NAME_USERAUTH {
        return Err(SshError::Protocol("expected userauth service".into()));
    }

    let mut svc_accept = vec![msg::SSH_MSG_SERVICE_ACCEPT];
    SshString::new(&service_name).encode(&mut svc_accept)?;
    send_encrypted_packet_server(&mut stream, &svc_accept, &mut transport, false, aead).await?;

    if let Some(ref banner_path) = config.banner {
        // OpenSSH's `Banner /path/to/file` sends the *contents* of the file.
        let banner_text = std::fs::read_to_string(banner_path).unwrap_or_default();
        if !banner_text.is_empty() {
            let mut banner = vec![53u8]; // SSH_MSG_USERAUTH_BANNER
            SshString::new(&banner_text).encode(&mut banner)?;
            SshString::new("en").encode(&mut banner)?;
            let _ = send_encrypted_packet_server(&mut stream, &banner, &mut transport, false, aead).await;
        }
    }

    let mut session_manager = SessionManager::new();
    let mut username = String::new();
    let mut authenticated = false;
    let mut auth_tries = 0;
    let mut pending_kbd_user: Option<String> = None;
    let mut auth_key_options: Option<crate::auth::AuthorizedKeyOptions> = None;
    // Methods successfully completed so far, in order, for AuthenticationMethods.
    let mut completed_methods: Vec<String> = Vec::new();

    while auth_tries < config.max_auth_tries {
        let auth_request = if config.login_grace_time > 0 {
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(config.login_grace_time as u64),
                receive_encrypted_packet_server(&mut stream, &mut transport, false, aead),
            ).await {
                Ok(res) => res?,
                Err(_) => {
                    tracing::info!("LoginGraceTime exceeded for {}, disconnecting", username);
                    return Err(SshError::AuthFailed("login grace time exceeded".into()));
                }
            }
        } else {
            receive_encrypted_packet_server(&mut stream, &mut transport, false, aead).await?
        };
        if auth_request.is_empty() {
            break;
        }

        match auth_request[0] {
            msg::SSH_MSG_USERAUTH_INFO_RESPONSE => {
                let mut r = &auth_request[1..];
                let num_answers = u32::decode(&mut r)? as usize;
                let mut answers = Vec::with_capacity(num_answers);
                for _ in 0..num_answers {
                    answers.push(SshString::decode(&mut r)?.as_str()?.to_string());
                }
                let current_user = pending_kbd_user.take().unwrap_or_default();
                let answer = answers.get(0).cloned().unwrap_or_default();
                if config.kbd_interactive_auth
                    && config.password_auth
                    && auth.lock().await.verify_password(&current_user, &answer)
                {
                    if complete_auth_step(
                        &mut stream,
                        &mut transport,
                        aead,
                        &config,
                        &mut completed_methods,
                        "keyboard-interactive",
                    ).await? {
                        authenticated = true;
                        break;
                    }
                } else {
                    let (methods, partial) = failure_methods(
                        &config,
                        &completed_methods,
                        enabled_auth_methods(&config),
                    );
                    send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                    if config.auth_failure_delay > 0 {
                        tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                    }
                    auth_tries += 1;
                }
            }
            msg::SSH_MSG_USERAUTH_REQUEST => {
                let mut r = &auth_request[1..];
                username = SshString::decode(&mut r)?.as_str()?.to_string();
                let _service = SshString::decode(&mut r)?.as_str()?.to_string();
                let method = SshString::decode(&mut r)?.as_str()?.to_string();

                // Re-evaluate `Match` blocks now that the username is known.
                let groups = crate::auth::get_user_groups(&username).unwrap_or_default();
                config = base_config.resolve_for_match(&username, &groups, &match_host, &match_addr);

                if !crate::auth::check_user_authorized(&username, &match_host, &config.allow_users, &config.deny_users) {
                    let (methods, partial) = failure_methods(
                        &config,
                        &completed_methods,
                        enabled_auth_methods(&config),
                    );
                    send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                    auth_tries += 1;
                    if config.auth_failure_delay > 0 {
                        tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                    }
                    continue;
                }

                let is_root = username == "root";
                let root_mode = config.permit_root_login_mode.clone();
                let root_login_ok = match root_mode.as_str() {
                    "yes" => true,
                    "no" => false,
                    "without-password" | "prohibit-password" => true,
                    "forced-commands-only" => config.force_command.is_some(),
                    _ => config.permit_root_login,
                };
                let root_password_ok = root_mode == "yes"
                    || (root_mode.is_empty() && config.permit_root_login);

                if is_root && !root_login_ok {
                    let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                    SshNameList(Vec::new()).encode(&mut failure)?;
                    failure.push(1);
                    send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                    return Err(SshError::AuthFailed("root login not permitted".into()));
                }

                if is_root
                    && !root_password_ok
                    && (method == "password" || method == "keyboard-interactive")
                {
                    let (methods, partial) = failure_methods(
                        &config,
                        &completed_methods,
                        vec!["publickey".to_string()],
                    );
                    send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                    auth_tries += 1;
                    continue;
                }

                if (!config.allow_groups.is_empty() || !config.deny_groups.is_empty())
                    && !crate::auth::check_group_membership(&username, &config.allow_groups, &config.deny_groups)
                {
                    let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                    SshNameList(Vec::new()).encode(&mut failure)?;
                    failure.push(1);
                    send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                    auth_tries += 1;
                    continue;
                }

                // AuthenticationMethods: reject any method that is not the next
                // required step, and advertise the expected step instead.
                if !config.authentication_methods.is_empty() && method != "none" {
                    let next = match next_auth_step(&config.authentication_methods, &completed_methods) {
                        AuthStep::Continue(next) => next,
                        AuthStep::Complete | AuthStep::Invalid => Vec::new(),
                    };
                    if !next.iter().any(|m| m == &method) {
                        let (methods, partial) = failure_methods(
                            &config,
                            &completed_methods,
                            enabled_auth_methods(&config),
                        );
                        send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                        auth_tries += 1;
                        if config.auth_failure_delay > 0 {
                            tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                        }
                        continue;
                    }
                }

                match method.as_str() {
                    "publickey" => {
                        let has_sig = bool::decode(&mut r)?;
                        let key_type = SshString::decode(&mut r)?.as_str()?.to_string();
                        let public_key = SshBytes::decode(&mut r)?.0;

                        // PubkeyAcceptedAlgorithms: reject client algorithms
                        // that are not in the server's allowed set.
                        if let Some(ref accepted) = config.pubkey_accepted_algorithms {
                            if !crate::config::pubkey_alg_accepted_server(&key_type, accepted) {
                                let (methods, partial) = failure_methods(
                                    &config,
                                    &completed_methods,
                                    enabled_auth_methods(&config),
                                );
                                send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                                if config.auth_failure_delay > 0 {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                                }
                                continue;
                            }
                        }

                        if has_sig {
                            let signature_blob = SshBytes::decode(&mut r)?.0;

                            if config.pubkey_auth && auth_verify_pubkey_signed(&auth, session_id, &username, &key_type, &public_key, &signature_blob).await
                            {
                                // Check authorized key options (command=, from=, no-pty)
                                let mut g = auth.lock().await;
                                g.load_user_authorized_keys(&username);
                                if let Some(entry) = g.find_matching_key(&key_type, &public_key) {
                                    // from= check against peer address
                                    if let Ok(peer_addr) = stream.peer_addr() {
                                        let peer_addr = peer_addr.to_string();
                                        if !g.check_from_pattern(entry, &peer_addr) {
                                            drop(g);
                                            let (methods, partial) = failure_methods(
                                                &config,
                                                &completed_methods,
                                                enabled_auth_methods(&config),
                                            );
                                            send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                                            if config.auth_failure_delay > 0 {
                                                tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                                            }
                                            continue;
                                        }
                                    }
                                    // Store the authorized key options for application to the session
                                    auth_key_options = Some(entry.options.clone());
                                }
                                drop(g);
                                if complete_auth_step(
                                    &mut stream,
                                    &mut transport,
                                    aead,
                                    &config,
                                    &mut completed_methods,
                                    "publickey",
                                ).await? {
                                    authenticated = true;
                                    break;
                                }
                            } else {
                                let (methods, partial) = failure_methods(
                                    &config,
                                    &completed_methods,
                                    enabled_auth_methods(&config),
                                );
                                send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                                if config.auth_failure_delay > 0 {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                                }
                            }
                        } else {
                            if config.pubkey_auth && auth_verify_public_key(&auth, &username, &key_type, &public_key).await {
                                let mut pk_ok = vec![msg::SSH_MSG_USERAUTH_PK_OK];
                                SshString::new(&key_type).encode(&mut pk_ok)?;
                                SshBytes(public_key).encode(&mut pk_ok)?;
                                send_encrypted_packet_server(&mut stream, &pk_ok, &mut transport, false, aead).await?;
                            } else {
                                let (methods, partial) = failure_methods(
                                    &config,
                                    &completed_methods,
                                    enabled_auth_methods(&config),
                                );
                                send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                                if config.auth_failure_delay > 0 {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                                }
                            }
                        }
                    }
                    "password" => {
                        let _change_password = bool::decode(&mut r)?;
                        let password = SshString::decode(&mut r)?.as_str()?.to_string();

                        // PermitEmptyPasswords: reject empty passwords unless enabled.
                        let empty_ok = config.permit_empty_passwords || !password.is_empty();
                        if config.password_auth && empty_ok
                            && auth.lock().await.verify_password(&username, &password) {
                            if config.print_last_log {
                                tracing::info!("Accepted password for {} from {}", username, match_addr);
                            }
                            if complete_auth_step(
                                &mut stream,
                                &mut transport,
                                aead,
                                &config,
                                &mut completed_methods,
                                "password",
                            ).await? {
                                authenticated = true;
                                break;
                            }
                        } else {
                            let mut default_methods = vec!["password".to_string()];
                            if config.pubkey_auth { default_methods.insert(0, "publickey".to_string()); }
                            if config.kbd_interactive_auth { default_methods.push("keyboard-interactive".to_string()); }
                            let (methods, partial) = failure_methods(
                                &config,
                                &completed_methods,
                                default_methods,
                            );
                            send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                            if config.auth_failure_delay > 0 {
                                tokio::time::sleep(tokio::time::Duration::from_secs(config.auth_failure_delay)).await;
                            }
                        }
                    }
                    "keyboard-interactive" => {
                        let _lang = SshString::decode(&mut r)?.as_str()?.to_string();
                        let _submethods = SshString::decode(&mut r)?.as_str()?.to_string();

                        if !config.kbd_interactive_auth {
                            let (methods, partial) = failure_methods(
                                &config,
                                &completed_methods,
                                enabled_auth_methods(&config),
                            );
                            send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                            continue;
                        }

                        pending_kbd_user = Some(username.clone());
                        let mut info_req = vec![msg::SSH_MSG_USERAUTH_INFO_REQUEST];
                        SshString::new("").encode(&mut info_req)?; // name
                        SshString::new("").encode(&mut info_req)?; // instruction
                        SshString::new("en").encode(&mut info_req)?; // language tag
                        1u32.encode(&mut info_req)?; // num prompts
                        SshString::new("Password: ").encode(&mut info_req)?; // prompt
                        false.encode(&mut info_req)?; // echo=false
                        send_encrypted_packet_server(&mut stream, &info_req, &mut transport, false, aead).await?;
                    }
                    "none" => {
                        let (methods, partial) = failure_methods(
                            &config,
                            &completed_methods,
                            enabled_auth_methods(&config),
                        );
                        send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                    }
                    _ => {
                        let (methods, partial) = failure_methods(
                            &config,
                            &completed_methods,
                            enabled_auth_methods(&config),
                        );
                        send_auth_failure(&mut stream, &mut transport, aead, methods, partial).await?;
                    }
                }
            }
            // RFC 4253 §11.2: IGNORE and DEBUG must be silently ignored.
            msg::SSH_MSG_IGNORE | msg::SSH_MSG_DEBUG => {
                continue;
            }
            _ => break,
        }

        auth_tries += 1;
    }

    if !authenticated {
        let mut no_methods = vec![msg::SSH_MSG_USERAUTH_FAILURE];
        SshNameList(Vec::new()).encode(&mut no_methods)?;
        no_methods.push(1);
        send_encrypted_packet_server(&mut stream, &no_methods, &mut transport, false, aead).await?;
        return Err(SshError::AuthFailed("authentication failed".into()));
    }

    if transport.client_to_server_compression == "zlib@openssh.com"
        || transport.client_to_server_compression == "zlib"
    {
        transport.compression_active_c2s = true;
    }
    if transport.server_to_client_compression == "zlib@openssh.com"
        || transport.server_to_client_compression == "zlib"
    {
        transport.compression_active_s2c = true;
    }

    handle_connection_service(&mut stream, &mut transport, &config, &host_keys, &username, &mut session_manager, &auth_key_options).await?;
    Ok(())
}

enum ChildOutputMsg {
    Stdout(u32, Vec<u8>),
    Stderr(u32, Vec<u8>),
}

fn permit_entry_matches(entry: &str, host: &str, port: u32, is_listen: bool) -> bool {
    let entry = entry.to_lowercase();
    if entry == "any" {
        return true;
    }
    let (h, p) = match entry.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => return false,
    };
    let host_ok = h == host.to_lowercase() || h == "*" || (is_listen && (h == "0.0.0.0" || h == "::"));
    let port_ok = p == "0" || p.parse::<u32>().ok() == Some(port);
    host_ok && port_ok
}

fn permit_list_allows(list: &[String], host: &str, port: u32, is_listen: bool) -> bool {
    if list.is_empty() {
        return true;
    }
    list.iter().any(|e| permit_entry_matches(e, host, port, is_listen))
}

fn forward_policy_allows_remote(
    cfg: &ServerConfig,
    auth_key_options: &Option<crate::auth::AuthorizedKeyOptions>,
    _bind_addr: &str,
    _port: u32,
) -> bool {
    // authorized_keys no-port-forwarding disables all forwarding.
    if let Some(opts) = auth_key_options {
        if opts.no_port_forwarding {
            return false;
        }
    }
    match cfg.allow_tcp_forwarding_mode.as_str() {
        "no" => false,
        "local" => false, // local-only: client→server allowed, remote (server→client) disallowed
        _ => true,
    }
}

struct MaxStartups {
    start: usize,
    rate: usize,
    full: usize,
}

impl MaxStartups {
    fn parse(s: &str) -> Option<MaxStartups> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return None;
        }
        let start = parts[0].parse().ok()?;
        let rate = parts[1].parse().ok()?;
        let full = parts[2].parse().ok()?;
        Some(MaxStartups { start, rate, full })
    }

    fn allowed(&self, count: usize) -> bool {
        if count < self.start {
            return true;
        }
        if count >= self.full {
            return false;
        }
        let span = self.full.saturating_sub(self.start).max(1);
        let pct = self.rate + (100usize.saturating_sub(self.rate)) * (count - self.start) / span;
        let roll: u32 = rand::random();
        (roll % 100) as usize >= pct
    }
}

#[cfg(unix)]
fn reverse_dns(ip: std::net::IpAddr) -> Option<String> {
    let (bytes, is_v4): (&[u8], bool) = match ip {
        std::net::IpAddr::V4(v) => (&v.octets(), true),
        std::net::IpAddr::V6(v) => (&v.octets(), false),
    };
    unsafe {
        let mut sockaddr_storage = std::mem::zeroed::<libc::sockaddr_storage>();
        let (sa, salen): (*const libc::sockaddr, libc::socklen_t) = if is_v4 {
            let sa = &mut sockaddr_storage as *mut _ as *mut libc::sockaddr_in;
            (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
            (*sa).sin_addr.s_addr = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            (sa as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        } else {
            let sa = &mut sockaddr_storage as *mut _ as *mut libc::sockaddr_in6;
            (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
            (*sa).sin6_addr.s6_addr = bytes.try_into().ok()?;
            (sa as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        };
        let mut host = [0i8; 1024];
        let rc = libc::getnameinfo(
            sa,
            salen,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        );
        if rc != 0 {
            return None;
        }
        let bytes: Vec<u8> = host.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect();
        Some(String::from_utf8_lossy(&bytes).to_string())
    }
}

#[cfg(not(unix))]
fn reverse_dns(_ip: std::net::IpAddr) -> Option<String> {
    None
}

fn forward_policy_allows_direct(
    cfg: &ServerConfig,
    auth_key_options: &Option<crate::auth::AuthorizedKeyOptions>,
    host: &str,
    port: u32,
) -> bool {
    // authorized_keys restrictions take precedence.
    if let Some(opts) = auth_key_options {
        if opts.no_port_forwarding {
            return false;
        }
        if !opts.permit_open.is_empty() && !permit_list_allows(&opts.permit_open, host, port, false) {
            return false;
        }
    }
    match cfg.allow_tcp_forwarding_mode.as_str() {
        "no" => false,
        "remote" => false, // remote-only: server→client allowed, direct (client→server) disallowed
        _ => permit_list_allows(&cfg.permit_open, host, port, false),
    }
}

fn forward_policy_allows_listen(
    cfg: &ServerConfig,
    auth_key_options: &Option<crate::auth::AuthorizedKeyOptions>,
    bind_addr: &str,
    port: u32,
) -> bool {
    // authorized_keys restrictions take precedence.
    if let Some(opts) = auth_key_options {
        if !opts.permit_listen.is_empty() && !permit_list_allows(&opts.permit_listen, bind_addr, port, true) {
            return false;
        }
    }
    permit_list_allows(&cfg.permit_listen, bind_addr, port, true)
}

/// StreamLocal forwarding policy: gated by `AllowStreamLocalForwarding` and the
/// authorized_keys `no-port-forwarding` option. OpenSSH applies the key's
/// `no-port-forwarding` restriction to streamlocal forwarding too, while the
/// server-level `AllowStreamLocalForwarding` controls the feature as a whole.
fn forward_policy_allows_streamlocal(
    cfg: &ServerConfig,
    auth_key_options: &Option<crate::auth::AuthorizedKeyOptions>,
) -> bool {
    if !cfg.allow_streamlocal_forwarding {
        return false;
    }
    if let Some(opts) = auth_key_options {
        if opts.no_port_forwarding {
            return false;
        }
    }
    true
}

async fn auth_verify_public_key(
    auth: &Arc<Mutex<ServerAuth>>,
    username: &str,
    key_type: &str,
    public_key: &[u8],
) -> bool {
    let mut g = auth.lock().await;
    g.load_user_authorized_keys(username);
    g.verify_public_key(key_type, public_key)
}

async fn auth_verify_pubkey_signed(
    auth: &Arc<Mutex<ServerAuth>>,
    session_id: &[u8],
    username: &str,
    key_type: &str,
    public_key: &[u8],
    signature_blob: &[u8],
) -> bool {
    let mut g = auth.lock().await;
    g.load_user_authorized_keys(username);
    if !g.verify_public_key(key_type, public_key) {
        return false;
    }
    g.verify_signature(session_id, username, key_type, public_key, signature_blob)
}

fn start_session_and_readers(
    session_manager: &mut SessionManager,
    sid: u32,
    work_dir: &str,
    chroot: Option<&str>,
    auth_key_options: &Option<crate::auth::AuthorizedKeyOptions>,
    permit_user_environment: bool,
    print_motd: bool,
    child_tx: tokio::sync::mpsc::UnboundedSender<ChildOutputMsg>,
    readers_done: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Result<()> {
    if let Some(ch) = chroot {
        session_manager.set_chroot_dir(sid, ch.to_string());
    }
    // Apply authorized_keys restrictions: command=, no-pty, environment= (if permitted)
    if let Some(opts) = auth_key_options {
        if let Some(ref cmd) = opts.command {
            session_manager.set_auth_key_command(sid, cmd.clone());
        }
        if opts.no_pty {
            session_manager.set_pty_disabled(sid);
        }
        if permit_user_environment {
            for (name, value) in &opts.environment {
                session_manager.set_env_var(sid, name.clone(), value.clone());
            }
        }
    }
    session_manager.start_session(sid, work_dir)?;

    // PrintMotd: emit /etc/motd on interactive (pty) sessions before the shell runs.
    if print_motd {
        let motd = std::fs::read_to_string("/etc/motd").unwrap_or_default();
        if !motd.is_empty() {
            if let Some(session) = session_manager.get_session_mut(sid) {
                if let Some(mut pw) = session.pty_write.take() {
                    let motd_bytes = motd.into_bytes();
                    tokio::spawn(async move {
                        use tokio::io::AsyncWriteExt;
                        let _ = pw.write_all(&motd_bytes).await;
                        let _ = pw.flush().await;
                    });
                }
            }
        }
    }

    if let Some(session) = session_manager.get_session_mut(sid) {
        if let Some(pr) = session.pty_read.take() {
            readers_done.store(1, std::sync::atomic::Ordering::SeqCst);
            let tx = child_tx;
            let sid = sid;
            let rd = readers_done.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut reader = pr;
                let mut buf = [0u8; 16384];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = tx.send(ChildOutputMsg::Stdout(sid, buf[..n].to_vec())); }
                        Err(_) => break,
                    }
                }
                rd.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        } else {
        let stdout_present = session.stdout.is_some();
        let stderr_present = session.stderr.is_some();
        let reader_count = (stdout_present as usize) + (stderr_present as usize);
        readers_done.store(reader_count, std::sync::atomic::Ordering::SeqCst);
        if let Some(stdout) = session.stdout.take() {
            let tx = child_tx.clone();
            let sid = sid;
            let rd = readers_done.clone();
            tokio::spawn(async move {
                let mut reader = stdout;
                let mut buf = [0u8; 16384];
                loop {
                    use tokio::io::AsyncReadExt;
                    match reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = tx.send(ChildOutputMsg::Stdout(sid, buf[..n].to_vec())); }
                        Err(_) => break,
                    }
                }
                rd.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
        if let Some(stderr) = session.stderr.take() {
            let tx = child_tx;
            let sid = sid;
            let rd = readers_done.clone();
            tokio::spawn(async move {
                let mut reader = stderr;
                let mut buf = [0u8; 16384];
                loop {
                    use tokio::io::AsyncReadExt;
                    match reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = tx.send(ChildOutputMsg::Stderr(sid, buf[..n].to_vec())); }
                        Err(_) => break,
                    }
                }
                rd.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
        }
    }

    Ok(())
}

async fn handle_connection_service(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    config: &ServerConfig,
    host_keys: &Arc<Mutex<HostKeyManager>>,
    username: &str,
    session_manager: &mut SessionManager,
    auth_key_options: &Option<crate::auth::AuthorizedKeyOptions>,
) -> Result<()> {
    use std::collections::HashMap;
    use tokio::sync::{mpsc, oneshot};
    use ssh_core::channel::ChannelId;

    let aead = transport.client_to_server_cipher.as_ref()
        .map(|c| c.is_aead())
        .unwrap_or(false);

    // OpenSSH does NOT use a SSH_MSG_SERVICE_REQUEST for "ssh-connection":
    // after userauth success the client opens a session channel directly, and
    // OpenSSH's sshd dispatch table never registers SSH2_MSG_SERVICE_REQUEST.
    // We therefore do not require it here; if a (non-standard) client does send
    // one, the connection loop below replies with SERVICE_ACCEPT.

    let user_info = crate::session::get_user_info(username)?;
    let mut work_dir = user_info.home_dir.clone();
    // Apply ChrootDirectory if configured
    if let Some(ref chroot) = config.chroot_directory {
        work_dir = format!("{}/{}", chroot, work_dir);
    }

    let mut channel_manager = ChannelManager::new();
    let mut session_started = false;
    let (child_tx, mut child_rx) = tokio::sync::mpsc::unbounded_channel::<ChildOutputMsg>();
    // Per-session data queued for the child's stdin because the pipe was full
    // (e.g. the remote command does not read stdin). Flushed non-blockingly at
    // the top of the loop so the loop is never blocked writing to the child and
    // can still drain child stdout (avoiding a bidirectional deadlock).
    let mut pending_stdin: std::collections::HashMap<u32, std::collections::VecDeque<Vec<u8>>> =
        std::collections::HashMap::new();

    let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel::<(ChannelId, Vec<u8>)>();
    let (eof_tx, mut eof_rx) = mpsc::unbounded_channel::<ChannelId>();
    let mut pending_open: HashMap<ChannelId, oneshot::Sender<(ChannelId, u32, u32)>> = HashMap::new();
    let mut pending_open_sockets: HashMap<ChannelId, (BoxStream, oneshot::Receiver<(ChannelId, u32, u32)>)> = HashMap::new();
    let mut sftp_channels: std::collections::HashSet<ChannelId> = std::collections::HashSet::new();
    // Set once exit-status + CHANNEL_CLOSE have been sent for the session, so
    // the connection can stay open (for ControlMaster multiplexing) instead of
    // being torn down after a single session finishes.
    let _session_exit_sent = false;
    // Per-session routing for multiplexed (ControlMaster) connections:
    // sid -> remote (server) channel id, and local channel id -> sid.
    let mut session_remote: std::collections::HashMap<u32, ChannelId> = std::collections::HashMap::new();
    let mut channel_session: std::collections::HashMap<ChannelId, u32> = std::collections::HashMap::new();
    let mut session_exit_sent_map: std::collections::HashMap<u32, bool> = std::collections::HashMap::new();
    // Per-session count of live child-output reader tasks. Readers decrement
    // this when they finish; the exit_poll arm waits until it reaches 0 before
    // sending exit-status/CLOSE so all child output is forwarded first (FIFO).
    let mut session_readers_done: std::collections::HashMap<u32, std::sync::Arc<std::sync::atomic::AtomicUsize>> =
        std::collections::HashMap::new();
    // After the client sends `no-more-sessions@openssh.com`, further `session`
    // channel opens must be rejected (OpenSSH behavior).
    let mut no_more_sessions = false;

    enum ForwardAccept {
        Incoming(u16, TcpStream, std::net::SocketAddr),
    }
    let (fwd_tx, mut fwd_rx) = mpsc::unbounded_channel::<ForwardAccept>();
    let mut forwarded_ports: Vec<u16> = Vec::new();
    // Track each `tcpip-forward` listener task so `cancel-tcpip-forward` can
    // close the underlying socket (OpenSSH closes the listener on cancel).
    let mut forwarded_listeners: std::collections::HashMap<u16, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();

    // StreamLocal (`-R`) forwarding: accept Unix-socket connections and open
    // `forwarded-streamlocal@openssh.com` channels to the client.
    enum StreamLocalAccept {
        Incoming(String, tokio::net::UnixStream),
    }
    let (streamlocal_tx, mut streamlocal_rx) = mpsc::unbounded_channel::<StreamLocalAccept>();
    let mut forwarded_streamlocal_paths: Vec<String> = Vec::new();
    let mut streamlocal_listeners: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();

    enum AgentAccept {
        Incoming(UnixStream),
    }
    let (agent_tx, mut agent_rx) = mpsc::unbounded_channel::<AgentAccept>();
    let mut agent_sock_path: Option<String> = None;

    enum X11Accept {
        Incoming(TcpStream, std::net::SocketAddr),
    }
    let (x11_tx, mut x11_rx) = mpsc::unbounded_channel::<X11Accept>();
    let mut x11_enabled = false;
    // Track the X11 listener task so it is aborted when the connection ends
    // (OpenSSH closes its X11 listener when the client's connection ends).
    // `AbortJoin` guarantees the abort runs on every exit path (including the
    // `?` error propagations), so the bound port is always released.
    let mut x11_listener_handle = AbortJoin(None);

    let mut missed_alive: u32 = 0;
    // True once the server has sent its rekey KEXINIT and is waiting for the
    // client's KEXINIT to complete the exchange (server-initiated rekey).
    let mut server_rekey_kex_sent = false;
    let alive_interval_ms = config.client_alive_interval.saturating_mul(1000);
    let alive_enabled = alive_interval_ms > 0;
    let mut alive_sleep: std::pin::Pin<Box<tokio::time::Sleep>> =
        Box::pin(tokio::time::sleep(tokio::time::Duration::from_millis(alive_interval_ms.max(1) as u64)));
    let mut rekey_sleep: std::pin::Pin<Box<tokio::time::Sleep>> =
        Box::pin(tokio::time::sleep(tokio::time::Duration::from_secs(60)));
    let mut exit_poll: std::pin::Pin<Box<tokio::time::Sleep>> =
        Box::pin(tokio::time::sleep(tokio::time::Duration::from_millis(50)));
    // ChannelTimeout: per-channel last-activity timestamps and a 1s watchdog.
    let mut channel_last_activity: std::collections::HashMap<ChannelId, std::time::Instant> =
        std::collections::HashMap::new();
    let mut channel_timeout_poll: std::pin::Pin<Box<tokio::time::Sleep>> =
        Box::pin(tokio::time::sleep(tokio::time::Duration::from_secs(1)));

    'conn: loop {
        tokio::task::yield_now().await;

        // Flush data queued for child stdins whose pipe was full. This is
        // non-blocking so the loop can keep processing child stdout and incoming
        // packets (avoids the bidirectional deadlock on large transfers where
        // the remote command does not read stdin).
        if !pending_stdin.is_empty() {
            let sids: Vec<u32> = pending_stdin.keys().copied().collect();
            for sid in sids {
                let Some(queue) = pending_stdin.get_mut(&sid) else { continue };
                let mut still: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
                while let Some(chunk) = queue.pop_front() {
                    let res = if let Some(session) = session_manager.get_session_mut(sid) {
                        if let Some(ref mut pw) = session.pty_write {
                            nonblocking_write_server(pw.as_mut(), &chunk)
                        } else if let Some(ref mut stdin) = session.stdin {
                            nonblocking_write_server(stdin, &chunk)
                        } else {
                            Ok(chunk.len())
                        }
                    } else {
                        Ok(chunk.len())
                    };
                    match res {
                        Ok(n) if n == chunk.len() => {}
                        Ok(n) => { still.push_back(chunk[n..].to_vec()); break; }
                        Err(_) => { still.push_back(chunk); break; }
                    }
                }
                if still.is_empty() {
                    pending_stdin.remove(&sid);
                } else {
                    *queue = still;
                }
            }
        }

        tokio::select! {
            biased;

            packet = receive_encrypted_packet_server(stream, transport, false, aead) => {
                let packet = packet?;
                if packet.is_empty() {
                    continue;
                }
                if packet[0] != msg::SSH_MSG_CHANNEL_DATA {
                    tracing::trace!("recv packet type {}", packet[0]);
                }

                match packet[0] {
                    msg::SSH_MSG_SERVICE_REQUEST => {
                        // RFC 4254: a client may request the "ssh-connection"
                        // service explicitly. OpenSSH's client does not, but
                        // accept it if sent and reply SERVICE_ACCEPT.
                        let mut r = &packet[1..];
                        if let Ok(service) = SshString::decode(&mut r) {
                            if let Ok(s) = service.as_str() {
                                if s == msg::SSH_SERVICE_NAME_CONNECTION {
                                    let mut accept = vec![msg::SSH_MSG_SERVICE_ACCEPT];
                                    SshString::new(msg::SSH_SERVICE_NAME_CONNECTION).encode(&mut accept)?;
                                    send_encrypted_packet_server(stream, &accept, transport, false, aead).await?;
                                }
                            }
                        }
                        continue;
                    }
                    msg::SSH_MSG_KEXINIT => {
                        match perform_rekey_server(stream, transport, config, host_keys, Some(packet), server_rekey_kex_sent).await {
                            Ok(()) => {
                                server_rekey_kex_sent = false;
                            }
                            Err(SshError::ConnectionClosed) => {
                                break 'conn;
                            }
                            Err(SshError::Io(ref e))
                                if matches!(e.kind(),
                                    std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::UnexpectedEof) =>
                            {
                                // Peer vanished mid-rekey; nothing left to do.
                                break 'conn;
                            }
                            Err(e) => {
                                tracing::warn!("rekey failed: {:?}", e);
                                server_rekey_kex_sent = false;
                            }
                        }
                        continue;
                    }
                    msg::SSH_MSG_GLOBAL_REQUEST => {
                        let mut r = &packet[1..];
                        let name = SshString::decode(&mut r)?.as_str()?.to_string();
                        let want_reply = bool::decode(&mut r)?;
                        match name.as_str() {
                            "tcpip-forward" => {
                                let bind_addr = SshString::decode(&mut r)?.as_str()?.to_string();
                                let bind_port = u32::decode(&mut r)?;

                                if !forward_policy_allows_remote(&config, auth_key_options, &bind_addr, bind_port)
                                    || !forward_policy_allows_listen(&config, auth_key_options, &bind_addr, bind_port)
                                {
                                    if want_reply {
                                        send_encrypted_packet_server(stream, &build_request_failure(), transport, false, aead).await?;
                                    }
                                    continue;
                                }

                                let listen_addr = if bind_addr.is_empty() || bind_addr == "0.0.0.0" {
                                    if config.gateway_ports == "yes" || config.gateway_ports == "clientspecified" {
                                        format!("0.0.0.0:{}", bind_port)
                                    } else {
                                        format!("127.0.0.1:{}", bind_port)
                                    }
                                } else {
                                    format!("{}:{}", bind_addr, bind_port)
                                };
                                match tokio::net::TcpListener::bind(&listen_addr).await {
                                    Ok(listener) => {
                                        let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(bind_port as u16);
                                        forwarded_ports.push(actual_port);
                                        let tx = fwd_tx.clone();
                                        let handle = tokio::spawn(async move {
                                            loop {
                                                match listener.accept().await {
                                                    Ok((s, p)) => {
                                                        if tx.send(ForwardAccept::Incoming(actual_port, s, p)).is_err() { break; }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });
                                        forwarded_listeners.insert(actual_port, handle);
                                        if want_reply {
                                            let mut succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                            (actual_port as u32).encode(&mut succ)?;
                                            send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                        }
                                    }
                                    Err(_) => {
                                        if want_reply {
                                            send_encrypted_packet_server(stream, &build_request_failure(), transport, false, aead).await?;
                                        }
                                    }
                                }
                            }
                            "cancel-tcpip-forward" => {
                                let _bind_addr = SshString::decode(&mut r)?.as_str()?.to_string();
                                let bind_port = u32::decode(&mut r)?;
                                forwarded_ports.retain(|&p| p != bind_port as u16);
                                // Abort the listener task so the bound socket is closed.
                                if let Some(handle) = forwarded_listeners.remove(&(bind_port as u16)) {
                                    handle.abort();
                                }
                                if want_reply {
                                    let succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                    send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                }
                            }
                            "streamlocal-forward@openssh.com" => {
                                let path = SshString::decode(&mut r)?.as_str()?.to_string();
                                if !forward_policy_allows_streamlocal(&config, auth_key_options) {
                                    if want_reply {
                                        send_encrypted_packet_server(stream, &build_request_failure(), transport, false, aead).await?;
                                    }
                                    continue;
                                }
                                let _ = std::fs::remove_file(&path);
                                match tokio::net::UnixListener::bind(&path) {
                                    Ok(listener) => {
                                        forwarded_streamlocal_paths.push(path.clone());
                                        let tx = streamlocal_tx.clone();
                                        let path2 = path.clone();
                                        let handle = tokio::spawn(async move {
                                            loop {
                                                match listener.accept().await {
                                                    Ok((s, _)) => {
                                                        if tx.send(StreamLocalAccept::Incoming(path2.clone(), s)).is_err() { break; }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });
                                        streamlocal_listeners.insert(path.clone(), handle);
                                        if want_reply {
                                            let succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                            send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                        }
                                    }
                                    Err(_) => {
                                        if want_reply {
                                            send_encrypted_packet_server(stream, &build_request_failure(), transport, false, aead).await?;
                                        }
                                    }
                                }
                            }
                            "cancel-streamlocal-forward@openssh.com" => {
                                let path = SshString::decode(&mut r)?.as_str()?.to_string();
                                forwarded_streamlocal_paths.retain(|p| p != &path);
                                if let Some(handle) = streamlocal_listeners.remove(&path) {
                                    handle.abort();
                                }
                                if want_reply {
                                    let succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                    send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                }
                            }
                            "no-more-sessions@openssh.com" => {
                                no_more_sessions = true;
                                if want_reply {
                                    let succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                    send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                }
                            }
                            "keepalive@openssh.com" => {
                                if want_reply {
                                    let succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                    send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                }
                            }
                            "hostkeys-00@openssh.com" => {
                                // OpenSSH hostkeys-00 protocol: reply with the
                                // server's host public keys as a sequence of
                                // string key blobs (client reads until empty).
                                if want_reply {
                                    let hk = host_keys.lock().await;
                                    let mut succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                    for key in hk.get_all_keys() {
                                        SshBytes(key.public_key_bytes()).encode(&mut succ)?;
                                    }
                                    drop(hk);
                                    send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                }
                            }
                            _ => {
                                if want_reply {
                                    send_encrypted_packet_server(stream, &build_request_failure(), transport, false, aead).await?;
                                }
                            }
                        }
                    }
                    msg::SSH_MSG_REQUEST_SUCCESS => {
                        missed_alive = 0;
                    }
                    msg::SSH_MSG_REQUEST_FAILURE => {}
                    msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                        if let Ok((recipient, sender, w, m)) = parse_channel_open_confirmation(&packet) {
                            if let Some(tx) = pending_open.remove(&recipient) {
                                channel_last_activity.insert(recipient, std::time::Instant::now());
                                channel_manager.set_remote_id(recipient, sender);
                                channel_manager.set_peer_window(recipient, w);
                                let _ = tx.send((sender, w, m));
                            }
                            if let Some((sock, _rx)) = pending_open_sockets.remove(&recipient) {
                                let rx = channel_manager.take_data_rx(recipient).unwrap();
                                pump_socket(sock, rx, sender, to_client_tx.clone(), eof_tx.clone());
                            }
                        }
                    }
                    msg::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                        if let Ok((recipient, _reason, _message)) = parse_channel_open_failure(&packet) {
                            pending_open.remove(&recipient);
                            pending_open_sockets.remove(&recipient);
                            channel_manager.close_channel(recipient);
                            channel_last_activity.remove(&recipient);
                        }
                    }
                    msg::SSH_MSG_CHANNEL_OPEN => {
                        let (channel_type, sender_channel, client_window, _max_packet) = parse_channel_open(&packet)?;

                        match channel_type.as_str() {
                            t if t == msg::SSH_CHANNEL_TYPE_SESSION => {
                                if no_more_sessions {
                                    let fail = build_channel_open_failure(sender_channel, 1, "no more sessions");
                                    send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                    continue;
                                }
                                if config.max_sessions > 0 && session_manager.len() as u32 >= config.max_sessions {
                                    let fail = build_channel_open_failure(sender_channel, 1, "too many sessions");
                                    send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                    continue;
                                }
                                let local_channel = channel_manager.alloc_channel(
                                    &channel_type,
                                    msg::CHANNEL_PACKET_WINDOW_SIZE,
                                    msg::CHANNEL_MAX_PACKET_SIZE,
                                );
                                channel_last_activity.insert(local_channel, std::time::Instant::now());
                                channel_manager.set_remote_id(local_channel, sender_channel);
                                channel_manager.set_peer_window(local_channel, client_window);
                                // Create a session up-front and associate it with this
                                // channel so multiplexed connections can run several
                                // independent sessions over one transport.
                                let sid = session_manager.create_session(
                                    username.to_string(), false, "dumb".to_string(), 80, 24,
                                );
                                channel_session.insert(local_channel, sid);
                                session_remote.insert(sid, sender_channel);
                                let confirmation = build_channel_open_confirmation(
                                    sender_channel, local_channel,
                                    msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE,
                                );
                                send_encrypted_packet_server(stream, &confirmation, transport, false, aead).await?;
                            }
                            t if t == msg::SSH_CHANNEL_TYPE_DIRECT_TCPIP => {
                                let (_st, _w, _m, host, port, _orig_host, _orig_port) =
                                    match parse_direct_tcpip_open(&packet) {
                                        Ok(v) => v,
                                        Err(_) => {
                                            let fail = build_channel_open_failure(sender_channel, 1, "parse failed");
                                            send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                            continue;
                                        }
                                    };
                                if !forward_policy_allows_direct(&config, auth_key_options, &host, port) {
                                    let fail = build_channel_open_failure(sender_channel, 1, "forwarding disabled");
                                    send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                    continue;
                                }
                                match TcpStream::connect(format!("{}:{}", host, port)).await {
                                    Ok(socket) => {
                                        let local_channel = channel_manager.alloc_channel(
                                            &channel_type,
                                            msg::CHANNEL_PACKET_WINDOW_SIZE,
                                            msg::CHANNEL_MAX_PACKET_SIZE,
                                        );
                                        channel_last_activity.insert(local_channel, std::time::Instant::now());
                                        channel_manager.set_remote_id(local_channel, sender_channel);
                                        channel_manager.set_peer_window(local_channel, client_window);
                                        let confirmation = build_channel_open_confirmation(
                                            sender_channel, local_channel,
                                            msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE,
                                        );
                                        send_encrypted_packet_server(stream, &confirmation, transport, false, aead).await?;
                                        let rx = channel_manager.take_data_rx(local_channel).unwrap();
                                        pump_socket(socket, rx, sender_channel, to_client_tx.clone(), eof_tx.clone());
                                    }
                                    Err(_) => {
                                        let fail = build_channel_open_failure(sender_channel, 1, "connect failed");
                                        send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                    }
                                }
                            }
                            t if t == msg::SSH_CHANNEL_TYPE_DIRECT_STREAMLOCAL => {
                                let (_st, _w, _m, socket_path) =
                                    match parse_direct_streamlocal_open(&packet) {
                                        Ok(v) => v,
                                        Err(_) => {
                                            let fail = build_channel_open_failure(sender_channel, 1, "parse failed");
                                            send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                            continue;
                                        }
                                    };
                                if !forward_policy_allows_streamlocal(&config, auth_key_options) {
                                    let fail = build_channel_open_failure(sender_channel, 1, "streamlocal forwarding disabled");
                                    send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                    continue;
                                }
                                match tokio::net::UnixStream::connect(&socket_path).await {
                                    Ok(socket) => {
                                        let local_channel = channel_manager.alloc_channel(
                                            &channel_type,
                                            msg::CHANNEL_PACKET_WINDOW_SIZE,
                                            msg::CHANNEL_MAX_PACKET_SIZE,
                                        );
                                        channel_last_activity.insert(local_channel, std::time::Instant::now());
                                        channel_manager.set_remote_id(local_channel, sender_channel);
                                        channel_manager.set_peer_window(local_channel, client_window);
                                        let confirmation = build_channel_open_confirmation(
                                            sender_channel, local_channel,
                                            msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE,
                                        );
                                        send_encrypted_packet_server(stream, &confirmation, transport, false, aead).await?;
                                        let rx = channel_manager.take_data_rx(local_channel).unwrap();
                                        pump_socket(socket, rx, sender_channel, to_client_tx.clone(), eof_tx.clone());
                                    }
                                    Err(_) => {
                                        let fail = build_channel_open_failure(sender_channel, 1, "connect failed");
                                        send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                                    }
                                }
                            }
                            _ => {
                                let fail = build_channel_open_failure(sender_channel, 4, "channel type not supported");
                                send_encrypted_packet_server(stream, &fail, transport, false, aead).await?;
                            }
                        }
                    }
                    msg::SSH_MSG_CHANNEL_DATA => {
                        // RFC 4254 §5.2: the recipient channel of an inbound
                        // message is *our* local channel id. Replies must
                        // target the peer's id for that channel.
                        let (recipient, data) = parse_channel_data(&packet)?;
                        let data_len = data.len() as u32;
                        let local_channel = channel_manager.get_channel(recipient)
                            .map(|c| c.local_id);
                        if let Some(lc) = local_channel {
                            channel_last_activity.insert(lc, std::time::Instant::now());
                        }
                        let reply_channel = channel_manager.reply_recipient(recipient)
                            .unwrap_or(recipient);
                        if let Some(local_id) = local_channel {
                            if let Some(ch) = channel_manager.get_channel(local_id) {
                                if ch.channel_type == "session" && !sftp_channels.contains(&local_id) {
                                    if let Some(sid) = channel_session.get(&local_id).copied() {
                                        if let Some(session) = session_manager.get_session_mut(sid) {
                                            // Non-blocking write to the child's stdin/pty.
                                            // If the pipe is full (remote command not
                                            // reading), buffer the remainder so the loop
                                            // can keep draining child stdout.
                                            let entry = pending_stdin.entry(sid).or_default();
                                            if !entry.is_empty() {
                                                entry.push_back(data);
                                            } else {
                                                let res = if let Some(ref mut pw) = session.pty_write {
                                                    nonblocking_write_server(pw.as_mut(), &data)
                                                } else if let Some(ref mut stdin) = session.stdin {
                                                    nonblocking_write_server(stdin, &data)
                                                } else {
                                                    Ok(data.len())
                                                };
                                                match res {
                                                    Ok(n) if n == data.len() => {}
                                                    Ok(n) => entry.push_back(data[n..].to_vec()),
                                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => entry.push_back(data),
                                                    Err(_) => {}
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if let Some(tx) = &ch.data_tx { let _ = tx.try_send(data); }
                                }
                            }
                        }
                        // Replenish the client's send window so large client->server
                        // transfers (uploads) do not stall once the window exhausts.
                        send_encrypted_packet_server(
                            stream,
                            &build_channel_window_adjust(reply_channel, data_len),
                            transport, false, aead,
                        ).await?;
                    }
                    msg::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                        let mut r = &packet[1..];
                        let recipient = u32::decode(&mut r)?;
                        let dt = u32::decode(&mut r)?;
                        let data = SshBytes::decode(&mut r)?.0;
                        let data_len = data.len() as u32;
                        if dt == 1 {
                            use std::io::Write;
                            let _ = std::io::stderr().write_all(&data);
                        }
                        // Replenish the client's send window for stderr too;
                        // the recipient field of that reply is the peer's id.
                        let reply_channel = channel_manager
                            .reply_recipient(recipient)
                            .unwrap_or(recipient);
                        send_encrypted_packet_server(
                            stream,
                            &build_channel_window_adjust(reply_channel, data_len),
                            transport, false, aead,
                        ).await?;
                    }
                    msg::SSH_MSG_CHANNEL_REQUEST => {
                        // Inbound recipient is our local id; every reply must
                        // carry the peer's id for that channel instead.
                        let (recipient, request_type, want_reply) = parse_channel_request(&packet)?;

                        let local_channel = channel_manager.get_channel(recipient)
                            .map(|c| c.local_id);
                        if let Some(lc) = local_channel {
                            channel_last_activity.insert(lc, std::time::Instant::now());
                        }

                        if local_channel.is_some() {
                            let channel_id = channel_manager.reply_recipient(recipient)
                                .unwrap_or(recipient);
                            let extra_offset = 10 + request_type.len();
                            let mut r = &packet[extra_offset..];
                            match request_type.as_str() {
                                "pty-req" => {
                                    let term = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let width = u32::decode(&mut r)?;
                                    let height = u32::decode(&mut r)?;
                                    let _pixel_width = u32::decode(&mut r)?;
                                    let _pixel_height = u32::decode(&mut r)?;

                                    if !config.permit_tty {
                                        // PermitTTY no: reject the request.
                                        if want_reply {
                                            let reply = build_channel_failure(channel_id);
                                            send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                        }
                                        continue;
                                    }

                                    // Enforce authorized_keys `no-pty` / `no-user-pty`.
                                    if auth_key_options.as_ref().map(|o| o.no_pty || o.no_user_ptm).unwrap_or(false) {
                                        if want_reply {
                                            let reply = build_channel_failure(channel_id);
                                            send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                        }
                                        continue;
                                    }

                                    // Session was created at channel-open time; just
                                    // update the PTY settings for this channel.
                                    if let Some(lc) = local_channel {
                                        if let Some(sid) = channel_session.get(&lc).copied() {
                                            session_manager.set_pty(sid, term, width, height);
                                        }
                                    }

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "exec" => {
                                    let command = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let command = config.force_command.clone().unwrap_or(command);

                                    // Resolve the session associated with this channel.
                                    let sid = local_channel.and_then(|lc| channel_session.get(&lc).copied())
                        .unwrap_or_else(|| {
                            let sid = session_manager.create_session(
                                username.to_string(), false, "dumb".to_string(), 80, 24,
                            );
                            if let Some(lc) = local_channel {
                                channel_session.insert(lc, sid);
                                session_remote.insert(sid, channel_id);
                            }
                            sid
                        });
                                    session_manager.set_command(sid, command.clone());
                                    let readers_done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                                    session_readers_done.insert(sid, readers_done.clone());
                                    if let Err(e) = start_session_and_readers(session_manager, sid, &work_dir, config.chroot_directory.as_deref(), auth_key_options, config.permit_user_environment, config.print_motd, child_tx.clone(), readers_done) {
                                        tracing::error!("Failed to start session: {}", e);
                                    }
                                    session_started = true;

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "shell" => {
                                    let sid = local_channel.and_then(|lc| channel_session.get(&lc).copied());
                                    if let Some(sid) = sid {
                                        if session_manager.get_session(sid)
                                            .map(|s| s.command.is_none() && s.child.is_none())
                                            .unwrap_or(false)
                                        {
                                            let readers_done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                                            session_readers_done.insert(sid, readers_done.clone());
                                            if let Err(e) = start_session_and_readers(session_manager, sid, &work_dir, config.chroot_directory.as_deref(), auth_key_options, config.permit_user_environment, config.print_motd, child_tx.clone(), readers_done) {
                                                tracing::error!("Failed to start shell: {}", e);
                                            }
                                            session_started = true;
                                        }
                                    }

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "env" => {
                                    let name = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let value = SshString::decode(&mut r)?.as_str()?.to_string();

                                    let allowed = env_allowed(&config.accept_env, &name);
                                    if allowed {
                                        if let Some(lc) = local_channel {
                                            if let Some(sid) = channel_session.get(&lc).copied() {
                                                session_manager.set_env_var(sid, name, value);
                                            }
                                        }
                                        if want_reply {
                                            let reply = build_channel_success(channel_id);
                                            send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                        }
                                    } else if want_reply {
                                        let reply = build_channel_failure(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "x11-req" => {
                                    let _single_conn = {
                                        let mut byte = [0u8; 1];
                                        byte.copy_from_slice(&r[..1]);
                                        r = &r[1..];
                                        byte[0] != 0
                                    };
                                    let _auth_proto = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let _auth_cookie = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let _screen = u32::decode(&mut r)?;

                                    // Enforce authorized_keys `no-x11-forwarding`.
                                    if auth_key_options.as_ref().map(|o| o.no_x11_forwarding).unwrap_or(false) {
                                        if want_reply {
                                            let reply = build_channel_failure(channel_id);
                                            send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                        }
                                        continue;
                                    }

                                    if config.x11_forwarding {
                                        if let Some(sid) = local_channel.and_then(|lc| channel_session.get(&lc).copied()) {
                                            let display = x11_display_name(config);
                                            session_manager.set_env_var(sid, "DISPLAY".to_string(), display);
                                        }
                                        if !x11_enabled {
                                            let bind_addr = x11_listen_addr(config);
                                            match tokio::net::TcpListener::bind(&bind_addr).await {
                                                Ok(listener) => {
                                                    x11_enabled = true;
                                                    let tx = x11_tx.clone();
                                                    x11_listener_handle = AbortJoin(Some(tokio::spawn(async move {
                                                        loop {
                                                            match listener.accept().await {
                                                                Ok((s, p)) => {
                                                                    if tx.send(X11Accept::Incoming(s, p)).is_err() { break; }
                                                                }
                                                                Err(_) => break,
                                                            }
                                                        }
                                                    })));
                                                }
                                                Err(e) => {
                                                    tracing::warn!("x11 listener bind on {} failed: {}", bind_addr, e);
                                                }
                                            }
                                        }
                                        if want_reply {
                                            let reply = build_channel_success(channel_id);
                                            send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                        }
                                    } else if want_reply {
                                        let reply = build_channel_failure(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "auth-agent-req@openssh.com" => {
                                    // Enforce authorized_keys `no-agent-forwarding`.
                                    if auth_key_options.as_ref().map(|o| o.no_agent_forwarding).unwrap_or(false) {
                                        if want_reply {
                                            let reply = build_channel_failure(channel_id);
                                            send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                        }
                                        continue;
                                    }

                                    if config.allow_agent_forwarding {
                                        let sid = local_channel.and_then(|lc| channel_session.get(&lc).copied())
                        .unwrap_or_else(|| {
                            let sid = session_manager.create_session(
                                username.to_string(), false, "dumb".to_string(), 80, 24,
                            );
                            if let Some(lc) = local_channel {
                                channel_session.insert(lc, sid);
                                session_remote.insert(sid, channel_id);
                            }
                            sid
                        });
                                        if agent_sock_path.is_none() {
                                            let dir = std::env::temp_dir().join(format!("ssh-{}", std::process::id()));
                                            let _ = std::fs::create_dir_all(&dir);
                                            let sock_path = dir.join("agent").to_string_lossy().to_string();
                                            let _ = std::fs::remove_file(&sock_path);
                                            match UnixListener::bind(&sock_path) {
                                                Ok(listener) => {
                                                    agent_sock_path = Some(sock_path.clone());
                                                    session_manager.set_env_var(sid, "SSH_AUTH_SOCK".to_string(), sock_path.clone());
                                                    let tx = agent_tx.clone();
                                                    tokio::spawn(async move {
                                                        loop {
                                                            match listener.accept().await {
                                                                Ok((s, _)) => {
                                                                    if tx.send(AgentAccept::Incoming(s)).is_err() { break; }
                                                                }
                                                                Err(_) => break,
                                                            }
                                                        }
                                                    });
                                                }
                                                Err(e) => {
                                                    tracing::warn!("agent listener bind failed: {}", e);
                                                }
                                            }
                                        }
                                        if want_reply {
                                            let reply = build_channel_success(channel_id);
                                            send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                        }
                                    } else if want_reply {
                                        let reply = build_channel_failure(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "window-change" => {
                                    let width = u32::decode(&mut r)?;
                                    let height = u32::decode(&mut r)?;

                                    if let Some(sid) = local_channel.and_then(|lc| channel_session.get(&lc).copied()) {
                                        session_manager.set_window_size(sid, width, height);
                                        let _ = session_manager.resize_pty(sid, width, height);
                                    }

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "subsystem" => {
                                    let subsystem_name = SshString::decode(&mut r)?.as_str()?.to_string();

                                    if let Some(subsystem_path) = config.subsystems.get(&subsystem_name) {
                                        if subsystem_path == "internal-sftp" {
                                            if let Some(sid) = local_channel.and_then(|lc| channel_session.get(&lc).copied()) {
                                                session_manager.set_command(sid, subsystem_path.clone());
                                            }
                                            if let Some(local_id) = local_channel {
                                                sftp_channels.insert(local_id);
                                                if let Some(sid) = channel_session.get(&local_id).copied() {
                                                    if let Some(remote_id) = session_remote.get(&sid).copied() {
                                                        if let Some(rx) = channel_manager.take_data_rx(local_id) {
                                                            let tx_ret = to_client_tx.clone();
                                                            let base = std::path::PathBuf::from(&work_dir);
                                                            tokio::spawn(async move {
                                                                run_internal_sftp(rx, remote_id, tx_ret, base).await;
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                            session_started = true;
                                        } else if let Some(sid) = local_channel.and_then(|lc| channel_session.get(&lc).copied()) {
                                            session_manager.set_command(sid, subsystem_path.clone());
                                            let readers_done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                                            session_readers_done.insert(sid, readers_done.clone());
                                            if let Err(e) = start_session_and_readers(session_manager, sid, &work_dir, config.chroot_directory.as_deref(), auth_key_options, config.permit_user_environment, config.print_motd, child_tx.clone(), readers_done) {
                                                tracing::error!("Failed to start subsystem {}: {}", subsystem_name, e);
                                            }
                                            session_started = true;
                                        }
                                    } else {
                                        tracing::error!("Unknown subsystem: {}", subsystem_name);
                                    }

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "signal" => {
                                    if let Some(sid) = local_channel.and_then(|lc| channel_session.get(&lc).copied()) {
                                        if let Some(session) = session_manager.get_session_mut(sid) {
                                            if let Some(ref mut child) = session.child {
                                                let signal_name = SshString::decode(&mut r)?.as_str()?.to_string();
                                                let signal = match signal_name.as_str() {
                                                    "INT" => libc::SIGINT,
                                                    "TERM" => libc::SIGTERM,
                                                    "QUIT" => libc::SIGQUIT,
                                                    "HUP" => libc::SIGHUP,
                                                    "USR1" => libc::SIGUSR1,
                                                    "USR2" => libc::SIGUSR2,
                                                    "WINCH" => libc::SIGWINCH,
                                                    _ => libc::SIGTERM,
                                                };
                                                unsafe {
                                                    if let Some(pid) = child.id() {
                                                        // Signal the whole process group so the signal reaches
                                                        // the actual foreground process (e.g. a shell's child
                                                        // such as `sleep`), matching OpenSSH.
                                                        libc::kill(-(pid as i32), signal);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "break" => {
                                    // Send SIGINT to the session's process group (OpenSSH
                                    // sends a break to the terminal).
                                    if let Some(sid) = local_channel.and_then(|lc| channel_session.get(&lc).copied()) {
                                        if let Some(session) = session_manager.get_session_mut(sid) {
                                            if let Some(ref mut child) = session.child {
                                                unsafe {
                                                    if let Some(pid) = child.id() {
                                                        libc::kill(-(pid as i32), libc::SIGINT);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "eow@openssh.com" => {
                                    // End of window: client has closed its side of the
                                    // channel. Take stdin so the child sees EOF.
                                    if let Some(sid) = local_channel.and_then(|lc| channel_session.get(&lc).copied()) {
                                        if let Some(session) = session_manager.get_session_mut(sid) {
                                            session.stdin.take();
                                        }
                                    }
                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                _ => {
                                    if want_reply {
                                        let reply = build_channel_failure(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                            }
                        }
                    }
                    msg::SSH_MSG_CHANNEL_EOF => {
                        let mut r = &packet[1..];
                        let recipient = u32::decode(&mut r)?;
                        let is_sftp_channel = sftp_channels.contains(&recipient);
                        if is_sftp_channel {
                            // The in-process SFTP subsystem has nothing further
                            // to send once the client signals EOF, so finish the
                            // channel the way OpenSSH's internal-sftp does:
                            // EOF, exit-status(0), CLOSE. OpenSSH's sftp client
                            // blocks in its shutdown path until it sees the
                            // peer's CLOSE; sending only EOF is not enough.
                            if let Some(remote_id) = channel_manager.reply_recipient(recipient)
                            {
                                let eof_msg = build_channel_eof(remote_id);
                                send_encrypted_packet_server(stream, &eof_msg, transport, false, aead).await?;
                                let mut exit = vec![msg::SSH_MSG_CHANNEL_REQUEST];
                                remote_id.encode(&mut exit)?;
                                SshString::new("exit-status").encode(&mut exit)?;
                                exit.push(0);
                                exit.extend(0u32.to_be_bytes());
                                send_encrypted_packet_server(stream, &exit, transport, false, aead).await?;
                                let close_msg = build_channel_close(remote_id);
                                send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                                // We have already sent CLOSE, so a later CLOSE
                                // from the peer needs no further reply.
                                channel_manager.close_channel(recipient);
                                sftp_channels.remove(&recipient);
                            }
                        }
                        if !is_sftp_channel {
                            if let Some(local_id) = channel_manager.get_channel(recipient).map(|c| c.local_id) {
                                if let Some(sid) = channel_session.get(&local_id).copied() {
                                    if let Some(session) = session_manager.get_session_mut(sid) {
                                        session.stdin.take();
                                    }
                                }
                            }
                        }
                        // For non-session channels (direct-tcpip etc), drop data_tx
                        // so pump_socket's channel_rx returns None and shuts down the TCP socket
                        if let Some(local_id) = channel_manager.get_channel(recipient).map(|c| c.local_id) {
                        if let Some(ch) = channel_manager.get_channel_mut(local_id) {
                            if ch.channel_type != "session" {
                                ch.data_tx.take();
                                }
                            }
                        }
                    }
                    msg::SSH_MSG_CHANNEL_CLOSE => {
                        let mut r = &packet[1..];
                        let recipient = u32::decode(&mut r)?;
                        if let Some(remote_id) = channel_manager.reply_recipient(recipient) {
                            let close_msg = build_channel_close(remote_id);
                            send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                            // Drop the channel (and its data_tx) so the
                            // subsystem/forwarding task sees the stream end.
                            channel_manager.close_channel(recipient);
                            channel_last_activity.remove(&recipient);
                        }
                    }
                    msg::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                        let mut r = &packet[1..];
                        let channel_id = u32::decode(&mut r)?;
                        let _amount = u32::decode(&mut r)?;
                        if let Some(lc) = channel_manager.get_channel(channel_id).map(|c| c.local_id) {
                            channel_last_activity.insert(lc, std::time::Instant::now());
                        }
                    }
                    msg::SSH_MSG_DISCONNECT => {
                        break 'conn;
                    }
                    // RFC 4253 §11.2: IGNORE and DEBUG must be silently ignored.
                    msg::SSH_MSG_IGNORE | msg::SSH_MSG_DEBUG => {
                        continue;
                    }
                    _ => {
                        let seq = transport.incoming_seq.saturating_sub(1) as u32;
                        send_encrypted_packet_server(stream, &build_unimplemented(seq)?, transport, false, aead).await?;
                    }
                }
            }

            () = &mut rekey_sleep => {
                rekey_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(60));
            }

            // While a server-initiated rekey is in flight, strict KEX forbids
            // sending generic packets. Do not poll the data-producing arms
            // until the client's KEXINIT completes the exchange.
            () = &mut exit_poll, if session_started && !server_rekey_kex_sent => {
                // Drain all pending child output first so exit-status and
                // CHANNEL_CLOSE are sent strictly after every CHANNEL_DATA
                // (FIFO ordering, matching OpenSSH). Without this, a child that
                // finishes writing before the client has received all its
                // output causes the server to send exit-status early and
                // truncate the transfer (the unbounded child_rx buffers the
                // child's output while exit_poll races ahead of it).
                // Bound how much output one pass may forward. A child that
                // emits a large burst must not monopolize the connection loop:
                // while we sit in this arm the peer's KEXINIT (rekey), window
                // adjustments and interrupts go unread. Forward a window-sized
                // chunk, then return to `select!` so inbound packets are
                // serviced; the timer is re-armed near-immediately while more
                // output is queued.
                const DRAIN_BUDGET: usize = 128 * 1024;
                let mut drained_bytes: usize = 0;
                let mut more_pending = false;
                loop {
                    match child_rx.try_recv() {
                        Ok(ChildOutputMsg::Stdout(sid, data)) => {
                            if session_exit_sent_map.get(&sid).copied().unwrap_or(false) { continue; }
                            if let Some(lc) = channel_session.iter().find(|(_, s)| **s == sid).map(|(c, _)| *c) {
                                channel_last_activity.insert(lc, std::time::Instant::now());
                            }
                            let remote = session_remote.get(&sid).copied().unwrap_or(0);
                            let data_len = data.len();
                            let mut channel_data = vec![msg::SSH_MSG_CHANNEL_DATA];
                            remote.encode(&mut channel_data)?;
                            SshBytes(data).encode(&mut channel_data)?;
                            send_encrypted_packet_server(stream, &channel_data, transport, false, aead).await?;
                            drained_bytes += data_len;
                            if drained_bytes >= DRAIN_BUDGET { more_pending = true; break; }
                        }
                        Ok(ChildOutputMsg::Stderr(sid, data)) => {
                            if session_exit_sent_map.get(&sid).copied().unwrap_or(false) { continue; }
                            if let Some(lc) = channel_session.iter().find(|(_, s)| **s == sid).map(|(c, _)| *c) {
                                channel_last_activity.insert(lc, std::time::Instant::now());
                            }
                            let remote = session_remote.get(&sid).copied().unwrap_or(0);
                            let data_len = data.len();
                            let mut channel_data = vec![msg::SSH_MSG_CHANNEL_EXTENDED_DATA];
                            remote.encode(&mut channel_data)?;
                            1u32.encode(&mut channel_data)?;
                            SshBytes(data).encode(&mut channel_data)?;
                            send_encrypted_packet_server(stream, &channel_data, transport, false, aead).await?;
                            drained_bytes += data_len;
                            if drained_bytes >= DRAIN_BUDGET { more_pending = true; break; }
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                        | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            // Channel drained (Disconnected never fires here because
                            // the caller keeps child_tx alive for multiplexing).
                            break;
                        }
                    }
                }
                // Send exit-status/CLOSE only once ALL reader tasks for a session
                // have finished (counter == 0, meaning every byte of child output
                // has been forwarded) AND the child has been reaped. This keeps the
                // FIFO ordering: exit always follows the last CHANNEL_DATA.
                // `more_pending` means the forward budget was hit while output is
                // still queued in child_rx, so this pass must not finalize yet.
                if !more_pending {
                    let sids: Vec<u32> = session_manager.session_ids();
                    for sid in sids {
                        if session_exit_sent_map.get(&sid).copied().unwrap_or(false) {
                            continue;
                        }
                        let readers_finished = session_readers_done.get(&sid)
                            .map(|c| c.load(std::sync::atomic::Ordering::SeqCst) == 0)
                            .unwrap_or(false);
                        if !readers_finished {
                            continue;
                        }
                        if let Some(exit) = session_manager.poll_child_exit(sid) {
                            let remote = session_remote.get(&sid).copied().unwrap_or(0);
                            send_child_exit_message(stream, transport, remote, &exit, aead).await?;
                            let close_msg = build_channel_close(remote);
                            send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                            session_exit_sent_map.insert(sid, true);
                            session_readers_done.remove(&sid);
                            // Do NOT close the whole connection here: a ControlMaster
                            // multiplexes several sessions over one connection. The
                            // client (master) keeps the connection alive and sends
                            // SSH_MSG_DISCONNECT when it is done. Regular clients also
                            // send DISCONNECT after their session ends, so the
                            // connection is still torn down promptly.
                        }
                    }
                }
                let next_delay_ms = if more_pending { 1 } else { 50 };
                exit_poll.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(next_delay_ms));
            }

            // ChannelTimeout: close channels that have been idle longer than
            // their configured timeout. Activity is recorded for every
            // inbound channel message and on channel open.
            () = &mut channel_timeout_poll, if !server_rekey_kex_sent && !channel_last_activity.is_empty() => {
                let now = std::time::Instant::now();
                let expired: Vec<(ChannelId, u64)> = channel_last_activity
                    .iter()
                    .filter_map(|(id, last)| {
                        let ch = channel_manager.get_channel(*id)?;
                        let secs = crate::config::channel_timeout_secs(&config, &ch.channel_type);
                        if secs == 0 {
                            return None;
                        }
                        if now.duration_since(*last).as_secs() >= secs {
                            Some((*id, secs))
                        } else {
                            None
                        }
                    })
                    .collect();
                for (local_id, secs) in expired {
                    let remote = channel_manager.get_channel(local_id)
                        .and_then(|c| c.remote_id)
                        .unwrap_or(0);
                    tracing::info!(
                        "channel {} idle for {}s, closing (ChannelTimeout)",
                        local_id, secs,
                    );
                    // Terminate the session's child so a timeout does not
                    // leave an orphan process behind, and suppress late
                    // child output for the closed channel.
                    if let Some(sid) = channel_session.get(&local_id).copied() {
                        if let Some(session) = session_manager.get_session_mut(sid) {
                            if let Some(ref mut child) = session.child {
                                if let Some(pid) = child.id() {
                                    unsafe { libc::kill(-(pid as i32), libc::SIGHUP); }
                                }
                            }
                        }
                        session_exit_sent_map.insert(sid, true);
                        session_readers_done.remove(&sid);
                    }
                    let close_msg = build_channel_close(remote);
                    send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                    channel_manager.close_channel(local_id);
                    sftp_channels.remove(&local_id);
                    channel_last_activity.remove(&local_id);
                }
                channel_timeout_poll.as_mut().reset(
                    tokio::time::Instant::now() + tokio::time::Duration::from_secs(1),
                );
            }

            to_client = to_client_rx.recv(), if !server_rekey_kex_sent => {
                if let Some((remote_id, data)) = to_client {
                    if let Some(local_id) = channel_manager.find_by_remote_id(remote_id).map(|c| c.local_id) {
                        channel_last_activity.insert(local_id, std::time::Instant::now());
                    }
                    let msg = build_channel_data(remote_id, &data);
                    let _ = send_encrypted_packet_server(stream, &msg, transport, false, aead).await;
                }
            }

            eof_ev = eof_rx.recv(), if !server_rekey_kex_sent => {
                if let Some(remote_id) = eof_ev {
                    let eof_msg = build_channel_eof(remote_id);
                    let _ = send_encrypted_packet_server(stream, &eof_msg, transport, false, aead).await;
                    let close_msg = build_channel_close(remote_id);
                    let _ = send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await;
                }
            }

            fwd_ev = fwd_rx.recv(), if !forwarded_ports.is_empty() && !server_rekey_kex_sent => {
                if let Some(ForwardAccept::Incoming(bind_port, sock, peer)) = fwd_ev {
                    let local_id = channel_manager.alloc_channel(
                        msg::SSH_CHANNEL_TYPE_FORWARDED_TCPIP,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                    );
                    let (otx, orx) = oneshot::channel();
                    pending_open.insert(local_id, otx);
                    pending_open_sockets.insert(local_id, (Box::new(sock), orx));
                    let pkt = build_forwarded_tcpip_open(
                        local_id,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                        "0.0.0.0",
                        bind_port as u32,
                        &peer.ip().to_string(),
                        peer.port() as u32,
                    );
                    send_encrypted_packet_server(stream, &pkt, transport, false, aead).await?;
                }
            }

            sl_ev = streamlocal_rx.recv(), if !forwarded_streamlocal_paths.is_empty() && !server_rekey_kex_sent => {
                if let Some(StreamLocalAccept::Incoming(path, sock)) = sl_ev {
                    let local_id = channel_manager.alloc_channel(
                        msg::SSH_CHANNEL_TYPE_FORWARDED_STREAMLOCAL,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                    );
                    let (otx, orx) = oneshot::channel();
                    pending_open.insert(local_id, otx);
                    pending_open_sockets.insert(local_id, (Box::new(sock), orx));
                    let pkt = build_forwarded_streamlocal_open(
                        local_id,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                        &path,
                    );
                    send_encrypted_packet_server(stream, &pkt, transport, false, aead).await?;
                }
            }

            agent_ev = agent_rx.recv(), if agent_sock_path.is_some() && !server_rekey_kex_sent => {
                if let Some(AgentAccept::Incoming(sock)) = agent_ev {
                    let local_id = channel_manager.alloc_channel(
                        msg::SSH_CHANNEL_TYPE_AUTH_AGENT,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                    );
                    let (otx, orx) = oneshot::channel();
                    pending_open.insert(local_id, otx);
                    pending_open_sockets.insert(local_id, (Box::new(sock), orx));
                    let pkt = build_auth_agent_open(
                        local_id,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                    );
                    send_encrypted_packet_server(stream, &pkt, transport, false, aead).await?;
                }
            }

            x11_ev = x11_rx.recv(), if x11_enabled && !server_rekey_kex_sent => {
                if let Some(X11Accept::Incoming(sock, peer)) = x11_ev {
                    let local_id = channel_manager.alloc_channel(
                        msg::SSH_CHANNEL_TYPE_X11,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                    );
                    let (otx, orx) = oneshot::channel();
                    pending_open.insert(local_id, otx);
                    pending_open_sockets.insert(local_id, (Box::new(sock), orx));
                    let pkt = build_x11_open(
                        local_id,
                        msg::CHANNEL_PACKET_WINDOW_SIZE,
                        msg::CHANNEL_MAX_PACKET_SIZE,
                        &peer.ip().to_string(),
                        peer.port() as u32,
                    );
                    send_encrypted_packet_server(stream, &pkt, transport, false, aead).await?;
                }
            }

            child_msg = child_rx.recv(), if !server_rekey_kex_sent => {
                match child_msg {
                    Some(ChildOutputMsg::Stdout(sid, data)) => {
                        if session_exit_sent_map.get(&sid).copied().unwrap_or(false) { continue; }
                        if let Some(lc) = channel_session.iter().find(|(_, s)| **s == sid).map(|(c, _)| *c) {
                            channel_last_activity.insert(lc, std::time::Instant::now());
                        }
                        let remote = session_remote.get(&sid).copied().unwrap_or(0);
                        let mut channel_data = vec![msg::SSH_MSG_CHANNEL_DATA];
                        remote.encode(&mut channel_data)?;
                        SshBytes(data).encode(&mut channel_data)?;
                        send_encrypted_packet_server(stream, &channel_data, transport, false, aead).await?;
                    }
                    Some(ChildOutputMsg::Stderr(sid, data)) => {
                        if session_exit_sent_map.get(&sid).copied().unwrap_or(false) { continue; }
                        if let Some(lc) = channel_session.iter().find(|(_, s)| **s == sid).map(|(c, _)| *c) {
                            channel_last_activity.insert(lc, std::time::Instant::now());
                        }
                        let remote = session_remote.get(&sid).copied().unwrap_or(0);
                        let mut channel_data = vec![msg::SSH_MSG_CHANNEL_EXTENDED_DATA];
                        remote.encode(&mut channel_data)?;
                        1u32.encode(&mut channel_data)?;
                        SshBytes(data).encode(&mut channel_data)?;
                        send_encrypted_packet_server(stream, &channel_data, transport, false, aead).await?;
                    }
                    None => {
                        // Child pipes closed (all senders dropped). Fall back to
                        // per-session polling for any session that hasn't been
                        // finalized, but keep the connection open for multiplexing.
                        // Note: this arm rarely fires because the connection loop
                        // keeps child_tx alive; exit_poll is the primary path.
                        if session_started {
                            let sids: Vec<u32> = session_manager.session_ids();
                            for sid in sids {
                                if session_exit_sent_map.get(&sid).copied().unwrap_or(false) { continue; }
                                let remote = session_remote.get(&sid).copied().unwrap_or(0);
                                if let Some(exit) = session_manager.poll_child_exit(sid) {
                                    send_child_exit_message(stream, transport, remote, &exit, aead).await?;
                                } else {
                                    // Child not reaped yet; exit_poll will handle it
                                    // on the next cycle. Do not close prematurely.
                                    continue;
                                }
                                let close_msg = build_channel_close(remote);
                                send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                                session_exit_sent_map.insert(sid, true);
                            }
                        }
                    }
                }
            }

            _ = &mut alive_sleep, if alive_enabled && !server_rekey_kex_sent => {
                missed_alive = missed_alive.saturating_add(1);
                if missed_alive >= config.client_alive_count_max {
                    tracing::info!("ClientAliveCountMax exceeded, disconnecting");
                    break 'conn;
                }
                let mut req = vec![msg::SSH_MSG_GLOBAL_REQUEST];
                SshString::new("keepalive@openssh.com").encode(&mut req)?;
                true.encode(&mut req)?;
                let _ = send_encrypted_packet_server(stream, &req, transport, false, aead).await;
                alive_sleep = Box::pin(tokio::time::sleep(tokio::time::Duration::from_millis(alive_interval_ms as u64)));
            }

        }

        // Rekey is checked *after* processing each packet (or the idle 60s
        // timer) rather than at the top of the loop. When due, the server
        // sends its KEXINIT and marks the exchange in progress, then returns
        // to the normal loop: any pre-rekey data the peer already sent (e.g. a
        // channel request) is processed normally, and the exchange completes
        // when the peer's KEXINIT arrives in the SSH_MSG_KEXINIT arm below.
        let tb = transport.total_bytes();
        let el = transport.last_rekey_instant.elapsed().as_secs();
        let server_should_rekey = transport.needs_rekey(tb, el);
        if server_should_rekey && !server_rekey_kex_sent
            && matches!(transport.state, ssh_core::transport::KexState::Established)
        {
            use ssh_core::transport::KexState;
            let aead = transport.client_to_server_cipher.as_ref().map(|c| c.is_aead()).unwrap_or(false);
            let sk = transport.prepare_rekey(true);
            match send_encrypted_packet_server(stream, &sk, transport, false, aead).await {
                Ok(()) => {
                    transport.state = KexState::RekeyInProgress;
                    server_rekey_kex_sent = true;
                }
                Err(e) => {
                    tracing::warn!("server-initiated rekey KEXINIT failed: {:?}", e);
                }
            }
        }
    }

    // Connection is closing: stop all forwarded listeners so their bound
    // sockets are released (OpenSSH closes listeners when the client's
    // connection ends).
    for (_, handle) in forwarded_listeners.drain() {
        handle.abort();
    }
    x11_listener_handle.abort();

    Ok(())
}

/// A `JoinHandle` that aborts the task when dropped, guaranteeing cleanup on
/// every function exit path (including early `?` error returns).
struct AbortJoin(Option<tokio::task::JoinHandle<()>>);

impl AbortJoin {
    fn abort(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

impl Drop for AbortJoin {
    fn drop(&mut self) {
        self.abort();
    }
}

fn pump_socket<S>(
    socket: S,
    channel_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    remote_id: ChannelId,
    to_client_tx: tokio::sync::mpsc::UnboundedSender<(ChannelId, Vec<u8>)>,
    eof_tx: tokio::sync::mpsc::UnboundedSender<ChannelId>,
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

    let eof_tx2 = eof_tx.clone();
    let remote_id2 = remote_id;
    tokio::spawn(async move {
        let mut buf = [0u8; 32768];
        loop {
            match sock_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if to_client_tx.send((remote_id, buf[..n].to_vec())).is_err() { break; }
                }
                Err(_) => break,
            }
        }
        let _ = eof_tx2.send(remote_id2);
    });
}

/// Send `exit-status` or `exit-signal` for a terminated session child
/// (OpenSSH sends exit-signal when a process dies from a signal).
async fn send_child_exit_message(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    remote: u32,
    exit: &crate::session::ChildExit,
    aead: bool,
) -> Result<()> {
    let mut msg = vec![msg::SSH_MSG_CHANNEL_REQUEST];
    remote.encode(&mut msg)?;
    match exit {
        crate::session::ChildExit::Status(code) => {
            SshString::new("exit-status").encode(&mut msg)?;
            msg.push(0);
            (*code as u32).encode(&mut msg)?;
        }
        crate::session::ChildExit::Signal(_sig, name) => {
            SshString::new("exit-signal").encode(&mut msg)?;
            msg.push(0);
            SshString::new(name).encode(&mut msg)?;
            msg.push(0); // core dumped
            SshString::new("").encode(&mut msg)?; // error message
            SshString::new("").encode(&mut msg)?; // language tag
        }
    }
    send_encrypted_packet_server(stream, &msg, transport, false, aead).await
}

async fn send_raw_packet(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
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

async fn receive_raw_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;

    // RFC 4253 §6: packet_length excludes its own 4-byte field, so the body
    // (padding_length + payload + padding) is exactly `total_len` bytes.
    let body_len = total_len;

    // `total_len` is peer-controlled: bound it before allocating, otherwise a
    // single 0xFFFFFFFF packet_length makes us reserve ~4 GiB.
    if body_len < 5 || body_len > ssh_core::transport::MAX_PACKET_SIZE {
        return Err(SshError::InvalidPacket(format!("invalid body size: {} (total_len={})", body_len, total_len)));
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;

    unpack_packet_body(&body)
}

/// A no-op waker used only to probe `poll_write` synchronously without ever
/// registering a persistent wake-up (we retry in the loop instead).
fn noop_waker_server() -> std::task::Waker {
    use std::sync::Arc;
    struct Noop;
    impl std::task::Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    std::task::Waker::from(Arc::new(Noop))
}

/// Attempt a single non-blocking write of `buf` on an async writer. Returns the
/// number of bytes written, or `WouldBlock` if the underlying sink is full.
/// Never registers a persistent waker (we poll again on the next loop iteration).
fn nonblocking_write_server<W: AsyncWrite + Unpin + ?Sized>(stream: &mut W, buf: &[u8]) -> std::io::Result<usize> {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    let waker = noop_waker_server();
    let mut cx = Context::from_waker(&waker);
    match Pin::new(stream).poll_write(&mut cx, buf) {
        Poll::Ready(r) => r,
        Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
    }
}

async fn send_encrypted_packet_server(
    stream: &mut TcpStream,
    payload: &[u8],
    transport: &mut SshTransport,
    _is_new_keys: bool,
    aead: bool,
) -> Result<()> {
    // Packet padding is always aligned to the cipher's block size. AES-GCM
    // reports 16 (it is an AEAD, but the *padding* rule is still
    // packet_length % 16 == 0); chacha20-poly1305 reports 8; before any cipher
    // exists (KEX/NEWKEYS) fall back to the RFC 4253 minimum of 8.
    let block_size = transport.server_to_client_cipher.as_ref()
        .map(|c| c.block_size())
        .unwrap_or(8);

    let has_cipher = transport.server_to_client_cipher.is_some();
    let etm = transport.server_to_client_mac.as_ref()
        .map(|m| m.is_etm()).unwrap_or(false);
    let chachapoly = transport.server_to_client_cipher.as_ref()
        .map(|c| c.is_chachapoly()).unwrap_or(false);
    // RFC 4253 §6.4 / RFC 6668: a non-ETM MAC (or the pre-key "none" cipher)
    // encrypts packet_length as part of the first cipher block; ETM and AEAD
    // ciphers leave packet_length in the clear (authenticated as AAD). OpenSSH's
    // chacha20-poly1305@openssh.com encrypts the length with a separate header
    // key but still uses aadlen=4 for the *padding* rule (authlen != 0).
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

    // Non-ETM MAC covers the plaintext packet (RFC 4253 §6.4):
    // H(seq || packet_length || padding_length || payload || padding).
    let mut non_etm_tag = None;
    if !aead && !etm {
        if let Some(ref mac) = transport.server_to_client_mac {
            if mac.tag_len() > 0 {
                non_etm_tag = Some(mac.compute_tag(seq, &packet)?);
            }
        }
    }

    if let Some(ref mut cipher) = transport.server_to_client_cipher {
        if length_encrypted_on_wire {
            // Non-ETM / chacha: encrypt the entire packet (packet_length
            // included). For chacha, encrypt() returns ciphertext || tag.
            let ciphertext = cipher.encrypt(seq, &packet)?;
            packet = ciphertext;
        } else {
            // ETM/AEAD: keep packet_length plaintext, encrypt the body only.
            // AES-GCM authenticates the cleartext length as AAD.
            let plaintext = packet[4..].to_vec();
            let ciphertext = if aead {
                cipher.encrypt_with_aad(seq, &packet[..4], &plaintext)?
            } else {
                cipher.encrypt(seq, &plaintext)?
            };
            packet.truncate(4);
            packet.extend_from_slice(&ciphertext);
        }
    }

    // ETM MAC covers seq || packet_length || ciphertext (RFC 6668 §2).
    if let Some(ref mac) = transport.server_to_client_mac {
        if mac.tag_len() > 0 {
            if etm {
                let tag = mac.compute_tag(seq, &packet)?;
                packet.extend_from_slice(&tag);
            } else if !aead {
                if let Some(t) = non_etm_tag {
                    packet.extend_from_slice(&t);
                }
            }
        }
    }

    stream.write_all(&packet).await?;
    stream.flush().await?;
    transport.bytes_out += packet.len() as u64;
    transport.outgoing_seq += 1;
    Ok(())
}

async fn receive_encrypted_packet_server(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    _is_new_keys: bool,
    aead: bool,
) -> Result<Vec<u8>> {
    let seq = transport.incoming_seq;

    // Before the first key exchange (and for NEWKEYS during a rekey) there is
    // no cipher installed: the packet is plaintext but still advances the
    // sequence number, since RFC 4253 §6 counts every packet.
    if transport.client_to_server_cipher.is_none() {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = u32::from_be_bytes(len_buf) as usize;
        if packet_len < 5 || packet_len > ssh_core::transport::MAX_PACKET_SIZE {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", packet_len)));
        }
        let mut body = vec![0u8; packet_len];
        stream.read_exact(&mut body).await?;
        transport.bytes_in += (4 + packet_len) as u64;
        transport.incoming_seq += 1;
        let payload = unpack_packet_body(&body)?;
        transport.check_strict_kex_packet(&payload)?;
        return Ok(payload);
    }

    let cipher = transport.client_to_server_cipher.as_mut().unwrap();
    let mac = transport.client_to_server_mac.as_ref();
    let chachapoly = cipher.is_chachapoly();
    let etm = mac.map(|m| m.is_etm()).unwrap_or(false);

    let wire_len: usize;

    let body: Vec<u8> = if chachapoly {
        // chacha20-poly1305@openssh.com: the 4-byte packet_length is encrypted
        // with the header key; decrypt_length to learn the body length. The
        // Poly1305 tag is verified by `cipher.decrypt`.
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = cipher.decrypt_length(seq, &len_buf)? as usize;
        if packet_len > ssh_core::transport::MAX_PACKET_SIZE
            || packet_len < 5
            || packet_len % cipher.block_size() != 0
        {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", packet_len)));
        }
        let mut ct = len_buf.to_vec();
        let mut body_ct = vec![0u8; packet_len];
        stream.read_exact(&mut body_ct).await?;
        ct.extend_from_slice(&body_ct);
        let tlen = cipher.tag_len();
        if tlen > 0 {
            let mut tag = vec![0u8; tlen];
            stream.read_exact(&mut tag).await?;
            ct.extend_from_slice(&tag);
        }
        let plain = cipher.decrypt(seq, &ct)?;
        if plain.len() < 4 {
            return Err(SshError::Protocol("chacha packet too short".into()));
        }
        wire_len = ct.len();
        plain[4..].to_vec()
    } else if aead {
        // GCM and other AEAD ciphers leave packet_length in the clear; the
        // auth tag is appended after the ciphertext (not counted in
        // packet_length).
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = u32::from_be_bytes(len_buf) as usize;
        if packet_len > ssh_core::transport::MAX_PACKET_SIZE
            || packet_len < 5
            || packet_len % cipher.block_size() != 0
        {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", packet_len)));
        }
        let mut body = vec![0u8; packet_len];
        stream.read_exact(&mut body).await?;
        let tlen = cipher.tag_len();
        if tlen > 0 {
            let mut tag = vec![0u8; tlen];
            stream.read_exact(&mut tag).await?;
            body.extend_from_slice(&tag);
        }
        // AES-GCM authenticates the cleartext packet_length as AAD.
        wire_len = 4 + body.len();
        cipher.decrypt_with_aad(seq, &len_buf, &body)?
    } else if etm {
        // RFC 6668: packet_length is in the clear and the MAC covers
        // seq || packet_length || ciphertext; verify before decrypting.
        let mac = mac.unwrap();
        let block_size = cipher.block_size().max(8);
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = u32::from_be_bytes(len_buf) as usize;
        if packet_len > ssh_core::transport::MAX_PACKET_SIZE
            || packet_len < 5
            || packet_len % block_size != 0
        {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", packet_len)));
        }
        let mut ct = vec![0u8; packet_len];
        stream.read_exact(&mut ct).await?;
        let mut tag_buf = vec![0u8; mac.tag_len()];
        stream.read_exact(&mut tag_buf).await?;
        let mut etm_input = Vec::with_capacity(4 + ct.len());
        etm_input.extend_from_slice(&len_buf);
        etm_input.extend_from_slice(&ct);
        if !mac.verify_tag(seq, &etm_input, &tag_buf)? {
            return Err(SshError::DecryptionFailed);
        }
        wire_len = 4 + packet_len + mac.tag_len();
        cipher.decrypt(seq, &ct)?
    } else {
        // RFC 4253 §6.4: a non-ETM MAC encrypts packet_length as part of the
        // first cipher block, so that block must be decrypted to learn the
        // body length. Early implementations read the length in the clear,
        // which shifted the whole ciphertext by four bytes and always failed
        // the MAC.
        let block_size = cipher.block_size().max(8);
        let mut first_block = vec![0u8; block_size];
        stream.read_exact(&mut first_block).await?;
        let plain_first = cipher.decrypt(seq, &first_block)?;
        if plain_first.len() < 4 {
            return Err(SshError::Protocol("non-ETM packet too short".into()));
        }
        let packet_len = u32::from_be_bytes([
            plain_first[0], plain_first[1], plain_first[2], plain_first[3],
        ]) as usize;
        if packet_len > ssh_core::transport::MAX_PACKET_SIZE || packet_len < 5 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", packet_len)));
        }
        // `packet_length` plus its own 4-byte field is the encrypted stream's
        // length, so it must be block-aligned and at least one block.
        if 4 + packet_len < block_size || (4 + packet_len) % block_size != 0 {
            return Err(SshError::InvalidPacket(format!(
                "invalid non-ETM packet size: {} (block size {})",
                packet_len, block_size
            )));
        }
        let rest_len = 4 + packet_len - block_size;
        let mut rest = vec![0u8; rest_len];
        stream.read_exact(&mut rest).await?;
        let rest_plain = cipher.decrypt(seq, &rest)?;

        let mut full = plain_first;
        full.extend_from_slice(&rest_plain);

        if let Some(mac) = mac {
            if mac.tag_len() > 0 {
                let mut tag_buf = vec![0u8; mac.tag_len()];
                stream.read_exact(&mut tag_buf).await?;
                if !mac.verify_tag(seq, &full, &tag_buf)? {
                    return Err(SshError::DecryptionFailed);
                }
            }
        }
        wire_len = 4 + packet_len + mac.map(|m| m.tag_len()).unwrap_or(0);
        full[4..].to_vec()
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

async fn run_internal_sftp(
    mut channel_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    remote_id: ssh_core::channel::ChannelId,
    to_client_tx: tokio::sync::mpsc::UnboundedSender<(ssh_core::channel::ChannelId, Vec<u8>)>,
    base_dir: std::path::PathBuf,
) {
    use ssh_core::encoding::*;
    use ssh_core::sftp::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    enum Handle {
        File { file: tokio::fs::File, path: PathBuf },
        Dir { entries: Vec<SftpNameEntry>, cursor: usize },
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut handles: HashMap<Vec<u8>, Handle> = HashMap::new();
    let mut next_handle_id: u64 = 1;

    fn send_raw(
        tx: &tokio::sync::mpsc::UnboundedSender<(ssh_core::channel::ChannelId, Vec<u8>)>,
        rid: ssh_core::channel::ChannelId,
        payload: &[u8],
    ) {
        let mut pkt = Vec::with_capacity(4 + payload.len());
        pkt.extend((payload.len() as u32).to_be_bytes());
        pkt.extend_from_slice(payload);
        let _ = tx.send((rid, pkt));
    }

    fn status_pkt(id: u32, code: u32, msg: &str) -> Vec<u8> {
        use ssh_core::SshEncode;
        let mut p = Vec::new();
        p.push(SSH_FXP_STATUS);
        p.extend(id.to_be_bytes());
        p.extend(code.to_be_bytes());
        SshString::new(msg).encode(&mut p).unwrap();
        SshString::new("").encode(&mut p).unwrap();
        p
    }

    fn handle_pkt(id: u32, handle: &[u8]) -> Vec<u8> {
        use ssh_core::SshEncode;
        let mut p = Vec::new();
        p.push(SSH_FXP_HANDLE);
        p.extend(id.to_be_bytes());
        SshBytes(handle.to_vec()).encode(&mut p).unwrap();
        p
    }

    fn attrs_pkt(id: u32, attrs: &SftpFileAttr) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(SSH_FXP_ATTRS);
        p.extend(id.to_be_bytes());
        p.extend(attrs.encode());
        p
    }

    fn data_pkt(id: u32, data: &[u8]) -> Vec<u8> {
        use ssh_core::SshEncode;
        let mut p = Vec::new();
        p.push(SSH_FXP_DATA);
        p.extend(id.to_be_bytes());
        SshBytes(data.to_vec()).encode(&mut p).unwrap();
        p
    }

    fn name_pkt(id: u32, entries: &[SftpNameEntry]) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(SSH_FXP_NAME);
        p.extend(id.to_be_bytes());
        p.extend((entries.len() as u32).to_be_bytes());
        for e in entries {
            p.extend(e.encode());
        }
        p
    }

    fn meta_to_attrs(meta: &std::fs::Metadata) -> SftpFileAttr {
        let mut attrs = SftpFileAttr::new();
        attrs.size = Some(meta.len());
        attrs.flags |= SSH_FILEXFER_ATTR_SIZE;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            attrs.uid = Some(meta.uid());
            attrs.gid = Some(meta.gid());
            attrs.permissions = Some(meta.mode());
            attrs.atime = Some(meta.atime() as u32);
            attrs.mtime = Some(meta.mtime() as u32);
            attrs.flags |= SSH_FILEXFER_ATTR_UIDGID
                | SSH_FILEXFER_ATTR_PERMISSIONS
                | SSH_FILEXFER_ATTR_ACMODTIME;
        }
        attrs
    }

    /// Render the `longname` field of an SSH_FXP_NAME entry the same way
    /// OpenSSH's sftp-server does: symbolic mode, link count, numeric uid/gid
    /// (used when the name cannot be resolved), real size and mtime.
    #[cfg(unix)]
    fn sftp_longname(meta: &std::fs::Metadata, name: &str) -> String {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        let type_char = match mode & libc::S_IFMT as u32 {
            x if x == libc::S_IFDIR as u32 => 'd',
            x if x == libc::S_IFLNK as u32 => 'l',
            x if x == libc::S_IFBLK as u32 => 'b',
            x if x == libc::S_IFCHR as u32 => 'c',
            x if x == libc::S_IFIFO as u32 => 'p',
            x if x == libc::S_IFSOCK as u32 => 's',
            _ => '-',
        };
        let mut perms = String::with_capacity(10);
        perms.push(type_char);
        for shift in [6u32, 3, 0] {
            let bits = (mode >> shift) & 0o7;
            perms.push(if bits & 4 != 0 { 'r' } else { '-' });
            perms.push(if bits & 2 != 0 { 'w' } else { '-' });
            perms.push(if bits & 1 != 0 { 'x' } else { '-' });
        }

        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let mtime = meta.mtime() as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let date = unsafe {
            if libc::localtime_r(&mtime, &mut tm).is_null() {
                format!("{}", mtime)
            } else {
                format!(
                    "{} {:>2} {:02}:{:02}",
                    MONTHS[tm.tm_mon.clamp(0, 11) as usize],
                    tm.tm_mday,
                    tm.tm_hour,
                    tm.tm_min,
                )
            }
        };
        format!(
            "{} {:>3} {:>8} {:>8} {:>8} {} {}",
            perms,
            meta.nlink(),
            meta.uid(),
            meta.gid(),
            meta.len(),
            date,
            name
        )
    }

    #[cfg(unix)]
    fn statvfs_fields(path: &std::path::Path) -> Option<[u64; 11]> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
            return None;
        }
        Some([
            st.f_bsize as u64,
            st.f_frsize as u64,
            st.f_blocks as u64,
            st.f_bfree as u64,
            st.f_bavail as u64,
            st.f_files as u64,
            st.f_ffree as u64,
            st.f_favail as u64,
            st.f_fsid as u64,
            st.f_flag as u64,
            st.f_namemax as u64,
        ])
    }

    fn ioerr_to_code(err: &std::io::Error) -> u32 {
        match err.kind() {
            std::io::ErrorKind::NotFound => SSH_FX_NO_SUCH_FILE,
            std::io::ErrorKind::PermissionDenied => SSH_FX_PERMISSION_DENIED,
            std::io::ErrorKind::AlreadyExists => SSH_FX_FAILURE,
            _ => SSH_FX_FAILURE,
        }
    }

    fn resolve_path(base: &Path, p: &str) -> PathBuf {
        let path = Path::new(p);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        }
    }

    fn sftp_string(data: SshString) -> Option<String> {
        data.as_str().ok().map(|s| s.to_string())
    }

    loop {
        // NOTE: do NOT clear `buf` here. The inner loop only consumes complete
        // frames; any partial frame stays in `buf` and must be preserved so a
        // large SFTP request that arrives split across several channel chunks
        // (e.g. a big write split into max-packet-size pieces) is reassembled.
        match channel_rx.recv().await {
            Some(d) => { buf.extend(d); }
            None => break,
        }
        while let Ok(d) = channel_rx.try_recv() {
            buf.extend(d);
        }
        loop {
            if buf.len() < 4 {
                break;
            }
            let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < 4 + frame_len {
                break;
            }
            let frame = buf[4..4 + frame_len].to_vec();
            buf.drain(0..4 + frame_len);
            if frame.is_empty() {
                continue;
            }
            let msg_type = frame[0];
            if msg_type == SSH_FXP_INIT {
                let mut resp = vec![SSH_FXP_VERSION];
                resp.extend(SFTP_PROTOCOL_VERSION.to_be_bytes());
                // Advertise supported OpenSSH extensions so clients enable them.
                for ext in [
                    ("posix-rename@openssh.com", "1"),
                    ("statvfs@openssh.com", "2"),
                    ("fstatvfs@openssh.com", "2"),
                    ("hardlink@openssh.com", "1"),
                    ("fsync@openssh.com", "1"),
                    ("limits@openssh.com", "1"),
                ] {
                    SshString::new(ext.0).encode(&mut resp).unwrap();
                    SshString::new(ext.1).encode(&mut resp).unwrap();
                }
                send_raw(&to_client_tx, remote_id, &resp);
                continue;
            }
            if frame.len() < 5 {
                continue;
            }
            let id = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
            let mut r: &[u8] = &frame[5..];
            match msg_type {
                SSH_FXP_OPEN => {
                    let path_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let pflags = u32::decode(&mut r).unwrap_or(0);
                    let _attrs = SftpFileAttr::decode(&mut r).unwrap_or_else(|_| SftpFileAttr::new());
                    let path_s = match path_s {
                        Some(v) => v,
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, "bad path"));
                            continue;
                        }
                    };
                    let full = resolve_path(&base_dir, &path_s);
                    let mut opts = tokio::fs::OpenOptions::new();
                    if pflags & SSH_FXF_READ != 0 { opts.read(true); }
                    if pflags & SSH_FXF_WRITE != 0 { opts.write(true); }
                    if pflags & SSH_FXF_APPEND != 0 { opts.append(true); }
                    if pflags & SSH_FXF_CREAT != 0 { opts.create(true); }
                    if pflags & SSH_FXF_TRUNC != 0 { opts.truncate(true); }
                    if pflags & SSH_FXF_EXCL != 0 { opts.create_new(true); }
                    match opts.open(&full).await {
                        Ok(f) => {
                            let hid = next_handle_id;
                            next_handle_id += 1;
                            let mut h = vec![b'F'];
                            h.extend_from_slice(&hid.to_be_bytes());
                            handles.insert(h.clone(), Handle::File { file: f, path: full.clone() });
                            send_raw(&to_client_tx, remote_id, &handle_pkt(id, &h));
                        }
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_CLOSE => {
                    let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                    if let Some(h) = h {
                        handles.remove(&h);
                    }
                    send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, ""));
                }
                SSH_FXP_READ => {
                    let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                    let offset = u64::decode(&mut r).unwrap_or(0);
                    let len = u32::decode(&mut r).unwrap_or(0) as usize;
                    // Cap the read so the SFTP DATA response, once wrapped as a
                    // CHANNEL_DATA SSH packet, stays under the 256 KiB transport
                    // limit (a full 256 KiB read would overflow by ~20 bytes).
                    let cap = len.min(64 * 1024);
                    let f = match h {
                        Some(h) => match handles.get_mut(&h) {
                            Some(Handle::File { file: f, .. }) => f,
                            _ => {
                                send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "bad handle"));
                                continue;
                            }
                        },
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "bad handle"));
                            continue;
                        }
                    };
                    if let Err(e) = f.seek(std::io::SeekFrom::Start(offset)).await {
                        send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, &e.to_string()));
                        continue;
                    }
                    let mut data = vec![0u8; cap];
                    match f.read(&mut data).await {
                        Ok(0) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_EOF, "eof"));
                        }
                        Ok(n) => {
                            send_raw(&to_client_tx, remote_id, &data_pkt(id, &data[..n]));
                        }
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, &e.to_string()));
                        }
                    }
                }
                SSH_FXP_WRITE => {
                    let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                    let offset = u64::decode(&mut r).unwrap_or(0);
                    let wdata = SshBytes::decode(&mut r).ok().map(|x| x.0).unwrap_or_default();
                    let f = match h {
                        Some(h) => match handles.get_mut(&h) {
                            Some(Handle::File { file: f, .. }) => f,
                            _ => {
                                send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "bad handle"));
                                continue;
                            }
                        },
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "bad handle"));
                            continue;
                        }
                    };
                    if let Err(e) = f.seek(std::io::SeekFrom::Start(offset)).await {
                        send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, &e.to_string()));
                        continue;
                    }
                    match f.write_all(&wdata).await {
                        Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                        Err(e) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, &e.to_string())),
                    }
                }
                SSH_FXP_LSTAT | SSH_FXP_STAT => {
                    let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let full = match p_s {
                        Some(p) => resolve_path(&base_dir, &p),
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, ""));
                            continue;
                        }
                    };
                    let res = if msg_type == SSH_FXP_STAT {
                        std::fs::metadata(&full)
                    } else {
                        std::fs::symlink_metadata(&full)
                    };
                    match res {
                        Ok(m) => send_raw(&to_client_tx, remote_id, &attrs_pkt(id, &meta_to_attrs(&m))),
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_FSTAT => {
                    let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                    let m = match h {
                        Some(h) => match handles.get_mut(&h) {
                            Some(Handle::File { file, .. }) => file.metadata().await.ok(),
                            _ => None,
                        },
                        None => None,
                    };
                    match m {
                        Some(m) => send_raw(&to_client_tx, remote_id, &attrs_pkt(id, &meta_to_attrs(&m))),
                        None => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "bad handle")),
                    }
                }
                SSH_FXP_SETSTAT | SSH_FXP_FSETSTAT => {
                    let target: Option<PathBuf> = if msg_type == SSH_FXP_SETSTAT {
                        let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                        match p_s {
                            Some(p) => Some(resolve_path(&base_dir, &p)),
                            None => {
                                send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, ""));
                                continue;
                            }
                        }
                    } else {
                        let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                        match h {
                            Some(h) => match handles.get_mut(&h) {
                                Some(Handle::File { path, .. }) => Some(path.clone()),
                                _ => None,
                            },
                            None => None,
                        }
                    };
                    let attrs = SftpFileAttr::decode(&mut r).unwrap_or_else(|_| SftpFileAttr::new());
                    let res: std::result::Result<(), std::io::Error> = (|| {
                        let full = match &target {
                            Some(f) => f,
                            None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad handle")),
                        };
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Some(perm) = attrs.permissions {
                                std::fs::set_permissions(full, std::fs::Permissions::from_mode(perm))?;
                            }
                            if attrs.atime.is_some() || attrs.mtime.is_some() {
                                use std::os::unix::fs::MetadataExt;
                                let meta = std::fs::metadata(full)?;
                                let atime = attrs.atime.unwrap_or(meta.atime() as u32) as i64;
                                let mtime = attrs.mtime.unwrap_or(meta.mtime() as u32) as i64;
                                let times = [libc::timespec { tv_sec: atime, tv_nsec: 0 }, libc::timespec { tv_sec: mtime, tv_nsec: 0 }];
                                let cpath = std::ffi::CString::new(full.as_os_str().as_encoded_bytes()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path"))?;
                                if unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) } != 0 {
                                    return Err(std::io::Error::last_os_error());
                                }
                            }
                        }
                        Ok(())
                    })();
                    match res {
                        Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_OPENDIR => {
                    let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let full = match p_s {
                        Some(p) => resolve_path(&base_dir, &p),
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, ""));
                            continue;
                        }
                    };
                    match std::fs::read_dir(&full) {
                        Ok(rd) => {
                            let mut entries: Vec<SftpNameEntry> = Vec::new();
                            for e in rd.flatten() {
                                let name = e.file_name().to_string_lossy().to_string();
                                let meta = e.metadata().ok();
                                let longname = meta.as_ref().map(|m| {
                                    #[cfg(unix)]
                                    { sftp_longname(m, &name) }
                                    #[cfg(not(unix))]
                                    { name.clone() }
                                }).unwrap_or_else(|| name.clone());
                                let attrs = meta.as_ref().map(meta_to_attrs).unwrap_or_else(SftpFileAttr::new);
                                entries.push(SftpNameEntry { filename: name, longname, attrs });
                            }
                            let hid = next_handle_id;
                            next_handle_id += 1;
                            let mut h = vec![b'D'];
                            h.extend_from_slice(&hid.to_be_bytes());
                            handles.insert(h.clone(), Handle::Dir { entries, cursor: 0 });
                            send_raw(&to_client_tx, remote_id, &handle_pkt(id, &h));
                        }
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_READDIR => {
                    let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                    let got = match h {
                        Some(h) => match handles.get_mut(&h) {
                            Some(Handle::Dir { ref entries, ref mut cursor }) => {
                                if *cursor >= entries.len() {
                                    None
                                } else {
                                    let start = *cursor;
                                    let end = (start + 100).min(entries.len());
                                    *cursor = end;
                                    Some(entries[start..end].to_vec())
                                }
                            }
                            _ => None,
                        },
                        None => None,
                    };
                    match got {
                        Some(v) if !v.is_empty() => send_raw(&to_client_tx, remote_id, &name_pkt(id, &v)),
                        _ => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_EOF, "eof")),
                    }
                }
                SSH_FXP_REMOVE => {
                    let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let full = match p_s {
                        Some(p) => resolve_path(&base_dir, &p),
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, ""));
                            continue;
                        }
                    };
                    match std::fs::remove_file(&full) {
                        Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_MKDIR => {
                    let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let _attrs = SftpFileAttr::decode(&mut r).unwrap_or_else(|_| SftpFileAttr::new());
                    let full = match p_s {
                        Some(p) => resolve_path(&base_dir, &p),
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, ""));
                            continue;
                        }
                    };
                    match std::fs::create_dir(&full) {
                        Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_RMDIR => {
                    let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let full = match p_s {
                        Some(p) => resolve_path(&base_dir, &p),
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, ""));
                            continue;
                        }
                    };
                    match std::fs::remove_dir(&full) {
                        Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_REALPATH => {
                    let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let raw = p_s.unwrap_or_else(|| ".".to_string());
                    let full = resolve_path(&base_dir, &raw);
                    let canon = std::fs::canonicalize(&full).unwrap_or_else(|_| full.clone());
                    let path_s = canon.to_string_lossy().to_string();
                    let entry = SftpNameEntry {
                        filename: path_s.clone(),
                        longname: path_s,
                        attrs: SftpFileAttr::new(),
                    };
                    send_raw(&to_client_tx, remote_id, &name_pkt(id, &[entry]));
                }
                SSH_FXP_RENAME => {
                    let old = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let new = SshString::decode(&mut r).ok().and_then(sftp_string);
                    match (old, new) {
                        (Some(o), Some(n)) => {
                            let fo = resolve_path(&base_dir, &o);
                            let fn_ = resolve_path(&base_dir, &n);
                            match std::fs::rename(&fo, &fn_) {
                                Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                                Err(e) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, &e.to_string())),
                            }
                        }
                        _ => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, "")),
                    }
                }
                SSH_FXP_READLINK => {
                    let p_s = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let full = match p_s {
                        Some(p) => resolve_path(&base_dir, &p),
                        None => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, ""));
                            continue;
                        }
                    };
                    match std::fs::read_link(&full) {
                        Ok(target) => {
                            let t = target.to_string_lossy().to_string();
                            let entry = SftpNameEntry {
                                filename: t.clone(),
                                longname: t,
                                attrs: SftpFileAttr::new(),
                            };
                            send_raw(&to_client_tx, remote_id, &name_pkt(id, &[entry]));
                        }
                        Err(e) => {
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string()));
                        }
                    }
                }
                SSH_FXP_SYMLINK => {
                    // v3 order: target (oldpath) first, then the link path.
                    let target = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let link = SshString::decode(&mut r).ok().and_then(sftp_string);
                    match (target, link) {
                        (Some(tp), Some(lp)) => {
                            let fl = resolve_path(&base_dir, &lp);
                            #[cfg(unix)]
                            match std::os::unix::fs::symlink(&tp, &fl) {
                                Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                                Err(e) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, &e.to_string())),
                            }
                            #[cfg(not(unix))]
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OP_UNSUPPORTED, "symlink unsupported"));
                        }
                        _ => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, "")),
                    }
                }
                SSH_FXP_EXTENDED => {
                    let ext_name = SshString::decode(&mut r).ok().and_then(sftp_string);
                    match ext_name.as_deref() {
                        Some("posix-rename@openssh.com") => {
                            let oldp = SshString::decode(&mut r).ok().and_then(sftp_string);
                            let newp = SshString::decode(&mut r).ok().and_then(sftp_string);
                            match (oldp, newp) {
                                (Some(o), Some(n)) => {
                                    let fo = resolve_path(&base_dir, &o);
                                    let fn_ = resolve_path(&base_dir, &n);
                                    match std::fs::rename(&fo, &fn_) {
                                        Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                                        Err(e) => send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string())),
                                    }
                                }
                                _ => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, "")),
                            }
                        }
                        Some("fsync@openssh.com") => {
                            let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                            let ok = match h {
                                Some(h) => match handles.get_mut(&h) {
                                    Some(Handle::File { file, .. }) => file.sync_all().await.is_ok(),
                                    _ => false,
                                },
                                None => false,
                            };
                            if ok {
                                send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, ""));
                            } else {
                                send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "bad handle or sync failed"));
                            }
                        }
                        Some("hardlink@openssh.com") => {
                            let oldp = SshString::decode(&mut r).ok().and_then(sftp_string);
                            let newp = SshString::decode(&mut r).ok().and_then(sftp_string);
                            match (oldp, newp) {
                                (Some(o), Some(n)) => {
                                    let fo = resolve_path(&base_dir, &o);
                                    let fn_ = resolve_path(&base_dir, &n);
                                    match std::fs::hard_link(&fo, &fn_) {
                                        Ok(_) => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OK, "")),
                                        Err(e) => send_raw(&to_client_tx, remote_id, &status_pkt(id, ioerr_to_code(&e), &e.to_string())),
                                    }
                                }
                                _ => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, "")),
                            }
                        }
                        Some("statvfs@openssh.com") | Some("fstatvfs@openssh.com") => {
                            let path: Option<PathBuf> = if ext_name.as_deref() == Some("statvfs@openssh.com") {
                                SshString::decode(&mut r).ok().and_then(sftp_string).map(|p| resolve_path(&base_dir, &p))
                            } else {
                                let h = SshBytes::decode(&mut r).ok().map(|x| x.0);
                                match h {
                                    Some(h) => match handles.get_mut(&h) {
                                        Some(Handle::File { path, .. }) => Some(path.clone()),
                                        _ => None,
                                    },
                                    None => None,
                                }
                            };
                            #[cfg(unix)]
                            {
                                match path {
                                    Some(p) => {
                                        let reply = statvfs_fields(&p);
                                        if let Some(fields) = reply {
                                            let mut out = vec![SSH_FXP_EXTENDED_REPLY];
                                            out.extend(id.to_be_bytes());
                                            for f in fields {
                                                out.extend(f.to_be_bytes());
                                            }
                                            send_raw(&to_client_tx, remote_id, &out);
                                        } else {
                                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "statvfs failed"));
                                        }
                                    }
                                    None => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_BAD_MESSAGE, "")),
                                }
                            }
                            #[cfg(not(unix))]
                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OP_UNSUPPORTED, "statvfs unsupported"));
                        }
                        Some("limits@openssh.com") => {
                            let mut rp = Vec::new();
                            // All four fields are uint64 per the limits@openssh.com
                            // payload. The last one used to be written as a uint32,
                            // which made OpenSSH's client report "incomplete message".
                            rp.extend((256u64 * 1024).to_be_bytes()); // max packet length
                            rp.extend((64u64 * 1024).to_be_bytes());  // max read length
                            rp.extend((64u64 * 1024).to_be_bytes());  // max write length
                            rp.extend(1000u64.to_be_bytes());         // max open handles
                            let mut out = vec![SSH_FXP_EXTENDED_REPLY];
                            out.extend(id.to_be_bytes());
                            out.extend(rp);
                            send_raw(&to_client_tx, remote_id, &out);
                        }
                        _ => send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OP_UNSUPPORTED, "unsupported extension")),
                    }
                }
                _ => {
                    send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_OP_UNSUPPORTED, "unknown"));
                }
            }
        }
    }
}

fn env_allowed(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|pat| glob_match(pat, name))
}

fn glob_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let sc: Vec<char> = s.chars().collect();
    let (m, n) = (p.len(), sc.len());
    let mut dp = vec![vec![false; n + 1]; m + 1];
    dp[0][0] = true;
    for i in 1..=m {
        if p[i-1] == '*' {
            dp[i][0] = dp[i-1][0];
        }
    }
    for i in 1..=m {
        for j in 1..=n {
            if p[i-1] == '*' {
                dp[i][j] = dp[i-1][j] || dp[i][j-1];
            } else if p[i-1] == '?' || p[i-1] == sc[j-1] {
                dp[i][j] = dp[i-1][j-1];
            }
        }
    }
    dp[m][n]
}

/// RFC 4253 §11.1: SSH_MSG_DISCONNECT may arrive at any point, including while
/// a key exchange is in flight (OpenSSH clients send it when a session finishes
/// mid-rekey). Surface it as a normal close so the connection loop stops in an
/// orderly way instead of reporting "expected <kex message>".
fn rekey_disconnect_guard(packet: &[u8]) -> Result<()> {
    if packet.first() == Some(&msg::SSH_MSG_DISCONNECT) {
        return Err(SshError::ConnectionClosed);
    }
    Ok(())
}

async fn perform_rekey_server(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    _config: &ServerConfig,
    host_keys: &Arc<Mutex<HostKeyManager>>,
    pre_received_client_kex: Option<Vec<u8>>,
    kex_sent: bool,
) -> Result<()> {
    use ssh_core::transport::KexState;
    if transport.state != KexState::Established && transport.state != KexState::RekeyInProgress {
        return Ok(());
    }
    transport.state = KexState::RekeyInProgress;

    let aead = transport.client_to_server_cipher.as_ref().map(|c| c.is_aead()).unwrap_or(false);

    let hk = host_keys.lock().await;
    let negotiation_pre = {
        let c_kex_init = {
            let p = pre_received_client_kex
                .ok_or_else(|| SshError::KexFailed("no client KEXINIT during rekey".into()))?;
            if p.first() != Some(&msg::SSH_MSG_KEXINIT) {
                return Err(SshError::KexFailed("expected KEXINIT during rekey".into()));
            }
            p
        };
        if !kex_sent {
            let sk = transport.prepare_rekey(true);
            send_encrypted_packet_server(stream, &sk, transport, false, aead).await?;
        }
        transport.client_kex_init = c_kex_init.clone();
        let neg = SshTransport::negotiate_algorithms(&transport.client_kex_init, &transport.server_kex_init)?;
        transport.strict_kex = neg.strict_kex;
        transport.strict_kex_peer_kexinit = neg.strict_kex;
        let (hk_name, pk_bytes) = {
            let algo = neg.host_key_algorithm.clone();
            let signer = hk.get_key_for_algorithm(&algo)
                .ok_or_else(|| SshError::Protocol("no matching host key for rekey".into()))?;
            (algo, signer.public_key_bytes())
        };
        (neg, hk_name.to_string(), pk_bytes)
    };
    let (negotiation, selected_hostkey_algorithm, hostkey_public_blob) = negotiation_pre;
    let selected_signer = hk.get_key_for_algorithm(&selected_hostkey_algorithm)
        .ok_or_else(|| SshError::Protocol("no matching host key for rekey".into()))?;

    let mut kex = SshTransport::create_kex_algorithm(&negotiation.kex_algorithm)?;

    let (shared_secret, exchange_hash, kex_hash_name) =
        if negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange") {
            let req = receive_encrypted_packet_server(stream, transport, false, aead).await?;
            rekey_disconnect_guard(&req)?;
            let (min, nbits, max) = match req.first() {
                Some(&msg::SSH_MSG_KEX_DH_GEX_REQUEST_OLD) => {
                    // RFC 4419 §3: legacy form carries min and n only.
                    let mut r = &req[1..];
                    (u32::decode(&mut r)?, u32::decode(&mut r)?, u32::MAX)
                }
                Some(&msg::SSH_MSG_KEX_DH_GEX_REQUEST) => {
                    let mut r = &req[1..];
                    (u32::decode(&mut r)?, u32::decode(&mut r)?, u32::decode(&mut r)?)
                }
                _ => return Err(SshError::Protocol("expected DH GEX request".into())),
            };
            let gex_hash: &'static str = if negotiation.kex_algorithm.contains("sha256") { "sha256" } else { "sha1" };
            let gex_name: &'static str = if negotiation.kex_algorithm.contains("sha256") {
                "diffie-hellman-group-exchange-sha256"
            } else {
                "diffie-hellman-group-exchange-sha1"
            };
            let group = ssh_core::kex::select_gex_group(min, nbits, max)
                .ok_or_else(|| SshError::KexFailed(format!(
                    "no supported group-exchange modulus in requested range [{}, {}]",
                    min, max
                )))?;
            let group_p = group.p.to_bytes_be();
            let group_g = group.g.to_bytes_be();
            let mut group_msg = Vec::new();
            group_msg.push(msg::SSH_MSG_KEX_DH_GEX_GROUP);
            SshMpInt(group_p.clone()).encode(&mut group_msg)?;
            SshMpInt(group_g.clone()).encode(&mut group_msg)?;
            send_encrypted_packet_server(stream, &group_msg, transport, false, aead).await?;

            let init = receive_encrypted_packet_server(stream, transport, false, aead).await?;
            rekey_disconnect_guard(&init)?;
            if init.first() != Some(&msg::SSH_MSG_KEX_DH_GEX_INIT) {
                return Err(SshError::Protocol("expected DH GEX INIT".into()));
            }
            let mut r = &init[1..];
            let client_pub = SshMpInt::decode(&mut r)?.0;

            let p_bu = num_bigint::BigUint::from_bytes_be(&group_p);
            let g_bu = num_bigint::BigUint::from_bytes_be(&group_g);
            let mut am = ssh_core::kex::ModpKex::with_params(gex_name, gex_hash, p_bu, g_bu, group.exp_bytes);
            am.generate_keypair()?;
            let srv_pub = am.public_key_bytes();
            let shared = am.compute_shared_secret(&client_pub)?;

            let exchange = KexExchange {
                client_version: transport.client_version.clone(),
                server_version: transport.server_version.clone(),
                client_kex_init: transport.client_kex_init.clone(),
                server_kex_init: transport.server_kex_init.clone(),
            };
            let hostkey_blob = hostkey_public_blob.clone();
            let exch_hash = ssh_core::kex::compute_gex_exchange_hash(
                am.hash_name(), &exchange, min, nbits, max,
                &group_p, &group_g,
                &hostkey_blob,
                &client_pub,
                &srv_pub,
                &shared,
            );

            let sig = selected_signer.sign(&exch_hash)?;
            let sig_blob = SshBytes(sig).0;
            let mut dh_reply = Vec::new();
            dh_reply.push(msg::SSH_MSG_KEX_DH_GEX_REPLY);
            SshBytes(hostkey_blob).encode(&mut dh_reply)?;
            SshMpInt(srv_pub).encode(&mut dh_reply)?;
            SshBytes(sig_blob).encode(&mut dh_reply)?;
            send_encrypted_packet_server(stream, &dh_reply, transport, false, aead).await?;

            kex = Box::new(am);
            (shared, exch_hash, gex_hash.to_string())
        } else {
            kex.generate_keypair()?;
            let server_pub = kex.public_key_bytes();
            let client_init = receive_encrypted_packet_server(stream, transport, false, aead).await?;
            rekey_disconnect_guard(&client_init)?;
            if client_init.first() != Some(&msg::SSH_MSG_KEXDH_INIT) {
                return Err(SshError::Protocol("expected SSH_MSG_KEXDH_INIT".into()));
            }
            let mut r = &client_init[1..];
            let client_pub = SshMpInt::decode(&mut r)?.0;

            let shared = kex.compute_shared_secret(&client_pub)?;
            let exchange = KexExchange {
                client_version: transport.client_version.clone(),
                server_version: transport.server_version.clone(),
                client_kex_init: transport.client_kex_init.clone(),
                server_kex_init: transport.server_kex_init.clone(),
            };
            let hostkey_blob = hostkey_public_blob.clone();
            let hash_name = kex.hash_name().to_string();
            let exch_hash = ssh_core::kex::compute_exchange_hash(
                &hash_name, &exchange, &hostkey_blob,
                &client_pub, &server_pub, &shared,
                negotiation.kex_algorithm.starts_with("diffie-hellman-group"),
            );
            let sig = selected_signer.sign(&exch_hash)?;
            let sig_blob = SshBytes(sig).0;
            let mut dh_reply = Vec::new();
            dh_reply.push(msg::SSH_MSG_KEXDH_REPLY);
            SshBytes(hostkey_blob).encode(&mut dh_reply)?;
            if negotiation.kex_algorithm.starts_with("diffie-hellman-group") {
                SshMpInt(server_pub).encode(&mut dh_reply)?;
            } else {
                SshBytes(server_pub).encode(&mut dh_reply)?;
            }
            SshBytes(sig_blob).encode(&mut dh_reply)?;
            send_encrypted_packet_server(stream, &dh_reply, transport, false, aead).await?;

            (shared, exch_hash, hash_name)
        };

    let session_id = transport.session_id.clone().unwrap_or_default();

    // RFC 4253 §7.3: NEWKEYS itself is exchanged under the OLD keys. Installing
    // the new keys before these two packets makes the peer fail to parse our
    // NEWKEYS (it still decrypts with the old keys). Install only after both
    // NEWKEYS messages have crossed the wire.
    let newkeys_send = vec![msg::SSH_MSG_NEWKEYS];
    send_encrypted_packet_server(stream, &newkeys_send, transport, true, aead).await?;
    transport.state = KexState::NewKeysSent;

    let nk = receive_encrypted_packet_server(stream, transport, true, aead).await?;
    rekey_disconnect_guard(&nk)?;
    if nk.first() != Some(&msg::SSH_MSG_NEWKEYS) {
        return Err(SshError::Protocol("expected NEWKEYS during rekey".into()));
    }
    transport.state = KexState::NewKeysReceived;
    transport.reset_sequences_after_newkeys();

    transport.install_new_keys(&negotiation, &kex_hash_name, &shared_secret, &exchange_hash, &session_id)?;

    transport.kex_algorithm = Some(kex);
    transport.state = KexState::Established;
    transport.last_rekey_bytes = transport.total_bytes();
    transport.last_rekey_instant = std::time::Instant::now();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(steps: &[&str]) -> Vec<String> {
        steps.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn auth_step_without_configuration_is_complete() {
        let done: Vec<String> = Vec::new();
        assert!(matches!(next_auth_step(&[], &done), AuthStep::Complete));
    }

    #[test]
    fn auth_step_first_step_offers_every_chain_head() {
        let required = vec![chain(&["publickey", "password"]), chain(&["password", "publickey"])];
        match next_auth_step(&required, &[]) {
            AuthStep::Continue(m) => assert_eq!(m, vec!["publickey", "password"]),
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn auth_step_advances_through_chain() {
        let required = vec![chain(&["publickey", "password"])];
        match next_auth_step(&required, &chain(&["publickey"])) {
            AuthStep::Continue(m) => assert_eq!(m, vec!["password"]),
            _ => panic!("expected Continue"),
        }
        assert!(matches!(
            next_auth_step(&required, &chain(&["publickey", "password"])),
            AuthStep::Complete
        ));
    }

    #[test]
    fn auth_step_rejects_out_of_order_sequence() {
        let required = vec![chain(&["publickey", "password"])];
        assert!(matches!(
            next_auth_step(&required, &chain(&["password"])),
            AuthStep::Invalid
        ));
        assert!(matches!(
            next_auth_step(&required, &chain(&["publickey", "publickey"])),
            AuthStep::Invalid
        ));
    }

    #[test]
    fn auth_step_supports_repeated_methods() {
        let required = vec![chain(&["publickey", "publickey"])];
        match next_auth_step(&required, &chain(&["publickey"])) {
            AuthStep::Continue(m) => assert_eq!(m, vec!["publickey"]),
            _ => panic!("expected Continue"),
        }
        assert!(matches!(
            next_auth_step(&required, &chain(&["publickey", "publickey"])),
            AuthStep::Complete
        ));
    }

    #[test]
    fn failure_advertises_next_step_with_partial_flag() {
        let mut config = ServerConfig::default();
        config.authentication_methods = vec![chain(&["publickey", "password"])];
        let (methods, partial) = failure_methods(&config, &chain(&["publickey"]), Vec::new());
        assert_eq!(methods, vec!["password"]);
        assert!(partial);
        // First step: no partial success yet.
        let (methods, partial) = failure_methods(&config, &[], Vec::new());
        assert_eq!(methods, vec!["publickey"]);
        assert!(!partial);
    }
}
