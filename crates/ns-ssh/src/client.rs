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
    use std::os::unix::io::AsRawFd;
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
}

impl SshClient {
    pub fn new(config: ResolvedConfig) -> Self {
        SshClient {
            config,
            stream: None,
            transport: SshTransport::new(),
            session_id: None,
            server_sig_algs: Vec::new(),
            agent: SshAgent::new(),
            loaded_signers: Vec::new(),
            channel_manager: ChannelManager::new(),
            pending_open: HashMap::new(),
            pending_global: VecDeque::new(),
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let target_host = self.config.hostname.clone();
        let target_port = self.config.port;

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

        self.connect_direct().await
    }

    async fn connect_direct(&mut self) -> Result<()> {
        let target_host = self.config.hostname.clone();
        let target_port = self.config.port;
        let addr = format!("{}:{}", target_host, target_port);
        let stream = if let Some(bind) = self.config.bind_address.clone() {
            let socket = tokio::net::TcpSocket::new_v4().map_err(SshError::Io)?;
            let bind_addr = format!("{}:0", bind);
            let bind_addr: std::net::SocketAddr = bind_addr.parse().map_err(|_| SshError::Protocol("invalid BindAddress".into()))?;
            socket.bind(bind_addr).map_err(SshError::Io)?;
            let target_addr = tokio::net::lookup_host(addr.as_str()).await
                .map_err(SshError::Io)?
                .next().ok_or_else(|| SshError::Protocol("cannot resolve target".into()))?;
            socket.connect(target_addr).await.map_err(SshError::Io)?
        } else {
            TcpStream::connect(&addr).await.map_err(SshError::Io)?
        };
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
        );
        send_raw_packet(stream, &kex_init).await?;
        self.transport.state = KexState::KexInitSent;

        let server_kex = receive_raw_packet(stream).await?;
        self.transport.server_kex_init = server_kex.clone();
        self.transport.state = KexState::KexInitReceived;

        let negotiation = SshTransport::negotiate_algorithms(
            &self.transport.client_kex_init,
            &self.transport.server_kex_init,
        )?;

        let mut kex = SshTransport::create_kex_algorithm(&negotiation.kex_algorithm)?;

        let (server_host_key_blob, server_public_key, server_signature_blob, shared_secret, exchange_hash, kex_hash_name) = if negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange") {
            let (min, nbits, max) = if negotiation.kex_algorithm.contains("sha256") {
                (2048u32, 4096u32, 8192u32)
            } else {
                (2048u32, 2048u32, 4096u32)
            };
            let mut req = Vec::new();
            req.push(msg::SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
            min.encode(&mut req)?;
            nbits.encode(&mut req)?;
            max.encode(&mut req)?;
            send_raw_packet(stream, &req).await?;

            let group_msg = receive_raw_packet(stream).await?;
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

            let reply = receive_raw_packet(stream).await?;
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
            SshBytes(kex.public_key_bytes()).encode(&mut dh_payload)?;
            send_raw_packet(stream, &dh_payload).await?;
            self.transport.state = KexState::KexDhInitSent;

            let reply = receive_raw_packet(stream).await?;
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
        } else {
            SshBytes::decode(&mut r2)?.0
        };

        let known_hosts = KnownHosts::new(KnownHosts::default_client_path());
        let status = known_hosts.check(
            &self.config.hostname,
            self.config.port,
            &host_key_type,
            &server_host_key_blob,
        );

        match status {
            HostKeyStatus::Known => {}
            HostKeyStatus::Unknown => {
                if self.config.strict_host_key_checking {
                    return Err(SshError::HostKeyVerificationFailed);
                }
                eprintln!("Warning: Permanently added '{}' ({}) to the list of known hosts.",
                    self.config.hostname, host_key_type);
                let mut kh = KnownHosts::new(KnownHosts::default_client_path());
                kh.add_host(
                    &self.config.hostname,
                    self.config.port,
                    &host_key_type,
                    &server_host_key_blob,
                )?;
            }
            HostKeyStatus::Changed => {
                eprintln!("WARNING: Remote host identification has changed!");
                if self.config.strict_host_key_checking {
                    return Err(SshError::HostKeyVerificationFailed);
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

        self.transport.install_new_keys(
            &negotiation,
            hash_name,
            &shared_secret,
            &exchange_hash,
            &exchange_hash,
        )?;

        self.session_id = Some(exchange_hash);

        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;

        let newkeys_msg = vec![msg::SSH_MSG_NEWKEYS];
        send_encrypted_packet(stream, &newkeys_msg, &mut self.transport, true, aead).await?;
        self.transport.state = KexState::NewKeysSent;

        let newkeys_response = receive_encrypted_packet(stream, &mut self.transport, true, aead).await?;
        if newkeys_response.first() != Some(&msg::SSH_MSG_NEWKEYS) {
            return Err(SshError::Protocol("expected NEWKEYS".into()));
        }
        self.transport.state = KexState::NewKeysReceived;
        self.transport.kex_algorithm = Some(kex);
        self.transport.state = KexState::Established;

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
                Some(&msg::SSH_EXT_INFO_C) | Some(&msg::SSH_EXT_INFO_S) => {
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
                        let method = AuthMethod::PublicKey(self.loaded_signers[i].clone());
                        let auth_msg = build_userauth_request_with_session(
                            &username,
                            msg::SSH_SERVICE_NAME_CONNECTION,
                            &method,
                            &session_id,
                        );
                        send_encrypted_packet(stream, &auth_msg, &mut self.transport, false, aead).await?;

                        let response = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
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
                                let resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
                                if resp.first() == Some(&msg::SSH_MSG_USERAUTH_SUCCESS) {
                                    auth_succeeded = true;
                                    break;
                                }
                            }
                            _ => continue,
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
                        let kbd_resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
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

                    let pwd_resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
                    if pwd_resp.first() == Some(&msg::SSH_MSG_USERAUTH_SUCCESS) {
                        auth_succeeded = true;
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
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;

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
        send_encrypted_packet(stream, &open_msg, &mut self.transport, false, aead).await?;

        let open_resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        match open_resp.first() {
            Some(&msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                let (recipient, sender, _w, _m) = parse_channel_open_confirmation(&open_resp)?;
                if recipient != local_id {
                    return Err(SshError::Protocol("unexpected recipient in open confirmation".into()));
                }
                self.channel_manager.set_remote_id(local_id, sender);
            }
            Some(&msg::SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                let (_, reason, message) = parse_channel_open_failure(&open_resp)?;
                return Err(SshError::Channel(format!("session open failed: {} ({})", message, reason)));
            }
            _ => return Err(SshError::Protocol("unexpected response to channel open".into())),
        }

        if self.config.forward_agent {
            let req = build_channel_request(local_id, msg::SSH_REQUEST_AUTH_AGENT, false, None);
            send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
        }

        if pty {
            let pty_data = build_pty_request(term, width, height, width * 8, height * 16, &[]);
            let pty_msg = build_channel_request(local_id, msg::SSH_REQUEST_PTY, true, Some(&pty_data));
            send_encrypted_packet(stream, &pty_msg, &mut self.transport, false, aead).await?;
            let _resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
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
            send_encrypted_packet(stream, &x11_msg, &mut self.transport, false, aead).await?;
            let _resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        }

        for (name, value) in &self.config.set_env {
            let env_data = build_env_request(name, value);
            let env_msg = build_channel_request(local_id, msg::SSH_REQUEST_ENV, false, Some(&env_data));
            send_encrypted_packet(stream, &env_msg, &mut self.transport, false, aead).await?;
        }
        if !self.config.send_env.is_empty() {
            let envs: Vec<(String, String)> = std::env::vars().collect();
            for pattern in &self.config.send_env {
                for (name, value) in &envs {
                    if env_pattern_match(name, pattern) {
                        let env_data = build_env_request(name, value);
                        let env_msg = build_channel_request(local_id, msg::SSH_REQUEST_ENV, false, Some(&env_data));
                        send_encrypted_packet(stream, &env_msg, &mut self.transport, false, aead).await?;
                    }
                }
            }
        }

        if let Some(cmd) = command {
            let exec_data = build_exec_request(cmd);
            let exec_msg = build_channel_request(local_id, msg::SSH_REQUEST_EXEC, true, Some(&exec_data));
            send_encrypted_packet(stream, &exec_msg, &mut self.transport, false, aead).await?;
            let _resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        } else {
            let shell_msg = build_channel_request(local_id, msg::SSH_REQUEST_SHELL, true, None);
            send_encrypted_packet(stream, &shell_msg, &mut self.transport, false, aead).await?;
            let _resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        }

        Ok(local_id)
    }

    pub async fn request_session_subsystem(&mut self, subsystem: &str) -> Result<ChannelId> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
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
        send_encrypted_packet(stream, &open_msg, &mut self.transport, false, aead).await?;
        let open_resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        match open_resp.first() {
            Some(&msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                let (recipient, sender, _w, _m) = parse_channel_open_confirmation(&open_resp)?;
                if recipient != local_id {
                    return Err(SshError::Protocol("unexpected recipient in open confirmation".into()));
                }
                self.channel_manager.set_remote_id(local_id, sender);
            }
            Some(&msg::SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                let (_, reason, message) = parse_channel_open_failure(&open_resp)?;
                return Err(SshError::Channel(format!("session open failed: {} ({})", message, reason)));
            }
            _ => return Err(SshError::Protocol("unexpected response to channel open".into())),
        }
        let sub_data = build_subsystem_request(subsystem);
        let sub_msg = build_channel_request(local_id, msg::SSH_REQUEST_SUBSYSTEM, true, Some(&sub_data));
        send_encrypted_packet(stream, &sub_msg, &mut self.transport, false, aead).await?;
        let _resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
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
        }
        let (accept_tx, mut accept_rx) = mpsc::unbounded_channel::<AcceptEvent>();

        let mut local_meta: Vec<(String, u16, u16)> = Vec::new();
        for (i, (bind_port, host, connect_port)) in self.config.local_forwards.clone().into_iter().enumerate() {
            let bind_addr = format!("127.0.0.1:{}", bind_port);
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
                }
            }
        }

        for socks_port in self.config.dynamic_forwards.clone() {
            let bind_addr = format!("127.0.0.1:{}", socks_port);
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
                }
            }
        }
        drop(accept_tx);

        let mut remote_forward_map: HashMap<u16, (String, u16)> = HashMap::new();
        for (remote_port, ref local_host, local_port) in self.config.remote_forwards.clone() {
            let req = build_global_request_tcpip_forward(true, "0.0.0.0", remote_port as u32);
            let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
            send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
            remote_forward_map.insert(remote_port, (local_host.clone(), local_port));
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
        let mut pending_forward_sockets: HashMap<ChannelId, TcpStream> = HashMap::new();

        #[cfg(unix)]
        let mut winch_sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .ok();
        #[cfg(not(unix))]
        let winch_sig: Option<tokio::signal::unix::Signal> = None;

        loop {
            if should_exit { break; }

            {
                let tb = self.transport.total_bytes();
                let el = self.transport.last_rekey_instant.elapsed().as_secs();
                if self.transport.needs_rekey(tb, el) {
                    if let Err(e) = self.perform_rekey().await {
                        tracing::warn!("rekey failed (continuing): {:?}", e);
                    }
                }
            }

            tokio::select! {
                biased;

                to_ssh = to_ssh_rx.recv() => {
                    if let Some((remote_id, data)) = to_ssh {
                        let msg = build_channel_data(remote_id, &data);
                        if let Some(stream) = self.stream.as_mut() {
                            let _ = send_encrypted_packet(stream, &msg, &mut self.transport, false, aead).await;
                        }
                    }
                }

                _ = async {
                    if let Some(ref mut s) = alive_sleep { s.as_mut().await; } else { std::future::pending().await }
                }, if alive_interval_ms > 0 => {
                    if last_any_packet.elapsed().as_secs() as u32 >= alive_interval_ms as u32 / 1000 * alive_max {
                        tracing::warn!("ServerAliveCountMax exceeded, disconnecting");
                        should_exit = true;
                    } else {
                        let _ = self.send_keepalive().await;
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

                ev = accept_rx.recv(), if self.config.local_forwards.len() + self.config.dynamic_forwards.len() > 0 => {
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
                            if let Some(rid) = stdio_forward_remote_id {
                                let msg = build_channel_data(rid, &data);
                                if let Some(stream) = self.stream.as_mut() {
                                    let _ = send_encrypted_packet(stream, &msg, &mut self.transport, false, aead).await;
                                }
                            } else if self.config.stdio_forward.is_some() {
                                stdio_forward_pending_data.push(data);
                            } else if let Some(sid) = session_id {
                                if let Some(ch) = self.channel_manager.get_channel(sid) {
                                    if let Some(remote_id) = ch.remote_id {
                                        let msg = build_channel_data(remote_id, &data);
                                        if let Some(stream) = self.stream.as_mut() {
                                            let _ = send_encrypted_packet(stream, &msg, &mut self.transport, false, aead).await;
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            stdin_active = false;
                            if let Some(rid) = stdio_forward_remote_id {
                                let eof = build_channel_eof(rid);
                                if let Some(stream) = self.stream.as_mut() {
                                    let _ = send_encrypted_packet(stream, &eof, &mut self.transport, false, aead).await;
                                }
                            } else if self.config.stdio_forward.is_some() {
                                stdio_forward_eof_pending = true;
                            } else if let Some(sid) = session_id {
                                if let Some(ch) = self.channel_manager.get_channel(sid) {
                                    if let Some(remote_id) = ch.remote_id {
                                        let eof = build_channel_eof(remote_id);
                                        if let Some(stream) = self.stream.as_mut() {
                                            let _ = send_encrypted_packet(stream, &eof, &mut self.transport, false, aead).await;
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

                packet = async {
                    let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
                    receive_encrypted_packet(stream, &mut self.transport, false, aead).await
                } => {
                    last_any_packet = std::time::Instant::now();
                    match packet {
                        Ok(payload) if !payload.is_empty() => {
                            match payload[0] {
                                msg::SSH_MSG_CHANNEL_DATA => {
                                    if let Ok((remote_id, data)) = parse_channel_data(&payload) {
                                        if let Some(rid) = stdio_forward_remote_id {
                                            if rid == remote_id {
                                                use std::io::Write;
                                                let _ = std::io::stdout().write_all(&data);
                                                let _ = std::io::stdout().flush();
                                                continue;
                                            }
                                        }
                                        if let Some(local_id) = self.channel_manager.find_by_remote_id(remote_id).map(|c| c.local_id) {
                                            if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                                if let Some(tx) = &ch.data_tx { let _ = tx.try_send(data); }
                                            }
                                        }
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                                    let mut r = &payload[1..];
                                    let remote_id = u32::decode(&mut r)?;
                                    let dt = u32::decode(&mut r)?;
                                    let data = SshBytes::decode(&mut r)?.0;
                                    if let Some(local_id) = self.channel_manager.find_by_remote_id(remote_id).map(|c| c.local_id) {
                                        if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                            if let Some(ref ext_tx) = ch.ext_data_tx {
                                                let _ = ext_tx.try_send((dt, data));
                                            }
                                        }
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_REQUEST => {
                                    if let Ok((remote_id, req_type, want_reply)) = parse_channel_request(&payload) {
                                        let local_id = self.channel_manager.find_by_remote_id(remote_id).map(|c| c.local_id);
                                        if req_type == "exit-status" {
                                            let mut r = &payload[10 + req_type.len()..];
                                            exit_code = u32::decode(&mut r)? as i32;
                                        }
                                        if want_reply {
                                            if let Some(lid) = local_id {
                                                if let Some(ch) = self.channel_manager.get_channel(lid) {
                                                    if let Some(rid) = ch.remote_id {
                                                        let reply = build_channel_success(rid);
                                                        if let Some(stream) = self.stream.as_mut() {
                                                            let _ = send_encrypted_packet(stream, &reply, &mut self.transport, false, aead).await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if req_type == "exit-status" || req_type == "exit-signal" {
                                            should_exit = true;
                                        }
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                                    if let Ok((recipient, sender, w, m)) = parse_channel_open_confirmation(&payload) {
                                        if let Some(tx) = self.pending_open.remove(&recipient) {
                                            self.channel_manager.set_remote_id(recipient, sender);
                                            let _ = tx.send(Ok((sender, w, m)));
                                        }
                                        // Handle -W stdio forward confirmation
                                        if stdio_forward_channel_id == Some(recipient) {
                                            stdio_forward_remote_id = Some(sender);
                                            for data in stdio_forward_pending_data.drain(..) {
                                                let msg = build_channel_data(sender, &data);
                                                if let Some(stream) = self.stream.as_mut() {
                                                    let _ = send_encrypted_packet(stream, &msg, &mut self.transport, false, aead).await;
                                                }
                                            }
                                            if stdio_forward_eof_pending {
                                                let eof = build_channel_eof(sender);
                                                if let Some(stream) = self.stream.as_mut() {
                                                    let _ = send_encrypted_packet(stream, &eof, &mut self.transport, false, aead).await;
                                                }
                                            }
                                        }
                                        if let Some(sock) = pending_forward_sockets.remove(&recipient) {
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
                                            let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_FORWARDED_TCPIP, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                            self.channel_manager.set_remote_id(local_id, sender_channel);
                                            let confirm = build_channel_open_confirmation(s, local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                            if let Some(stream) = self.stream.as_mut() {
                                                let _ = send_encrypted_packet(stream, &confirm, &mut self.transport, false, aead).await;
                                            }
                                            match TcpStream::connect(format!("{}:{}", lh, lp)).await {
                                                Ok(socket) => {
                                                    let rx = self.channel_manager.take_data_rx(local_id).unwrap();
                                                    pump_socket_with_channel(socket, rx, sender_channel, to_ssh_tx.clone());
                                                }
                                                Err(_) => {
                                                    if let Some(ch) = self.channel_manager.get_channel(local_id) {
                                                        if let Some(rid) = ch.remote_id {
                                                            let close = build_channel_close(rid);
                                                            if let Some(stream) = self.stream.as_mut() {
                                                                let _ = send_encrypted_packet(stream, &close, &mut self.transport, false, aead).await;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            let fail = build_channel_open_failure(sender_channel, 1, "forward not allowed");
                                            if let Some(stream) = self.stream.as_mut() {
                                                let _ = send_encrypted_packet(stream, &fail, &mut self.transport, false, aead).await;
                                            }
                                        }
                                    } else if channel_type == msg::SSH_CHANNEL_TYPE_AUTH_AGENT && self.config.forward_agent {
                                        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_AUTH_AGENT, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        self.channel_manager.set_remote_id(local_id, sender_channel);
                                        let confirm = build_channel_open_confirmation(sender_channel, local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        if let Some(stream) = self.stream.as_mut() {
                                            let _ = send_encrypted_packet(stream, &confirm, &mut self.transport, false, aead).await;
                                        }
                                        if let Ok(sock) = connect_agent_socket().await {
                                            let rx = self.channel_manager.take_data_rx(local_id).unwrap();
                                            pump_socket_with_channel(sock, rx, sender_channel, to_ssh_tx.clone());
                                        }
                                    } else if channel_type == msg::SSH_CHANNEL_TYPE_X11 && self.config.forward_x11 {
                                        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_X11, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        self.channel_manager.set_remote_id(local_id, sender_channel);
                                        let confirm = build_channel_open_confirmation(sender_channel, local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
                                        if let Some(stream) = self.stream.as_mut() {
                                            let _ = send_encrypted_packet(stream, &confirm, &mut self.transport, false, aead).await;
                                        }
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
                                                        if let Some(stream) = self.stream.as_mut() {
                                                            let _ = send_encrypted_packet(stream, &close, &mut self.transport, false, aead).await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        let fail = build_channel_open_failure(sender_channel, 1, "channel type not supported");
                                        if let Some(stream) = self.stream.as_mut() {
                                            let _ = send_encrypted_packet(stream, &fail, &mut self.transport, false, aead).await;
                                        }
                                    }
                                }
                                msg::SSH_MSG_CHANNEL_EOF | msg::SSH_MSG_CHANNEL_CLOSE => {
                                    if let Some(sid) = session_id {
                                        let mut r = &payload[1..];
                                        if let Ok(rid) = u32::decode(&mut r) {
                                            if self.channel_manager.find_by_remote_id(rid).map(|c| c.local_id) == Some(sid) {
                                                should_exit = true;
                                            }
                                        }
                                    } else if let Some(rid) = stdio_forward_remote_id {
                                        let mut r = &payload[1..];
                                        if let Ok(remote_id) = u32::decode(&mut r) {
                                            if rid == remote_id {
                                                should_exit = true;
                                            }
                                        }
                                    }
                                }
                                msg::SSH_MSG_DISCONNECT => {
                                    should_exit = true;
                                }
                                msg::SSH_MSG_REQUEST_SUCCESS => {
                                    if let Some(tx) = self.pending_global.pop_front() {
                                        let extra = if payload.len() > 1 { Some(payload[1..].to_vec()) } else { None };
                                        let _ = tx.send(Ok(extra));
                                    }
                                }
                                msg::SSH_MSG_REQUEST_FAILURE => {
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
                                            if let Some(stream) = self.stream.as_mut() {
                                                let _ = send_encrypted_packet(stream, &resp, &mut self.transport, false, aead).await;
                                            }
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

        if let Some(sid) = session_id {
            let _ = self.send_channel_close(sid).await;
        }

        let _ = self.send_disconnect().await;

        Ok(exit_code)
    }

    pub async fn open_direct_tcpip(&mut self, host: &str, port: u32, orig_ip: &str, orig_port: u32) -> Result<ChannelId> {
        let aead = self.is_aead();
        let local_id = self.channel_manager.alloc_channel(msg::SSH_CHANNEL_TYPE_DIRECT_TCPIP, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE);
        let msg_bytes = build_direct_tcpip_open(local_id, msg::CHANNEL_PACKET_WINDOW_SIZE, msg::CHANNEL_MAX_PACKET_SIZE, host, port, orig_ip, orig_port);
        let (tx, rx) = oneshot::channel();
        self.pending_open.insert(local_id, tx);
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        send_encrypted_packet(stream, &msg_bytes, &mut self.transport, false, aead).await?;
        match rx.await {
            Ok(Ok((remote_id, _w, _m))) => {
                self.channel_manager.set_remote_id(local_id, remote_id);
                Ok(local_id)
            }
            Ok(Err(e)) => {
                self.channel_manager.close_channel(local_id);
                Err(e)
            }
            Err(_) => {
                self.channel_manager.close_channel(local_id);
                Err(SshError::Channel("open cancelled".into()))
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

    pub async fn send_global_request(&mut self, req: &[u8]) -> Result<Option<Vec<u8>>> {        let aead = self.is_aead();
        let (tx, rx) = oneshot::channel();
        self.pending_global.push_back(tx);
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        send_encrypted_packet(stream, req, &mut self.transport, false, aead).await?;
        rx.await.map_err(|_| SshError::Channel("global request cancelled".into()))?
    }

    fn is_aead(&self) -> bool {
        self.transport.client_to_server_cipher.as_ref()
            .map(|c| c.is_aead())
            .unwrap_or(false)
    }

    pub async fn perform_rekey(&mut self) -> Result<()> {
        use ssh_core::transport::KexState;
        if self.transport.state != KexState::Established {
            return Ok(());
        }
        self.transport.state = KexState::RekeyInProgress;
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;

        let client_kex_init = self.transport.prepare_rekey();
        send_encrypted_packet(stream, &client_kex_init, &mut self.transport, false, aead).await?;

        let server_kex = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        if server_kex.first() != Some(&msg::SSH_MSG_KEXINIT) {
            return Err(SshError::KexFailed("expected KEXINIT during rekey".into()));
        }
        self.transport.server_kex_init = server_kex.clone();

        let negotiation = SshTransport::negotiate_algorithms(
            &self.transport.client_kex_init,
            &self.transport.server_kex_init,
        )?;

        let mut kex = SshTransport::create_kex_algorithm(&negotiation.kex_algorithm)?;

        let (server_host_key_blob, server_pub_key, server_sig_blob, shared_secret, exchange_hash, kex_hash_name) =
            if negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange") {
                let (min, nbits, max) = if negotiation.kex_algorithm.contains("sha256") {
                    (2048u32, 4096u32, 8192u32)
                } else {
                    (2048u32, 2048u32, 4096u32)
                };
                let mut req = Vec::new();
                req.push(msg::SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
                min.encode(&mut req)?;
                nbits.encode(&mut req)?;
                max.encode(&mut req)?;
                send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;

                let group_msg = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
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

                let reply = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
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
                dh_payload.extend(SshBytes(kex.public_key_bytes()).0);
                send_encrypted_packet(stream, &dh_payload, &mut self.transport, false, aead).await?;

                let reply = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
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
                );
                (host_key_blob, srv_pub, sig_blob, shared, exch_hash, hash_name)
            };

        let session_id = self.session_id.clone().unwrap_or_default();

        self.transport.install_new_keys(
            &negotiation,
            &kex_hash_name,
            &shared_secret,
            &exchange_hash,
            &session_id,
        )?;

        let newkeys_msg = vec![msg::SSH_MSG_NEWKEYS];
        send_encrypted_packet(stream, &newkeys_msg, &mut self.transport, true, aead).await?;
        self.transport.state = KexState::NewKeysSent;

        let newkeys_response = receive_encrypted_packet(stream, &mut self.transport, true, aead).await?;
        if newkeys_response.first() != Some(&msg::SSH_MSG_NEWKEYS) {
            return Err(SshError::Protocol("expected NEWKEYS during rekey".into()));
        }
        self.transport.state = KexState::NewKeysReceived;
        self.transport.kex_algorithm = Some(kex);
        self.transport.state = KexState::Established;
        self.transport.last_rekey_bytes = self.transport.total_bytes();
        self.transport.last_rekey_instant = std::time::Instant::now();
        Ok(())
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

async fn connect_agent_socket() -> Result<tokio::net::UnixStream> {
    let path = std::env::var("SSH_AUTH_SOCK").map_err(|_| SshError::Protocol("SSH_AUTH_SOCK not set".into()))?;
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
            jump_client.connect_direct().await?;
        }
        jump_client.handshake().await?;
        jump_client.authenticate().await?;

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
        .map(|ch| ch.window_size)
        .unwrap_or(2u32 << 20);

    let mut local_window = 2u32 << 20;

    let aead = transport.client_to_server_cipher.as_ref()
        .map(|c| c.is_aead())
        .unwrap_or(false);

    let stream = stream.take().unwrap();
    let (r, w) = tokio::io::split(stream);
    let (mut duplex_rd, mut outer_wr) = tokio::io::duplex(1 << 20);
    let (mut outer_rd, mut duplex_wr) = tokio::io::duplex(1 << 20);

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
    child: tokio::process::Child,
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
    Ok(Box::pin(ProxyStream { child, stdout, stdin }))
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
    use ssh_core::encoding::{SshDecode, SshEncode as _};
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
    let remainder = base % 8;
    let mut padding_len = if remainder == 0 { 0 } else { 8 - remainder };
    if padding_len < 4 { padding_len += 8; }
    let packet_len_field = (4 + base + padding_len) as u32;
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
    if total_len < 12 || total_len > 256 * 1024 {
        return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
    }
    let body_len = total_len - 4;
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

async fn send_encrypted_packet(
    stream: &mut (impl AsyncWrite + Unpin + ?Sized),
    payload: &[u8],
    transport: &mut SshTransport,
    _is_new_keys: bool,
    aead: bool,
) -> Result<()> {
    let block_size = if aead { 8 } else {
        transport.client_to_server_cipher.as_ref()
            .map(|c| c.block_size())
            .unwrap_or(8)
    };

    let base = 1 + payload.len();
    let remainder = base % block_size;
    let mut padding_len = if remainder == 0 { 0 } else { block_size - remainder };
    if padding_len < 4 { padding_len += block_size; }
    let body_len = base + padding_len;
    let packet_len_field = (4 + body_len) as u32;

    let mut packet = Vec::with_capacity(4 + body_len);
    packet.extend_from_slice(&packet_len_field.to_be_bytes());
    packet.push(padding_len as u8);
    packet.extend_from_slice(payload);
    let mut padding = vec![0u8; padding_len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
    packet.extend_from_slice(&padding);

    let seq = transport.outgoing_seq;

    if aead {
        if let Some(ref mut cipher) = transport.client_to_server_cipher {
            let plaintext = packet[4..].to_vec();
            let ciphertext = cipher.encrypt(seq, &plaintext)?;
            packet.truncate(4);
            packet.extend_from_slice(&ciphertext);
        }

        if let Some(ref mac) = transport.client_to_server_mac {
            if mac.tag_len() > 0 {
                let mac_data = &packet[4..];
                let tag = mac.compute_tag(seq, mac_data)?;
                packet.extend_from_slice(&tag);
            }
        }
    } else {
        if let Some(ref mut cipher) = transport.client_to_server_cipher {
            let plaintext = packet[4..].to_vec();
            let ciphertext = cipher.encrypt(seq, &plaintext)?;
            packet.truncate(4);
            packet.extend_from_slice(&ciphertext);
        }

        if let Some(ref mac) = transport.client_to_server_mac {
            if mac.tag_len() > 0 {
                let mac_data = &packet[4..];
                let tag = mac.compute_tag(seq, mac_data)?;
                packet.extend_from_slice(&tag);
            }
        }
    }

    stream.write_all(&packet).await?;
    stream.flush().await?;
    transport.outgoing_seq += 1;
    Ok(())
}

async fn receive_encrypted_packet(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    transport: &mut SshTransport,
    _is_new_keys: bool,
    aead: bool,
) -> Result<Vec<u8>> {
    let seq = transport.incoming_seq;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;

    let packet_len = u32::from_be_bytes(len_buf) as usize;
    if packet_len > 256 * 1024 || packet_len < 12 {
        return Err(SshError::InvalidPacket(format!("invalid packet size: {}", packet_len)));
    }
    let body_len = packet_len - 4;

    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    let ciphertext = body.clone();

    if aead {
        if let Some(ref mut cipher) = transport.server_to_client_cipher {
            let decrypted = cipher.decrypt(seq, &body)?;
            body = decrypted;
        }

        if let Some(ref mac) = transport.server_to_client_mac {
            if mac.tag_len() > 0 {
                let mut tag_buf = vec![0u8; mac.tag_len()];
                stream.read_exact(&mut tag_buf).await?;
                if !mac.verify_tag(seq, &ciphertext, &tag_buf)? {
                    return Err(SshError::DecryptionFailed);
                }
            }
        }
    } else {
        if let Some(ref mut cipher) = transport.server_to_client_cipher {
            let decrypted = cipher.decrypt(seq, &body)?;
            body = decrypted;
        }

        if let Some(ref mac) = transport.server_to_client_mac {
            if mac.tag_len() > 0 {
                let mut tag_buf = vec![0u8; mac.tag_len()];
                stream.read_exact(&mut tag_buf).await?;
                if !mac.verify_tag(seq, &ciphertext, &tag_buf)? {
                    return Err(SshError::DecryptionFailed);
                }
            }
        }
    }

    transport.incoming_seq += 1;

    if body.is_empty() {
        return Err(SshError::Protocol("empty packet".into()));
    }

    let padding_len = body[0] as usize;
    if padding_len >= body.len() {
        return Err(SshError::InvalidPacket("invalid padding".into()));
    }

    Ok(body[1..body.len() - padding_len].to_vec())
}

impl SshClient {
    pub async fn request_connection_service(&mut self) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        let req = vec![msg::SSH_MSG_SERVICE_REQUEST]
            .into_iter()
            .chain(SshString::new(msg::SSH_SERVICE_NAME_CONNECTION).0)
            .collect::<Vec<u8>>();
        send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
        let resp = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
        if resp.first() != Some(&msg::SSH_MSG_SERVICE_ACCEPT) {
            return Err(SshError::Protocol("connection service not accepted".into()));
        }
        Ok(())
    }

    pub async fn enable_agent_forwarding(&mut self, session_local_id: ChannelId) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        let remote_id = self.channel_manager.get_channel(session_local_id)
            .and_then(|c| c.remote_id)
            .unwrap_or(0);
        let req = build_channel_request(remote_id, msg::SSH_REQUEST_AUTH_AGENT, false, None);
        send_encrypted_packet(stream, &req, &mut self.transport, false, aead).await?;
        Ok(())
    }

    pub async fn send_channel_data(&mut self, session_local_id: ChannelId, data: &[u8]) -> Result<()> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        let remote_id = self.channel_manager.get_channel(session_local_id)
            .and_then(|c| c.remote_id)
            .unwrap_or(0);
        let msg_data = build_channel_data(remote_id, data);
        send_encrypted_packet(stream, &msg_data, &mut self.transport, false, aead).await?;
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

    pub async fn recv_channel_data(&mut self, local_id: ChannelId) -> Result<Option<Vec<u8>>> {
        let aead = self.is_aead();
        let stream = self.stream.as_mut().ok_or_else(|| SshError::Protocol("not connected".into()))?;
        loop {
            let packet = receive_encrypted_packet(stream, &mut self.transport, false, aead).await?;
            if packet.is_empty() { continue; }
            match packet[0] {
                msg::SSH_MSG_CHANNEL_DATA => {
                    let mut r = &packet[1..];
                    let remote_id = u32::decode(&mut r)?;
                    let data = SshBytes::decode(&mut r)?.0;
                    if self.channel_manager.find_by_remote_id(remote_id).map(|c| c.local_id) == Some(local_id) {
                        return Ok(Some(data));
                    }
                }
                msg::SSH_MSG_CHANNEL_EOF | msg::SSH_MSG_CHANNEL_CLOSE => {
                    return Ok(None);
                }
                _ => {}
            }
        }
    }
}

pub fn run_client(config: crate::config::ResolvedConfig, cmd: Option<String>, force_tty: bool) -> i32 {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut client = SshClient::new(config.clone());

        if client.connect().await.is_err() {
            eprintln!("ns-ssh: connect to {}:{} failed", config.hostname, config.port);
            return 1;
        }
        if let Err(e) = client.handshake().await {
            eprintln!("ns-ssh: handshake failed: {}", e);
            return 1;
        }
        if client.authenticate().await.is_err() {
            eprintln!("ns-ssh: authentication failed");
            return 1;
        }
        if client.request_connection_service().await.is_err() {
            eprintln!("ns-ssh: connection service request failed");
            return 1;
        }

        let use_pty = config.request_tty || force_tty || (cmd.is_none() && atty::is(atty::Stream::Stdout));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
        let final_cmd = config.remote_command.clone().or(cmd);

        let has_session = !config.no_remote_command && config.stdio_forward.is_none();

        // -s subsystem request
        if let Some(ref sub) = config.subsystem {
            let sid = match client.request_session_subsystem(sub).await {
                Ok(sid) => sid,
                Err(e) => { eprintln!("ns-ssh: subsystem request failed: {}", e); return 1; }
            };
            return client.run_event_loop(Some(sid)).await.unwrap_or(1);
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
                    return 1;
                }
            }
        } else {
            None
        };

        client.run_event_loop(session_id).await.unwrap_or(1)
    })
}
