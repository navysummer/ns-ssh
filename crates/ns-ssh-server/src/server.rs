use crate::config::ServerConfig;
use crate::hostkey::HostKeyManager;
use crate::auth::ServerAuth;
use crate::session::SessionManager;
use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::msg;
use ssh_core::transport::*;
use ssh_core::auth::*;
use ssh_core::channel::*;
use ssh_core::kex::{KexExchange, KexAlgorithm};
use ssh_core::hostkey::*;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::io::{AsyncRead, AsyncWrite};

trait StreamBox: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> StreamBox for T {}
type BoxStream = Box<dyn StreamBox + Send + Unpin>;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).take(32).collect()
}

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
                if let Err(e) = handle_connection(
                    stream,
                    config,
                    host_keys,
                    auth,
                ).await {
                    tracing::error!("Connection error from {}: {}", peer_addr, e);
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
    let mut transport = SshTransport::new();
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
    transport.client_kex_init = client_kex.clone();

    let host_key_algs: Vec<String> = {
            let hk = host_keys.lock().await;
            hk.get_all_keys().iter().map(|k| k.algorithm_name().to_string()).collect()
        };
    let kex_init = transport.build_kex_init(Some(&host_key_algs), None, None, None);
    send_raw_packet(&mut stream, &kex_init).await?;
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

    let mut kex = SshTransport::create_kex_algorithm(&negotiation.kex_algorithm)?;

    let (host_key_blob, server_signature, shared_secret, exchange_hash, kex_hash) = {
        let hk = host_keys.lock().await;
        let selected_host_key = hk.get_key_for_algorithm(&negotiation.host_key_algorithm)
            .ok_or_else(|| SshError::Protocol("no matching host key".into()))?;

        let host_key_blob = selected_host_key.public_key_bytes();

        let (client_public_key, min, nbits, max, p_bytes, g_bytes, actual_modp) =
            if negotiation.kex_algorithm.starts_with("diffie-hellman-group-exchange") {
                let req_msg = receive_raw_packet(&mut stream).await?;
                let (min, nbits, max) = match req_msg.first() {
                    Some(&msg::SSH_MSG_KEX_DH_GEX_REQUEST_OLD) => {
                        let mut r = &req_msg[1..];
                        let mn = u32::decode(&mut r)?;
                        let nb = u32::decode(&mut r)?;
                        let mx = u32::decode(&mut r)?;
                        (mn, nb, mx)
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
                let gex_hash: &'static str = if negotiation.kex_algorithm.contains("sha256") { "sha256" } else { "sha1" };
                let exp_bytes = if negotiation.kex_algorithm.contains("sha256") { 512 } else { 256 };
                let gex_name: &'static str = if negotiation.kex_algorithm.contains("sha256") {
                    "diffie-hellman-group-exchange-sha256"
                } else {
                    "diffie-hellman-group-exchange-sha1"
                };
                let template_modp = if negotiation.kex_algorithm.contains("sha256") {
                    ssh_core::kex::ModpKex::gex_sha256()
                } else {
                    ssh_core::kex::ModpKex::gex_sha1()
                };
                let p_bytes = template_modp.p().to_bytes_be();
                let g_bytes = template_modp.g().to_bytes_be();
                let p = template_modp.p().clone();
                let g = template_modp.g().clone();
                let mut group_msg = Vec::new();
                group_msg.push(msg::SSH_MSG_KEX_DH_GEX_GROUP);
                use ssh_core::encoding::SshMpInt;
                SshMpInt(p_bytes.clone()).encode(&mut group_msg)?;
                SshMpInt(g_bytes.clone()).encode(&mut group_msg)?;
                send_raw_packet(&mut stream, &group_msg).await?;

                let init_msg = receive_raw_packet(&mut stream).await?;
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
                let mut r = &client_dh_init[1..];
                use ssh_core::encoding::SshBytes;
                let client_pub = SshBytes::decode(&mut r)?.0;
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
    } else {
        SshBytes(kex.public_key_bytes()).encode(&mut dh_reply)?;
    }
    SshBytes(server_signature).encode(&mut dh_reply)?;
    send_raw_packet(&mut stream, &dh_reply).await?;

    let aead = negotiation.server_to_client_cipher.contains("gcm")
        || negotiation.server_to_client_cipher.contains("chacha20");

    transport.install_new_keys(
        &negotiation,
        &kex_hash,
        &shared_secret,
        &exchange_hash,
        &exchange_hash,
    )?;

    transport.session_id = Some(exchange_hash.clone());

    let newkeys_client = receive_encrypted_packet_server(&mut stream, &mut transport, true, aead).await?;
    if newkeys_client.first() != Some(&msg::SSH_MSG_NEWKEYS) {
        return Err(SshError::Protocol("expected NEWKEYS from client".into()));
    }

    let newkeys_msg = vec![msg::SSH_MSG_NEWKEYS];
    send_encrypted_packet_server(&mut stream, &newkeys_msg, &mut transport, true, aead).await?;

    transport.state = KexState::Established;

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

    handle_authenticated_session(stream, transport, config, host_keys.clone(), auth.clone(), &exchange_hash).await?;

    Ok(())
}

async fn handle_authenticated_session(
    mut stream: TcpStream,
    mut transport: SshTransport,
    config: ServerConfig,
    host_keys: Arc<Mutex<HostKeyManager>>,
    auth: Arc<Mutex<ServerAuth>>,
    session_id: &[u8],
) -> Result<()> {
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

    if let Some(ref banner_text) = config.banner {
        let mut banner = vec![53u8]; // SSH_MSG_USERAUTH_BANNER
        SshString::new(banner_text).encode(&mut banner)?;
        SshString::new("en").encode(&mut banner)?;
        let _ = send_encrypted_packet_server(&mut stream, &banner, &mut transport, false, aead).await;
    }

    let mut session_manager = SessionManager::new();
    let mut username = String::new();
    let mut authenticated = false;
    let mut auth_tries = 0;
    let mut pending_kbd_user: Option<String> = None;

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
                    let success = vec![msg::SSH_MSG_USERAUTH_SUCCESS];
                    send_encrypted_packet_server(&mut stream, &success, &mut transport, false, aead).await?;
                    authenticated = true;
                    break;
                } else {
                    let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                    let mut methods = Vec::new();
                    if config.pubkey_auth { methods.push("publickey".to_string()); }
                    if config.password_auth { methods.push("password".to_string()); }
                    if config.kbd_interactive_auth { methods.push("keyboard-interactive".to_string()); }
                    SshNameList(methods).encode(&mut failure)?;
                    failure.push(0);
                    send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                    auth_tries += 1;
                }
            }
            msg::SSH_MSG_USERAUTH_REQUEST => {
                let mut r = &auth_request[1..];
                username = SshString::decode(&mut r)?.as_str()?.to_string();
                let _service = SshString::decode(&mut r)?.as_str()?.to_string();
                let method = SshString::decode(&mut r)?.as_str()?.to_string();

                if !crate::auth::check_user_authorized(&username) {
                    let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                    let mut methods = vec!["publickey".to_string(), "password".to_string()];
                    if config.kbd_interactive_auth { methods.push("keyboard-interactive".to_string()); }
                    SshNameList(methods).encode(&mut failure)?;
                    failure.push(0);
                    send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                    auth_tries += 1;
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
                    let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                    let mut methods = Vec::new();
                    if config.pubkey_auth { methods.push("publickey".to_string()); }
                    SshNameList(methods).encode(&mut failure)?;
                    failure.push(0);
                    send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
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

                match method.as_str() {
                    "publickey" => {
                        let has_sig = bool::decode(&mut r)?;
                        let key_type = SshString::decode(&mut r)?.as_str()?.to_string();
                        let public_key = SshBytes::decode(&mut r)?.0;

                        if has_sig {
                            let signature_blob = SshBytes::decode(&mut r)?.0;

                            if config.pubkey_auth
                                && auth_verify_pubkey_signed(&auth, session_id, &username, &key_type, &public_key, &signature_blob).await
                            {
                                let success = vec![msg::SSH_MSG_USERAUTH_SUCCESS];
                                send_encrypted_packet_server(&mut stream, &success, &mut transport, false, aead).await?;
                                authenticated = true;
                                break;
                            } else {
                                let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                                let mut methods = vec!["publickey".to_string()];
                                if config.password_auth { methods.push("password".to_string()); }
                                if config.kbd_interactive_auth { methods.push("keyboard-interactive".to_string()); }
                                SshNameList(methods).encode(&mut failure)?;
                                failure.push(0);
                                send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                            }
                        } else {
                            if config.pubkey_auth && auth_verify_public_key(&auth, &username, &key_type, &public_key).await {
                                let mut pk_ok = vec![msg::SSH_MSG_USERAUTH_PK_OK];
                                SshString::new(&key_type).encode(&mut pk_ok)?;
                                SshBytes(public_key).encode(&mut pk_ok)?;
                                send_encrypted_packet_server(&mut stream, &pk_ok, &mut transport, false, aead).await?;
                            } else {
                                let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                                let mut methods = vec!["publickey".to_string()];
                                if config.password_auth { methods.push("password".to_string()); }
                                if config.kbd_interactive_auth { methods.push("keyboard-interactive".to_string()); }
                                SshNameList(methods).encode(&mut failure)?;
                                failure.push(0);
                                send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                            }
                        }
                    }
                    "password" => {
                        let _change_password = bool::decode(&mut r)?;
                        let password = SshString::decode(&mut r)?.as_str()?.to_string();

                        if config.password_auth && auth.lock().await.verify_password(&username, &password) {
                            let success = vec![msg::SSH_MSG_USERAUTH_SUCCESS];
                            send_encrypted_packet_server(&mut stream, &success, &mut transport, false, aead).await?;
                            authenticated = true;
                            break;
                        } else {
                            let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                            let mut methods = vec!["password".to_string()];
                            if config.pubkey_auth { methods.insert(0, "publickey".to_string()); }
                            if config.kbd_interactive_auth { methods.push("keyboard-interactive".to_string()); }
                            SshNameList(methods).encode(&mut failure)?;
                            failure.push(0);
                            send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                        }
                    }
                    "keyboard-interactive" => {
                        let _lang = SshString::decode(&mut r)?.as_str()?.to_string();
                        let _submethods = SshString::decode(&mut r)?.as_str()?.to_string();

                        if !config.kbd_interactive_auth {
                            let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                            let mut methods = Vec::new();
                            if config.pubkey_auth { methods.push("publickey".to_string()); }
                            if config.password_auth { methods.push("password".to_string()); }
                            SshNameList(methods).encode(&mut failure)?;
                            failure.push(0);
                            send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
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
                        let mut methods = Vec::new();
                        if config.pubkey_auth {
                            methods.push("publickey".to_string());
                        }
                        if config.password_auth {
                            methods.push("password".to_string());
                        }
                        if config.kbd_interactive_auth {
                            methods.push("keyboard-interactive".to_string());
                        }
                        let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                        SshNameList(methods).encode(&mut failure)?;
                        failure.push(0);
                        send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                    }
                    _ => {
                        let mut failure = vec![msg::SSH_MSG_USERAUTH_FAILURE];
                        let mut methods = vec!["publickey".to_string()];
                        if config.password_auth { methods.push("password".to_string()); }
                        if config.kbd_interactive_auth { methods.push("keyboard-interactive".to_string()); }
                        SshNameList(methods).encode(&mut failure)?;
                        failure.push(0);
                        send_encrypted_packet_server(&mut stream, &failure, &mut transport, false, aead).await?;
                    }
                }
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

    handle_connection_service(&mut stream, &mut transport, &config, &host_keys, &username, &mut session_manager).await?;
    Ok(())
}

enum ChildOutputMsg {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

fn forward_policy_allows_remote(cfg: &ServerConfig, _bind_addr: &str, _port: u32) -> bool {
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

fn forward_policy_allows_direct(cfg: &ServerConfig, host: &str, port: u32) -> bool {
    match cfg.allow_tcp_forwarding_mode.as_str() {
        "no" => false,
        "remote" => false, // remote-only: server→client allowed, direct (client→server) disallowed
        _ => {
            if cfg.permit_open.is_empty() {
                return true;
            }
            cfg.permit_open.iter().any(|entry| {
                let entry = entry.to_lowercase();
                if entry == "any" {
                    return true;
                }
                let (h, p) = match entry.rsplit_once(':') {
                    Some((h, p)) => (h.to_string(), p.to_string()),
                    None => return false,
                };
                let host_ok = h == host.to_lowercase() || h == "*";
                let port_ok = p == "0" || p.parse::<u32>().ok() == Some(port);
                host_ok && port_ok
            })
        }
    }
}

fn forward_policy_allows_listen(cfg: &ServerConfig, bind_addr: &str, port: u32) -> bool {
    if cfg.permit_listen.is_empty() {
        return true;
    }
    cfg.permit_listen.iter().any(|entry| {
        let entry = entry.to_lowercase();
        if entry == "any" {
            return true;
        }
        let (h, p) = match entry.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => return false,
        };
        let host_ok = h == bind_addr.to_lowercase() || h == "*" || h == "0.0.0.0";
        let port_ok = p == "0" || p.parse::<u32>().ok() == Some(port);
        host_ok && port_ok
    })
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
    child_tx: tokio::sync::mpsc::UnboundedSender<ChildOutputMsg>,
) -> Result<()> {
    session_manager.start_session(sid, work_dir)?;

    if let Some(session) = session_manager.get_session_mut(sid) {
        if let Some(pr) = session.pty_read.take() {
            let tx = child_tx;
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut reader = pr;
                let mut buf = [0u8; 16384];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = tx.send(ChildOutputMsg::Stdout(buf[..n].to_vec())); }
                        Err(_) => break,
                    }
                }
            });
        } else {
        if let Some(stdout) = session.stdout.take() {
            let tx = child_tx.clone();
            tokio::spawn(async move {
                let mut reader = stdout;
                let mut buf = [0u8; 16384];
                loop {
                    use tokio::io::AsyncReadExt;
                    match reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = tx.send(ChildOutputMsg::Stdout(buf[..n].to_vec())); }
                        Err(_) => break,
                    }
                }
            });
        }
        if let Some(stderr) = session.stderr.take() {
            let tx = child_tx;
            tokio::spawn(async move {
                let mut reader = stderr;
                let mut buf = [0u8; 16384];
                loop {
                    use tokio::io::AsyncReadExt;
                    match reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = tx.send(ChildOutputMsg::Stderr(buf[..n].to_vec())); }
                        Err(_) => break,
                    }
                }
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
) -> Result<()> {
    use std::collections::HashMap;
    use tokio::sync::{mpsc, oneshot};
    use ssh_core::channel::ChannelId;

    let aead = transport.client_to_server_cipher.as_ref()
        .map(|c| c.is_aead())
        .unwrap_or(false);

    let svc_request = receive_encrypted_packet_server(stream, transport, false, aead).await?;
    if svc_request.first() != Some(&msg::SSH_MSG_SERVICE_REQUEST) {
        return Err(SshError::Protocol("expected connection service".into()));
    }

    let mut svc_accept = vec![msg::SSH_MSG_SERVICE_ACCEPT];
    SshString::new(msg::SSH_SERVICE_NAME_CONNECTION).encode(&mut svc_accept)?;
    send_encrypted_packet_server(stream, &svc_accept, transport, false, aead).await?;

    let user_info = crate::session::get_user_info(username)?;
    let work_dir = user_info.home_dir.clone();

    let mut channel_manager = ChannelManager::new();
    let mut session_started = false;
    let (child_tx, mut child_rx) = tokio::sync::mpsc::unbounded_channel::<ChildOutputMsg>();
    let mut child_tx = Some(child_tx);

    let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel::<(ChannelId, Vec<u8>)>();
    let (eof_tx, mut eof_rx) = mpsc::unbounded_channel::<ChannelId>();
    let mut pending_open: HashMap<ChannelId, oneshot::Sender<(ChannelId, u32, u32)>> = HashMap::new();
    let mut pending_open_sockets: HashMap<ChannelId, (BoxStream, oneshot::Receiver<(ChannelId, u32, u32)>)> = HashMap::new();
    let mut session_remote_id: Option<ChannelId> = None;
    let mut session_local_id: Option<ChannelId> = None;
    let mut session_is_sftp = false;

    enum ForwardAccept {
        Incoming(u16, TcpStream, std::net::SocketAddr),
    }
    let (fwd_tx, mut fwd_rx) = mpsc::unbounded_channel::<ForwardAccept>();
    let mut forwarded_ports: Vec<u16> = Vec::new();

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

    let mut missed_alive: u32 = 0;
    let alive_interval_ms = config.client_alive_interval.saturating_mul(1000);
    let alive_enabled = alive_interval_ms > 0;
    let mut alive_sleep: std::pin::Pin<Box<tokio::time::Sleep>> =
        Box::pin(tokio::time::sleep(tokio::time::Duration::from_millis(alive_interval_ms.max(1) as u64)));
    let mut rekey_sleep: std::pin::Pin<Box<tokio::time::Sleep>> =
        Box::pin(tokio::time::sleep(tokio::time::Duration::from_secs(60)));
    let mut exit_poll: std::pin::Pin<Box<tokio::time::Sleep>> =
        Box::pin(tokio::time::sleep(tokio::time::Duration::from_millis(50)));

    'conn: loop {
        tokio::task::yield_now().await;
        let tb = transport.total_bytes();
        let el = transport.last_rekey_instant.elapsed().as_secs();
        let server_should_rekey = transport.needs_rekey(tb, el);

        if server_should_rekey && matches!(transport.state, ssh_core::transport::KexState::Established) {
            match perform_rekey_server(stream, transport, config, host_keys, None).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!("server-initiated rekey failed: {:?}", e);
                }
            }
        }

        tokio::select! {
            biased;

            () = &mut rekey_sleep => {
                rekey_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(60));
            }

            () = &mut exit_poll, if session_started => {
                if let Some(sid) = session_manager.first_session_id() {
                    if let Some(code) = session_manager.check_exit_status(sid) {
                        let remote = session_remote_id.unwrap_or(0);
                        let mut exit_msg = vec![msg::SSH_MSG_CHANNEL_REQUEST];
                        remote.encode(&mut exit_msg)?;
                        SshString::new("exit-status").encode(&mut exit_msg)?;
                        exit_msg.push(0);
                        (code as u32).encode(&mut exit_msg)?;
                        send_encrypted_packet_server(stream, &exit_msg, transport, false, aead).await?;
                        let close_msg = vec![msg::SSH_MSG_CHANNEL_CLOSE, 0, 0, 0, 0];
                        send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                        break 'conn;
                    }
                }
                exit_poll.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(50));
            }

            to_client = to_client_rx.recv() => {
                if let Some((remote_id, data)) = to_client {
                    let msg = build_channel_data(remote_id, &data);
                    let _ = send_encrypted_packet_server(stream, &msg, transport, false, aead).await;
                }
            }

            eof_ev = eof_rx.recv() => {
                if let Some(remote_id) = eof_ev {
                    let eof_msg = build_channel_eof(remote_id);
                    let _ = send_encrypted_packet_server(stream, &eof_msg, transport, false, aead).await;
                    let close_msg = build_channel_close(remote_id);
                    let _ = send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await;
                }
            }

            fwd_ev = fwd_rx.recv(), if !forwarded_ports.is_empty() => {
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

            agent_ev = agent_rx.recv(), if agent_sock_path.is_some() => {
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

            x11_ev = x11_rx.recv(), if x11_enabled => {
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

            child_msg = child_rx.recv() => {
                match child_msg {
                    Some(ChildOutputMsg::Stdout(data)) => {
                        let remote = session_remote_id.unwrap_or(0);
                        let mut channel_data = vec![msg::SSH_MSG_CHANNEL_DATA];
                        remote.encode(&mut channel_data)?;
                        SshBytes(data).encode(&mut channel_data)?;
                        send_encrypted_packet_server(stream, &channel_data, transport, false, aead).await?;
                    }
                    Some(ChildOutputMsg::Stderr(data)) => {
                        let remote = session_remote_id.unwrap_or(0);
                        let mut channel_data = vec![msg::SSH_MSG_CHANNEL_EXTENDED_DATA];
                        remote.encode(&mut channel_data)?;
                        1u32.encode(&mut channel_data)?;
                        SshBytes(data).encode(&mut channel_data)?;
                        send_encrypted_packet_server(stream, &channel_data, transport, false, aead).await?;
                    }
                    Some(ChildOutputMsg::Exit(code)) => {
                        let remote = session_remote_id.unwrap_or(0);
                        let mut exit_msg = vec![msg::SSH_MSG_CHANNEL_REQUEST];
                        remote.encode(&mut exit_msg)?;
                        SshString::new("exit-status").encode(&mut exit_msg)?;
                        exit_msg.push(0);
                        (code as u32).encode(&mut exit_msg)?;
                        send_encrypted_packet_server(stream, &exit_msg, transport, false, aead).await?;

                        let close_msg = build_channel_close(remote);
                        send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                        break 'conn;
                    }
                    None => {
                        if session_started {
                            if let Some(sid) = session_manager.first_session_id() {
                                if let Some(code) = session_manager.check_exit_status(sid) {
                                    let remote = session_remote_id.unwrap_or(0);
                                    let mut exit_msg = vec![msg::SSH_MSG_CHANNEL_REQUEST];
                                    remote.encode(&mut exit_msg)?;
                                    SshString::new("exit-status").encode(&mut exit_msg)?;
                                    exit_msg.push(0);
                                    (code as u32).encode(&mut exit_msg)?;
                                    send_encrypted_packet_server(stream, &exit_msg, transport, false, aead).await?;
                                }
                            }
                            let close_msg = vec![msg::SSH_MSG_CHANNEL_CLOSE, 0, 0, 0, 0];
                            send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                            break 'conn;
                        }
                    }
                }
            }

            _ = &mut alive_sleep, if alive_enabled => {
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

            packet = receive_encrypted_packet_server(stream, transport, false, aead) => {
                let packet = packet?;
                if packet.is_empty() {
                    continue;
                }

                match packet[0] {
                    msg::SSH_MSG_KEXINIT => {
                        match perform_rekey_server(stream, transport, config, host_keys, Some(packet)).await {
                            Ok(()) => {}
                            Err(e) => {
                                tracing::warn!("client-initiated rekey failed: {:?}", e);
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

                                if !forward_policy_allows_remote(&config, &bind_addr, bind_port)
                                    || !forward_policy_allows_listen(&config, &bind_addr, bind_port)
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
                                        tokio::spawn(async move {
                                            loop {
                                                match listener.accept().await {
                                                    Ok((s, p)) => {
                                                        if tx.send(ForwardAccept::Incoming(actual_port, s, p)).is_err() { break; }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });
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
                                if want_reply {
                                    let succ = vec![msg::SSH_MSG_REQUEST_SUCCESS];
                                    send_encrypted_packet_server(stream, &succ, transport, false, aead).await?;
                                }
                            }
                            "no-more-sessions@openssh.com" => {
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
                                channel_manager.set_remote_id(recipient, sender);
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
                        }
                    }
                    msg::SSH_MSG_CHANNEL_OPEN => {
                        let (channel_type, sender_channel, _window_size, _max_packet) = parse_channel_open(&packet)?;

                        match channel_type.as_str() {
                            t if t == msg::SSH_CHANNEL_TYPE_SESSION => {
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
                                channel_manager.set_remote_id(local_channel, sender_channel);
                                session_remote_id = Some(sender_channel);
                                session_local_id = Some(local_channel);
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
                                if !forward_policy_allows_direct(&config, &host, port) {
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
                                        channel_manager.set_remote_id(local_channel, sender_channel);
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
                        let (channel_id, data) = parse_channel_data(&packet)?;
                        let local_channel = channel_manager.find_by_remote_id(channel_id)
                            .map(|c| c.local_id);
                        if let Some(local_id) = local_channel {
                            if let Some(ch) = channel_manager.get_channel(local_id) {
                                if ch.channel_type == "session" && !session_is_sftp {
                                    if let Some(sid) = session_manager.first_session_id() {
                                        if let Some(session) = session_manager.get_session_mut(sid) {
                                            if let Some(ref mut pw) = session.pty_write {
                                                let _ = pw.write_all(&data).await;
                                            } else if let Some(ref mut stdin) = session.stdin {
                                                let _ = stdin.write_all(&data).await;
                                            }
                                        }
                                    }
                                } else {
                                    if let Some(tx) = &ch.data_tx { let _ = tx.try_send(data); }
                                }
                            }
                        }
                    }
                    msg::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                        let mut r = &packet[1..];
                        let remote = u32::decode(&mut r)?;
                        let dt = u32::decode(&mut r)?;
                        let data = SshBytes::decode(&mut r)?.0;
                        if Some(remote) == session_remote_id {
                            if dt == 1 {
                                use std::io::Write;
                                let _ = std::io::stderr().write_all(&data);
                            }
                        }
                    }
                    msg::SSH_MSG_CHANNEL_REQUEST => {
                        let (channel_id, request_type, want_reply) = parse_channel_request(&packet)?;

                        let local_channel = channel_manager.find_by_remote_id(channel_id)
                            .map(|c| c.local_id);

                        if let Some(_local_id) = local_channel {
                            let extra_offset = 10 + request_type.len();
                            let mut r = &packet[extra_offset..];
                            match request_type.as_str() {
                                "pty-req" => {
                                    let term = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let width = u32::decode(&mut r)?;
                                    let height = u32::decode(&mut r)?;
                                    let _pixel_width = u32::decode(&mut r)?;
                                    let _pixel_height = u32::decode(&mut r)?;

                                    let _sid = session_manager.create_session(
                                        username.to_string(),
                                        true,
                                        term,
                                        width,
                                        height,
                                    );

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "env" => {
                                    let name = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let value = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let sid = session_manager.first_session_id().unwrap_or_else(|| {
                                        session_manager.create_session(username.to_string(), false, "dumb".to_string(), 80, 24)
                                    });
                                    session_manager.set_env_var(sid, name, value);
                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "exec" => {
                                    let command = SshString::decode(&mut r)?.as_str()?.to_string();
                                    let command = config.force_command.clone().unwrap_or(command);

                                    let sid = session_manager.first_session_id().unwrap_or_else(|| {
                                        session_manager.create_session(username.to_string(), false, "dumb".to_string(), 80, 24)
                                    });
                                    session_manager.set_command(sid, command.clone());
                                    if let Err(e) = start_session_and_readers(session_manager, sid, &work_dir, child_tx.take().unwrap()) {
                                        tracing::error!("Failed to start session: {}", e);
                                    }
                                    session_started = true;

                                    if want_reply {
                                        let reply = build_channel_success(channel_id);
                                        send_encrypted_packet_server(stream, &reply, transport, false, aead).await?;
                                    }
                                }
                                "shell" => {
                                    if let Some(sid) = session_manager.first_session_id() {
                                        if session_manager.get_session(sid)
                                            .map(|s| s.command.is_none() && s.child.is_none())
                                            .unwrap_or(false)
                                        {
                                            if let Err(e) = start_session_and_readers(session_manager, sid, &work_dir, child_tx.take().unwrap()) {
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
                                        if let Some(sid) = session_manager.first_session_id() {
                                            session_manager.set_env_var(sid, name, value);
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

                                    if config.x11_forwarding {
                                        if let Some(sid) = session_manager.first_session_id() {
                                            let display = format!("localhost:{}", config.x11_display_offset);
                                            session_manager.set_env_var(sid, "DISPLAY".to_string(), display);
                                        }
                                        if !x11_enabled {
                                            let x11_port = 6000u16 + config.x11_display_offset as u16;
                                            match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", x11_port)).await {
                                                Ok(listener) => {
                                                    x11_enabled = true;
                                                    let tx = x11_tx.clone();
                                                    tokio::spawn(async move {
                                                        loop {
                                                            match listener.accept().await {
                                                                Ok((s, p)) => {
                                                                    if tx.send(X11Accept::Incoming(s, p)).is_err() { break; }
                                                                }
                                                                Err(_) => break,
                                                            }
                                                        }
                                                    });
                                                }
                                                Err(e) => {
                                                    tracing::warn!("x11 listener bind on {} failed: {}", x11_port, e);
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
                                    if config.allow_agent_forwarding {
                                        let sid = session_manager.first_session_id().unwrap_or_else(|| {
                                            session_manager.create_session(username.to_string(), false, "dumb".to_string(), 80, 24)
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

                                    if let Some(sid) = session_manager.first_session_id() {
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
                                            session_is_sftp = true;
                                            if let Some(sid) = session_manager.first_session_id() {
                                                session_manager.set_command(sid, subsystem_path.clone());
                                            }
                                            if let Some(local_id) = session_local_id {
                                                if let Some(remote_id) = session_remote_id {
                                                    if let Some(rx) = channel_manager.take_data_rx(local_id) {
                                                        let tx_ret = to_client_tx.clone();
                                                        let base = std::path::PathBuf::from(&work_dir);
                                                        tokio::spawn(async move {
                                                            run_internal_sftp(rx, remote_id, tx_ret, base).await;
                                                        });
                                                    }
                                                }
                                            }
                                            session_started = true;
                                        } else if let Some(sid) = session_manager.first_session_id() {
                                            session_manager.set_command(sid, subsystem_path.clone());
                                            if let Some(tx) = child_tx.take() {
                                                if let Err(e) = start_session_and_readers(session_manager, sid, &work_dir, tx) {
                                                    tracing::error!("Failed to start subsystem {}: {}", subsystem_name, e);
                                                }
                                                session_started = true;
                                            }
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
                                    if let Some(sid) = session_manager.first_session_id() {
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
                                                        libc::kill(pid as i32, signal);
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
                        let channel_id = u32::decode(&mut r)?;
                        if !session_is_sftp {
                            if let Some(sid) = session_manager.first_session_id() {
                                if let Some(session) = session_manager.get_session_mut(sid) {
                                    session.stdin.take();
                                }
                            }
                        }
                        // For non-session channels (direct-tcpip etc), drop data_tx
                        // so pump_socket's channel_rx returns None and shuts down the TCP socket
                        if let Some(local_id) = channel_manager.find_by_remote_id(channel_id).map(|c| c.local_id) {
                        if let Some(ch) = channel_manager.get_channel_mut(local_id) {
                            if ch.channel_type != "session" {
                                ch.data_tx.take();
                                }
                            }
                        }
                    }
                    msg::SSH_MSG_CHANNEL_CLOSE => {
                        let mut r = &packet[1..];
                        let channel_id = u32::decode(&mut r)?;
                        let close_msg = build_channel_close(channel_id);
                        send_encrypted_packet_server(stream, &close_msg, transport, false, aead).await?;
                    }
                    msg::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                        let mut r = &packet[1..];
                        let _channel_id = u32::decode(&mut r)?;
                        let _amount = u32::decode(&mut r)?;
                    }
                    msg::SSH_MSG_DISCONNECT => {
                        break 'conn;
                    }
                    _ => {
                        let seq = transport.incoming_seq.saturating_sub(1) as u32;
                        send_encrypted_packet_server(stream, &build_unimplemented(seq), transport, false, aead).await?;
                    }
                }
            }
        }
    }

    Ok(())
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

async fn handle_session_data(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    remote_channel: u32,
    local_channel: u32,
    data: &[u8],
    session_manager: &mut SessionManager,
    channel_manager: &ChannelManager,
    username: &str,
    work_dir: &str,
    aead: bool,
) -> Result<()> {
    if let Some(sid) = session_manager.first_session_id() {
        if let Some(session) = session_manager.get_session_mut(sid) {
            if let Some(ref mut child) = session.child {
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(data).await.map_err(|e| SshError::Io(e))?;
                }
            }
        }
    }

    Ok(())
}

async fn send_raw_packet(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let base = 1 + payload.len();
    let remainder = base % 8;
    let mut padding_len = if remainder == 0 { 0 } else { 8 - remainder };
    if padding_len < 4 { padding_len += 8; }
    // OpenSSH-compatible: packet_length field value includes its own 4 bytes
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

async fn receive_raw_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;

    // Try compatible parse:
    // Case A (OpenSSH): total_len includes own 4 bytes → body_len = total_len - 4
    // Case B (RFC literal): total_len excludes own 4 bytes → body_len = total_len
    let (body_len, used_total_len) = if total_len >= 12 && total_len % 8 == 4 {
        (total_len - 4, true)
    } else if total_len >= 12 && total_len % 8 == 0 {
        (total_len, false)
    } else {
        // Fallback: heuristic: if total_len < 12 probably invalid, take total_len-4 if >=12 else total_len
        if total_len >= 12 { (total_len - 4, true) } else { (total_len, false) }
    };

    if body_len < 5 {
        return Err(SshError::InvalidPacket(format!("invalid body size: {} (total_len={} used_total_included_self={})", body_len, total_len, used_total_len)));
    }
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

async fn send_encrypted_packet_server(
    stream: &mut TcpStream,
    payload: &[u8],
    transport: &mut SshTransport,
    _is_new_keys: bool,
    aead: bool,
) -> Result<()> {
    let block_size = if aead { 8 } else {
        transport.server_to_client_cipher.as_ref()
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
        if let Some(ref mut cipher) = transport.server_to_client_cipher {
            let plaintext = packet[4..].to_vec();
            let ciphertext = cipher.encrypt(seq, &plaintext)?;
            packet.truncate(4);
            packet.extend_from_slice(&ciphertext);
        }
    } else {
        if let Some(ref mut cipher) = transport.server_to_client_cipher {
            let plaintext = packet[4..].to_vec();
            let ciphertext = cipher.encrypt(seq, &plaintext)?;
            packet.truncate(4);
            packet.extend_from_slice(&ciphertext);
        }
    }

    if let Some(ref mac) = transport.server_to_client_mac {
        if mac.tag_len() > 0 {
            let mac_data = &packet[4..];
            let tag = mac.compute_tag(seq, mac_data)?;
            packet.extend_from_slice(&tag);
        }
    }

    stream.write_all(&packet).await?;
    stream.flush().await?;
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
        if let Some(ref mut cipher) = transport.client_to_server_cipher {
            let decrypted = cipher.decrypt(seq, &body)?;
            body = decrypted;
        }
    } else {
        if let Some(ref mut cipher) = transport.client_to_server_cipher {
            let decrypted = cipher.decrypt(seq, &body)?;
            body = decrypted;
        }
    }

    if let Some(ref mac) = transport.client_to_server_mac {
        if mac.tag_len() > 0 {
            let mut tag_buf = vec![0u8; mac.tag_len()];
            stream.read_exact(&mut tag_buf).await?;
            if !mac.verify_tag(seq, &ciphertext, &tag_buf)? {
                return Err(SshError::DecryptionFailed);
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
        buf.clear();
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
                    let cap = len.min(256 * 1024);
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
                                    {
                                        use std::os::unix::fs::MetadataExt;
                                        let is_dir = m.is_dir();
                                        let perms = m.mode() & 0o7777;
                                        format!("{}{:o} {} {} {} {} {} {}",
                                            if is_dir { 'd' } else { '-' },
                                            perms, 1u32, m.uid(), m.gid(), m.len(), "Jan  1 00:00", name)
                                    }
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
                    let link = SshString::decode(&mut r).ok().and_then(sftp_string);
                    let target = SshString::decode(&mut r).ok().and_then(sftp_string);
                    match (link, target) {
                        (Some(lp), Some(tp)) => {
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
                                use std::os::unix::fs::MetadataExt;
                                match path {
                                    Some(p) => {
                                        let meta = std::fs::metadata(&p);
                                        let reply = match meta {
                                            Ok(m) => {
                                                let bsize = 4096u64;
                                                let frsize = 4096u64;
                                                let blocks = m.blocks() * 512 / frsize;
                                                let bfree = blocks;
                                                let bavail = blocks;
                                                let files = 0u64;
                                                let ffree = 0u64;
                                                let favail = 0u64;
                                                let fsid = 0u64;
                                                let flag = 0u64;
                                                let namemax = 255u32;
                                                let mut rp = Vec::new();
                                                rp.extend(bsize.to_be_bytes());
                                                rp.extend(frsize.to_be_bytes());
                                                rp.extend(blocks.to_be_bytes());
                                                rp.extend(bfree.to_be_bytes());
                                                rp.extend(bavail.to_be_bytes());
                                                rp.extend(files.to_be_bytes());
                                                rp.extend(ffree.to_be_bytes());
                                                rp.extend(favail.to_be_bytes());
                                                rp.extend(fsid.to_be_bytes());
                                                rp.extend(flag.to_be_bytes());
                                                rp.extend(namemax.to_be_bytes());
                                                rp
                                            }
                                            Err(_) => Vec::new(),
                                        };
                                        if reply.is_empty() {
                                            send_raw(&to_client_tx, remote_id, &status_pkt(id, SSH_FX_FAILURE, "statvfs failed"));
                                        } else {
                                            let mut out = vec![SSH_FXP_EXTENDED_REPLY];
                                            out.extend(id.to_be_bytes());
                                            out.extend(reply);
                                            send_raw(&to_client_tx, remote_id, &out);
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
                            // max packet size, max read length, max write length, max open handles
                            rp.extend((256u64 * 1024 * 1024).to_be_bytes());
                            rp.extend((256u64 * 1024 * 1024).to_be_bytes());
                            rp.extend((256u64 * 1024 * 1024).to_be_bytes());
                            rp.extend(0u32.to_be_bytes());
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

async fn perform_rekey_server(
    stream: &mut TcpStream,
    transport: &mut SshTransport,
    config: &ServerConfig,
    host_keys: &Arc<Mutex<HostKeyManager>>,
    pre_received_client_kex: Option<Vec<u8>>,
) -> Result<()> {
    use ssh_core::transport::KexState;
    if transport.state != KexState::Established { return Ok(()); }
    transport.state = KexState::RekeyInProgress;

    let aead = transport.client_to_server_cipher.as_ref().map(|c| c.is_aead()).unwrap_or(false);

    let hk = host_keys.lock().await;
    let negotiation_pre = {
        let sk = transport.prepare_rekey();
        let c_kex_init = if pre_received_client_kex.is_none() {
            send_encrypted_packet_server(stream, &sk, transport, false, aead).await?;
            let p = receive_encrypted_packet_server(stream, transport, false, aead).await?;
            if p.first() != Some(&msg::SSH_MSG_KEXINIT) {
                return Err(SshError::KexFailed("expected KEXINIT during rekey".into()));
            }
            p
        } else {
            send_encrypted_packet_server(stream, &sk, transport, false, aead).await?;
            let p = pre_received_client_kex.unwrap();
            if p.first() != Some(&msg::SSH_MSG_KEXINIT) {
                return Err(SshError::KexFailed("expected KEXINIT in pre-received rekey".into()));
            }
            p
        };
        transport.client_kex_init = c_kex_init.clone();
        let neg = SshTransport::negotiate_algorithms(&transport.client_kex_init, &transport.server_kex_init)?;
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
            let (min, nbits, max) = match req.first() {
                Some(&msg::SSH_MSG_KEX_DH_GEX_REQUEST_OLD) => {
                    let mut r = &req[1..];
                    let nbits32 = u32::decode(&mut r)?;
                    (2048u32, nbits32, 4096u32)
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
            let group_p = ssh_core::kex::ModpKex::group14_p();
            let group_g = ssh_core::kex::ModpKex::group14_g();
            let mut group_msg = Vec::new();
            group_msg.push(msg::SSH_MSG_KEX_DH_GEX_GROUP);
            SshMpInt(group_p.clone()).encode(&mut group_msg)?;
            SshMpInt(group_g.clone()).encode(&mut group_msg)?;
            send_encrypted_packet_server(stream, &group_msg, transport, false, aead).await?;

            let init = receive_encrypted_packet_server(stream, transport, false, aead).await?;
            if init.first() != Some(&msg::SSH_MSG_KEX_DH_GEX_INIT) {
                return Err(SshError::Protocol("expected DH GEX INIT".into()));
            }
            let mut r = &init[1..];
            let client_pub = SshMpInt::decode(&mut r)?.0;

            let p_bu = num_bigint::BigUint::from_bytes_be(&group_p);
            let g_bu = num_bigint::BigUint::from_bytes_be(&group_g);
            let mut am = ssh_core::kex::ModpKex::with_params(gex_name, gex_hash, p_bu, g_bu, if gex_hash == "sha256" { 512 } else { 256 });
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
            if client_init.first() != Some(&msg::SSH_MSG_KEXDH_INIT) {
                return Err(SshError::Protocol("expected SSH_MSG_KEXDH_INIT".into()));
            }
            let mut r = &client_init[1..];
            let client_pub = SshBytes::decode(&mut r)?.0;

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
            );
            let sig = selected_signer.sign(&exch_hash)?;
            let sig_blob = SshBytes(sig).0;
            let mut dh_reply = Vec::new();
            dh_reply.push(msg::SSH_MSG_KEXDH_REPLY);
            SshBytes(hostkey_blob).encode(&mut dh_reply)?;
            SshBytes(server_pub).encode(&mut dh_reply)?;
            SshBytes(sig_blob).encode(&mut dh_reply)?;
            send_encrypted_packet_server(stream, &dh_reply, transport, false, aead).await?;

            (shared, exch_hash, hash_name)
        };

    let session_id = transport.session_id.clone().unwrap_or_default();
    transport.install_new_keys(&negotiation, &kex_hash_name, &shared_secret, &exchange_hash, &session_id)?;

    let newkeys_send = vec![msg::SSH_MSG_NEWKEYS];
    send_encrypted_packet_server(stream, &newkeys_send, transport, true, aead).await?;
    transport.state = KexState::NewKeysSent;

    let nk = receive_encrypted_packet_server(stream, transport, true, aead).await?;
    if nk.first() != Some(&msg::SSH_MSG_NEWKEYS) {
        return Err(SshError::Protocol("expected NEWKEYS during rekey".into()));
    }
    transport.state = KexState::NewKeysReceived;
    transport.kex_algorithm = Some(kex);
    transport.state = KexState::Established;
    transport.last_rekey_bytes = transport.total_bytes();
    transport.last_rekey_instant = std::time::Instant::now();
    Ok(())
}
