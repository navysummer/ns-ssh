mod config;
mod hostkey;
mod auth;
mod session;
mod server;

use config::ServerConfig;
use config::parse_pubkey_auth_options;
use config::parse_ca_signature_algorithms;
use clap::Parser;

#[derive(Parser)]
#[command(name = "ns-ssh-server")]
#[command(about = "Secure Shell Server - Pure Rust SSH server implementation")]
#[command(version)]
struct SshdArgs {
    #[arg(short, long)]
    config_file: Option<String>,

    #[arg(short, long)]
    port: Option<u16>,

    #[arg(short = 'd')]
    debug: bool,

    #[arg(short = 'D')]
    no_daemon: bool,

    #[arg(short = 'e')]
    log_to_stderr: bool,

    #[arg(short = 'f')]
    config_path: Option<String>,

    #[arg(short = 'g')]
    gateway_ports: bool,

    #[arg(long)]
    host_key_file: Option<String>,

    #[arg(short = 'o', long, action = clap::ArgAction::Append)]
    options: Vec<String>,
}

fn main() {
    let args = SshdArgs::parse();

    let mut config = if let Some(ref path) = args.config_path.or(args.config_file) {
        ServerConfig::load_from(std::path::Path::new(path))
    } else {
        ServerConfig::load()
    };

    if let Some(port) = args.port {
        config.port = port;
    }

    if let Some(ref key_file) = args.host_key_file {
        config.host_key_files = vec![key_file.clone()];
    }

    for opt in &args.options {
        if let Some((key, value)) = opt.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            match key.as_str() {
                "port" => {
                    if let Ok(p) = value.parse() {
                        config.port = p;
                    }
                }
                "listenaddress" | "listen_address" => {
                    config.listen_address = value.to_string();
                }
                "hostkey" | "host_key" | "hostdsakey" => {
                    config.host_key_files.push(value.to_string());
                }
                "hostkeyalgorithms" | "host_key_algorithms" => {
                    config.host_key_algorithms = Some(value.to_string());
                }
                "kexalgorithms" | "kex_algorithms" => {
                    config.kex_algorithms = Some(value.to_string());
                }
                "ciphers" => {
                    config.ciphers = Some(value.to_string());
                }
                "macs" => {
                    config.macs = Some(value.to_string());
                }
                "passwordauthentication" | "password_auth" => {
                    config.password_auth = value == "yes";
                }
                "kbdinteractiveauthentication" | "keyboardinteractive" | "kbd_interactive_auth"
                | "challengeresponseauthentication" | "challenge_response_authentication"
                | "skeyauthentication" => {
                    config.kbd_interactive_auth = value == "yes";
                }
                "pubkeyauthentication" | "pubkey_auth" | "dsaauthentication" => {
                    config.pubkey_auth = value == "yes";
                }
                "pubkeyauthoptions" | "pubkey_auth_options" => {
                    config.pubkey_auth_options =
                        parse_pubkey_auth_options(value).unwrap_or_default();
                }
                "casignaturealgorithms" | "ca_signature_algorithms" => {
                    config.ca_signature_algorithms =
                        parse_ca_signature_algorithms(value).unwrap_or_default();
                }
                "modulifile" | "moduli_file" => {
                    config.moduli_file = Some(value.to_string());
                }
                "permitrootlogin" | "permit_root_login" => {
                    let v = value.to_lowercase();
                    config.permit_root_login_mode = v.clone();
                    config.permit_root_login = v == "yes";
                }
                "authorizedkeysfile" | "authorized_keys_file" => {
                    config.authorized_keys_files.push(value.to_string());
                }
                "allowgroups" | "allow_groups" => {
                    config.allow_groups.extend(value.split_whitespace().map(|s| s.to_string()));
                }
                "denygroups" | "deny_groups" => {
                    config.deny_groups.extend(value.split_whitespace().map(|s| s.to_string()));
                }
                "maxauthtries" | "max_auth_tries" => {
                    if let Ok(v) = value.parse() {
                        config.max_auth_tries = v;
                    }
                }
                "maxsessions" | "max_sessions" => {
                    if let Ok(v) = value.parse() {
                        config.max_sessions = v;
                    }
                }
                "clientaliveinterval" | "client_alive_interval" => {
                    if let Ok(v) = value.parse() {
                        config.client_alive_interval = v;
                    }
                }
                "clientalivecountmax" | "client_alive_count_max" => {
                    if let Ok(v) = value.parse() {
                        config.client_alive_count_max = v;
                    }
                }
                "rekeylimit" | "rekey_limit" => {
                    if let Some((bytes, secs)) = config::parse_rekey_limit_server(value) {
                        config.rekey_limit_bytes = bytes;
                        config.rekey_limit_time = secs;
                    }
                }
                "pubkeyacceptedalgorithms" | "pubkey_accepted_algorithms" | "pubkeyacceptedkeytypes" => {
                    config.pubkey_accepted_algorithms = Some(config::resolve_pubkey_algorithms_server(value));
                }
                "compression" => {
                    config.compression = value == "yes";
                }
                "usedns" | "use_dns" => {
                    config.use_dns = value == "yes";
                }
                "pidfile" | "pid_file" => {
                    config.pid_file = value.to_string();
                }
                "logfile" | "log_file" => {
                    config.log_file = Some(value.to_string());
                }
                "banner" => {
                    config.banner = Some(value.to_string());
                }
                "maxstartups" | "max_startups" => {
                    config.max_startups = value.to_string();
                }
                "logingracetime" | "login_grace_time" => {
                    if let Ok(v) = value.parse() {
                        config.login_grace_time = v;
                    }
                }
                "strictmodes" | "strict_modes" => {
                    config.strict_modes = value == "yes";
                }
                "requiredrsasize" | "required_rsa_size" => {
                    if let Ok(v) = value.parse::<u32>() {
                        config.required_rsa_size = v.max(1024);
                    }
                }
                "authenticationmethods" | "authentication_methods" => {
                    config.authentication_methods = config::parse_authentication_methods(value);
                }
                "channeltimeout" | "channel_timeout" => {
                    config.channel_timeouts = config::parse_channel_timeout(value);
                }
                "permittty" | "permit_tty" => {
                    config.permit_tty = value == "yes";
                }
                "permitemptypasswords" | "permit_empty_passwords" => {
                    config.permit_empty_passwords = value == "yes";
                }
                "ignorerhosts" | "ignore_rhosts" => {
                    config.ignore_rhosts = value == "yes";
                }
                "hostbasedauthentication" | "hostbased_auth" => {
                    config.hostbased_auth = value == "yes";
                }
                "hostbasedacceptedalgorithms" | "hostbased_accepted_algorithms" | "hostbasedacceptedkeytypes" => {
                    config.hostbased_accepted_algorithms = Some(
                        value.split([',', ' ']).filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()
                    );
                }
                "printlastlog" | "print_last_log" => {
                    config.print_last_log = value == "yes";
                }
                "tcpkeepalive" | "tcp_keep_alive" | "keepalive" => {
                    config.tcp_keep_alive = value == "yes";
                }
                "ipqos" | "ip_qos" => {
                    if let Some((i, b)) = config::parse_ipqos(value) {
                        config.ip_qos_interactive = i;
                        config.ip_qos_bulk = b;
                    }
                }
                "allowagentforwarding" | "allow_agent_forwarding" => {
                    config.allow_agent_forwarding = value == "yes";
                }
                "allowstreamlocalforwarding" | "allow_streamlocal_forwarding" => {
                    config.allow_streamlocal_forwarding = value == "yes";
                }
                "x11forwarding" | "x11_forwarding" => {
                    config.x11_forwarding = value == "yes";
                }
                "x11displayoffset" | "x11_display_offset" => {
                    if let Ok(v) = value.parse() {
                        config.x11_display_offset = v;
                    }
                }
                "x11uselocalhost" | "x11_use_localhost" => {
                    config.x11_use_localhost = value == "yes";
                }
                "streamlocalbindmask" | "stream_local_bind_mask" => {
                    if let Ok(v) = u32::from_str_radix(value.trim_start_matches("0o"), 8) {
                        config.stream_local_bind_mask = v;
                    }
                }
                "streamlocalbindunlink" | "stream_local_bind_unlink" => {
                    config.stream_local_bind_unlink = value == "yes";
                }
                "unusedconnectiontimeout" | "unused_connection_timeout" => {
                    config.unused_connection_timeout = crate::config::parse_time_suffix(value).unwrap_or(0);
                }
                "refuseconnection" | "refuse_connection" => {
                    config.refuse_connection = crate::config::parse_refuse_connection(value);
                }
                "permituserrc" | "permit_user_rc" => {
                    config.permit_user_rc = value == "yes";
                }
                "exposeauthinfo" | "expose_auth_info" => {
                    config.expose_auth_info = value == "yes";
                }
                "trustedusercakeys" | "trusted_user_ca_keys" => {
                    config.trusted_user_ca_keys =
                        value.split_whitespace().map(|s| s.to_string()).collect();
                }
                "revokedkeys" | "revoked_keys" => {
                    config.revoked_keys = if value.eq_ignore_ascii_case("none") {
                        None
                    } else {
                        Some(value.to_string())
                    };
                }
                "authorizedprincipalsfile" | "authorized_principals_file" => {
                    config.authorized_principals_file = if value.eq_ignore_ascii_case("none") {
                        None
                    } else {
                        Some(value.to_string())
                    };
                }
                "authorizedprincipalscommand" | "authorized_principals_command" => {
                    config.authorized_principals_command = if value.eq_ignore_ascii_case("none") {
                        None
                    } else {
                        Some(value.to_string())
                    };
                }
                "authorizedprincipalscommanduser" | "authorized_principals_command_user" => {
                    config.authorized_principals_command_user = Some(value.to_string());
                }
                "hostcertificate" | "host_certificate" => {
                    config.host_certificates =
                        value.split_whitespace().map(|s| s.to_string()).collect();
                }
                "persourcemaxstartups" | "per_source_max_startups" => {
                    config.per_source_max_startups = if value.eq_ignore_ascii_case("none") {
                        None
                    } else {
                        value.parse().ok()
                    };
                }
                "persourcenetblocksize" | "per_source_net_block_size" => {
                    if let Some(b) = crate::config::parse_net_block_size(value) {
                        config.per_source_net_block_size = b;
                    }
                }
                "forcecommand" | "force_command" => {
                    config.force_command = Some(value.to_string());
                }
                "acceptenv" | "accept_env" => {
                    // OpenSSH allows whitespace-separated and repeated patterns.
                    config.accept_env.extend(
                        value.split([',', ' ']).filter(|s| !s.is_empty()).map(|s| s.to_string())
                    );
                }
                "setenv" | "set_env" => {
                    if let Ok(pair) = config::parse_set_env(value) {
                        config.set_env.push(pair);
                    }
                }
                "allowtcpforwarding" | "allow_tcp_forwarding" => {
                    config.allow_tcp_forwarding_mode = value.to_lowercase();
                }
                "permitopen" | "permit_open" => {
                    config.permit_open.extend(value.split([',', ' ']).filter(|s| !s.is_empty()).map(|s| s.to_string()));
                }
                "permitlisten" | "permit_listen" => {
                    config.permit_listen.extend(value.split([',', ' ']).filter(|s| !s.is_empty()).map(|s| s.to_string()));
                }
                "gatewayports" | "gateway_ports" => {
                    config.gateway_ports = value.to_lowercase();
                }
                "loglevel" | "log_level" => {
                    config.log_level = Some(value.to_string());
                }
                "authorizedkeyscommand" | "authorized_keys_command" => {
                    config.authorized_keys_command = Some(value.to_string());
                }
                "authorizedkeyscommanduser" | "authorized_keys_command_user" => {
                    config.authorized_keys_command_user = Some(value.to_string());
                }
                _ => {}
            }
        }

        if args.gateway_ports && config.gateway_ports != "no" {
            // -g is a no-op unless the config already allows remote forwards;
            // when set, permit binding to all interfaces like "yes".
            config.gateway_ports = "yes".to_string();
        }
    }

    // Initialize logging after config is loaded so `LogLevel`/`-d`/`-e` apply.
    init_logging(&config, args.debug || args.log_to_stderr);

    if !args.no_daemon && !args.debug {
        if let Err(e) = session::daemonize() {
            eprintln!("ns-ssh-server: failed to daemonize: {}", e);
            std::process::exit(1);
        }
    }

    if let Err(e) = session::write_pid_file(&config.pid_file) {
        eprintln!("Warning: failed to write PID file: {}", e);
    }

    tracing::info!("ns-ssh-server starting on port {}", config.port);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut sshd = server::SshServer::new(config.clone());
        if let Err(e) = sshd.init().await {
            eprintln!("ns-ssh-server: initialization failed: {}", e);
            std::process::exit(1);
        }

        if let Err(e) = sshd.run().await {
            eprintln!("ns-ssh-server: fatal error: {}", e);
            std::process::exit(1);
        }
    });
}

/// Initialize the tracing subscriber, honoring `LogLevel`/`-d`/`-e`/`RUST_LOG`.
fn init_logging(cfg: &ServerConfig, debug_to_stderr: bool) {
    let level = if std::env::var("RUST_LOG").is_ok() {
        "info" // RUST_LOG overrides via EnvFilter::try_from_default_env
    } else if let Some(l) = &cfg.log_level {
        match l.to_uppercase().as_str() {
            "QUIET" | "FATAL" => "error",
            "ERROR" => "error",
            "INFO" => "info",
            "VERBOSE" => "info",
            "DEBUG" | "DEBUG1" | "DEBUG2" => "debug",
            "DEBUG3" => "trace",
            _ => "info",
        }
    } else if debug_to_stderr {
        "debug"
    } else {
        "info"
    };
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();
}
