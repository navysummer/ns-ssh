mod config;
mod hostkey;
mod auth;
mod session;
mod server;

use config::ServerConfig;
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

    let log_level = if args.debug || args.log_to_stderr {
        "debug"
    } else {
        "info"
    };

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let mut config = if let Some(ref path) = args.config_file {
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
                "hostkey" | "host_key" => {
                    config.host_key_files.push(value.to_string());
                }
                "passwordauthentication" | "password_auth" => {
                    config.password_auth = value == "yes";
                }
                "kbdinteractiveauthentication" | "keyboardinteractive" | "kbd_interactive_auth" => {
                    config.kbd_interactive_auth = value == "yes";
                }
                "pubkeyauthentication" | "pubkey_auth" => {
                    config.pubkey_auth = value == "yes";
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
                "allowagentforwarding" | "allow_agent_forwarding" => {
                    config.allow_agent_forwarding = value == "yes";
                }
                "x11forwarding" | "x11_forwarding" => {
                    config.x11_forwarding = value == "yes";
                }
                "x11displayoffset" | "x11_display_offset" => {
                    if let Ok(v) = value.parse() {
                        config.x11_display_offset = v;
                    }
                }
                "forcecommand" | "force_command" => {
                    config.force_command = Some(value.to_string());
                }
                "acceptenv" | "accept_env" => {
                    config.accept_env.push(value.to_string());
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
                _ => {}
            }
        }

        if args.gateway_ports && config.gateway_ports != "no" {
            // -g is a no-op unless the config already allows remote forwards;
            // when set, permit binding to all interfaces like "yes".
            config.gateway_ports = "yes".to_string();
        }
    }

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
