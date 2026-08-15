mod config;
mod agent;
mod client;
mod scp;

use config::ResolvedConfig;
use clap::Parser;

#[derive(Parser)]
#[command(name = "ns-ssh")]
#[command(about = "Secure Shell Client - Pure Rust SSH implementation")]
#[command(version)]
struct SshArgs {
    #[arg(short, long)]
    verbose: bool,

    #[arg(short = 'p', long)]
    port: Option<u16>,

    #[arg(short = 'l', long)]
    login_name: Option<String>,

    #[arg(short = 'i', long)]
    identity_file: Option<String>,

    #[arg(short = 'o', long, action = clap::ArgAction::Append)]
    options: Vec<String>,

    #[arg(short = 'F', long)]
    config_file: Option<String>,

    #[arg(short = 'C')]
    compression: bool,

    #[arg(short = 'f')]
    fork_to_background: bool,

    #[arg(short = 'n')]
    no_stdin: bool,

    #[arg(short = 't', long)]
    force_tty: bool,

    #[arg(short = 'N')]
    no_remote_command: bool,

    #[arg(short = 'R', long, action = clap::ArgAction::Append)]
    remote_forwards: Vec<String>,

    #[arg(short = 'L', long, action = clap::ArgAction::Append)]
    local_forwards: Vec<String>,

    #[arg(short = 'D', long, action = clap::ArgAction::Append)]
    dynamic_forwards: Vec<String>,

    #[arg(short = 'J', long)]
    proxy_jump: Option<String>,

    #[arg(short = 'A', long)]
    agent_forwarding: bool,

    target: Option<String>,

    command: Vec<String>,
}

fn main() {
    let args = SshArgs::parse();

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let mut config = load_config(&args);

    if let Some(ref target) = args.target {
        parse_target(target, &mut config);
    }

    if let Some(port) = args.port {
        config.port = port;
    }

    if let Some(ref user) = args.login_name {
        config.user = user.clone();
    }

    if let Some(ref identity) = args.identity_file {
        config.identity_file = Some(std::path::PathBuf::from(identity));
    }

    if args.compression {
        config.compression = true;
    }

    if args.force_tty {
        config.request_tty = true;
    }

    if let Some(ref proxy) = args.proxy_jump {
        config.proxy_jump = Some(proxy.clone());
    }

    if args.agent_forwarding {
        config.forward_agent = true;
    }

    for spec in &args.local_forwards {
        if let Some(fwd) = config::parse_forward_spec(spec) {
            config.local_forwards.push(fwd);
        } else {
            eprintln!("ns-ssh: invalid local forward specification: {}", spec);
            std::process::exit(1);
        }
    }

    for spec in &args.remote_forwards {
        if let Some(fwd) = config::parse_forward_spec(spec) {
            config.remote_forwards.push(fwd);
        } else {
            eprintln!("ns-ssh: invalid remote forward specification: {}", spec);
            std::process::exit(1);
        }
    }

    for spec in &args.dynamic_forwards {
        if let Ok(port) = spec.parse::<u16>() {
            config.dynamic_forwards.push(port);
        } else {
            eprintln!("ns-ssh: invalid dynamic forward port: {}", spec);
            std::process::exit(1);
        }
    }

    if args.no_remote_command {
        config.no_remote_command = true;
    }

    if config.hostname.is_empty() {
        eprintln!("ns-ssh: no hostname specified");
        eprintln!("usage: ns-ssh [-p port] [login@]hostname [command]");
        std::process::exit(1);
    }

    let remote_command = if args.command.is_empty() {
        None
    } else {
        Some(args.command.join(" "))
    };

    let code = client::run_client(config, remote_command, args.force_tty);
    std::process::exit(code);
}

fn load_config(args: &SshArgs) -> ResolvedConfig {
    let ssh_config = if let Some(ref path) = args.config_file {
        config::SshConfig::load_from(std::path::Path::new(path))
    } else {
        config::SshConfig::load()
    };

    let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let mut resolved = ResolvedConfig::default_for_user(&default_user);

    if let Some(ref target) = args.target {
        let host_configs: Vec<&config::HostConfig> = ssh_config.hosts.iter().filter(|h| {
            let t = target.as_str();
            h.host.split(',').map(str::trim).any(|p| {
                p == t
                    || (p.contains('*') && config::glob_match(p, t))
                    || (p.starts_with('!') && !config::glob_match(&p[1..], t))
            })
            || config::glob_match(&h.host, t)
            || h.host.as_str() == t
        }).collect();

        for host_config in host_configs {
            if resolved.hostname.is_empty() {
                resolved.hostname = host_config.hostname.clone().unwrap_or_else(|| target.clone());
            } else if let Some(h) = &host_config.hostname {
                resolved.hostname = h.clone();
            }
            if let Some(ref user) = host_config.user {
                resolved.user = user.clone();
            }
            if let Some(port) = host_config.port {
                resolved.port = port;
            }
            if let Some(ref identity) = host_config.identity_file {
                resolved.identity_file = Some(std::path::PathBuf::from(identity));
            }
            if let Some(v) = host_config.identities_only {
                resolved.identities_only = v;
            }
            if let Some(fwd) = host_config.forward_agent {
                resolved.forward_agent = fwd;
            }
            if let Some(x) = host_config.forward_x11 {
                resolved.forward_x11 = x;
            }
            if let Some(c) = host_config.compression {
                resolved.compression = c;
            }
            if let Some(strict) = &host_config.strict_host_key_checking {
                resolved.strict_host_key_checking = strict != "no";
            }
            if let Some(p) = &host_config.user_known_hosts_file {
                resolved.user_known_hosts_file = Some(std::path::PathBuf::from(p));
            }
            if let Some(p) = &host_config.global_known_hosts_file {
                resolved.global_known_hosts_file = Some(std::path::PathBuf::from(p));
            }
            if let Some(v) = host_config.connect_timeout {
                resolved.connect_timeout = Some(v);
            }
            if let Some(v) = host_config.server_alive_interval {
                resolved.server_alive_interval = Some(v);
            }
            if let Some(v) = host_config.server_alive_count_max {
                resolved.server_alive_count_max = Some(v);
            }
            if let Some(v) = host_config.tcp_keep_alive {
                resolved.tcp_keep_alive = v;
            }
            if let Some(v) = host_config.batch_mode {
                resolved.batch_mode = v;
            }
            if let Some(v) = host_config.password_authentication {
                resolved.password_authentication = v;
            }
            if let Some(v) = host_config.pubkey_authentication {
                resolved.pubkey_authentication = v;
            }
            if let Some(v) = host_config.kbd_interactive_authentication {
                resolved.kbd_interactive_authentication = v;
            }
            if let Some(v) = &host_config.preferred_authentications {
                resolved.preferred_authentications = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &host_config.host_key_algorithms {
                resolved.host_key_algorithms = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &host_config.kex_algorithms {
                resolved.kex_algorithms = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &host_config.ciphers {
                resolved.ciphers = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &host_config.macs {
                resolved.macs = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &host_config.log_level {
                resolved.log_level = Some(v.clone());
            }
            if let Some(v) = host_config.exit_on_forward_failure {
                resolved.exit_on_forward_failure = v;
            }
            if let Some(list) = &host_config.send_env {
                resolved.send_env.extend(list.iter().cloned());
            }
            if let Some(list) = &host_config.set_env {
                for s in list {
                    if let Some((k, v)) = s.split_once('=') {
                        resolved.set_env.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
            }
            if let Some(ref proxy) = host_config.proxy_jump {
                resolved.proxy_jump = Some(proxy.clone());
            }
            if let Some(ref p) = host_config.proxy_command {
                resolved.proxy_command = Some(p.clone());
            }
            if let Some(ref tty) = host_config.request_tty {
                resolved.request_tty = tty == "yes" || tty == "force";
            }
            if let Some(ref cmd) = host_config.remote_command {
                resolved.remote_command = Some(cmd.clone());
            }
            if let Some(v) = &host_config.add_keys_to_agent {
                resolved.add_keys_to_agent = v == "yes" || v == "confirm";
            }
            if let Some(list) = &host_config.local_forward {
                for spec in list {
                    if let Some(fwd) = config::parse_forward_spec(spec) {
                        resolved.local_forwards.push(fwd);
                    }
                }
            }
            if let Some(list) = &host_config.remote_forward {
                for spec in list {
                    if let Some(fwd) = config::parse_forward_spec(spec) {
                        resolved.remote_forwards.push(fwd);
                    }
                }
            }
            if let Some(list) = &host_config.dynamic_forward {
                for spec in list {
                    if let Ok(port) = spec.parse::<u16>() {
                        resolved.dynamic_forwards.push(port);
                    } else if let Some(colon) = spec.rfind(':') {
                        if let Ok(port) = spec[colon+1..].parse::<u16>() {
                            resolved.dynamic_forwards.push(port);
                        }
                    }
                }
            }
        }
    }

    for opt in &args.options {
        let opt = opt.trim();
        if let Some((key, value)) = opt.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            match key.as_str() {
                "port" => {
                    if let Ok(p) = value.parse() {
                        resolved.port = p;
                    }
                }
                "user" | "login_name" => resolved.user = value.to_string(),
                "hostname" => resolved.hostname = value.to_string(),
                "identityfile" | "identity_file" => {
                    resolved.identity_file = Some(std::path::PathBuf::from(value));
                }
                "identitiesonly" | "identities_only" => resolved.identities_only = value != "no",
                "stricthostkeychecking" | "strict_host_key_checking" => {
                    resolved.strict_host_key_checking = value != "no";
                }
                "userknownhostsfile" | "user_known_hosts_file" => {
                    resolved.user_known_hosts_file = Some(std::path::PathBuf::from(value));
                }
                "globalknownhostsfile" | "global_known_hosts_file" => {
                    resolved.global_known_hosts_file = Some(std::path::PathBuf::from(value));
                }
                "connecttimeout" | "connect_timeout" => {
                    if let Ok(v) = value.parse::<u32>() { resolved.connect_timeout = Some(v); }
                }
                "serveraliveinterval" | "server_alive_interval" => {
                    if let Ok(v) = value.parse::<u32>() { resolved.server_alive_interval = Some(v); }
                }
                "serveralivecountmax" | "server_alive_count_max" => {
                    if let Ok(v) = value.parse::<u32>() { resolved.server_alive_count_max = Some(v); }
                }
                "batchmode" | "batch_mode" => resolved.batch_mode = value != "no",
                "passwordauthentication" | "password_authentication" => resolved.password_authentication = value != "no",
                "pubkeyauthentication" | "pubkey_authentication" => resolved.pubkey_authentication = value != "no",
                "kbdinteractiveauthentication" | "kbd_interactive_authentication" => resolved.kbd_interactive_authentication = value != "no",
                "preferredauthentications" | "preferred_authentications" => {
                    resolved.preferred_authentications = Some(value.split(',').map(str::trim).map(|s| s.to_string()).collect());
                }
                "hostkeyalgorithms" | "host_key_algorithms" => {
                    resolved.host_key_algorithms = Some(value.split(',').map(str::trim).map(|s| s.to_string()).collect());
                }
                "kexalgorithms" | "kex_algorithms" => {
                    resolved.kex_algorithms = Some(value.split(',').map(str::trim).map(|s| s.to_string()).collect());
                }
                "ciphers" => {
                    resolved.ciphers = Some(value.split(',').map(str::trim).map(|s| s.to_string()).collect());
                }
                "macs" => {
                    resolved.macs = Some(value.split(',').map(str::trim).map(|s| s.to_string()).collect());
                }
                "forwardagent" | "forward_agent" => resolved.forward_agent = value != "no",
                "forwardx11" | "forward_x11" => resolved.forward_x11 = value != "no",
                "compression" => resolved.compression = value != "no",
                "proxyjump" | "proxy_jump" => resolved.proxy_jump = Some(value.to_string()),
                "proxycommand" | "proxy_command" => resolved.proxy_command = Some(value.to_string()),
                "requesttty" | "request_tty" => resolved.request_tty = value != "no",
                "loglevel" | "log_level" => resolved.log_level = Some(value.to_string()),
                "exitonforwardfailure" | "exit_on_forward_failure" => resolved.exit_on_forward_failure = value != "no",
                "remotecommand" | "remote_command" => resolved.remote_command = Some(value.to_string()),
                "addkeystoagent" | "add_keys_to_agent" => resolved.add_keys_to_agent = value != "no",
                _ => {}
            }
        }
    }

    resolved
}

fn parse_target(target: &str, config: &mut ResolvedConfig) {
    if let Some((user, host)) = target.rsplit_once('@') {
        config.user = user.to_string();
        config.hostname = host.to_string();
    } else {
        config.hostname = target.to_string();
    }
}
