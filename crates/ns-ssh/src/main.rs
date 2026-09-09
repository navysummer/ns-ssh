mod config;
mod agent;
mod client;
mod scp;
mod sftp;

use config::ResolvedConfig;
use config::parse_stdio_forward;
use clap::Parser;

#[derive(Parser)]
#[command(name = "ns-ssh")]
#[command(about = "Secure Shell Client - Pure Rust SSH implementation")]
#[command(version)]
struct SshArgs {
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

    #[arg(short = 'T', long)]
    disable_tty: bool,

    #[arg(short = 'X', long)]
    forward_x11: bool,

    #[arg(short = 'Y', long)]
    forward_x11_trusted: bool,

    #[arg(short = 'b', long)]
    bind_address: Option<String>,

    #[arg(short = 'G', long)]
    print_config: bool,

    #[arg(short = 'N')]
    no_remote_command: bool,

    #[arg(short = '4')]
    prefer_ipv4: bool,

    #[arg(short = '6')]
    prefer_ipv6: bool,

    #[arg(short = 'q')]
    quiet: bool,

    #[arg(short = 'e', default_value = "~")]
    escape_char: String,

    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short = 'W', value_parser = parse_stdio_forward)]
    stdio_forward: Option<(String, u16)>,

    #[arg(short = 's', long)]
    subsystem: Option<String>,

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
    let invoked_as_scp = std::env::args_os().next()
        .map(|a| {
            let name = std::path::PathBuf::from(a);
            let base = name.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
            base == "scp" || base == "ns-scp"
        })
        .unwrap_or(false);

    let invoked_as_sftp = std::env::args_os().next()
        .map(|a| {
            let name = std::path::PathBuf::from(a);
            let base = name.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
            base == "sftp" || base == "ns-sftp"
        })
        .unwrap_or(false);

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    // If invoked as "scp" or "ns-scp", route to the SCP subcommand with
    // manual argument parsing (the scp flag set is incompatible with clap).
    if invoked_as_scp {
        let code = run_scp_mode();
        std::process::exit(code);
    }

    // If invoked as "sftp" or "ns-sftp", route to the SFTP subcommand.
    if invoked_as_sftp {
        let code = run_sftp_mode();
        std::process::exit(code);
    }

    let args = SshArgs::parse();

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

    if args.disable_tty {
        config.request_tty = false;
    }

    if args.forward_x11 || args.forward_x11_trusted {
        config.forward_x11 = true;
    }

    if !args.forward_x11_trusted {
        // -Y sets trusted; -X sets untrusted; for simplicity both enable forwarding
    }

    if let Some(bind) = args.bind_address.clone() {
        config.bind_address = Some(bind);
    }

    if let Some(ref proxy) = args.proxy_jump {
        config.proxy_jump = Some(proxy.clone());
    }

    if args.agent_forwarding {
        config.forward_agent = true;
    }

    if args.prefer_ipv4 {
        config.prefer_ipv4 = true;
    }
    if args.prefer_ipv6 {
        config.prefer_ipv6 = true;
    }
    if args.quiet {
        config.quiet = true;
    }
    config.verbosity = args.verbose;
    if args.escape_char != "~" {
        config.escape_char = args.escape_char.clone();
    }
    if let Some((host, port)) = args.stdio_forward {
        config.stdio_forward = Some((host, port));
    }
    if let Some(ref sub) = args.subsystem {
        config.subsystem = Some(sub.clone());
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

    if args.print_config {
        print_effective_config(&config);
        std::process::exit(0);
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

    let force_tty = args.force_tty && !args.disable_tty;
    let code = client::run_client(config, remote_command, force_tty);
    std::process::exit(code);
}

fn print_effective_config(cfg: &ResolvedConfig) {
    let yesno = |b: bool| if b { "yes" } else { "no" };
    println!("hostname {}", cfg.hostname);
    println!("port {}", cfg.port);
    println!("user {}", cfg.user);
    if let Some(i) = &cfg.identity_file {
        println!("identityfile {}", i.display());
    }
    println!("identitiesonly {}", yesno(cfg.identities_only));
    println!("forwardagent {}", yesno(cfg.forward_agent));
    println!("forwardx11 {}", yesno(cfg.forward_x11));
    println!("compression {}", yesno(cfg.compression));
    println!("stricthostkeychecking {}", yesno(cfg.strict_host_key_checking));
    println!("hashknownhosts {}", yesno(cfg.hash_known_hosts));
    if let Some(p) = &cfg.user_known_hosts_file {
        println!("userknownhostsfile {}", p.display());
    }
    if let Some(p) = &cfg.global_known_hosts_file {
        println!("globalknownhostsfile {}", p.display());
    }
    if let Some(v) = cfg.connect_timeout {
        println!("connecttimeout {}", v);
    }
    if let Some(v) = cfg.server_alive_interval {
        println!("serveraliveinterval {}", v);
    }
    if let Some(v) = cfg.server_alive_count_max {
        println!("serveralivecountmax {}", v);
    }
    println!("batchmode {}", yesno(cfg.batch_mode));
    println!("passwordauthentication {}", yesno(cfg.password_authentication));
    println!("pubkeyauthentication {}", yesno(cfg.pubkey_authentication));
    println!("kbdinteractiveauthentication {}", yesno(cfg.kbd_interactive_authentication));
    if let Some(v) = &cfg.preferred_authentications {
        println!("preferredauthentications {}", v.join(","));
    }
    if let Some(v) = &cfg.host_key_algorithms {
        println!("hostkeyalgorithms {}", v.join(","));
    }
    if let Some(v) = &cfg.kex_algorithms {
        println!("kexalgorithms {}", v.join(","));
    }
    if let Some(v) = &cfg.ciphers {
        println!("ciphers {}", v.join(","));
    }
    if let Some(v) = &cfg.macs {
        println!("macs {}", v.join(","));
    }
    if let Some(v) = &cfg.log_level {
        println!("loglevel {}", v);
    }
    println!("exitonforwardfailure {}", yesno(cfg.exit_on_forward_failure));
    if !cfg.send_env.is_empty() {
        println!("sendenv {}", cfg.send_env.join(" "));
    }
    for (k, v) in &cfg.set_env {
        println!("setenv {}={}", k, v);
    }
    if let Some(p) = &cfg.proxy_jump {
        println!("proxyjump {}", p);
    }
    if let Some(p) = &cfg.proxy_command {
        println!("proxycommand {}", p);
    }
    if let Some(b) = &cfg.bind_address {
        println!("bindaddress {}", b);
    }
    for (port, host, lport) in &cfg.local_forwards {
        println!("localforward {} {} {}", port, host, lport);
    }
    for (port, host, lport) in &cfg.remote_forwards {
        println!("remoteforward {} {} {}", port, host, lport);
    }
    for port in &cfg.dynamic_forwards {
        println!("dynamicforward {}", port);
    }
    println!("requesttty {}", yesno(cfg.request_tty));
    println!("noremotecommand {}", yesno(cfg.no_remote_command));
    let af = if cfg.prefer_ipv4 { "inet" } else if cfg.prefer_ipv6 { "inet6" } else { "any" };
    println!("addressfamily {}", af);
    println!("escapechar {}", cfg.escape_char);
    if cfg.verbosity > 0 {
        println!("loglevel {}", match cfg.verbosity { 1 => "VERBOSE", 2 => "DEBUG", _ => "DEBUG3" });
    }
    if let Some((ref h, p)) = cfg.stdio_forward {
        println!("stdioforward {}:{}", h, p);
    }
    if let Some(ref s) = cfg.subsystem {
        println!("subsystem {}", s);
    }
    println!("quiet {}", yesno(cfg.quiet));
}

fn run_scp_mode() -> i32 {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    let mut _recursive = false;
    let mut port = None;
    let mut identity = None;
    let mut options: Vec<String> = Vec::new();
    let mut config_file: Option<String> = None;
    let mut login_name: Option<String> = None;
    let mut sources: Vec<String> = Vec::new();
    let mut target: Option<String> = None;

    let mut iter = raw.iter();
    while let Some(arg) = iter.next() {
        if arg == "-r" {
            _recursive = true;
        } else if arg == "-v" || arg == "-q" || arg == "-t" || arg == "-f" {
            // verbose / quiet / remote-side mode flags
        } else if let Some(v) = arg.strip_prefix("-P") {
            if !v.is_empty() {
                if let Ok(p) = v.parse::<u16>() {
                    port = Some(p);
                }
            } else if let Some(next) = iter.next() {
                if let Ok(p) = next.parse::<u16>() {
                    port = Some(p);
                }
            }
        } else if arg == "-P" {
            if let Some(next) = iter.next() {
                if let Ok(p) = next.parse::<u16>() {
                    port = Some(p);
                }
            }
        } else if let Some(v) = arg.strip_prefix("-i") {
            if !v.is_empty() {
                identity = Some(v.to_string());
            }
        } else if arg == "-i" {
            if let Some(next) = iter.next() {
                identity = Some(next.clone());
            }
        } else if let Some(v) = arg.strip_prefix("-o") {
            if !v.is_empty() {
                options.push(v.to_string());
            }
        } else if arg == "-o" {
            if let Some(next) = iter.next() {
                options.push(next.clone());
            }
        } else if let Some(v) = arg.strip_prefix("-F") {
            if !v.is_empty() {
                config_file = Some(v.to_string());
            }
        } else if arg == "-F" {
            if let Some(next) = iter.next() {
                config_file = Some(next.clone());
            }
        } else if let Some(v) = arg.strip_prefix("-l") {
            if !v.is_empty() {
                login_name = Some(v.to_string());
            }
        } else if arg == "-l" {
            if let Some(next) = iter.next() {
                login_name = Some(next.clone());
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            // unknown flag: consume a value token if it does not start with '-'
            if let Some(next) = iter.clone().next() {
                if !next.starts_with('-') {
                    iter.next();
                }
            }
        } else if contains_scp_remote(arg) && target.is_none() && sources.len() == 1 {
            target = Some(arg.clone());
        } else if contains_scp_remote(arg) && target.is_none() && sources.is_empty() {
            // first arg is remote: keep as source until we see a local target
            sources.push(arg.clone());
        } else {
            sources.push(arg.clone());
        }
    }

    // scp source... target  → if the last remote-looking token is the target,
    // pull it out of sources. Otherwise the single remote token is a source.
    if let Some(t) = target.clone() {
        if let Some(pos) = sources.iter().position(|s| *s == t) {
            sources.remove(pos);
        }
    }

    // Build config from ssh options (used for hostname/user via -o and ~/.ssh/config).
    let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let mut base = ResolvedConfig::default_for_user(&default_user);

    // Decide direction: if exactly one source is a remote path and target is
    // remote, that's an error. Standard scp semantics:
    //   scp local remote           → upload
    //   scp remote local           → download
    let remote_indices: Vec<usize> = sources.iter().enumerate()
        .filter(|(_, s)| contains_scp_remote(s))
        .map(|(i, _)| i)
        .collect();

    let rt = tokio::runtime::Runtime::new().unwrap();

    if remote_indices.len() == 1 {
        let remote_idx = remote_indices[0];
        let remote = &sources[remote_idx];
        let rt_target = parse_scp_remote(remote);
        let (host, remote_path) = match (&rt_target.host, &rt_target.path) {
            (Some(h), Some(p)) => (h.clone(), p.clone()),
            _ => {
                eprintln!("ns-scp: invalid remote path: {}", remote);
                return 1;
            }
        };

        let mut config = base;
        config.hostname = host;
        if let Some(u) = rt_target.user {
            config.user = u;
        }
        if let Some(u) = login_name {
            config.user = u;
        }
        if let Some(p) = port {
            config.port = p;
        }
        if let Some(id) = identity {
            config.identity_file = Some(std::path::PathBuf::from(id));
        }
        if let Some(ref path) = config_file {
            let ssh_cfg = config::SshConfig::load_from(std::path::Path::new(path));
            apply_scp_ssh_config(&ssh_cfg, &mut config);
        }
        for opt in &options {
            let mut it = opt.splitn(2, '=');
            if let (Some(k), Some(v)) = (it.next(), it.next()) {
                match k.to_lowercase().as_str() {
                    "user" => config.user = v.to_string(),
                    "identityfile" | "identity_file" => {
                        config.identity_file = Some(std::path::PathBuf::from(v));
                    }
                    "port" => {
                        if let Ok(p) = v.parse::<u16>() {
                            config.port = p;
                        }
                    }
                    _ => {}
                }
            }
        }

        if remote_idx == 0 {
            // scp remote local  → download
            let local = sources.get(1).cloned().unwrap_or_else(|| ".".to_string());
            return rt.block_on(async move {
                match scp::scp_download(&config, &remote_path, std::path::Path::new(&local)).await {
                    Ok(_) => 0,
                    Err(e) => {
                        eprintln!("ns-scp: download failed: {}", e);
                        1
                    }
                }
            });
        } else {
            // scp local remote  → upload
            let local = &sources[0];
            return rt.block_on(async move {
                let path = std::path::Path::new(local);
                match scp::scp_upload(&config, path, &remote_path).await {
                    Ok(_) => 0,
                    Err(e) => {
                        eprintln!("ns-scp: upload failed: {}", e);
                        1
                    }
                }
            });
        }
    }

    eprintln!("ns-scp: invalid arguments; expected: scp [options] source... target");
    1
}

fn run_sftp_mode() -> i32 {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    let mut port: Option<u16> = None;
    let mut login_name: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut config_file: Option<String> = None;
    let mut options: Vec<String> = Vec::new();
    let mut batch_file: Option<String> = None;
    let mut target: Option<String> = None;

    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "-P" | "-p" => {
                if let Some(v) = raw.get(i + 1) {
                    port = v.parse().ok();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-l" => {
                if let Some(v) = raw.get(i + 1) {
                    login_name = Some(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-i" => {
                if let Some(v) = raw.get(i + 1) {
                    identity = Some(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-F" => {
                if let Some(v) = raw.get(i + 1) {
                    config_file = Some(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-o" => {
                if let Some(v) = raw.get(i + 1) {
                    options.push(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-b" => {
                if let Some(v) = raw.get(i + 1) {
                    batch_file = Some(v.clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-h" | "--help" => {
                println!("usage: sftp [-P port] [-l user] [-i identity] [-F config] [-o option=value] [-b batchfile] host");
                return 0;
            }
            _ => {
                if a.starts_with('-') && a.len() > 1 {
                    eprintln!("ns-sftp: unknown option: {}", a);
                    return 1;
                }
                target = Some(a.clone());
                i += 1;
            }
        }
    }

    let host = match target {
        Some(t) => t,
        None => {
            eprintln!("ns-sftp: no host specified");
            eprintln!("usage: sftp [-P port] [-l user] [-i identity] [-F config] [-o option=value] host");
            return 1;
        }
    };

    let mut config = load_config_for_sftp(&host, &config_file, &options);
    if let Some(u) = login_name {
        config.user = u;
    }
    if let Some(p) = port {
        config.port = p;
    }
    if let Some(id) = identity {
        config.identity_file = Some(std::path::PathBuf::from(id));
    }
    if config.hostname.is_empty() {
        eprintln!("ns-sftp: no hostname specified");
        return 1;
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    if let Some(bf) = batch_file {
        let content = match std::fs::read_to_string(&bf) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("ns-sftp: cannot read batch file {}: {}", bf, e);
                return 1;
            }
        };
        rt.block_on(async move {
            match sftp::run_sftp_batch(&config, &content).await {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("ns-sftp: {}", e);
                    1
                }
            }
        })
    } else {
        rt.block_on(async move {
            match sftp::run_sftp(&config).await {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("ns-sftp: {}", e);
                    1
                }
            }
        })
    }
}

fn load_config_for_sftp(host: &str, config_file: &Option<String>, options: &[String]) -> ResolvedConfig {
    let ssh_config = if let Some(path) = config_file {
        config::SshConfig::load_from(std::path::Path::new(path))
    } else {
        config::SshConfig::load()
    };

    let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let mut resolved = ResolvedConfig::default_for_user(&default_user);

    if let Some((user, hostname)) = host.rsplit_once('@') {
        resolved.user = user.to_string();
        resolved.hostname = hostname.to_string();
    } else {
        resolved.hostname = host.to_string();
    }

    let target = host.rsplit('@').next().unwrap_or(host).to_string();
    let matched: Vec<&config::HostConfig> = ssh_config.hosts.iter()
        .filter(|h| {
            h.host.split(',').map(str::trim).any(|p| {
                p == target
                    || (p.contains('*') && config::glob_match(p, &target))
                    || (p.starts_with('!') && !config::glob_match(&p[1..], &target))
            })
        })
        .collect();
    for h in matched {
        if let Some(hn) = &h.hostname {
            resolved.hostname = hn.clone();
        }
        if let Some(u) = &h.user {
            resolved.user = u.clone();
        }
        if let Some(p) = h.port {
            resolved.port = p;
        }
        if let Some(id) = &h.identity_file {
            resolved.identity_file = Some(std::path::PathBuf::from(id));
        }
        if let Some(v) = h.identities_only {
            resolved.identities_only = v;
        }
        if let Some(v) = h.batch_mode {
            resolved.batch_mode = v;
        }
        if let Some(v) = h.compression {
            resolved.compression = v;
        }
        if let Some(hk) = &h.user_known_hosts_file {
            resolved.user_known_hosts_file = Some(std::path::PathBuf::from(hk));
        }
        if let Some(hk) = &h.global_known_hosts_file {
            resolved.global_known_hosts_file = Some(std::path::PathBuf::from(hk));
        }
        if let Some(v) = h.hash_known_hosts {
            resolved.hash_known_hosts = v;
        }
    }

    for opt in options {
        let opt = opt.trim();
        if let Some((key, value)) = opt.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            match key.as_str() {
                "port" => { if let Ok(p) = value.parse() { resolved.port = p; } }
                "user" => resolved.user = value.to_string(),
                "hostname" => resolved.hostname = value.to_string(),
                "identityfile" | "identity_file" => {
                    resolved.identity_file = Some(std::path::PathBuf::from(value));
                }
                "identitiesonly" | "identities_only" => resolved.identities_only = value != "no",
                "batchmode" | "batch_mode" => resolved.batch_mode = value != "no",
                "compression" => resolved.compression = value != "no",
                "userknownhostsfile" | "user_known_hosts_file" => {
                    resolved.user_known_hosts_file = Some(std::path::PathBuf::from(value));
                }
                "globalknownhostsfile" | "global_known_hosts_file" => {
                    resolved.global_known_hosts_file = Some(std::path::PathBuf::from(value));
                }
                "hashknownhosts" | "hash_known_hosts" => resolved.hash_known_hosts = value != "no",
                "stricthostkeychecking" | "strict_host_key_checking" => {
                    resolved.strict_host_key_checking = value != "no";
                }
                _ => {}
            }
        }
    }

    resolved
}

struct ScpTarget {
    user: Option<String>,
    host: Option<String>,
    path: Option<String>,
}

fn apply_scp_ssh_config(ssh_cfg: &config::SshConfig, config: &mut ResolvedConfig) {
    let hostname = config.hostname.clone();
    let matched: Vec<&config::HostConfig> = ssh_cfg.hosts.iter()
        .filter(|h| {
            h.host.split(',').map(str::trim).any(|p| {
                p == hostname
                    || (p.contains('*') && config::glob_match(p, &hostname))
            })
        })
        .collect();
    for host_cfg in matched {
        if let Some(h) = &host_cfg.hostname {
            config.hostname = h.clone();
        }
        if let Some(u) = &host_cfg.user {
            config.user = u.clone();
        }
        if let Some(id) = &host_cfg.identity_file {
            config.identity_file = Some(std::path::PathBuf::from(id));
        }
    }
}

fn contains_scp_remote(s: &str) -> bool {
    // A remote path looks like [user@]host:path (a single ':' before any '/')
    if let Some(idx) = s.find(':') {
        let before = &s[..idx];
        !before.contains('/')
    } else {
        false
    }
}

fn parse_scp_remote(s: &str) -> ScpTarget {
    let mut target = ScpTarget { user: None, host: None, path: None };
    if let Some(idx) = s.find(':') {
        let (host_part, path) = s.split_at(idx);
        target.path = Some(path[1..].to_string());
        if let Some(at) = host_part.rfind('@') {
            target.user = Some(host_part[..at].to_string());
            target.host = Some(host_part[at + 1..].to_string());
        } else {
            target.host = Some(host_part.to_string());
        }
    }
    target
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
            if let Some(h) = host_config.hash_known_hosts {
                resolved.hash_known_hosts = h;
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
            if let Some(ref b) = host_config.bind_address {
                resolved.bind_address = Some(b.clone());
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
                "hashknownhosts" | "hash_known_hosts" => resolved.hash_known_hosts = value != "no",
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
                "bindaddress" | "bind_address" => resolved.bind_address = Some(value.to_string()),
                "requesttty" | "request_tty" => resolved.request_tty = value != "no",
                "sendenv" | "send_env" => {
                    resolved.send_env = value.split_whitespace().map(|s| s.to_string()).collect();
                }
                "setenv" | "set_env" => {
                    if let Some((k, v)) = value.split_once('=') {
                        resolved.set_env.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
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
