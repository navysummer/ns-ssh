mod config;
mod agent;
mod client;
mod control;
mod scp;
mod sftp;
mod dns_sshfp;

use config::ResolvedConfig;
use config::parse_stdio_forward;
use clap::Parser;
use base64::Engine;

/// Add a local forward (`-L`/LocalForward) spec, routing StreamLocal vs TCP.
fn push_local_forward(cfg: &mut ResolvedConfig, spec: &str) -> bool {
    if let Some((l, r)) = config::parse_streamlocal_forward(spec) {
        cfg.local_streamlocal.push((l, r));
        true
    } else if let Some(fwd) = config::parse_forward_spec(spec) {
        cfg.local_forwards.push(fwd);
        true
    } else {
        false
    }
}

/// Add a remote forward (`-R`/RemoteForward) spec, routing StreamLocal vs TCP.
fn push_remote_forward(cfg: &mut ResolvedConfig, spec: &str) -> bool {
    if let Some((l, r)) = config::parse_streamlocal_forward(spec) {
        cfg.remote_streamlocal.push((l, r));
        true
    } else if let Some(fwd) = config::parse_forward_spec(spec) {
        cfg.remote_forwards.push(fwd);
        true
    } else {
        false
    }
}

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

    #[arg(short = 'Q')]
    query_algorithms: Option<String>,

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

    #[arg(short = 's')]
    subsystem_request: bool,

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

    #[arg(short = 'E', long)]
    log_file: Option<String>,

    #[arg(short = 'c', long)]
    cipher_spec: Option<String>,

    #[arg(short = 'm', long)]
    mac_spec: Option<String>,

    #[arg(short = 'a')]
    disable_agent_forwarding: bool,

    #[arg(short = 'g', long)]
    allow_remote_to_local: bool,

    #[arg(short = 'k')]
    disable_forwarding: bool,

    #[arg(short = 'M')]
    control_master: bool,

    #[arg(short = 'S')]
    control_path: Option<String>,

    #[arg(short = 'O')]
    control_command: Option<String>,

    #[arg(short = 'x')]
    disable_x11_forwarding: bool,

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

    let invoked_as_keyscan = std::env::args_os().next()
        .map(|a| {
            let name = std::path::PathBuf::from(a);
            let base = name.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
            base == "ssh-keyscan" || base == "ns-ssh-keyscan"
        })
        .unwrap_or(false);

    let invoked_as_keygen = std::env::args_os().next()
        .map(|a| {
            let name = std::path::PathBuf::from(a);
            let base = name.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
            base == "ssh-keygen" || base == "ns-ssh-keygen"
        })
        .unwrap_or(false);

    let invoked_as_ssh_add = std::env::args_os().next()
        .map(|a| {
            let name = std::path::PathBuf::from(a);
            let base = name.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
            base == "ssh-add" || base == "ns-ssh-add"
        })
        .unwrap_or(false);

    // Logging is initialized after config resolution so `-v`/LogLevel can apply.

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

    // If invoked as "ssh-keyscan" or "ns-ssh-keyscan", route to keyscan.
    if invoked_as_keyscan {
        let code = run_keyscan_mode();
        std::process::exit(code);
    }

    // If invoked as "ssh-keygen" or "ns-ssh-keygen", route to keygen.
    if invoked_as_keygen {
        let code = run_keygen_mode();
        std::process::exit(code);
    }

    // If invoked as "ssh-add" or "ns-ssh-add", route to ssh-add.
    if invoked_as_ssh_add {
        let code = run_ssh_add_mode();
        std::process::exit(code);
    }

    let args = SshArgs::parse();

    // -Q query algorithms and exit.
    if let Some(ref q) = args.query_algorithms {
        match ssh_core::transport::supported_algorithms(q) {
            Some(list) => {
                for a in list { println!("{}", a); }
                std::process::exit(0);
            }
            None => {
                eprintln!("ns-ssh: unsupported query type: {}", q);
                std::process::exit(1);
            }
        }
    }

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
    if args.disable_x11_forwarding {
        config.forward_x11 = false;
    }

    if args.forward_x11_trusted {
        // -Y: remote X11 clients are trusted with full display access.
        config.forward_x11_trusted = true;
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
    if args.disable_agent_forwarding {
        config.forward_agent = false;
    }
    if args.disable_forwarding {
        config.forward_agent = false;
        config.forward_x11 = false;
        config.local_forwards.clear();
        config.remote_forwards.clear();
        config.dynamic_forwards.clear();
        config.local_streamlocal.clear();
        config.remote_streamlocal.clear();
    }
    if args.allow_remote_to_local {
        config.gateway_ports = true;
    }
    if let Some(ref cs) = args.cipher_spec {
        config.ciphers = Some(cs.split(',').map(|s| s.trim().to_string()).collect());
    }
    if let Some(ref ms) = args.mac_spec {
        config.macs = Some(ms.split(',').map(|s| s.trim().to_string()).collect());
    }
    if let Some(ref lf) = args.log_file {
        config.log_file = Some(std::path::PathBuf::from(lf));
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
    if args.subsystem_request {
        // OpenSSH: `ssh -s host subsystem` — the subsystem name is the first
        // command argument; `-s` itself is a boolean flag.
        let sub = args.command.first().cloned().unwrap_or_default();
        if sub.is_empty() {
            eprintln!("ns-ssh: subsystem name required with -s");
            std::process::exit(1);
        }
        config.subsystem = Some(sub);
    }

    for spec in &args.local_forwards {
        if !push_local_forward(&mut config, spec) {
            eprintln!("ns-ssh: invalid local forward specification: {}", spec);
            std::process::exit(1);
        }
    }

    for spec in &args.remote_forwards {
        if !push_remote_forward(&mut config, spec) {
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

    // -M / -S are short aliases for -o ControlMaster=yes / -o ControlPath=...
    if args.control_master {
        config.control_master = true;
        config.control_master_auto = false;
    }
    if let Some(ref cp) = args.control_path {
        config.control_path = Some(cp.clone());
    }

    // -O <command>: send a ControlMaster command (check/exit/stop) to the
    // master at the control socket and exit without opening a session.
    if let Some(ref cmd) = args.control_command {
        let Some(ref sock) = config.control_path else {
            eprintln!("ns-ssh: -O requires ControlPath (-S) to locate the control socket");
            std::process::exit(1);
        };
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let code = rt.block_on(async {
            match tokio::net::UnixStream::connect(sock).await {
                Ok(s) => crate::control::run_control_command(s, cmd).await,
                Err(e) => {
                    eprintln!("ns-ssh: Control socket {} not connected: {}", sock, e);
                    255
                }
            }
        });
        std::process::exit(code);
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
    init_logging(&config);
    let code = client::run_client(config, remote_command, force_tty);
    std::process::exit(code);
}

/// Initialize the tracing subscriber, honoring `LogLevel`/`-v`/`RUST_LOG`.
fn init_logging(cfg: &ResolvedConfig) {
    let level = if std::env::var("RUST_LOG").is_ok() {
        "error" // RUST_LOG overrides via EnvFilter::try_from_default_env
    } else if let Some(l) = &cfg.log_level {
        match l.to_uppercase().as_str() {
            "QUIET" | "FATAL" | "ERROR" => "error",
            "INFO" => "info",
            "VERBOSE" => "info",
            "DEBUG" | "DEBUG1" | "DEBUG2" => "debug",
            "DEBUG3" => "trace",
            _ => "error",
        }
    } else {
        match cfg.verbosity {
            0 => "error",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let writer: tracing_subscriber::fmt::writer::BoxMakeWriter = if let Some(ref lf) = cfg.log_file {
        // -E log_file: write diagnostics to a file (append).
        match std::fs::OpenOptions::new().create(true).append(true).open(lf) {
            Ok(f) => tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::sync::Mutex::new(f)),
            Err(_) => tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stderr),
        }
    } else {
        tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stderr)
    };
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();
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
    println!("forwardx11trusted {}", yesno(cfg.forward_x11_trusted));
    println!("forwardx11timeout {}", cfg.forward_x11_timeout);
    println!("compression {}", yesno(cfg.compression));
    println!("stricthostkeychecking {}", cfg.strict_host_key_checking.as_str());
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
    for (bind, port, host, lport) in &cfg.local_forwards {
        if bind.is_empty() {
            println!("localforward {} {} {}", port, host, lport);
        } else {
            println!("localforward {}:{} {} {}", bind, port, host, lport);
        }
    }
    for (bind, port, host, lport) in &cfg.remote_forwards {
        if bind.is_empty() {
            println!("remoteforward {} {} {}", port, host, lport);
        } else {
            println!("remoteforward {}:{} {} {}", bind, port, host, lport);
        }
    }
    for port in &cfg.dynamic_forwards {
        println!("dynamicforward {}", port);
    }
    for (local, remote) in &cfg.local_streamlocal {
        println!("localforward {} {}", local, remote);
    }
    for (remote, local) in &cfg.remote_streamlocal {
        println!("remoteforward {} {}", remote, local);
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
    if let Some(ref lf) = cfg.log_file {
        println!("logfile {}", lf.display());
    }
    if cfg.gateway_ports {
        println!("gatewayports yes");
    }
    if let Some(ref c) = cfg.ciphers {
        println!("ciphers {}", c.join(","));
    }
    if let Some(ref m) = cfg.macs {
        println!("macs {}", m.join(","));
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
            } else if let Some(next) = iter.next() {
                identity = Some(next.clone());
            }
        } else if let Some(v) = arg.strip_prefix("-o") {
            if !v.is_empty() {
                options.push(v.to_string());
            } else if let Some(next) = iter.next() {
                options.push(next.clone());
            }
        } else if let Some(v) = arg.strip_prefix("-F") {
            if !v.is_empty() {
                config_file = Some(v.to_string());
            } else if let Some(next) = iter.next() {
                config_file = Some(next.clone());
            }
        } else if let Some(v) = arg.strip_prefix("-l") {
            if !v.is_empty() {
                login_name = Some(v.to_string());
            } else if let Some(next) = iter.next() {
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

    // scp source... target: the last positional token is the target. If it was
    // not captured above (e.g. a download's local target, or an upload whose
    // remote target had no preceding source yet), pull it out of `sources`.
    if target.is_none() && sources.len() >= 2 {
        target = sources.pop();
    }
    if let Some(t) = target.clone() {
        if let Some(pos) = sources.iter().position(|s| *s == t) {
            sources.remove(pos);
        }
    }

    // Build config from ssh options (used for hostname/user via -o and ~/.ssh/config).
    let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let base = ResolvedConfig::default_for_user(&default_user);

    // Decide direction. Standard scp semantics:
    //   scp local remote           → upload   (target is remote)
    //   scp remote local           → download (one source is remote)
    //   scp remote                 → download to "."
    let rt = tokio::runtime::Runtime::new().unwrap();

    let target_is_remote = target.as_ref().map(|t| contains_scp_remote(t)).unwrap_or(false);
    let upload_remote = if target_is_remote { target.clone() } else { None };
    let download_remote = if upload_remote.is_none() {
        sources.iter().find(|s| contains_scp_remote(s)).cloned()
    } else {
        None
    };

    let remote = match (&upload_remote, &download_remote) {
        (Some(r), _) => r.clone(),
        (_, Some(r)) => r.clone(),
        _ => {
            eprintln!("ns-scp: invalid arguments; expected: scp [options] source... target");
            return 1;
        }
    };
    let rt_target = parse_scp_remote(&remote);
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
            apply_ssh_option(&mut config, &k.to_lowercase(), v.trim());
        }
    }

    if upload_remote.is_some() {
        // scp local remote  → upload
        let local = sources.first().cloned().unwrap_or_default();
        return rt.block_on(async move {
            let path = std::path::Path::new(&local);
            match scp::scp_upload(&config, path, &remote_path).await {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("ns-scp: upload failed: {}", e);
                    1
                }
            }
        });
    } else {
        // scp remote local  → download
        let local = target.clone().unwrap_or_else(|| ".".to_string());
        return rt.block_on(async move {
            match scp::scp_download(&config, &remote_path, std::path::Path::new(&local)).await {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("ns-scp: download failed: {}", e);
                    1
                }
            }
        });
    }
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

/// `ssh-keyscan` mode: connect to hosts and print their public host keys.
fn run_keyscan_mode() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut port = 22u16;
    let mut key_types: Vec<String> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-p" => {
                i += 1;
                if i < args.len() { port = args[i].parse().unwrap_or(22); }
            }
            "-t" => {
                i += 1;
                if i < args.len() { key_types.push(args[i].clone()); }
            }
            "-h" | "--help" => {
                eprintln!("usage: ssh-keyscan [-p port] [-t keytype] [host ...]");
                return 1;
            }
            "-4" | "-6" | "-v" | "-q" => {}
            _ => hosts.push(a.clone()),
        }
        i += 1;
    }
    if hosts.is_empty() {
        eprintln!("ssh-keyscan: no host specified");
        return 1;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut any_ok = false;
    rt.block_on(async {
        for host in &hosts {
            let (h, hp) = split_host_port(host, port);
            match scan_one_host(&h, hp, &key_types).await {
                Some((keytype, blob)) => {
                    println!(
                        "{} {} {}",
                        h,
                        keytype,
                        base64::engine::general_purpose::STANDARD.encode(&blob)
                    );
                    any_ok = true;
                }
                None => {
                    eprintln!("ssh-keyscan: failed to scan {}", host);
                }
            }
        }
    });
    if any_ok { 0 } else { 1 }
}

/// Connect to a host, perform the handshake, and return (keytype, key blob).
async fn scan_one_host(host: &str, port: u16, key_types: &[String]) -> Option<(String, Vec<u8>)> {
    let mut cfg = ResolvedConfig::default_for_user("keyscan");
    cfg.hostname = host.to_string();
    cfg.port = port;
    cfg.ssh_keyscan = true;
    cfg.strict_host_key_checking = config::HostKeyChecking::No;
    cfg.batch_mode = true;
    cfg.connect_timeout = Some(10);
    if !key_types.is_empty() {
        cfg.host_key_algorithms = Some(key_types.to_vec());
    }
    let mut client = client::SshClient::new(cfg);
    client.connect().await.ok()?;
    client.handshake().await.ok()?;
    client.captured_host_key.clone()
}

/// Split `host[:port]` (IPv6 in brackets) into (host, port).
fn split_host_port(host: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let h = &rest[..end];
            let p = rest[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok());
            return (h.to_string(), p.unwrap_or(default_port));
        }
    }
    if let Some((h, p)) = host.rsplit_once(':') {
        if !h.contains(':') && !h.is_empty() {
            if let Ok(p) = p.parse::<u16>() {
                return (h.to_string(), p);
            }
        }
    }
    (host.to_string(), default_port)
}

/// `ssh-keygen` mode: generate OpenSSH keys, print fingerprints, export public keys.
fn run_keygen_mode() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut key_type = "ed25519".to_string();
    let mut output_file: Option<String> = None;
    let mut export_public = false;
    let mut fingerprint = false;
    let mut list_known = false;
    let mut remove_known = false;
    let mut hostname: Option<String> = None;
    let mut bits: Option<u32> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-t" => {
                i += 1;
                if i < args.len() { key_type = args[i].clone(); }
            }
            "-f" => {
                i += 1;
                if i < args.len() { output_file = Some(args[i].clone()); }
            }
            "-b" => {
                i += 1;
                if i < args.len() { bits = args[i].parse().ok(); }
            }
            "-y" => export_public = true,
            "-l" => fingerprint = true,
            "-F" => {
                i += 1;
                if i < args.len() { hostname = Some(args[i].clone()); }
                list_known = true;
            }
            "-R" => {
                i += 1;
                if i < args.len() { hostname = Some(args[i].clone()); }
                remove_known = true;
            }
            "-N" | "-C" | "-q" => {
                // Passphrase/comment/quiet: consume the value for -N/-C, ignore for -q.
                if a == "-N" || a == "-C" {
                    i += 1;
                }
            }
            "-p" | "-P" => {
                // Passphrase change prompt: consume value for -P, ignore for -p.
                if a == "-P" { i += 1; }
            }
            "-h" | "--help" => {
                eprintln!("usage: ssh-keygen [-t type] [-f file] [-b bits] [-y] [-l] [-F hostname] [-R hostname]");
                return 1;
            }
            _ => {}
        }
        i += 1;
    }

    // -F hostname: search known_hosts.
    if list_known {
        if let Some(host) = &hostname {
            return keygen_find_in_known_hosts(host);
        }
        eprintln!("ssh-keygen: -F requires a hostname");
        return 1;
    }

    // -R hostname: remove from known_hosts.
    if remove_known {
        if let Some(host) = &hostname {
            let file = output_file.clone()
                .or_else(|| dirs::home_dir().map(|h| h.join(".ssh/known_hosts").to_string_lossy().into_owned()))
                .unwrap_or_else(|| "~/.ssh/known_hosts".to_string());
            return keygen_remove_from_known_hosts(host, &file);
        }
        eprintln!("ssh-keygen: -R requires a hostname");
        return 1;
    }

    // -l: print fingerprint of a key file.
    if fingerprint {
        let path = output_file.clone().unwrap_or_default();
        if path.is_empty() {
            eprintln!("ssh-keygen: -l requires -f <file>");
            return 1;
        }
        return keygen_fingerprint(&path);
    }

    // -y: export the public key.
    if export_public {
        let path = output_file.clone().unwrap_or_default();
        if path.is_empty() {
            eprintln!("ssh-keygen: -y requires -f <file>");
            return 1;
        }
        return keygen_export_public(&path);
    }

    // Generate a new key pair.
    let Some(path) = output_file else {
        eprintln!("ssh-keygen: no output file specified (-f)");
        return 1;
    };
    keygen_generate(&key_type, &path, bits)
}

/// Generate a key pair and write it to `path` (plus `path.pub`).
fn keygen_generate(key_type: &str, path: &str, bits: Option<u32>) -> i32 {
    match key_type.to_lowercase().as_str() {
        "ed25519" => {
            let key = ssh_core::hostkey::Ed25519HostKey::generate().expect("generate");
            let secret = key.secret_bytes();
            let content = ssh_core::keygen::format_openssh_ed25519(&secret);
            if let Err(e) = ssh_core::keygen::write_private_key(std::path::Path::new(path), &content) {
                eprintln!("ssh-keygen: write {}: {}", path, e);
                return 1;
            }
            use ssh_core::hostkey::HostKeySigner;
            let blob = key.public_key_bytes();
            let raw: [u8; 32] = blob[blob.len() - 32..].try_into().unwrap();
            let pub_line = ssh_core::keygen::format_public_ed25519(&raw);
            let pub_path = format!("{}.pub", path);
            if let Err(e) = std::fs::write(&pub_path, format!("{}\n", pub_line)) {
                eprintln!("ssh-keygen: write {}: {}", pub_path, e);
                return 1;
            }
            println!("Your identification has been saved in {}", path);
            println!("Your public key has been saved in {}", pub_path);
            println!("The key fingerprint is:");
            let _ = bits;
            0
        }
        "ecdsa" | "ecdsa-sha2-nistp256" => {
            let key = ssh_core::hostkey::EcdsaP256HostKey::generate().expect("generate");
            let secret = key.secret_bytes();
            let content = match ssh_core::keygen::format_openssh_ecdsa(&secret) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("ssh-keygen: {}", e);
                    return 1;
                }
            };
            if let Err(e) = ssh_core::keygen::write_private_key(std::path::Path::new(path), &content) {
                eprintln!("ssh-keygen: write {}: {}", path, e);
                return 1;
            }
            use ssh_core::hostkey::HostKeySigner;
            let pub_blob = key.public_key_bytes();
            let encoded = base64::engine::general_purpose::STANDARD.encode(&pub_blob);
            let pub_line = format!("ecdsa-sha2-nistp256 {}", encoded);
            let pub_path = format!("{}.pub", path);
            if let Err(e) = std::fs::write(&pub_path, format!("{}\n", pub_line)) {
                eprintln!("ssh-keygen: write {}: {}", pub_path, e);
                return 1;
            }
            println!("Your identification has been saved in {}", path);
            println!("Your public key has been saved in {}", pub_path);
            0
        }
        "rsa" => {
            // RSA generation requires the rsa crate; use a fixed 2048-bit key.
            let key = ssh_core::hostkey::RsaHostKey::generate(2048).expect("generate rsa");
            let _ = key;
            eprintln!("ssh-keygen: RSA private-key serialization is not yet supported");
            1
        }
        other => {
            eprintln!("ssh-keygen: unknown key type: {}", other);
            1
        }
    }
}

/// Print the fingerprint of a private or public key file.
fn keygen_fingerprint(path: &str) -> i32 {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ssh-keygen: read {}: {}", path, e);
            return 1;
        }
    };
    // If this is a public key line (ssh-ed25519 AAAA comment), use the blob directly.
    let pub_line: Option<String> = content.lines().find_map(|l| {
        let l = l.trim();
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() >= 2 && (parts[0].starts_with("ssh-") || parts[0].starts_with("ecdsa-")) {
            Some(parts[1].to_string())
        } else {
            None
        }
    });
    if let Some(b64) = pub_line {
        if let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(&b64) {
            return print_fingerprint(&blob, path);
        }
    }

    // Private key: decode openssh-key-v1 and extract the public key blob.
    let base64_content: String = content.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let decoded = match base64::engine::general_purpose::STANDARD.decode(&base64_content) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ssh-keygen: invalid key: {}", e);
            return 1;
        }
    };
    let mut r = &decoded[..];
    if r.starts_with(b"openssh-key-v1\0") {
        r = &r[15..];
        let _ = read_simple_string(&mut r);
        let _ = read_simple_string(&mut r);
        let _ = read_simple_string(&mut r);
        let _ = read_simple_u32(&mut r);
        if let Ok(Some(pub_len)) = read_simple_u32(&mut r) {
            if r.len() >= pub_len as usize {
                let pub_blob = &r[..pub_len as usize];
                return print_fingerprint(pub_blob, path);
            }
        }
    }
    eprintln!("ssh-keygen: unsupported key format in {}", path);
    1
}

fn print_fingerprint(blob: &[u8], path: &str) -> i32 {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(blob);
    let fp = base64::engine::general_purpose::STANDARD.encode(&digest);
    let fp = fp.trim_end_matches('=');
    // Determine key type from the blob's leading string.
    let mut p = blob;
    let kind = read_simple_string(&mut p).unwrap_or_else(|_| "SSH".to_string());
    println!("256 SHA256:{} {} ({})", fp, path, kind);
    0
}

/// Export the public key from a private key file (`-y`).
fn keygen_export_public(path: &str) -> i32 {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ssh-keygen: read {}: {}", path, e);
            return 1;
        }
    };
    let base64_content: String = content.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let decoded = match base64::engine::general_purpose::STANDARD.decode(&base64_content) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ssh-keygen: invalid key: {}", e);
            return 1;
        }
    };
    // Parse openssh-key-v1: public key blob follows the header.
    let mut r = &decoded[..];
    if r.starts_with(b"openssh-key-v1\0") {
        r = &r[15..];
        let _cipher = read_simple_string(&mut r);
        let _kdf = read_simple_string(&mut r);
        let _kdfopts = read_simple_string(&mut r);
        let _nkeys = read_simple_u32(&mut r);
        if let Ok(Some(pub_len)) = read_simple_u32(&mut r) {
            if r.len() >= pub_len as usize {
                let pub_blob = &r[..pub_len as usize];
                let mut p = pub_blob;
                if let Ok(kt) = read_simple_string(&mut p) {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(pub_blob);
                    println!("{} {}", kt, encoded);
                    return 0;
                }
            }
        }
    }
    eprintln!("ssh-keygen: unsupported private key format in {}", path);
    1
}

fn read_simple_string<'a>(r: &mut &'a [u8]) -> Result<String, ()> {
    let len = read_simple_u32(r)?.ok_or(())? as usize;
    if r.len() < len {
        return Err(());
    }
    let s = std::str::from_utf8(&r[..len]).map_err(|_| ())?.to_string();
    *r = &r[len..];
    Ok(s)
}

fn read_simple_u32(r: &mut &[u8]) -> Result<Option<u32>, ()> {
    if r.len() < 4 {
        return Err(());
    }
    let v = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
    *r = &r[4..];
    Ok(Some(v))
}

/// Search a hostname in the user's known_hosts file (`-F`).
fn keygen_find_in_known_hosts(hostname: &str) -> i32 {
    let path = std::path::PathBuf::from(
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    ).join(".ssh/known_hosts");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("ssh-keygen: {}: No such file or directory", path.display());
            return 1;
        }
    };
    let mut found = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(hostname) || line.starts_with(&format!("|1|")) {
            // Hashed entries can't be matched by hostname directly; report non-hashed only.
            if !line.starts_with(&format!("|1|")) {
                println!("{}", line);
                found = true;
            }
        }
    }
    if found { 0 } else { 1 }
}

/// Does a known_hosts line's host list match the given hostname?
fn known_hosts_line_matches(line: &str, hostname: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or("");
    for entry in first.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if entry == hostname {
            return true;
        }
        // entry may be "[host]:port" while hostname is bare "host".
        if let Some(inner) = entry.strip_prefix('[') {
            if let Some(bracket_end) = inner.find(']') {
                if &inner[..bracket_end] == hostname {
                    return true;
                }
            }
        }
        // hostname may be "[host]:port" while entry is bare "host".
        if let Some(inner) = hostname.strip_prefix('[') {
            if let Some(bracket_end) = inner.find(']') {
                if &inner[..bracket_end] == entry {
                    return true;
                }
            }
        }
    }
    false
}

/// Remove a hostname from a known_hosts file (`-R`).
fn keygen_remove_from_known_hosts(hostname: &str, file: &str) -> i32 {
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("ssh-keygen: {}: No such file or directory", file);
            return 1;
        }
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut first_line: Option<usize> = None;
    let mut removed = 0;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            kept.push(line);
            continue;
        }
        if known_hosts_line_matches(trimmed, hostname) {
            if first_line.is_none() {
                first_line = Some(idx + 1);
            }
            removed += 1;
            continue;
        }
        kept.push(line);
    }
    if removed == 0 {
        println!("Host {} not found in {}", hostname, file);
        return 1;
    }
    // Preserve a backup of the original, like OpenSSH.
    let _ = std::fs::write(format!("{}.old", file), &content);
    let mut new_content = kept.join("\n");
    if content.ends_with('\n') {
        new_content.push('\n');
    }
    if let Err(e) = std::fs::write(file, &new_content) {
        eprintln!("ssh-keygen: write {}: {}", file, e);
        return 1;
    }
    let line = first_line.unwrap_or(1);
    println!("# Host {} found: line {}", hostname, line);
    println!("{} updated.", file);
    println!("Original contents retained as {}.old", file);
    0
}

/// Map an SSH key algorithm name to the short type used by `ssh-add -l`.
fn fingerprint_kind(alg: &str) -> &'static str {
    if alg == "ssh-ed25519" {
        "ED25519"
    } else if alg.starts_with("ecdsa-") {
        "ECDSA"
    } else if alg == "ssh-rsa" || alg.starts_with("rsa-") {
        "RSA"
    } else if alg == "ssh-dss" {
        "DSA"
    } else {
        "SSH"
    }
}

/// `ssh-add` mode: add private keys to the SSH agent, list, or remove all.
fn run_ssh_add_mode() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut list_fingerprints = false;
    let mut list_keys = false;
    let mut remove_all = false;
    let mut key_files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-l" => list_fingerprints = true,
            "-L" => list_keys = true,
            "-D" => remove_all = true,
            "-h" | "--help" => {
                eprintln!("usage: ssh-add [-l] [-L] [-D] [keyfile ...]");
                return 1;
            }
            _ => {
                if !a.starts_with('-') {
                    key_files.push(a.clone());
                }
            }
        }
        i += 1;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let agent = agent::SshAgent::new();
        if !agent.is_available() {
            eprintln!("ssh-add: could not connect to ssh-agent (is SSH_AUTH_SOCK set?)");
            return 1;
        }

        if list_fingerprints || list_keys {
            match agent.request_identities().await {
                Ok(ids) => {
                    for (comment, blob) in &ids {
                        let alg = agent::blob_algorithm(blob).unwrap_or_else(|| "unknown".to_string());
                        if list_fingerprints {
                            // `-l`: SHA256 fingerprint (matches OpenSSH output).
                            use sha2::Digest;
                            let digest = sha2::Sha256::digest(blob);
                            let fp = base64::engine::general_purpose::STANDARD.encode(&digest);
                            let fp = fp.trim_end_matches('=');
                            let kind = fingerprint_kind(&alg);
                            println!("256 SHA256:{} {} ({})", fp, comment, kind);
                        } else {
                            // `-L`: full public key (base64 blob).
                            let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
                            println!("{} {} {}", alg, b64, comment);
                        }
                    }
                    0
                }
                Err(e) => {
                    eprintln!("ssh-add: {}", e);
                    1
                }
            }
        } else if remove_all {
            match agent.remove_all_identities().await {
                Ok(()) => {
                    println!("All identities removed.");
                    0
                }
                Err(e) => {
                    eprintln!("ssh-add: {}", e);
                    1
                }
            }
        } else {
            if key_files.is_empty() {
                key_files = agent::get_identity_files()
                    .into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                if key_files.is_empty() {
                    eprintln!("ssh-add: no key files specified and no default keys found");
                    return 1;
                }
            }
            let mut ok = true;
            for path in &key_files {
                match agent::load_private_key(std::path::Path::new(path)) {
                    Ok(key) => {
                        let alg = key.algorithm_name().to_string();
                        match agent.add_identity(&*key).await {
                            Ok(()) => {
                                println!("Identity added: {} ({})", path, alg);
                            }
                            Err(e) => {
                                eprintln!("ssh-add: failed to add {}: {}", path, e);
                                ok = false;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ssh-add: {}", e);
                        ok = false;
                    }
                }
            }
            if ok { 0 } else { 1 }
        }
    })
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
            apply_ssh_option(&mut resolved, &key, value);
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
            if let Some(x) = host_config.forward_x11_trusted {
                resolved.forward_x11_trusted = x;
            }
            if let Some(x) = host_config.forward_x11_timeout {
                resolved.forward_x11_timeout = x;
            }
            if let Some(x) = host_config.stream_local_bind_mask {
                resolved.stream_local_bind_mask = x;
            }
            if let Some(x) = host_config.stream_local_bind_unlink {
                resolved.stream_local_bind_unlink = x;
            }
            if let Some(c) = host_config.compression {
                resolved.compression = c;
            }
            if let Some(strict) = &host_config.strict_host_key_checking {
                resolved.strict_host_key_checking = config::HostKeyChecking::parse(strict);
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
            if let Some(ref rk) = host_config.rekey_limit {
                if let Some((bytes, secs)) = config::parse_rekey_limit(rk) {
                    resolved.rekey_limit_bytes = bytes;
                    resolved.rekey_limit_time = secs;
                }
            }
            if let Some(ref ia) = host_config.identity_agent {
                resolved.identity_agent = if ia == "none" { None } else { Some(ia.clone()) };
            }
            if let Some(ref af) = host_config.address_family {
                match af.to_ascii_lowercase().as_str() {
                    "inet" => { resolved.prefer_ipv4 = true; resolved.prefer_ipv6 = false; }
                    "inet6" => { resolved.prefer_ipv6 = true; resolved.prefer_ipv4 = false; }
                    _ => { resolved.prefer_ipv4 = false; resolved.prefer_ipv6 = false; }
                }
            }
            if let Some(ref ec) = host_config.escape_char {
                resolved.escape_char = ec.clone();
            }
            if let Some(ref sub) = host_config.subsystem {
                resolved.subsystem = Some(sub.clone());
            }
            if let Some(ref paa) = host_config.pubkey_accepted_algorithms {
                resolved.pubkey_accepted_algorithms = Some(config::resolve_pubkey_algorithms(paa));
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
                    push_local_forward(&mut resolved, spec);
                }
            }
            if let Some(list) = &host_config.remote_forward {
                for spec in list {
                    push_remote_forward(&mut resolved, spec);
                }
            }
            if let Some(list) = &host_config.permit_remote_open {
                resolved.permit_remote_open = list.clone();
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
            if let Some(ref cmd) = host_config.local_command {
                resolved.local_command = Some(cmd.clone());
            }
            if let Some(v) = host_config.permit_local_command {
                resolved.permit_local_command = v;
            }
            if let Some(ref a) = host_config.host_key_alias {
                resolved.host_key_alias = Some(a.clone());
            }
            if let Some(ref f) = host_config.fingerprint_hash {
                resolved.fingerprint_hash = f.to_ascii_lowercase();
            }
            if let Some(v) = host_config.visual_host_key {
                resolved.visual_host_key = v;
            }
            if let Some(v) = host_config.check_host_ip {
                resolved.check_host_ip = v;
            }
            if let Some(v) = host_config.number_of_password_prompts {
                resolved.number_of_password_prompts = v;
            }
            if let Some(v) = host_config.connection_attempts {
                resolved.connection_attempts = v;
            }
            if let Some(v) = &host_config.verify_host_key_dns {
                resolved.verify_host_key_dns = v.to_ascii_lowercase();
            }
            if let Some(v) = host_config.no_host_authentication_for_localhost {
                resolved.no_host_authentication_for_localhost = v;
            }
            if let Some(ref v) = host_config.control_master {
                match v.to_ascii_lowercase().as_str() {
                    "yes" => { resolved.control_master = true; resolved.control_master_auto = false; }
                    "auto" => { resolved.control_master = true; resolved.control_master_auto = true; }
                    _ => { resolved.control_master = false; resolved.control_master_auto = false; }
                }
            }
            if let Some(ref p) = host_config.control_path {
                resolved.control_path = Some(p.clone());
            }
            if let Some(ref p) = host_config.control_persist {
                if p.to_ascii_lowercase() != "no" {
                    if let Some(v) = config::parse_time_suffix(p) {
                        resolved.control_persist = Some(v as u32);
                    }
                } else {
                    resolved.control_persist = None;
                }
            }
            if let Some(v) = host_config.gateway_ports {
                resolved.gateway_ports = v;
            }
            if let Some(v) = host_config.required_rsa_size {
                resolved.required_rsa_size = v;
            }
            if let Some(v) = &host_config.channel_timeouts {
                resolved.channel_timeouts = v.clone();
            }
            if let Some(v) = host_config.clear_all_forwardings {
                if v {
                    resolved.local_forwards.clear();
                    resolved.remote_forwards.clear();
                    resolved.dynamic_forwards.clear();
                    resolved.local_streamlocal.clear();
                    resolved.remote_streamlocal.clear();
                }
            }
        }

        // Apply matching Match blocks (OpenSSH: Match blocks are applied AFTER Host blocks)
        let target_host = target.as_str();
        for match_block in &ssh_config.match_blocks {
            if !match_block.matches(target_host, &resolved.user) {
                continue;
            }
            let mc = &match_block.config;
            if resolved.hostname.is_empty() {
                resolved.hostname = mc.hostname.clone().unwrap_or_else(|| target.clone());
            } else if let Some(h) = &mc.hostname {
                resolved.hostname = h.clone();
            }
            if let Some(ref user) = mc.user {
                resolved.user = user.clone();
            }
            if let Some(port) = mc.port {
                resolved.port = port;
            }
            if let Some(ref identity) = mc.identity_file {
                resolved.identity_file = Some(std::path::PathBuf::from(identity));
            }
            if let Some(v) = mc.identities_only {
                resolved.identities_only = v;
            }
            if let Some(fwd) = mc.forward_agent {
                resolved.forward_agent = fwd;
            }
            if let Some(x) = mc.forward_x11 {
                resolved.forward_x11 = x;
            }
            if let Some(x) = mc.forward_x11_trusted {
                resolved.forward_x11_trusted = x;
            }
            if let Some(x) = mc.forward_x11_timeout {
                resolved.forward_x11_timeout = x;
            }
            if let Some(x) = mc.stream_local_bind_mask {
                resolved.stream_local_bind_mask = x;
            }
            if let Some(x) = mc.stream_local_bind_unlink {
                resolved.stream_local_bind_unlink = x;
            }
            if let Some(c) = mc.compression {
                resolved.compression = c;
            }
            if let Some(strict) = &mc.strict_host_key_checking {
                resolved.strict_host_key_checking = config::HostKeyChecking::parse(strict);
            }
            if let Some(h) = mc.hash_known_hosts {
                resolved.hash_known_hosts = h;
            }
            if let Some(p) = &mc.user_known_hosts_file {
                resolved.user_known_hosts_file = Some(std::path::PathBuf::from(p));
            }
            if let Some(p) = &mc.global_known_hosts_file {
                resolved.global_known_hosts_file = Some(std::path::PathBuf::from(p));
            }
            if let Some(v) = mc.connect_timeout {
                resolved.connect_timeout = Some(v);
            }
            if let Some(v) = mc.server_alive_interval {
                resolved.server_alive_interval = Some(v);
            }
            if let Some(v) = mc.server_alive_count_max {
                resolved.server_alive_count_max = Some(v);
            }
            if let Some(v) = mc.tcp_keep_alive {
                resolved.tcp_keep_alive = v;
            }
            if let Some(v) = mc.batch_mode {
                resolved.batch_mode = v;
            }
            if let Some(v) = mc.password_authentication {
                resolved.password_authentication = v;
            }
            if let Some(v) = mc.pubkey_authentication {
                resolved.pubkey_authentication = v;
            }
            if let Some(v) = mc.kbd_interactive_authentication {
                resolved.kbd_interactive_authentication = v;
            }
            if let Some(v) = &mc.preferred_authentications {
                resolved.preferred_authentications = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &mc.host_key_algorithms {
                resolved.host_key_algorithms = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &mc.kex_algorithms {
                resolved.kex_algorithms = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &mc.ciphers {
                resolved.ciphers = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &mc.macs {
                resolved.macs = Some(v.split(',').map(str::trim).map(|s| s.to_string()).collect());
            }
            if let Some(v) = &mc.log_level {
                resolved.log_level = Some(v.clone());
            }
            if let Some(v) = mc.exit_on_forward_failure {
                resolved.exit_on_forward_failure = v;
            }
            if let Some(ref rk) = mc.rekey_limit {
                if let Some((bytes, secs)) = config::parse_rekey_limit(rk) {
                    resolved.rekey_limit_bytes = bytes;
                    resolved.rekey_limit_time = secs;
                }
            }
            if let Some(ref ia) = mc.identity_agent {
                resolved.identity_agent = if ia == "none" { None } else { Some(ia.clone()) };
            }
            if let Some(ref af) = mc.address_family {
                match af.to_ascii_lowercase().as_str() {
                    "inet" => { resolved.prefer_ipv4 = true; resolved.prefer_ipv6 = false; }
                    "inet6" => { resolved.prefer_ipv6 = true; resolved.prefer_ipv4 = false; }
                    _ => { resolved.prefer_ipv4 = false; resolved.prefer_ipv6 = false; }
                }
            }
            if let Some(ref ec) = mc.escape_char {
                resolved.escape_char = ec.clone();
            }
            if let Some(ref sub) = mc.subsystem {
                resolved.subsystem = Some(sub.clone());
            }
            if let Some(ref paa) = mc.pubkey_accepted_algorithms {
                resolved.pubkey_accepted_algorithms = Some(config::resolve_pubkey_algorithms(paa));
            }
            if let Some(list) = &mc.send_env {
                resolved.send_env.extend(list.iter().cloned());
            }
            if let Some(list) = &mc.set_env {
                for s in list {
                    if let Some((k, v)) = s.split_once('=') {
                        resolved.set_env.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
            }
            if let Some(ref proxy) = mc.proxy_jump {
                resolved.proxy_jump = Some(proxy.clone());
            }
            if let Some(ref p) = mc.proxy_command {
                resolved.proxy_command = Some(p.clone());
            }
            if let Some(ref b) = mc.bind_address {
                resolved.bind_address = Some(b.clone());
            }
            if let Some(ref tty) = mc.request_tty {
                resolved.request_tty = tty == "yes" || tty == "force";
            }
            if let Some(ref cmd) = mc.remote_command {
                resolved.remote_command = Some(cmd.clone());
            }
            if let Some(v) = &mc.add_keys_to_agent {
                resolved.add_keys_to_agent = v == "yes" || v == "confirm";
            }
            if let Some(list) = &mc.local_forward {
                for spec in list {
                    push_local_forward(&mut resolved, spec);
                }
            }
            if let Some(list) = &mc.remote_forward {
                for spec in list {
                    push_remote_forward(&mut resolved, spec);
                }
            }
            if let Some(list) = &mc.permit_remote_open {
                resolved.permit_remote_open = list.clone();
            }
            if let Some(list) = &mc.dynamic_forward {
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
            if let Some(ref cmd) = mc.local_command {
                resolved.local_command = Some(cmd.clone());
            }
            if let Some(v) = mc.permit_local_command {
                resolved.permit_local_command = v;
            }
            if let Some(ref a) = mc.host_key_alias {
                resolved.host_key_alias = Some(a.clone());
            }
            if let Some(ref f) = mc.fingerprint_hash {
                resolved.fingerprint_hash = f.to_ascii_lowercase();
            }
            if let Some(v) = mc.visual_host_key {
                resolved.visual_host_key = v;
            }
            if let Some(v) = mc.check_host_ip {
                resolved.check_host_ip = v;
            }
            if let Some(v) = mc.number_of_password_prompts {
                resolved.number_of_password_prompts = v;
            }
            if let Some(v) = mc.connection_attempts {
                resolved.connection_attempts = v;
            }
            if let Some(v) = &mc.verify_host_key_dns {
                resolved.verify_host_key_dns = v.to_ascii_lowercase();
            }
            if let Some(v) = mc.no_host_authentication_for_localhost {
                resolved.no_host_authentication_for_localhost = v;
            }
            if let Some(v) = mc.required_rsa_size {
                resolved.required_rsa_size = v;
            }
            if let Some(v) = &mc.channel_timeouts {
                resolved.channel_timeouts = v.clone();
            }
        }
    }

    for opt in &args.options {
        let opt = opt.trim();
        if let Some((key, value)) = opt.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            apply_ssh_option(&mut resolved, &key, value);
        }
    }

    resolved
}

/// Apply a single `-o key=value` option to a resolved config. Shared by the
/// main ssh path, SCP mode, and SFTP mode so every option is honored
/// consistently (e.g. `UserKnownHostsFile`, `StrictHostKeyChecking`).
fn apply_ssh_option(resolved: &mut ResolvedConfig, key: &str, value: &str) {
    match key {
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
            resolved.strict_host_key_checking = config::HostKeyChecking::parse(value);
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
        "kbdinteractiveauthentication" | "kbd_interactive_authentication"
            | "challengeresponseauthentication" | "challenge_response_authentication" =>
            resolved.kbd_interactive_authentication = value != "no",
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
        "forwardx11trusted" | "forward_x11_trusted" => resolved.forward_x11_trusted = value != "no",
        "forwardx11timeout" | "forward_x11_timeout" => {
            if let Some(v) = config::parse_time_suffix(value) {
                resolved.forward_x11_timeout = v as u32;
            }
        }
        "streamlocalbindmask" | "stream_local_bind_mask" => {
            if let Ok(v) = u32::from_str_radix(value.trim_start_matches("0o"), 8) {
                resolved.stream_local_bind_mask = v;
            }
        }
        "streamlocalbindunlink" | "stream_local_bind_unlink" => {
            resolved.stream_local_bind_unlink = value != "no";
        }
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
        "controlmaster" | "control_master" => {
            match value {
                "yes" => { resolved.control_master = true; resolved.control_master_auto = false; }
                "auto" => { resolved.control_master = true; resolved.control_master_auto = true; }
                _ => { resolved.control_master = false; resolved.control_master_auto = false; }
            }
        }
        "controlpath" | "control_path" => resolved.control_path = Some(value.to_string()),
        "controlpersist" | "control_persist" => {
            if value != "no" {
                if let Ok(v) = value.parse::<u32>() { resolved.control_persist = Some(v); }
            } else {
                resolved.control_persist = None;
            }
        }
        "hostkeyalias" | "host_key_alias" => resolved.host_key_alias = Some(value.to_string()),
        "fingerprinthash" | "fingerprint_hash" => resolved.fingerprint_hash = value.to_ascii_lowercase(),
        "visualhostkey" | "visual_host_key" => resolved.visual_host_key = value != "no",
        "checkhostip" | "check_host_ip" => resolved.check_host_ip = value != "no",
        "numberofpasswordprompts" | "number_of_password_prompts" => {
            if let Ok(v) = value.parse::<u32>() { resolved.number_of_password_prompts = v; }
        }
        "connectionattempts" | "connection_attempts" => {
            if let Ok(v) = value.parse::<u32>() { resolved.connection_attempts = v; }
        }
        "verifyhostkeydns" | "verify_host_key_dns" => resolved.verify_host_key_dns = value.to_ascii_lowercase(),
        "requiredrsasize" | "required_rsa_size" => {
            if let Ok(v) = value.parse::<u32>() { resolved.required_rsa_size = v; }
        }
        "permitremoteopen" | "permit_remote_open" => {
            resolved.permit_remote_open = config::parse_permit_remote_open(value);
        }
        "channeltimeout" | "channel_timeout" => {
            resolved.channel_timeouts = config::parse_channel_timeout(value);
        }
        "nohostauthenticationforlocalhost" | "no_host_authentication_for_localhost" => {
            resolved.no_host_authentication_for_localhost = value != "no";
        }
        "addressfamily" | "address_family" => {
            match value.to_ascii_lowercase().as_str() {
                "inet" | "ipv4" => { resolved.prefer_ipv4 = true; resolved.prefer_ipv6 = false; }
                "inet6" | "ipv6" => { resolved.prefer_ipv4 = false; resolved.prefer_ipv6 = true; }
                _ => { resolved.prefer_ipv4 = false; resolved.prefer_ipv6 = false; }
            }
        }
        "escapechar" | "escape_char" => resolved.escape_char = value.to_string(),
        "localcommand" | "local_command" => resolved.local_command = Some(value.to_string()),
        "permitlocalcommand" | "permit_local_command" => resolved.permit_local_command = value != "no",
        "gatewayports" | "gateway_ports" => resolved.gateway_ports = value != "no",
        "tcpkeepalive" | "tcp_keep_alive" => resolved.tcp_keep_alive = value != "no",
        "logfile" | "log_file" => resolved.log_file = Some(std::path::PathBuf::from(value)),
        "rekeylimit" | "rekey_limit" => {
            if let Some((bytes, secs)) = config::parse_rekey_limit(value) {
                resolved.rekey_limit_bytes = bytes;
                resolved.rekey_limit_time = secs;
            }
        }
        "identityagent" | "identity_agent" => {
            if value != "none" {
                resolved.identity_agent = Some(value.to_string());
            } else {
                resolved.identity_agent = None;
            }
        }
        "pubkeyacceptedalgorithms" | "pubkey_accepted_algorithms" | "pubkeyacceptedkeytypes" => {
            resolved.pubkey_accepted_algorithms = Some(config::resolve_pubkey_algorithms(value));
        }
        _ => {}
    }
}

fn parse_target(target: &str, config: &mut ResolvedConfig) {
    let (user, host) = if let Some((user, host)) = target.rsplit_once('@') {
        (Some(user.to_string()), host)
    } else {
        (None, target)
    };
    if let Some(user) = user {
        config.user = user;
    }
    // Only override the hostname if SSH config did not provide HostName.
    if config.hostname.is_empty() {
        config.hostname = host.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("example.com", 22), ("example.com".to_string(), 22));
        assert_eq!(split_host_port("example.com:2222", 22), ("example.com".to_string(), 2222));
        assert_eq!(split_host_port("[::1]:22", 22), ("::1".to_string(), 22));
        assert_eq!(split_host_port("2001:db8::1", 22), ("2001:db8::1".to_string(), 22));
    }
}
