use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use serde::Deserialize;

/// Match a glob pattern (supports `*` and `?`) against text. Used for `Include` globs.
fn simple_glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti] || p[pi] == '?') {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    #[serde(default)]
    pub host_key_files: Vec<String>,

    #[serde(default)]
    pub host_key_algorithms: Option<String>,

    #[serde(default)]
    pub kex_algorithms: Option<String>,

    #[serde(default)]
    pub ciphers: Option<String>,

    #[serde(default)]
    pub macs: Option<String>,

    #[serde(default = "default_rekey_bytes")]
    pub rekey_limit_bytes: u64,

    #[serde(default = "default_rekey_seconds")]
    pub rekey_limit_time: u64,

    #[serde(default)]
    pub pubkey_accepted_algorithms: Option<Vec<String>>,

    #[serde(default)]
    pub compression: bool,

    #[serde(default = "default_true")]
    pub password_auth: bool,

    #[serde(default = "default_true")]
    pub kbd_interactive_auth: bool,

    #[serde(default = "default_true")]
    pub pubkey_auth: bool,

    #[serde(default)]
    pub permit_root_login: bool,

    /// Raw PermitRootLogin value: yes/no/without-password/forced-commands-only/prohibit-password.
    #[serde(default)]
    pub permit_root_login_mode: String,

    #[serde(default)]
    pub authorized_keys_files: Vec<String>,

    #[serde(default)]
    pub allow_groups: Vec<String>,

    #[serde(default)]
    pub deny_groups: Vec<String>,

    #[serde(default)]
    pub allow_users: Vec<String>,

    #[serde(default)]
    pub deny_users: Vec<String>,

    #[serde(default = "default_max_auth_tries")]
    pub max_auth_tries: u32,

    #[serde(default = "default_max_sessions")]
    pub max_sessions: u32,

    #[serde(default = "default_client_alive_interval")]
    pub client_alive_interval: u32,

    #[serde(default = "default_client_alive_count_max")]
    pub client_alive_count_max: u32,

    #[serde(default = "default_use_dns")]
    pub use_dns: bool,

    #[serde(default)]
    pub subsystems: HashMap<String, String>,

    #[serde(default = "default_pid_file")]
    pub pid_file: String,

    #[serde(default = "default_log_file")]
    pub log_file: Option<String>,

    #[serde(default = "default_true")]
    pub strict_modes: bool,

    #[serde(default = "default_true")]
    pub permit_tty: bool,

    #[serde(default)]
    pub permit_empty_passwords: bool,

    #[serde(default = "default_true")]
    pub ignore_rhosts: bool,

    #[serde(default)]
    pub hostbased_auth: bool,

    #[serde(default = "default_true")]
    pub print_last_log: bool,

    #[serde(default = "default_true")]
    pub tcp_keep_alive: bool,

    #[serde(default)]
    pub force_command: Option<String>,

    #[serde(default = "default_banner")]
    pub banner: Option<String>,

    #[serde(default = "default_max_startups")]
    pub max_startups: String,

    #[serde(default = "default_login_grace_time")]
    pub login_grace_time: u32,

    #[serde(default = "default_accept_env")]
    pub accept_env: Vec<String>,

    #[serde(default = "default_true")]
    pub allow_agent_forwarding: bool,

    /// AllowStreamLocalForwarding: enable Unix-socket forwarding (default yes).
    #[serde(default = "default_true")]
    pub allow_streamlocal_forwarding: bool,

    #[serde(default)]
    pub x11_forwarding: bool,

    #[serde(default = "default_x11_display_offset")]
    pub x11_display_offset: u32,

    /// AllowTcpForwarding value: yes/no/local/remote/all.
    #[serde(default = "default_forwarding_mode")]
    pub allow_tcp_forwarding_mode: String,

    /// PermitOpen: "any" or a list of "host:port" (port 0 = any port).
    #[serde(default)]
    pub permit_open: Vec<String>,

    /// PermitListen: "any" or a list of "host:port" bind addresses.
    #[serde(default)]
    pub permit_listen: Vec<String>,

    /// GatewayPorts: yes/no/clientspecified.
    #[serde(default)]
    pub gateway_ports: String,

    /// ChrootDirectory: optionally chroot the user after authentication.
    #[serde(default)]
    pub chroot_directory: Option<String>,

    /// AuthenticationFailureDelay: minimum seconds to wait before next auth attempt.
    #[serde(default = "default_auth_failure_delay")]
    pub auth_failure_delay: u64,

    /// PermitUserEnvironment: allow environment= options in authorized_keys.
    #[serde(default)]
    pub permit_user_environment: bool,

    /// LogLevel: QUIET/FATAL/ERROR/INFO/VERBOSE/DEBUG/DEBUG1/DEBUG2/DEBUG3.
    #[serde(default)]
    pub log_level: Option<String>,

    /// SyslogFacility: AUTH/DAEMON/USER/LOCAL0..LOCAL7.
    #[serde(default)]
    pub syslog_facility: Option<String>,

    /// PrintMotd: print /etc/motd on interactive login (default yes).
    #[serde(default = "default_true")]
    pub print_motd: bool,

    /// AuthorizedKeysCommand: external command to obtain authorized keys.
    #[serde(default)]
    pub authorized_keys_command: Option<String>,

    /// AuthorizedKeysCommandUser: run the command as this user.
    #[serde(default)]
    pub authorized_keys_command_user: Option<String>,

    /// Match blocks from sshd_config, evaluated per-connection.
    #[serde(skip, default)]
    pub match_blocks: Vec<ServerMatch>,
}

/// A `Match` block in sshd_config: conditions and the directives they override.
#[derive(Debug, Clone, Default)]
pub struct ServerMatch {
    pub conditions: Vec<(String, String)>,
    pub overrides: MatchOverrides,
}

/// The subset of sshd_config directives that can appear inside a `Match` block.
#[derive(Debug, Clone, Default)]
pub struct MatchOverrides {
    pub force_command: Option<String>,
    pub permit_root_login_mode: Option<String>,
    pub password_auth: Option<bool>,
    pub pubkey_auth: Option<bool>,
    pub kbd_interactive_auth: Option<bool>,
    pub allow_tcp_forwarding_mode: Option<String>,
    pub x11_forwarding: Option<bool>,
    pub allow_agent_forwarding: Option<bool>,
    pub allow_streamlocal_forwarding: Option<bool>,
    pub allow_users: Option<Vec<String>>,
    pub deny_users: Option<Vec<String>>,
    pub allow_groups: Option<Vec<String>>,
    pub deny_groups: Option<Vec<String>>,
    pub chroot_directory: Option<String>,
    pub authorized_keys_files: Option<Vec<String>>,
    pub max_sessions: Option<u32>,
    pub banner: Option<String>,
    pub permit_open: Option<Vec<String>>,
    pub permit_listen: Option<Vec<String>>,
    pub print_motd: Option<bool>,
    pub permit_tty: Option<bool>,
    pub permit_empty_passwords: Option<bool>,
    pub max_auth_tries: Option<u32>,
    pub client_alive_interval: Option<u32>,
    pub client_alive_count_max: Option<u32>,
    pub tcp_keep_alive: Option<bool>,
    pub permit_user_environment: Option<bool>,
    pub accept_env: Option<Vec<String>>,
    pub login_grace_time: Option<u32>,
    pub log_level: Option<String>,
    pub hostbased_auth: Option<bool>,
    pub ignore_rhosts: Option<bool>,
}

impl ServerMatch {
    fn new(condition_str: &str) -> Self {
        let conditions: Vec<(String, String)> = condition_str
            .split_whitespace()
            .collect::<Vec<_>>()
            .chunks(2)
            .filter_map(|pair| {
                if pair.len() == 2 {
                    Some((pair[0].to_lowercase(), pair[1].to_string()))
                } else {
                    None
                }
            })
            .collect();
        ServerMatch { conditions, overrides: MatchOverrides::default() }
    }

    /// Evaluate whether this block applies given the connection context.
    fn matches(&self, username: &str, groups: &[String], host: &str, addr: &str) -> bool {
        for (key, value) in &self.conditions {
            match key.as_str() {
                "all" => {}
                "user" => {
                    if !glob_any(value, username) { return false; }
                }
                "group" => {
                    if !groups.iter().any(|g| glob_any(value, g)) { return false; }
                }
                "host" => {
                    if !glob_any(value, host) { return false; }
                }
                "address" => {
                    if !addr_match(value, addr) { return false; }
                }
                _ => return false, // unknown condition never matches
            }
        }
        true
    }

    fn apply_to(&self, cfg: &mut ServerConfig) {
        let o = &self.overrides;
        if let Some(v) = &o.force_command { cfg.force_command = Some(v.clone()); }
        if let Some(v) = &o.permit_root_login_mode {
            cfg.permit_root_login_mode = v.clone();
            cfg.permit_root_login = v == "yes";
        }
        if let Some(v) = o.password_auth { cfg.password_auth = v; }
        if let Some(v) = o.pubkey_auth { cfg.pubkey_auth = v; }
        if let Some(v) = o.kbd_interactive_auth { cfg.kbd_interactive_auth = v; }
        if let Some(v) = &o.allow_tcp_forwarding_mode { cfg.allow_tcp_forwarding_mode = v.clone(); }
        if let Some(v) = o.x11_forwarding { cfg.x11_forwarding = v; }
        if let Some(v) = o.allow_agent_forwarding { cfg.allow_agent_forwarding = v; }
        if let Some(v) = o.allow_streamlocal_forwarding { cfg.allow_streamlocal_forwarding = v; }
        if let Some(v) = &o.allow_users { cfg.allow_users = v.clone(); }
        if let Some(v) = &o.deny_users { cfg.deny_users = v.clone(); }
        if let Some(v) = &o.allow_groups { cfg.allow_groups = v.clone(); }
        if let Some(v) = &o.deny_groups { cfg.deny_groups = v.clone(); }
        if let Some(v) = &o.chroot_directory { cfg.chroot_directory = Some(v.clone()); }
        if let Some(v) = &o.authorized_keys_files { cfg.authorized_keys_files = v.clone(); }
        if let Some(v) = o.max_sessions { cfg.max_sessions = v; }
        if let Some(v) = &o.banner { cfg.banner = Some(v.clone()); }
        if let Some(v) = &o.permit_open { cfg.permit_open = v.clone(); }
        if let Some(v) = &o.permit_listen { cfg.permit_listen = v.clone(); }
        if let Some(v) = o.print_motd { cfg.print_motd = v; }
        if let Some(v) = o.permit_tty { cfg.permit_tty = v; }
        if let Some(v) = o.permit_empty_passwords { cfg.permit_empty_passwords = v; }
        if let Some(v) = o.max_auth_tries { cfg.max_auth_tries = v; }
        if let Some(v) = o.client_alive_interval { cfg.client_alive_interval = v; }
        if let Some(v) = o.client_alive_count_max { cfg.client_alive_count_max = v; }
        if let Some(v) = o.tcp_keep_alive { cfg.tcp_keep_alive = v; }
        if let Some(v) = o.permit_user_environment { cfg.permit_user_environment = v; }
        if let Some(v) = &o.accept_env { cfg.accept_env = v.clone(); }
        if let Some(v) = o.login_grace_time { cfg.login_grace_time = v; }
        if let Some(v) = &o.log_level { cfg.log_level = Some(v.clone()); }
        if let Some(v) = o.hostbased_auth { cfg.hostbased_auth = v; }
        if let Some(v) = o.ignore_rhosts { cfg.ignore_rhosts = v; }
    }
}

/// Match a comma-separated pattern list (supports `*`/`?`) against text.
fn glob_any(patterns: &str, text: &str) -> bool {
    patterns.split(',').any(|p| {
        let p = p.trim();
        p == text || (p.contains('*') || p.contains('?')) && simple_glob_match(p, text)
    })
}

/// Apply a single directive to a MatchOverrides, for directives valid in `Match` blocks.
fn apply_match_override(o: &mut MatchOverrides, key: &str, value: &str) {
    match key {
        "forcecommand" | "force_command" => o.force_command = Some(value.to_string()),
        "permitrootlogin" | "permit_root_login" => o.permit_root_login_mode = Some(value.to_lowercase()),
        "passwordauthentication" | "password_auth" => o.password_auth = Some(value == "yes"),
        "pubkeyauthentication" | "pubkey_auth" => o.pubkey_auth = Some(value == "yes"),
        "kbdinteractiveauthentication" | "keyboardinteractive" | "kbd_interactive_auth" => {
            o.kbd_interactive_auth = Some(value == "yes");
        }
        "allowtcpforwarding" | "allow_tcp_forwarding" => {
            o.allow_tcp_forwarding_mode = Some(value.to_lowercase());
        }
        "x11forwarding" | "x11_forwarding" => o.x11_forwarding = Some(value == "yes"),
        "allowagentforwarding" | "allow_agent_forwarding" => {
            o.allow_agent_forwarding = Some(value == "yes");
        }
        "allowstreamlocalforwarding" | "allow_streamlocal_forwarding" => {
            o.allow_streamlocal_forwarding = Some(value == "yes");
        }
        "allowusers" | "allow_users" => {
            o.allow_users = Some(value.split_whitespace().map(|s| s.to_string()).collect());
        }
        "denyusers" | "deny_users" => {
            o.deny_users = Some(value.split_whitespace().map(|s| s.to_string()).collect());
        }
        "allowgroups" | "allow_groups" => {
            o.allow_groups = Some(value.split_whitespace().map(|s| s.to_string()).collect());
        }
        "denygroups" | "deny_groups" => {
            o.deny_groups = Some(value.split_whitespace().map(|s| s.to_string()).collect());
        }
        "chrootdirectory" | "chroot_directory" => o.chroot_directory = Some(value.to_string()),
        "authorizedkeysfile" | "authorized_keys_file" => {
            let mut list = o.authorized_keys_files.take().unwrap_or_default();
            list.push(value.to_string());
            o.authorized_keys_files = Some(list);
        }
        "maxsessions" | "max_sessions" => {
            if let Ok(v) = value.parse() { o.max_sessions = Some(v); }
        }
        "banner" => o.banner = Some(value.to_string()),
        "permitopen" | "permit_open" => {
            let mut list = o.permit_open.take().unwrap_or_default();
            list.push(value.to_string());
            o.permit_open = Some(list);
        }
        "permitlisten" | "permit_listen" => {
            let mut list = o.permit_listen.take().unwrap_or_default();
            list.push(value.to_string());
            o.permit_listen = Some(list);
        }
        "printmotd" | "print_motd" => o.print_motd = Some(value == "yes"),
        "permittty" | "permit_tty" => o.permit_tty = Some(value == "yes"),
        "permitemptypasswords" | "permit_empty_passwords" => o.permit_empty_passwords = Some(value == "yes"),
        "maxauthtries" | "max_auth_tries" => {
            if let Ok(v) = value.parse() { o.max_auth_tries = Some(v); }
        }
        "clientaliveinterval" | "client_alive_interval" => {
            if let Ok(v) = value.parse() { o.client_alive_interval = Some(v); }
        }
        "clientalivecountmax" | "client_alive_count_max" => {
            if let Ok(v) = value.parse() { o.client_alive_count_max = Some(v); }
        }
        "tcpkeepalive" | "tcp_keep_alive" => o.tcp_keep_alive = Some(value == "yes"),
        "permituserenvironment" | "permit_user_environment" => o.permit_user_environment = Some(value == "yes"),
        "acceptenv" | "accept_env" => {
            let mut list = o.accept_env.take().unwrap_or_default();
            list.extend(value.split_whitespace().map(|s| s.to_string()));
            o.accept_env = Some(list);
        }
        "logingracetime" | "login_grace_time" => {
            if let Ok(v) = value.parse() { o.login_grace_time = Some(v); }
        }
        "loglevel" | "log_level" => o.log_level = Some(value.to_string()),
        "hostbasedauthentication" | "hostbased_auth" => o.hostbased_auth = Some(value == "yes"),
        "ignorerhosts" | "ignore_rhosts" => o.ignore_rhosts = Some(value == "yes"),
        _ => {}
    }
}

/// Match an address pattern: exact, glob, or CIDR prefix.
fn addr_match(pattern: &str, addr: &str) -> bool {
    let pattern = pattern.trim();
    if pattern == addr {
        return true;
    }
    if let Some((net, bits)) = pattern.split_once('/') {
        if let (Ok(net_ip), Ok(bits)) = (net.parse::<std::net::IpAddr>(), bits.parse::<u32>()) {
            if let Ok(addr_ip) = addr.parse::<std::net::IpAddr>() {
                return ip_in_network(addr_ip, net_ip, bits);
            }
        }
        return false;
    }
    pattern.contains('*') && simple_glob_match(pattern, addr)
}

fn ip_in_network(ip: std::net::IpAddr, net: std::net::IpAddr, bits: u32) -> bool {
    match (ip, net) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            let mask = if bits >= 32 { u32::MAX } else { (!0u32) << (32 - bits) };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            let mask = if bits >= 128 { u128::MAX } else { (!0u128) << (128 - bits) };
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

fn default_auth_failure_delay() -> u64 { 2 }

fn default_port() -> u16 { 22 }
fn default_listen_address() -> String { "0.0.0.0".to_string() }
fn default_true() -> bool { true }
fn default_max_auth_tries() -> u32 { 6 }
fn default_max_sessions() -> u32 { 10 }
fn default_client_alive_interval() -> u32 { 0 }
fn default_client_alive_count_max() -> u32 { 3 }
fn default_use_dns() -> bool { false }
fn default_pid_file() -> String { "/var/run/ns-ssh-server.pid".to_string() }
fn default_log_file() -> Option<String> { None }
fn default_banner() -> Option<String> { None }

fn default_rekey_bytes() -> u64 { 1 << 30 }

fn default_rekey_seconds() -> u64 { 3600 }

/// Parse an OpenSSH `RekeyLimit` value (see ssh_config(5)). Returns
/// `Some((bytes, seconds))`; `0` bytes means time-only rekeying.
pub fn parse_rekey_limit_server(value: &str) -> Option<(u64, u64)> {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("default") {
        return None;
    }
    let mut size: u64 = 0;
    let mut time: u64 = 0;
    let mut have_size = false;
    let mut have_time = false;
    for tok in v.split_whitespace() {
        // OpenSSH parses a bare number as time; a K/M/G-suffixed value as size.
        if let Some(s) = parse_time_suffix(tok) {
            time = s;
            have_time = true;
        } else if let Some(b) = parse_size_suffix(tok) {
            size = b;
            have_size = true;
        }
    }
    if !have_size && !have_time {
        return None;
    }
    Some((
        if have_size { size } else { 0 },
        if have_time { time } else { 3600 },
    ))
}

fn parse_size_suffix(tok: &str) -> Option<u64> {
    let (digits, mult) = match tok.chars().last()? {
        'k' | 'K' => (&tok[..tok.len() - 1], 1u64 << 10),
        'm' | 'M' => (&tok[..tok.len() - 1], 1u64 << 20),
        'g' | 'G' => (&tok[..tok.len() - 1], 1u64 << 30),
        c if c.is_ascii_digit() => (tok, 1u64),
        _ => return None,
    };
    digits.parse::<u64>().ok().map(|n| n.saturating_mul(mult))
}

fn parse_time_suffix(tok: &str) -> Option<u64> {
    let (digits, mult) = match tok.chars().last()? {
        // OpenSSH time suffixes are lowercase; 'M' is size/Mega, not minutes.
        's' => (&tok[..tok.len() - 1], 1u64),
        'm' => (&tok[..tok.len() - 1], 60u64),
        'h' => (&tok[..tok.len() - 1], 3600u64),
        'd' => (&tok[..tok.len() - 1], 86400u64),
        c if c.is_ascii_digit() => (tok, 1u64),
        _ => return None,
    };
    digits.parse::<u64>().ok().map(|n| n.saturating_mul(mult))
}

/// OpenSSH default `PubkeyAcceptedAlgorithms` base list for sshd. Matches the
/// key algorithms this server can verify, excluding the SHA-1 `ssh-rsa`
/// (OpenSSH >= 8.8 disables it by default).
pub const PUBKEY_ACCEPTED_BASE_SERVER: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

/// Resolve an OpenSSH `PubkeyAcceptedAlgorithms` pattern list for sshd.
/// `+algo` appends to the base, `-algo` removes, a bare `algo` replaces the
/// base, and `default` resets it. Wildcards (`*`) are supported.
pub fn resolve_pubkey_algorithms_server(value: &str) -> Vec<String> {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("default") {
        return PUBKEY_ACCEPTED_BASE_SERVER.iter().map(|s| s.to_string()).collect();
    }
    let mut list: Vec<String> = PUBKEY_ACCEPTED_BASE_SERVER.iter().map(|s| s.to_string()).collect();
    let mut replaced = false;
    for item in v.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (op, pat) = if let Some(rest) = item.strip_prefix('+') {
            ('+', rest.trim())
        } else if let Some(rest) = item.strip_prefix('-') {
            ('-', rest.trim())
        } else {
            ('=', item)
        };
        match op {
            '+' => {
                if !list.iter().any(|a| a == pat) {
                    list.push(pat.to_string());
                }
            }
            '-' => {
                list.retain(|a| !pattern_matches_server(pat, a));
            }
            _ => {
                if !replaced {
                    list.clear();
                    replaced = true;
                }
                if !list.iter().any(|a| a == pat) {
                    list.push(pat.to_string());
                }
            }
        }
    }
    list
}

/// Whether a signature algorithm is allowed by a resolved `PubkeyAcceptedAlgorithms` list.
pub fn pubkey_alg_accepted_server(alg: &str, accepted: &[String]) -> bool {
    accepted.iter().any(|pat| pattern_matches_server(pat, alg))
}

fn pattern_matches_server(pattern: &str, alg: &str) -> bool {
    if pattern == alg {
        return true;
    }
    if pattern.contains('*') || pattern.contains('?') {
        return simple_glob_match_server(pattern, alg);
    }
    false
}

/// Minimal glob matcher (`*` and `?`) used for algorithm pattern matching.
fn simple_glob_match_server(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut star_ti) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}
fn default_max_startups() -> String { "10:30:60".to_string() }
fn default_login_grace_time() -> u32 { 120 }

fn default_accept_env() -> Vec<String> {
    vec!["LANG".to_string(), "LC_*".to_string()]
}

fn default_x11_display_offset() -> u32 { 10 }

fn default_forwarding_mode() -> String { "yes".to_string() }

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            port: default_port(),
            listen_address: default_listen_address(),
            host_key_files: vec![
                "/etc/ssh/ssh_host_ed25519_key".to_string(),
                "/etc/ssh/ssh_host_rsa_key".to_string(),
                "/etc/ssh/ssh_host_ecdsa_key".to_string(),
            ],
            host_key_algorithms: None,
            kex_algorithms: None,
            ciphers: None,
            macs: None,
            rekey_limit_bytes: default_rekey_bytes(),
            rekey_limit_time: default_rekey_seconds(),
            pubkey_accepted_algorithms: None,
            compression: false,
            password_auth: default_true(),
            kbd_interactive_auth: default_true(),
            pubkey_auth: default_true(),
            permit_root_login: false,
            permit_root_login_mode: "no".to_string(),
            authorized_keys_files: vec![
                "~/.ssh/authorized_keys".to_string(),
                "~/.ssh/authorized_keys2".to_string(),
            ],
            allow_groups: Vec::new(),
            deny_groups: Vec::new(),
            allow_users: Vec::new(),
            deny_users: Vec::new(),
            max_auth_tries: default_max_auth_tries(),
            max_sessions: default_max_sessions(),
            client_alive_interval: default_client_alive_interval(),
            client_alive_count_max: default_client_alive_count_max(),
            use_dns: default_use_dns(),
            subsystems: {
                let mut m = HashMap::new();
                m.insert("sftp".to_string(), "internal-sftp".to_string());
                m
            },
            pid_file: default_pid_file(),
            log_file: default_log_file(),
            force_command: None,
            strict_modes: default_true(),
            permit_tty: default_true(),
            permit_empty_passwords: false,
            ignore_rhosts: default_true(),
            hostbased_auth: false,
            print_last_log: default_true(),
            tcp_keep_alive: default_true(),
            banner: default_banner(),
            max_startups: default_max_startups(),
            login_grace_time: default_login_grace_time(),
            accept_env: default_accept_env(),
            allow_agent_forwarding: default_true(),
            allow_streamlocal_forwarding: default_true(),
            x11_forwarding: false,
            x11_display_offset: default_x11_display_offset(),
            allow_tcp_forwarding_mode: default_forwarding_mode(),
            permit_open: Vec::new(),
            permit_listen: Vec::new(),
            gateway_ports: "no".to_string(),
            chroot_directory: None,
            auth_failure_delay: default_auth_failure_delay(),
            permit_user_environment: false,
            log_level: None,
            syslog_facility: None,
            print_motd: true,
            authorized_keys_command: None,
            authorized_keys_command_user: None,
            match_blocks: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// Resolve `Match` blocks against the given connection context, returning a
    /// new config with matching blocks' overrides applied on top of `self`.
    pub fn resolve_for_match(&self, username: &str, groups: &[String], host: &str, addr: &str) -> ServerConfig {
        let mut cfg = self.clone();
        for m in &self.match_blocks {
            if m.matches(username, groups, host, addr) {
                m.apply_to(&mut cfg);
            }
        }
        cfg
    }

    pub fn load() -> Self {
        let paths = [
            "/etc/ssh/sshd_config",
            "/etc/ns-ssh/sshd_config",
        ];

        for path in &paths {
            if Path::new(path).exists() {
                return Self::load_from(Path::new(path));
            }
        }

        Self::default()
    }

    pub fn load_from(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        let mut seen: Vec<PathBuf> = Vec::new();
        let content = Self::collect_config(path, 0, &mut seen);
        Self::parse(&content)
    }

    /// Recursively read a config file, expanding `Include` directives (with glob
    /// support and relative-to-file resolution) into a single line stream.
    fn collect_config(path: &Path, depth: usize, seen: &mut Vec<PathBuf>) -> String {
        if depth > 10 {
            return String::new();
        }
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if seen.contains(&canon) {
            return String::new();
        }
        seen.push(canon);

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return String::new(),
        };
        let base = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();

        let mut out = String::new();
        for line in content.lines() {
            let t = line.trim();
            let mut parts = t.splitn(2, |c: char| c.is_whitespace());
            let key = parts.next().unwrap_or("").to_lowercase();
            if key == "include" {
                let pattern = parts.next().unwrap_or("").trim();
                if pattern.is_empty() {
                    continue;
                }
                for f in Self::expand_glob(&base, pattern) {
                    out.push_str(&Self::collect_config(&f, depth + 1, seen));
                    out.push('\n');
                }
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    fn expand_glob(base: &Path, pattern: &str) -> Vec<PathBuf> {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let pattern = if pattern == "~" {
            home.to_string_lossy().to_string()
        } else if let Some(rest) = pattern.strip_prefix("~/") {
            format!("{}/{}", home.to_string_lossy(), rest)
        } else if let Some(rest) = pattern.strip_prefix("~") {
            format!("{}/{}", home.to_string_lossy(), rest.trim_start_matches('/'))
        } else {
            pattern.to_string()
        };

        let pat = Path::new(&pattern);
        let pat_path: PathBuf = if pat.is_absolute() {
            pat.to_path_buf()
        } else {
            base.join(pat)
        };
        let comps: Vec<String> = pat_path
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
                _ => None,
            })
            .collect();
        if comps.is_empty() {
            return vec![pat_path];
        }
        let start: PathBuf = if pat_path.is_absolute() {
            PathBuf::from("/")
        } else {
            base.to_path_buf()
        };
        let mut out = Vec::new();
        Self::glob_walk(&start, &comps, 0, &mut out);
        out.sort();
        out.dedup();
        out
    }

    fn glob_walk(dir: &Path, comps: &[String], idx: usize, out: &mut Vec<PathBuf>) {
        if idx == comps.len() {
            out.push(dir.to_path_buf());
            return;
        }
        let seg = &comps[idx];
        if seg == "**" {
            Self::glob_walk(dir, comps, idx + 1, out);
            if let Ok(rd) = fs::read_dir(dir) {
                for e in rd.flatten() {
                    if e.path().is_dir() {
                        Self::glob_walk(&e.path(), comps, idx, out);
                    }
                }
            }
        } else if seg.contains('*') || seg.contains('?') || seg.contains('[') {
            if let Ok(rd) = fs::read_dir(dir) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if simple_glob_match(seg, &name) {
                        Self::glob_walk(&e.path(), comps, idx + 1, out);
                    }
                }
            }
        } else {
            Self::glob_walk(&dir.join(seg), comps, idx + 1, out);
        }
    }

    pub fn parse(content: &str) -> Self {
        let mut config = ServerConfig::default();
        let mut current_match: Option<ServerMatch> = None;
        let mut host_key_seen = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut parts = line.splitn(2, |c: char| c.is_whitespace());
            let key = parts.next().unwrap_or("").to_lowercase();
            let value = parts.next().unwrap_or("").trim();

            // A `Match` line starts a new conditional block that extends to the
            // next `Match` line (OpenSSH requires indentation but we are lenient).
            if key == "match" {
                if let Some(m) = current_match.take() {
                    config.match_blocks.push(m);
                }
                current_match = Some(ServerMatch::new(value));
                continue;
            }

            // Directives inside a Match block populate its overrides.
            if let Some(m) = current_match.as_mut() {
                apply_match_override(&mut m.overrides, &key, value);
                continue;
            }

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
                    // The first HostKey directive replaces the default key list.
                    if !host_key_seen {
                        config.host_key_files.clear();
                        host_key_seen = true;
                    }
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
                "allowusers" | "allow_users" => {
                    config.allow_users.extend(value.split_whitespace().map(|s| s.to_string()));
                }
                "denyusers" | "deny_users" => {
                    config.deny_users.extend(value.split_whitespace().map(|s| s.to_string()));
                }
                "chrootdirectory" | "chroot_directory" => {
                    config.chroot_directory = Some(value.to_string());
                }
                "permituserenvironment" | "permit_user_environment" => {
                    config.permit_user_environment = value == "yes";
                }
                "loglevel" | "log_level" => {
                    config.log_level = Some(value.to_string());
                }
                "syslogfacility" | "syslog_facility" => {
                    config.syslog_facility = Some(value.to_string());
                }
                "printmotd" | "print_motd" => {
                    config.print_motd = value != "no";
                }
                "authorizedkeyscommand" | "authorized_keys_command" => {
                    config.authorized_keys_command = Some(value.to_string());
                }
                "authorizedkeyscommanduser" | "authorized_keys_command_user" => {
                    config.authorized_keys_command_user = Some(value.to_string());
                }
                "authenticationfailuredelay" | "authentication_failure_delay" => {
                    if let Ok(v) = value.parse::<u64>() {
                        config.auth_failure_delay = v;
                    }
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
                    if let Some((bytes, secs)) = parse_rekey_limit_server(value) {
                        config.rekey_limit_bytes = bytes;
                        config.rekey_limit_time = secs;
                    }
                }
                "pubkeyacceptedalgorithms" | "pubkey_accepted_algorithms" | "pubkeyacceptedkeytypes" => {
                    config.pubkey_accepted_algorithms = Some(resolve_pubkey_algorithms_server(value));
                }
                "compression" => {
                    config.compression = value == "yes";
                }
                "usedns" | "use_dns" => {
                    config.use_dns = value == "yes";
                }
                "allowtcpforwarding" | "allow_tcp_forwarding" => {
                    config.allow_tcp_forwarding_mode = value.to_lowercase();
                }
                "x11forwarding" | "x11_forwarding" => {
                    config.x11_forwarding = value == "yes";
                }
                "allowagentforwarding" | "allow_agent_forwarding" => {
                    config.allow_agent_forwarding = value == "yes";
                }
                "allowstreamlocalforwarding" | "allow_streamlocal_forwarding" => {
                    config.allow_streamlocal_forwarding = value == "yes";
                }
                "x11displayoffset" | "x11_display_offset" => {
                    if let Ok(n) = value.parse() {
                        config.x11_display_offset = n;
                    }
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
                "subsystem" => {
                    let mut sub_parts = value.splitn(2, |c: char| c.is_whitespace());
                    if let (Some(name), Some(path)) = (sub_parts.next(), sub_parts.next()) {
                        config.subsystems.insert(name.to_string(), path.to_string());
                    }
                }
                "pidfile" | "pid_file" => {
                    config.pid_file = value.to_string();
                }
                "logfile" | "log_file" => {
                    config.log_file = Some(value.to_string());
                }
                "forcecommand" | "force_command" => {
                    config.force_command = Some(value.to_string());
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
                "printlastlog" | "print_last_log" => {
                    config.print_last_log = value == "yes";
                }
                "tcpkeepalive" | "tcp_keep_alive" => {
                    config.tcp_keep_alive = value == "yes";
                }
                "include" => {
                    // Handled during load (collect_config). Ignore here for raw parse().
                }
                _ => {}
            }
        }

        if let Some(m) = current_match {
            config.match_blocks.push(m);
        }

        config
    }

    pub fn get_host_key_files(&self) -> Vec<PathBuf> {
        self.host_key_files.iter().map(|p| {
            if p.starts_with("~/") {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(&p[2..])
            } else {
                PathBuf::from(p)
            }
        }).collect()
    }

    pub fn get_authorized_keys_files(&self) -> Vec<PathBuf> {
        self.authorized_keys_files.iter().map(|p| {
            if p.starts_with("~/") {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(&p[2..])
            } else {
                PathBuf::from(p)
            }
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_accepted_algorithms_server_parsing() {
        // Bare list replaces the base.
        let l = resolve_pubkey_algorithms_server("ssh-ed25519");
        assert!(pubkey_alg_accepted_server("ssh-ed25519", &l));
        assert!(!pubkey_alg_accepted_server("rsa-sha2-512", &l));
        // `+ssh-rsa` appends to the base.
        let l = resolve_pubkey_algorithms_server("+ssh-rsa");
        assert!(pubkey_alg_accepted_server("ssh-rsa", &l));
        assert!(pubkey_alg_accepted_server("rsa-sha2-512", &l));
        // `-rsa-sha2-*` removes the rsa family.
        let l = resolve_pubkey_algorithms_server("-rsa-sha2-*");
        assert!(!pubkey_alg_accepted_server("rsa-sha2-512", &l));
        assert!(pubkey_alg_accepted_server("ssh-ed25519", &l));
        // `ecdsa-sha2-*` wildcard accepts the ecdsa family.
        let l = resolve_pubkey_algorithms_server("ecdsa-sha2-*");
        assert!(pubkey_alg_accepted_server("ecdsa-sha2-nistp256", &l));
        assert!(!pubkey_alg_accepted_server("ssh-ed25519", &l));
        // Base excludes ssh-rsa by default.
        let l = resolve_pubkey_algorithms_server("default");
        assert!(!pubkey_alg_accepted_server("ssh-rsa", &l));
        assert!(pubkey_alg_accepted_server("ssh-ed25519", &l));
    }

    #[test]
    fn match_block_parses_conditions_and_overrides() {
        let content = "\
Port 2222
Match User alice,root
    ForceCommand /bin/echo hi
    PasswordAuthentication no
Match Address 10.0.0.0/8
    X11Forwarding yes
";
        let cfg = ServerConfig::parse(content);
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.match_blocks.len(), 2);

        let m0 = &cfg.match_blocks[0];
        assert_eq!(m0.conditions[0], ("user".to_string(), "alice,root".to_string()));
        assert_eq!(m0.overrides.force_command.as_deref(), Some("/bin/echo hi"));
        assert_eq!(m0.overrides.password_auth, Some(false));

        let m1 = &cfg.match_blocks[1];
        assert_eq!(m1.conditions[0], ("address".to_string(), "10.0.0.0/8".to_string()));
        assert_eq!(m1.overrides.x11_forwarding, Some(true));
    }

    #[test]
    fn match_condition_evaluation() {
        let cfg = ServerConfig::parse("\
Match User alice,root
    ForceCommand echo A
Match Group admin
    ForceCommand echo G
Match Address 192.168.1.0/24
    ForceCommand echo N
Match All
    Banner /etc/banner
");
        // User alice matches; group/staff not; address not.
        let r = cfg.resolve_for_match("alice", &["staff".to_string()], "srv", "10.0.0.5");
        assert_eq!(r.force_command.as_deref(), Some("echo A"));

        // Group admin matches.
        let r = cfg.resolve_for_match("bob", &["admin".to_string()], "srv", "10.0.0.5");
        assert_eq!(r.force_command.as_deref(), Some("echo G"));

        // Address 192.168.1.50 matches.
        let r = cfg.resolve_for_match("bob", &[], "srv", "192.168.1.50");
        assert_eq!(r.force_command.as_deref(), Some("echo N"));

        // Match All always applies (banner set).
        let r = cfg.resolve_for_match("carol", &[], "srv", "10.0.0.5");
        assert_eq!(r.banner.as_deref(), Some("/etc/banner"));
    }

    #[test]
    fn addr_match_cidr_and_glob() {
        assert!(addr_match("10.0.0.0/8", "10.1.2.3"));
        assert!(!addr_match("10.0.0.0/8", "11.1.2.3"));
        assert!(addr_match("192.168.*", "192.168.5.9"));
        assert!(addr_match("127.0.0.1", "127.0.0.1"));
        assert!(!addr_match("127.0.0.1", "127.0.0.2"));
    }

    #[test]
    fn host_key_replaces_defaults() {
        let cfg = ServerConfig::parse("HostKey /tmp/custom_ed25519\nHostKey /tmp/custom_rsa\n");
        assert_eq!(cfg.host_key_files, vec!["/tmp/custom_ed25519".to_string(), "/tmp/custom_rsa".to_string()]);
    }

    #[test]
    fn algorithm_directives_parse() {
        let cfg = ServerConfig::parse(
            "KexAlgorithms curve25519-sha256\n\
             Ciphers aes256-ctr\n\
             MACs hmac-sha2-256\n\
             HostKeyAlgorithms ssh-ed25519\n\
             StrictModes no\n\
             PermitTTY no\n",
        );
        assert_eq!(cfg.kex_algorithms.as_deref(), Some("curve25519-sha256"));
        assert_eq!(cfg.ciphers.as_deref(), Some("aes256-ctr"));
        assert_eq!(cfg.macs.as_deref(), Some("hmac-sha2-256"));
        assert_eq!(cfg.host_key_algorithms.as_deref(), Some("ssh-ed25519"));
        assert!(!cfg.strict_modes);
        assert!(!cfg.permit_tty);
    }

    #[test]
    fn security_directives_parse() {
        let cfg = ServerConfig::parse(
            "IgnoreRhosts no\n\
             HostbasedAuthentication yes\n\
             PrintLastLog no\n\
             TCPKeepAlive no\n\
             PermitEmptyPasswords yes\n",
        );
        assert!(!cfg.ignore_rhosts);
        assert!(cfg.hostbased_auth);
        assert!(!cfg.print_last_log);
        assert!(!cfg.tcp_keep_alive);
        assert!(cfg.permit_empty_passwords);
    }
}
