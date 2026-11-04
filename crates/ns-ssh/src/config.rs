use std::path::{Path, PathBuf};
use std::fs;
use serde::Deserialize;
use ssh_core::error::{SshError, Result};

/// OpenSSH `StrictHostKeyChecking` mode: `yes`, `no`, or `ask`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyChecking {
    Yes,
    No,
    Ask,
}

impl HostKeyChecking {
    /// Parse an OpenSSH config value ("yes"/"no"/"ask").
    pub fn parse(value: &str) -> HostKeyChecking {
        match value.to_ascii_lowercase().as_str() {
            "no" => HostKeyChecking::No,
            "ask" => HostKeyChecking::Ask,
            _ => HostKeyChecking::Yes,
        }
    }

    /// True when an unknown host key should be rejected without prompting.
    pub fn is_strict(&self) -> bool {
        matches!(self, HostKeyChecking::Yes)
    }

    /// True when the user should be prompted to accept an unknown host key.
    pub fn is_ask(&self) -> bool {
        matches!(self, HostKeyChecking::Ask)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HostKeyChecking::Yes => "yes",
            HostKeyChecking::No => "no",
            HostKeyChecking::Ask => "ask",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SshConfig {
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
    #[serde(skip, default)]
    pub match_blocks: Vec<MatchConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostConfig {
    pub host: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub identity_file: Option<String>,
    #[serde(default)]
    pub identities_only: Option<bool>,
    #[serde(default)]
    pub forward_agent: Option<bool>,
    #[serde(default)]
    pub forward_x11: Option<bool>,
    #[serde(default)]
    pub compression: Option<bool>,
    #[serde(default)]
    pub strict_host_key_checking: Option<String>,
    #[serde(default)]
    pub hash_known_hosts: Option<bool>,
    #[serde(default)]
    pub user_known_hosts_file: Option<String>,
    #[serde(default)]
    pub global_known_hosts_file: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<u32>,
    #[serde(default)]
    pub server_alive_interval: Option<u32>,
    #[serde(default)]
    pub server_alive_count_max: Option<u32>,
    #[serde(default)]
    pub tcp_keep_alive: Option<bool>,
    #[serde(default)]
    pub batch_mode: Option<bool>,
    #[serde(default)]
    pub password_authentication: Option<bool>,
    #[serde(default)]
    pub pubkey_authentication: Option<bool>,
    #[serde(default)]
    pub kbd_interactive_authentication: Option<bool>,
    #[serde(default)]
    pub preferred_authentications: Option<String>,
    #[serde(default)]
    pub host_key_algorithms: Option<String>,
    #[serde(default)]
    pub kex_algorithms: Option<String>,
    #[serde(default)]
    pub ciphers: Option<String>,
    #[serde(default)]
    pub macs: Option<String>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub exit_on_forward_failure: Option<bool>,
    #[serde(default)]
    pub send_env: Option<Vec<String>>,
    #[serde(default)]
    pub set_env: Option<Vec<String>>,
    #[serde(default)]
    pub proxy_jump: Option<String>,
    #[serde(default)]
    pub proxy_command: Option<String>,
    #[serde(default)]
    pub bind_address: Option<String>,
    #[serde(default)]
    pub local_forward: Option<Vec<String>>,
    #[serde(default)]
    pub remote_forward: Option<Vec<String>>,
    #[serde(default)]
    pub dynamic_forward: Option<Vec<String>>,
    #[serde(default)]
    pub request_tty: Option<String>,
    #[serde(default)]
    pub remote_command: Option<String>,
    #[serde(default)]
    pub add_keys_to_agent: Option<String>,
    #[serde(default)]
    pub no_host_authentication_for_localhost: Option<bool>,
    #[serde(default)]
    pub verify_host_key_dns: Option<String>,
    #[serde(default)]
    pub address_family: Option<String>,
    #[serde(default)]
    pub escape_char: Option<String>,
    #[serde(default)]
    pub subsystem: Option<String>,
    #[serde(default)]
    pub local_command: Option<String>,
    #[serde(default)]
    pub permit_local_command: Option<bool>,
    #[serde(default)]
    pub host_key_alias: Option<String>,
    #[serde(default)]
    pub fingerprint_hash: Option<String>,
    #[serde(default)]
    pub visual_host_key: Option<bool>,
    #[serde(default)]
    pub check_host_ip: Option<bool>,
    #[serde(default)]
    pub number_of_password_prompts: Option<u32>,
    #[serde(default)]
    pub connection_attempts: Option<u32>,
    #[serde(default)]
    pub rekey_limit: Option<String>,
    #[serde(default)]
    pub identity_agent: Option<String>,
    #[serde(default)]
    pub pubkey_accepted_algorithms: Option<String>,
    #[serde(default)]
    /// ControlMaster: "yes", "no", or "auto" (auto = only as master if no existing socket).
    pub control_master: Option<String>,
    #[serde(default)]
    pub control_path: Option<String>,
    #[serde(default)]
    /// ControlPersist: "no" or seconds (OpenSSH also accepts time suffixes like "10m").
    pub control_persist: Option<String>,
    #[serde(default)]
    pub gateway_ports: Option<bool>,
    #[serde(default)]
    pub clear_all_forwardings: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct MatchConfig {
    pub conditions: Vec<(String, String)>,
    pub config: HostConfig,
}

impl MatchConfig {
    /// Check whether this Match block applies to the given host and user.
    pub fn matches(&self, target_host: &str, target_user: &str) -> bool {
        for (key, value) in &self.conditions {
            match key.as_str() {
                "host" => {
                    let matched = value.split(',').any(|p| {
                        let p = p.trim();
                        p == target_host || (p.contains('*') && glob_match(p, target_host))
                    });
                    if !matched { return false; }
                }
                "user" => {
                    let matched = value.split(',').any(|p| {
                        let p = p.trim();
                        p == target_user || (p.contains('*') && glob_match(p, target_user))
                    });
                    if !matched { return false; }
                }
                _ => {} // unknown conditions are ignored
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<PathBuf>,
    pub identities_only: bool,
    pub forward_agent: bool,
    pub forward_x11: bool,
    pub compression: bool,
    pub strict_host_key_checking: HostKeyChecking,
    pub hash_known_hosts: bool,
    pub user_known_hosts_file: Option<PathBuf>,
    pub global_known_hosts_file: Option<PathBuf>,
    pub connect_timeout: Option<u32>,
    pub server_alive_interval: Option<u32>,
    pub server_alive_count_max: Option<u32>,
    pub tcp_keep_alive: bool,
    pub batch_mode: bool,
    pub password_authentication: bool,
    pub pubkey_authentication: bool,
    pub kbd_interactive_authentication: bool,
    pub preferred_authentications: Option<Vec<String>>,
    pub host_key_algorithms: Option<Vec<String>>,
    pub kex_algorithms: Option<Vec<String>>,
    pub ciphers: Option<Vec<String>>,
    pub macs: Option<Vec<String>>,
    pub log_level: Option<String>,
    pub exit_on_forward_failure: bool,
    pub send_env: Vec<String>,
    pub set_env: Vec<(String, String)>,
    pub request_tty: bool,
    pub remote_command: Option<String>,
    pub add_keys_to_agent: bool,
    /// TCP forwards as `(bind_addr, bind_port, host, connect_port)`. A forward
    /// with an empty `bind_addr` uses the global BindAddress / GatewayPorts policy.
    pub local_forwards: Vec<(String, u16, String, u16)>,
    pub remote_forwards: Vec<(String, u16, String, u16)>,
    pub dynamic_forwards: Vec<u16>,
    /// StreamLocal `-L local_socket:remote_socket` forwards (Unix sockets).
    pub local_streamlocal: Vec<(String, String)>,
    /// StreamLocal `-R remote_socket:local_socket` forwards (Unix sockets).
    pub remote_streamlocal: Vec<(String, String)>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub bind_address: Option<String>,
    pub no_remote_command: bool,
    pub prefer_ipv4: bool,
    pub prefer_ipv6: bool,
    pub quiet: bool,
    pub escape_char: String,
    pub verbosity: u8,
    pub stdio_forward: Option<(String, u16)>,
    pub subsystem: Option<String>,
    /// Set by ssh-keyscan: capture the host key without verifying it.
    pub ssh_keyscan: bool,
    /// LocalCommand/PermitLocalCommand: run a command on the local machine after connect.
    pub local_command: Option<String>,
    pub permit_local_command: bool,
    /// -E log file: write diagnostics to a file instead of stderr.
    pub log_file: Option<PathBuf>,
    /// -g: allow remote hosts to connect to local forwards.
    pub gateway_ports: bool,
    /// ControlMaster: auto/yes/no (whether to multiplex the connection).
    pub control_master: bool,
    /// ControlMaster auto: only act as master if no existing socket.
    pub control_master_auto: bool,
    /// ControlPath: Unix socket used for connection multiplexing.
    pub control_path: Option<String>,
    /// ControlPersist: seconds to keep the master alive after the last session.
    pub control_persist: Option<u32>,
    /// HostKeyAlias: use this hostname for host-key verification instead of the real one.
    pub host_key_alias: Option<String>,
    /// FingerprintHash: md5 or sha256 (default sha256) for displaying key fingerprints.
    pub fingerprint_hash: String,
    /// VisualHostKey: print ASCII randomart of the host key.
    pub visual_host_key: bool,
    /// CheckHostIP: also verify the server's IP in known_hosts (default yes).
    pub check_host_ip: bool,
    /// NumberOfPasswordPrompts: max password prompt attempts (default 3).
    pub number_of_password_prompts: u32,
    /// ConnectionAttempts: TCP connect retries (default 1).
    pub connection_attempts: u32,
    /// VerifyHostKeyDNS: yes/no/ask — verify the host key against SSHFP records.
    pub verify_host_key_dns: String,
    /// NoHostAuthenticationForLocalhost: skip host-key verification for localhost.
    pub no_host_authentication_for_localhost: bool,
    /// RekeyLimit: bytes before rekeying (0 = time-only; default 1 GiB).
    pub rekey_limit_bytes: u64,
    /// RekeyLimit: seconds before rekeying (default 3600).
    pub rekey_limit_time: u64,
    /// IdentityAgent: use this Unix socket for ssh-agent instead of $SSH_AUTH_SOCK.
    pub identity_agent: Option<String>,
    /// PubkeyAcceptedAlgorithms: restrict which public-key signature algorithms
    /// are offered during publickey authentication. `None` = accept all (default).
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
}

impl ResolvedConfig {
    pub fn default_for_user(user: &str) -> Self {
        ResolvedConfig {
            hostname: String::new(),
            port: 22,
            user: user.to_string(),
            identity_file: None,
            identities_only: false,
            forward_agent: false,
            forward_x11: false,
            compression: false,
            strict_host_key_checking: HostKeyChecking::Yes,
            hash_known_hosts: false,
            user_known_hosts_file: None,
            global_known_hosts_file: None,
            connect_timeout: None,
            server_alive_interval: None,
            server_alive_count_max: None,
            tcp_keep_alive: true,
            batch_mode: false,
            password_authentication: true,
            pubkey_authentication: true,
            kbd_interactive_authentication: true,
            preferred_authentications: None,
            host_key_algorithms: None,
            kex_algorithms: None,
            ciphers: None,
            macs: None,
            log_level: None,
            exit_on_forward_failure: false,
            // OpenSSH's default `SendEnv` is empty; variables are only sent when
            // the user opts in via `-o SendEnv`/config `SendEnv`.
            send_env: Vec::new(),
            set_env: Vec::new(),
            request_tty: false,
            remote_command: None,
            add_keys_to_agent: false,
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forwards: Vec::new(),
            local_streamlocal: Vec::new(),
            remote_streamlocal: Vec::new(),
            proxy_jump: None,
            proxy_command: None,
            bind_address: None,
            no_remote_command: false,
            prefer_ipv4: false,
            prefer_ipv6: false,
            quiet: false,
            escape_char: "~".to_string(),
            verbosity: 0,
            stdio_forward: None,
            subsystem: None,
            ssh_keyscan: false,
            local_command: None,
            permit_local_command: false,
            log_file: None,
            gateway_ports: false,
            control_master: false,
            control_master_auto: false,
            control_path: None,
            control_persist: None,
            host_key_alias: None,
            fingerprint_hash: "sha256".to_string(),
            visual_host_key: false,
            check_host_ip: true,
            number_of_password_prompts: 3,
            connection_attempts: 1,
            // OpenSSH's default is "no"; doing an SSHFP lookup for every
            // connection is both a surprise and a wire-visible leak of the
            // target hostname.
            verify_host_key_dns: "no".to_string(),
            no_host_authentication_for_localhost: false,
            rekey_limit_bytes: 1 << 30,
            rekey_limit_time: 3600,
            identity_agent: None,
            pubkey_accepted_algorithms: None,
        }
    }
}

impl SshConfig {
    pub fn load() -> Self {
        let config_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ssh")
            .join("config");

        Self::load_from(&config_path)
    }

    pub fn load_from(path: &Path) -> Self {
        if !path.exists() {
            return SshConfig { hosts: Vec::new(), match_blocks: Vec::new() };
        }

        let mut seen: Vec<PathBuf> = Vec::new();
        let content = Self::collect_config(path, 0, &mut seen);
        Self::parse(&content).expect("failed to parse client config")
    }

    /// Recursively read a config file, expanding `Include` directives. Returns the
    /// concatenated text of the file and all included files (in include order).
    fn collect_config(path: &Path, depth: usize, seen: &mut Vec<PathBuf>) -> String {
        if depth > 10 {
            return String::new();
        }
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if seen.contains(&canon) {
            return String::new(); // avoid include cycles
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

    /// Expand a glob pattern (supporting `*`, `?` and `**`) relative to `base`.
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

    /// Parse a single config file (no include expansion) from raw text.
    pub fn parse(content: &str) -> Result<Self> {
        let mut hosts = Vec::new();
        let mut match_blocks = Vec::new();
        let mut current_host: Option<String> = None;
        let mut current_match_conditions: Option<Vec<(String, String)>> = None;
        let mut hostname = None;
        let mut user = None;
        let mut port = None;
        let mut identity_file = None;
        let mut identities_only = None;
        let mut forward_agent = None;
        let mut forward_x11 = None;
        let mut compression = None;
        let mut strict_host_key_checking = None;
        let mut hash_known_hosts = None;
        let mut user_known_hosts_file = None;
        let mut global_known_hosts_file = None;
        let mut connect_timeout = None;
        let mut server_alive_interval = None;
        let mut server_alive_count_max = None;
        let mut tcp_keep_alive = None;
        let mut batch_mode = None;
        let mut password_authentication = None;
        let mut pubkey_authentication = None;
        let mut kbd_interactive_authentication = None;
        let mut preferred_authentications = None;
        let mut host_key_algorithms = None;
        let mut kex_algorithms = None;
        let mut ciphers = None;
        let mut macs = None;
        let mut log_level = None;
        let mut exit_on_forward_failure = None;
        let mut send_env: Option<Vec<String>> = None;
        let mut set_env: Option<Vec<String>> = None;
        let mut proxy_jump = None;
        let mut proxy_command = None;
        let mut bind_address = None;
        let mut local_forward = None;
        let mut remote_forward = None;
        let mut dynamic_forward = None;
        let mut request_tty = None;
        let mut remote_command = None;
        let mut add_keys_to_agent = None;
        let mut no_host_authentication_for_localhost = None;
        let mut verify_host_key_dns = None;
        let mut address_family = None;
        let mut escape_char = None;
        let mut subsystem = None;
        let mut local_command = None;
        let mut permit_local_command = None;
        let mut host_key_alias = None;
        let mut fingerprint_hash = None;
        let mut visual_host_key = None;
        let mut check_host_ip = None;
        let mut number_of_password_prompts = None;
        let mut connection_attempts = None;
        let mut rekey_limit = None;
        let mut identity_agent = None;
        let mut pubkey_accepted_algorithms = None;
        let mut control_master = None;
        let mut control_path = None;
        let mut control_persist = None;
        let mut gateway_ports = None;
        let mut clear_all_forwardings = None;

        let yes = |v: &str| v.eq_ignore_ascii_case("yes") || v.eq_ignore_ascii_case("true");
        let parse_u32 = |v: &str| v.parse::<u32>().ok();
        let push_list = |list: &mut Option<Vec<String>>, v: &str| {
            list.get_or_insert_with(Vec::new).push(v.to_string());
        };

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut parts = line.splitn(2, |c: char| c.is_whitespace());
            let key = parts.next().unwrap_or("").to_lowercase();
            let value = parts.next().unwrap_or("").trim();

            match key.as_str() {
                "host" => {
                    if let Some(h) = current_host.take() {
                        hosts.push(HostConfig {
                            host: h,
                            hostname: hostname.take(),
                            user: user.take(),
                            port: port.take(),
                            identity_file: identity_file.take(),
                            identities_only: identities_only.take(),
                            forward_agent: forward_agent.take(),
                            forward_x11: forward_x11.take(),
                            compression: compression.take(),
                            strict_host_key_checking: strict_host_key_checking.take(),
                            hash_known_hosts: hash_known_hosts.take(),
                            user_known_hosts_file: user_known_hosts_file.take(),
                            global_known_hosts_file: global_known_hosts_file.take(),
                            connect_timeout: connect_timeout.take(),
                            server_alive_interval: server_alive_interval.take(),
                            server_alive_count_max: server_alive_count_max.take(),
                            tcp_keep_alive: tcp_keep_alive.take(),
                            batch_mode: batch_mode.take(),
                            password_authentication: password_authentication.take(),
                            pubkey_authentication: pubkey_authentication.take(),
                            kbd_interactive_authentication: kbd_interactive_authentication.take(),
                            preferred_authentications: preferred_authentications.take(),
                            host_key_algorithms: host_key_algorithms.take(),
                            kex_algorithms: kex_algorithms.take(),
                            ciphers: ciphers.take(),
                            macs: macs.take(),
                            log_level: log_level.take(),
                            exit_on_forward_failure: exit_on_forward_failure.take(),
                            send_env: send_env.take(),
                            set_env: set_env.take(),
                            proxy_jump: proxy_jump.take(),
                            proxy_command: proxy_command.take(),
                            bind_address: bind_address.take(),
                            local_forward: local_forward.take(),
                            remote_forward: remote_forward.take(),
                            dynamic_forward: dynamic_forward.take(),
                            request_tty: request_tty.take(),
                            remote_command: remote_command.take(),
                            add_keys_to_agent: add_keys_to_agent.take(),
                             no_host_authentication_for_localhost: no_host_authentication_for_localhost.take(),
                             verify_host_key_dns: verify_host_key_dns.take(),
                             address_family: address_family.take(),
                             escape_char: escape_char.take(),
                             subsystem: subsystem.take(),
                             local_command: local_command.take(),
                             permit_local_command: permit_local_command.take(),
                             host_key_alias: host_key_alias.take(),
                             fingerprint_hash: fingerprint_hash.take(),
                             visual_host_key: visual_host_key.take(),
                             check_host_ip: check_host_ip.take(),
                             number_of_password_prompts: number_of_password_prompts.take(),
                             connection_attempts: connection_attempts.take(),
                             rekey_limit: rekey_limit.take(),
                             identity_agent: identity_agent.take(),
                             pubkey_accepted_algorithms: pubkey_accepted_algorithms.take(),
                             control_master: control_master.take(),
                             control_path: control_path.take(),
                             control_persist: control_persist.take(),
                             gateway_ports: gateway_ports.take(),
                             clear_all_forwardings: clear_all_forwardings.take(),
                         });
                    }
                    current_host = Some(value.to_string());
                }
                "match" => {
                    // Flush any open host block first
                    if let Some(h) = current_host.take() {
                        hosts.push(HostConfig {
                            host: h,
                            hostname: hostname.take(),
                            user: user.take(),
                            port: port.take(),
                            identity_file: identity_file.take(),
                            identities_only: identities_only.take(),
                            forward_agent: forward_agent.take(),
                            forward_x11: forward_x11.take(),
                            compression: compression.take(),
                            strict_host_key_checking: strict_host_key_checking.take(),
                            hash_known_hosts: hash_known_hosts.take(),
                            user_known_hosts_file: user_known_hosts_file.take(),
                            global_known_hosts_file: global_known_hosts_file.take(),
                            connect_timeout: connect_timeout.take(),
                            server_alive_interval: server_alive_interval.take(),
                            server_alive_count_max: server_alive_count_max.take(),
                            tcp_keep_alive: tcp_keep_alive.take(),
                            batch_mode: batch_mode.take(),
                            password_authentication: password_authentication.take(),
                            pubkey_authentication: pubkey_authentication.take(),
                            kbd_interactive_authentication: kbd_interactive_authentication.take(),
                            preferred_authentications: preferred_authentications.take(),
                            host_key_algorithms: host_key_algorithms.take(),
                            kex_algorithms: kex_algorithms.take(),
                            ciphers: ciphers.take(),
                            macs: macs.take(),
                            log_level: log_level.take(),
                            exit_on_forward_failure: exit_on_forward_failure.take(),
                            send_env: send_env.take(),
                            set_env: set_env.take(),
                            proxy_jump: proxy_jump.take(),
                            proxy_command: proxy_command.take(),
                            bind_address: bind_address.take(),
                            local_forward: local_forward.take(),
                            remote_forward: remote_forward.take(),
                            dynamic_forward: dynamic_forward.take(),
                            request_tty: request_tty.take(),
                            remote_command: remote_command.take(),
                            add_keys_to_agent: add_keys_to_agent.take(),
                             no_host_authentication_for_localhost: no_host_authentication_for_localhost.take(),
                             verify_host_key_dns: verify_host_key_dns.take(),
                             address_family: address_family.take(),
                             escape_char: escape_char.take(),
                             subsystem: subsystem.take(),
                             local_command: local_command.take(),
                             permit_local_command: permit_local_command.take(),
                             host_key_alias: host_key_alias.take(),
                             fingerprint_hash: fingerprint_hash.take(),
                             visual_host_key: visual_host_key.take(),
                             check_host_ip: check_host_ip.take(),
                             number_of_password_prompts: number_of_password_prompts.take(),
                             connection_attempts: connection_attempts.take(),
                             rekey_limit: rekey_limit.take(),
                             identity_agent: identity_agent.take(),
                             pubkey_accepted_algorithms: pubkey_accepted_algorithms.take(),
                             control_master: control_master.take(),
                             control_path: control_path.take(),
                             control_persist: control_persist.take(),
                             gateway_ports: gateway_ports.take(),
                             clear_all_forwardings: clear_all_forwardings.take(),
                          });
                    }
                    // Parse match conditions (comma-separated key=value pairs)
                    let mut conditions = Vec::new();
                    for cond in value.split(',') {
                        let cond = cond.trim();
                        if let Some((k, v)) = cond.split_once(' ') {
                            conditions.push((k.trim().to_lowercase(), v.trim().to_string()));
                        }
                    }
                    current_match_conditions = Some(conditions);
                }
                "hostname" => hostname = Some(value.to_string()),
                "user" => user = Some(value.to_string()),
                "port" => port = value.parse().ok(),
                "identityfile" | "identity_file" => identity_file = Some(value.to_string()),
                "identitiesonly" | "identities_only" => identities_only = Some(yes(value)),
                "forwardagent" | "forward_agent" => forward_agent = Some(yes(value)),
                "forwardx11" | "forward_x11" => forward_x11 = Some(yes(value)),
                "compression" => compression = Some(yes(value)),
                "stricthostkeychecking" | "strict_host_key_checking" => {
                    strict_host_key_checking = Some(value.to_string())
                }
                "hashknownhosts" | "hash_known_hosts" => hash_known_hosts = Some(yes(value)),
                "userknownhostsfile" | "user_known_hosts_file" => {
                    user_known_hosts_file = Some(value.to_string())
                }
                "globalknownhostsfile" | "global_known_hosts_file" => {
                    global_known_hosts_file = Some(value.to_string())
                }
                "connecttimeout" | "connect_timeout" => connect_timeout = parse_u32(value),
                "serveraliveinterval" | "server_alive_interval" => server_alive_interval = parse_u32(value),
                "serveralivecountmax" | "server_alive_count_max" => server_alive_count_max = parse_u32(value),
                "tcpkeepalive" | "tcp_keep_alive" => tcp_keep_alive = Some(yes(value)),
                "batchmode" | "batch_mode" => batch_mode = Some(yes(value)),
                "passwordauthentication" | "password_authentication" => password_authentication = Some(yes(value)),
                "pubkeyauthentication" | "pubkey_authentication" => pubkey_authentication = Some(yes(value)),
                "kbdinteractiveauthentication" | "kbd_interactive_authentication"
                    | "challenge-response-authentication" => kbd_interactive_authentication = Some(yes(value)),
                "preferredauthentications" | "preferred_authentications" => preferred_authentications = Some(value.to_string()),
                "hostkeyalgorithms" | "host_key_algorithms" => host_key_algorithms = Some(value.to_string()),
                "kexalgorithms" | "kex_algorithms" => kex_algorithms = Some(value.to_string()),
                "ciphers" | "ciphers_strict" => ciphers = Some(value.to_string()),
                "macs" | "macs_strict" => macs = Some(value.to_string()),
                "loglevel" | "log_level" | "verbose" => log_level = Some(value.to_string()),
                "exitonforwardfailure" | "exit_on_forward_failure" => exit_on_forward_failure = Some(yes(value)),
                "sendenv" | "send_env" => for tok in value.split_whitespace() { push_list(&mut send_env, tok); },
                "setenv" | "set_env" => for tok in value.split_whitespace() { push_list(&mut set_env, tok); },
                "proxyjump" | "proxy_jump" => proxy_jump = Some(value.to_string()),
                "proxycommand" | "proxy_command" => proxy_command = Some(value.to_string()),
                "bindaddress" | "bind_address" => bind_address = Some(value.to_string()),
                "localforward" | "local_forward" => {
                    local_forward.get_or_insert_with(Vec::new).push(value.to_string());
                }
                "remoteforward" | "remote_forward" => {
                    remote_forward.get_or_insert_with(Vec::new).push(value.to_string());
                }
                "dynamicforward" | "dynamic_forward" => {
                    dynamic_forward.get_or_insert_with(Vec::new).push(value.to_string());
                }
                "requesttty" | "request_tty" | "tty" | "allocate-tty" => request_tty = Some(value.to_string()),
                "remotecommand" | "remote_command" | "remote-cmd" => remote_command = Some(value.to_string()),
                "addkeystoagent" | "add_keys_to_agent" => add_keys_to_agent = Some(value.to_string()),
                "nohostauthenticationforlocalhost" | "no_host_authentication_for_localhost" => {
                    no_host_authentication_for_localhost = Some(yes(value))
                }

                "verifyhostkeydns" | "verify_host_key_dns" => verify_host_key_dns = Some(value.to_string()),
                "addressfamily" | "address_family" => address_family = Some(value.to_string()),
                "escapechar" | "escape_char" => escape_char = Some(value.to_string()),
                "subsystem" => subsystem = Some(value.to_string()),
                "localcommand" | "local_command" => local_command = Some(value.to_string()),
                "permitlocalcommand" | "permit_local_command" => {
                    permit_local_command = Some(value != "no");
                }
                "hostkeyalias" | "host_key_alias" => host_key_alias = Some(value.to_string()),
                "fingerprinthash" | "fingerprint_hash" => fingerprint_hash = Some(value.to_string()),
                "visualhostkey" | "visual_host_key" => visual_host_key = Some(yes(value)),
                "checkhostip" | "check_host_ip" => check_host_ip = Some(yes(value)),
                "numberofpasswordprompts" | "number_of_password_prompts" => number_of_password_prompts = parse_u32(value),
                "connectionattempts" | "connection_attempts" => connection_attempts = parse_u32(value),
                "rekeylimit" | "rekey_limit" => rekey_limit = Some(value.to_string()),
                "identityagent" | "identity_agent" => identity_agent = Some(value.to_string()),
                "pubkeyacceptedalgorithms" | "pubkey_accepted_algorithms" | "pubkeyacceptedkeytypes" => {
                    pubkey_accepted_algorithms = Some(value.to_string());
                }
                "controlmaster" | "control_master" => control_master = Some(value.to_string()),
                "controlpath" | "control_path" => control_path = Some(value.to_string()),
                "controlpersist" | "control_persist" => control_persist = Some(value.to_string()),
                "gatewayports" | "gateway_ports" => gateway_ports = Some(yes(value)),
                "clearallforwardings" | "clear_all_forwardings" => clear_all_forwardings = Some(yes(value)),
                "include" => { /* ignored */ }
                _ => return Err(SshError::Config(format!(
                    "unknown directive: {}",
                    key
                ))),
            }
        }

        // Flush any remaining host block
        if let Some(h) = current_host {
            hosts.push(HostConfig {
                host: h,
                hostname: hostname.clone(),
                user: user.clone(),
                port,
                identity_file: identity_file.clone(),
                identities_only,
                forward_agent,
                forward_x11,
                compression,
                strict_host_key_checking: strict_host_key_checking.clone(),
                hash_known_hosts,
                user_known_hosts_file: user_known_hosts_file.clone(),
                global_known_hosts_file: global_known_hosts_file.clone(),
                connect_timeout,
                server_alive_interval,
                server_alive_count_max,
                tcp_keep_alive,
                batch_mode,
                password_authentication,
                pubkey_authentication,
                kbd_interactive_authentication,
                preferred_authentications: preferred_authentications.clone(),
                host_key_algorithms: host_key_algorithms.clone(),
                kex_algorithms: kex_algorithms.clone(),
                ciphers: ciphers.clone(),
                macs: macs.clone(),
                log_level: log_level.clone(),
                exit_on_forward_failure,
                send_env: send_env.clone(),
                set_env: set_env.clone(),
                proxy_jump: proxy_jump.clone(),
                proxy_command: proxy_command.clone(),
                bind_address: bind_address.clone(),
                local_forward: local_forward.clone(),
                remote_forward: remote_forward.clone(),
                dynamic_forward: dynamic_forward.clone(),
                request_tty: request_tty.clone(),
                remote_command: remote_command.clone(),
                add_keys_to_agent: add_keys_to_agent.clone(),
                no_host_authentication_for_localhost,
                verify_host_key_dns: verify_host_key_dns.clone(),
                address_family: address_family.clone(),
                escape_char: escape_char.clone(),
                subsystem: subsystem.clone(),
                local_command: local_command.clone(),
                permit_local_command: permit_local_command.clone(),
                host_key_alias: host_key_alias.clone(),
                fingerprint_hash: fingerprint_hash.clone(),
                visual_host_key: visual_host_key.clone(),
                check_host_ip: check_host_ip.clone(),
                number_of_password_prompts: number_of_password_prompts.clone(),
                connection_attempts: connection_attempts.clone(),
                rekey_limit: rekey_limit.clone(),
                identity_agent: identity_agent.clone(),
                pubkey_accepted_algorithms: pubkey_accepted_algorithms.clone(),
                control_master: control_master.clone(),
                control_path: control_path.clone(),
                control_persist: control_persist.clone(),
                gateway_ports,
                clear_all_forwardings,
            });
        }

        // Flush any remaining match block
        if let Some(conditions) = current_match_conditions {
            match_blocks.push(MatchConfig {
                conditions,
                config: HostConfig {
                    host: String::new(),
                    hostname: hostname.clone(),
                    user: user.clone(),
                    port,
                    identity_file: identity_file.clone(),
                    identities_only,
                    forward_agent,
                    forward_x11,
                    compression,
                    strict_host_key_checking: strict_host_key_checking.clone(),
                    hash_known_hosts,
                    user_known_hosts_file: user_known_hosts_file.clone(),
                    global_known_hosts_file: global_known_hosts_file.clone(),
                    connect_timeout,
                    server_alive_interval,
                    server_alive_count_max,
                    tcp_keep_alive,
                    batch_mode,
                    password_authentication,
                    pubkey_authentication,
                    kbd_interactive_authentication,
                    preferred_authentications: preferred_authentications.clone(),
                    host_key_algorithms: host_key_algorithms.clone(),
                    kex_algorithms: kex_algorithms.clone(),
                    ciphers: ciphers.clone(),
                    macs: macs.clone(),
                    log_level: log_level.clone(),
                    exit_on_forward_failure,
                    send_env: send_env.clone(),
                    set_env: set_env.clone(),
                    proxy_jump: proxy_jump.clone(),
                    proxy_command: proxy_command.clone(),
                    bind_address: bind_address.clone(),
                    local_forward: local_forward.clone(),
                    remote_forward: remote_forward.clone(),
                    dynamic_forward: dynamic_forward.clone(),
                    request_tty: request_tty.clone(),
                    remote_command: remote_command.clone(),
                    add_keys_to_agent: add_keys_to_agent.clone(),
                    no_host_authentication_for_localhost,
                    verify_host_key_dns: verify_host_key_dns.clone(),
                    address_family: address_family.clone(),
                    escape_char: escape_char.clone(),
                    subsystem: subsystem.clone(),
                    local_command: local_command.clone(),
                    permit_local_command: permit_local_command.clone(),
                    host_key_alias: host_key_alias.clone(),
                    fingerprint_hash: fingerprint_hash.clone(),
                    visual_host_key: visual_host_key.clone(),
                    check_host_ip: check_host_ip.clone(),
                    number_of_password_prompts: number_of_password_prompts.clone(),
                    connection_attempts: connection_attempts.clone(),
                    rekey_limit: rekey_limit.clone(),
                    identity_agent: identity_agent.clone(),
                    pubkey_accepted_algorithms: pubkey_accepted_algorithms.clone(),
                    control_master: control_master.clone(),
                    control_path: control_path.clone(),
                    control_persist: control_persist.clone(),
                    gateway_ports,
                    clear_all_forwardings,
                },
            });
        }

        Ok(SshConfig { hosts, match_blocks })
    }

}

pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    glob_match_recursive(&pattern_chars, &text_chars)
}

fn glob_match_recursive(pattern: &[char], text: &[char]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }

    if pattern[0] == '*' {
        for i in 0..=text.len() {
            if glob_match_recursive(&pattern[1..], &text[i..]) {
                return true;
            }
        }
        return false;
    }

    if !text.is_empty() && pattern[0] == text[0] {
        return glob_match_recursive(&pattern[1..], &text[1..]);
    }

    false
}

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

/// Split on `:` but ignore colons inside bracketed IPv6 literals (`[::1]`).
fn split_colon_outside_brackets(spec: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_brackets = false;
    for (i, c) in spec.char_indices() {
        match c {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            ':' if !in_brackets => {
                parts.push(&spec[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&spec[start..]);
    parts
}

/// Parse an OpenSSH TCP forward spec (`-L`/`-R`, `LocalForward`/`RemoteForward`)
/// into `(bind_addr, bind_port, host, connect_port)`.
///
/// Accepted forms (OpenSSH `[bind_address:]port:host:hostport`):
/// - `port:host:hostport`  (no bind address → `bind_addr` is empty, caller applies
///   its global BindAddress / GatewayPorts policy)
/// - `bind_address:port:host:hostport`
/// - `port:hostport`       (local-only shorthand; host defaults to 127.0.0.1)
///
/// IPv6 addresses must be bracketed (`[::1]:31400:host:22`); brackets are
/// stripped from the returned bind_addr and host.
pub fn parse_forward_spec(spec: &str) -> Option<(String, u16, String, u16)> {
    let parts: Vec<&str> = split_colon_outside_brackets(spec);
    let strip_brackets = |s: &str| -> String {
        if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    };
    match parts.len() {
        // bind_address:port:host:hostport
        4 => {
            let bind_addr = strip_brackets(parts[0]);
            let bind_port: u16 = parts[1].parse().ok()?;
            let host = strip_brackets(parts[2]);
            let connect_port: u16 = parts[3].parse().ok()?;
            Some((bind_addr, bind_port, host, connect_port))
        }
        // port:host:hostport
        3 => {
            let bind_port: u16 = parts[0].parse().ok()?;
            let host = strip_brackets(parts[1]);
            let connect_port: u16 = parts[2].parse().ok()?;
            Some((String::new(), bind_port, host, connect_port))
        }
        // port:hostport
        2 => {
            let bind_port: u16 = parts[0].parse().ok()?;
            let connect_port: u16 = parts[1].parse().ok()?;
            Some((String::new(), bind_port, "127.0.0.1".to_string(), connect_port))
        }
        _ => None,
    }
}

/// Parse an OpenSSH StreamLocal forward spec (`local_socket:remote_socket`).
/// A spec with exactly two colon-separated non-empty fields is treated as a
/// StreamLocal forward (TCP forwards have 3+ fields or numeric ports).
pub fn parse_streamlocal_forward(spec: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    if parts[0].is_empty() || parts[1].is_empty() {
        return None;
    }
    // Both purely numeric => a TCP `port:port` forward, not StreamLocal.
    if parts[0].parse::<u16>().is_ok() && parts[1].parse::<u16>().is_ok() {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

pub fn parse_stdio_forward(spec: &str) -> std::result::Result<(String, u16), String> {
    let (host, port) = spec.rsplit_once(':').ok_or_else(|| format!("invalid stdio forward: {}", spec))?;
    let port: u16 = port.parse().map_err(|_| format!("invalid port: {}", port))?;
    if host.is_empty() {
        return Err("empty host in stdio forward".to_string());
    }
    Ok((host.to_string(), port))
}

/// Parse an OpenSSH `RekeyLimit` value.
///
/// Syntax: `RekeyLimit [time] [size]` (either order), where `size` may carry a
/// K/M/G suffix and `time` a s/m/h/d suffix (or a bare number of seconds).
/// `default` resets to the built-in defaults (1 GiB / 1 h).
///
/// Returns `None` for `default` (caller keeps defaults); otherwise
/// `Some((bytes, seconds))`, where a `0` byte value means time-only rekeying.
pub fn parse_rekey_limit(value: &str) -> Option<(u64, u64)> {
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

pub fn parse_time_suffix(tok: &str) -> Option<u64> {
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

/// OpenSSH default `PubkeyAcceptedAlgorithms` base list. Matches the key
/// algorithms this client can actually sign with, excluding the SHA-1
/// `ssh-rsa` (OpenSSH >= 8.8 disables it by default).
pub const PUBKEY_ACCEPTED_BASE: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

/// Resolve an OpenSSH `PubkeyAcceptedAlgorithms` pattern list.
///
/// Semantics: `+algo` appends to the base list, `-algo` removes, and a bare
/// `algo` replaces the base list. Wildcards (`*`) are supported.
pub fn resolve_pubkey_algorithms(value: &str) -> Vec<String> {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("default") {
        return PUBKEY_ACCEPTED_BASE.iter().map(|s| s.to_string()).collect();
    }
    let mut list: Vec<String> = PUBKEY_ACCEPTED_BASE.iter().map(|s| s.to_string()).collect();
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
                list.retain(|a| !pattern_matches(pat, a));
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
pub fn pubkey_alg_accepted(alg: &str, accepted: &[String]) -> bool {
    accepted.iter().any(|pat| pattern_matches(pat, alg))
}

fn pattern_matches(pattern: &str, alg: &str) -> bool {
    if pattern == alg {
        return true;
    }
    if pattern.contains('*') || pattern.contains('?') {
        return simple_glob_match(pattern, alg);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn glob_match_basic() {
        assert!(simple_glob_match("*.conf", "a.conf"));
        assert!(!simple_glob_match("*.conf", "a.txt"));
        assert!(simple_glob_match("host?", "host1"));
        assert!(!simple_glob_match("host?", "host12"));
        assert!(simple_glob_match("config.d/*.conf", "config.d/a.conf"));
    }

    #[test]
    fn streamlocal_forward_parsing() {
        // Two path-like fields -> StreamLocal.
        assert_eq!(
            parse_streamlocal_forward("/tmp/lsock:/tmp/rsock"),
            Some(("/tmp/lsock".to_string(), "/tmp/rsock".to_string()))
        );
        // Both numeric -> not StreamLocal (TCP port:port).
        assert_eq!(parse_streamlocal_forward("8080:22"), None);
        // Three fields -> not StreamLocal.
        assert_eq!(parse_streamlocal_forward("8080:localhost:22"), None);
        // Empty fields -> not StreamLocal.
        assert_eq!(parse_streamlocal_forward("/tmp/lsock:"), None);
    }

    #[test]
    fn tcp_forward_spec_parsing() {
        // `port:host:hostport` (no bind address -> empty bind_addr).
        assert_eq!(
            parse_forward_spec("8080:example.com:22"),
            Some(("".to_string(), 8080, "example.com".to_string(), 22))
        );
        // `bind_address:port:host:hostport` carries the bind address.
        assert_eq!(
            parse_forward_spec("127.0.0.1:8080:example.com:22"),
            Some(("127.0.0.1".to_string(), 8080, "example.com".to_string(), 22))
        );
        // `port:hostport` local-only shorthand (host defaults to 127.0.0.1).
        assert_eq!(
            parse_forward_spec("8080:22"),
            Some(("".to_string(), 8080, "127.0.0.1".to_string(), 22))
        );
        // Bracketed IPv6 bind address is stripped.
        assert_eq!(
            parse_forward_spec("[::1]:8080:example.com:22"),
            Some(("::1".to_string(), 8080, "example.com".to_string(), 22))
        );
        // Invalid specs.
        assert_eq!(parse_forward_spec(""), None);
        assert_eq!(parse_forward_spec("8080"), None);
        assert_eq!(parse_forward_spec("a:b:c:d:e"), None);
    }

    #[test]
    fn rekey_limit_parsing() {
        // "default" resets to built-in defaults (None -> caller keeps defaults).
        assert_eq!(parse_rekey_limit("default"), None);
        assert_eq!(parse_rekey_limit(""), None);
        // Size with K/M/G suffix; time falls back to the default (3600).
        assert_eq!(parse_rekey_limit("1G"), Some((1 << 30, 3600)));
        assert_eq!(parse_rekey_limit("64M"), Some((64 << 20, 3600)));
        assert_eq!(parse_rekey_limit("512K"), Some((512 << 10, 3600)));
        // Time alone (bare seconds or suffixed); size = 0 (time-only rekey).
        assert_eq!(parse_rekey_limit("600"), Some((0, 600)));
        assert_eq!(parse_rekey_limit("1h"), Some((0, 3600)));
        assert_eq!(parse_rekey_limit("2d"), Some((0, 172800)));
        // Size + time, either order.
        assert_eq!(parse_rekey_limit("2G 1h"), Some((2 << 30, 3600)));
        assert_eq!(parse_rekey_limit("1h 2G"), Some((2 << 30, 3600)));
        assert_eq!(parse_rekey_limit("256M 30m"), Some((256 << 20, 1800)));
        // Garbage -> None.
        assert_eq!(parse_rekey_limit("bogus"), None);
    }

    #[test]
    fn pubkey_accepted_algorithms_parsing() {
        // Bare list replaces the base.
        let l = resolve_pubkey_algorithms("ssh-ed25519");
        assert!(pubkey_alg_accepted("ssh-ed25519", &l));
        assert!(!pubkey_alg_accepted("rsa-sha2-512", &l));
        // `+ssh-rsa` appends to the base.
        let l = resolve_pubkey_algorithms("+ssh-rsa");
        assert!(pubkey_alg_accepted("ssh-rsa", &l));
        assert!(pubkey_alg_accepted("rsa-sha2-512", &l));
        // `-rsa-sha2-*` removes the rsa family.
        let l = resolve_pubkey_algorithms("-rsa-sha2-*");
        assert!(!pubkey_alg_accepted("rsa-sha2-512", &l));
        assert!(!pubkey_alg_accepted("rsa-sha2-256", &l));
        assert!(pubkey_alg_accepted("ssh-ed25519", &l));
        // `ecdsa-sha2-*` wildcard accepts the ecdsa family.
        let l = resolve_pubkey_algorithms("ecdsa-sha2-*");
        assert!(pubkey_alg_accepted("ecdsa-sha2-nistp256", &l));
        assert!(pubkey_alg_accepted("ecdsa-sha2-nistp521", &l));
        assert!(!pubkey_alg_accepted("ssh-ed25519", &l));
        // Base excludes ssh-rsa by default.
        let l = resolve_pubkey_algorithms("default");
        assert!(!pubkey_alg_accepted("ssh-rsa", &l));
        assert!(pubkey_alg_accepted("ssh-ed25519", &l));
    }

    #[test]
    fn include_expands_hosts() {
        let dir = std::env::temp_dir().join(format!("ns-ssh-cfg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("config.d")).unwrap();
        fs::write(
            dir.join("config.d/a.conf"),
            "Host inc-a\n  HostName inc-a.example.com\n",
        )
        .unwrap();
        fs::write(
            dir.join("config"),
            "Host main\n  HostName main.example.com\nInclude config.d/*.conf\n",
        )
        .unwrap();

        let cfg = SshConfig::load_from(&dir.join("config"));
        assert!(cfg.hosts.iter().any(|h| h.host == "main"));
        assert!(cfg.hosts.iter().any(|h| h.host == "inc-a"));
        let _ = fs::remove_dir_all(&dir);
    }
}

    #[test]
    fn hostname_parse_works() {
        let dir = std::env::temp_dir().join(format!("ns-ssh-cfg-hn-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config");
        fs::write(&path, "Host testhost\n  HostName 127.0.0.1\n  Port 2222\n  User alice\n").unwrap();
        let cfg = SshConfig::load_from(&path);
        assert_eq!(cfg.hosts.len(), 1);
        assert_eq!(cfg.hosts[0].host, "testhost");
        assert_eq!(cfg.hosts[0].hostname.as_deref(), Some("127.0.0.1"));
        assert_eq!(cfg.hosts[0].port, Some(2222));
        assert_eq!(cfg.hosts[0].user.as_deref(), Some("alice"));
    }

    #[test]
    fn unknown_directive_in_host_block_is_fatal() {
        assert!(SshConfig::parse("Host foo\n  TypoDirective yes\n").is_err());
    }

