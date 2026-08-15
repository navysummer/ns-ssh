use std::path::{Path, PathBuf};
use std::fs;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SshConfig {
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
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
    pub enable_ssh_keysign: Option<bool>,
    #[serde(default)]
    pub verify_host_key_dns: Option<String>,
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
    pub strict_host_key_checking: bool,
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
    pub local_forwards: Vec<(u16, String, u16)>,
    pub remote_forwards: Vec<(u16, String, u16)>,
    pub dynamic_forwards: Vec<u16>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub no_remote_command: bool,
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
            strict_host_key_checking: true,
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
            send_env: vec!["LANG".into(), "LC_*".into()],
            set_env: Vec::new(),
            request_tty: true,
            remote_command: None,
            add_keys_to_agent: false,
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            dynamic_forwards: Vec::new(),
            proxy_jump: None,
            proxy_command: None,
            no_remote_command: false,
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
            return SshConfig { hosts: Vec::new() };
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return SshConfig { hosts: Vec::new() },
        };

        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Self {
        let mut hosts = Vec::new();
        let mut current_host: Option<String> = None;
        let mut hostname = None;
        let mut user = None;
        let mut port = None;
        let mut identity_file = None;
        let mut identities_only = None;
        let mut forward_agent = None;
        let mut forward_x11 = None;
        let mut compression = None;
        let mut strict_host_key_checking = None;
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
        let mut local_forward = None;
        let mut remote_forward = None;
        let mut dynamic_forward = None;
        let mut request_tty = None;
        let mut remote_command = None;
        let mut add_keys_to_agent = None;
        let mut no_host_authentication_for_localhost = None;
        let mut enable_ssh_keysign = None;
        let mut verify_host_key_dns = None;

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
                            local_forward: local_forward.take(),
                            remote_forward: remote_forward.take(),
                            dynamic_forward: dynamic_forward.take(),
                            request_tty: request_tty.take(),
                            remote_command: remote_command.take(),
                            add_keys_to_agent: add_keys_to_agent.take(),
                            no_host_authentication_for_localhost: no_host_authentication_for_localhost.take(),
                            enable_ssh_keysign: enable_ssh_keysign.take(),
                            verify_host_key_dns: verify_host_key_dns.take(),
                        });
                    }
                    current_host = Some(value.to_string());
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
                "enablesshkeysign" | "enable_ssh_keysign" => enable_ssh_keysign = Some(yes(value)),
                "verifyhostkeydns" | "verify_host_key_dns" => verify_host_key_dns = Some(value.to_string()),
                "include" => { /* ignored */ }
                _ => {}
            }
        }

        if let Some(h) = current_host {
            hosts.push(HostConfig {
                host: h,
                hostname,
                user,
                port,
                identity_file,
                identities_only,
                forward_agent,
                forward_x11,
                compression,
                strict_host_key_checking,
                user_known_hosts_file,
                global_known_hosts_file,
                connect_timeout,
                server_alive_interval,
                server_alive_count_max,
                tcp_keep_alive,
                batch_mode,
                password_authentication,
                pubkey_authentication,
                kbd_interactive_authentication,
                preferred_authentications,
                host_key_algorithms,
                kex_algorithms,
                ciphers,
                macs,
                log_level,
                exit_on_forward_failure,
                send_env,
                set_env,
                proxy_jump,
                proxy_command,
                local_forward,
                remote_forward,
                dynamic_forward,
                request_tty,
                remote_command,
                add_keys_to_agent,
                no_host_authentication_for_localhost,
                enable_ssh_keysign,
                verify_host_key_dns,
            });
        }

        SshConfig { hosts }
    }

    pub fn find_host(&self, host: &str) -> Option<&HostConfig> {
        self.hosts.iter().find(|h| {
            h.host == host
                || h.host.contains('*')
                || glob_match(&h.host, host)
        })
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

pub fn parse_forward_spec(spec: &str) -> Option<(u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        3 => {
            let bind_port: u16 = parts[0].parse().ok()?;
            let host = parts[1].to_string();
            let connect_port: u16 = parts[2].parse().ok()?;
            Some((bind_port, host, connect_port))
        }
        2 => {
            let bind_port: u16 = parts[0].parse().ok()?;
            let connect_port: u16 = parts[1].parse().ok()?;
            Some((bind_port, "127.0.0.1".to_string(), connect_port))
        }
        _ => None,
    }
}
