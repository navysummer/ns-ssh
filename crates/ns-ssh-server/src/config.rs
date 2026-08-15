use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    #[serde(default)]
    pub host_key_files: Vec<String>,

    #[serde(default = "default_true")]
    pub password_auth: bool,

    #[serde(default = "default_true")]
    pub pubkey_auth: bool,

    #[serde(default)]
    pub permit_root_login: bool,

    #[serde(default)]
    pub authorized_keys_files: Vec<String>,

    #[serde(default)]
    pub allow_groups: Vec<String>,

    #[serde(default)]
    pub deny_groups: Vec<String>,

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

    #[serde(default)]
    pub x11_forwarding: bool,

    #[serde(default = "default_x11_display_offset")]
    pub x11_display_offset: u32,
}

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
fn default_max_startups() -> String { "10:30:60".to_string() }
fn default_login_grace_time() -> u32 { 120 }

fn default_accept_env() -> Vec<String> {
    vec!["LANG".to_string(), "LC_*".to_string()]
}

fn default_x11_display_offset() -> u32 { 10 }

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
            password_auth: default_true(),
            pubkey_auth: default_true(),
            permit_root_login: false,
            authorized_keys_files: vec![
                "~/.ssh/authorized_keys".to_string(),
                "~/.ssh/authorized_keys2".to_string(),
            ],
            allow_groups: Vec::new(),
            deny_groups: Vec::new(),
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
            banner: default_banner(),
            max_startups: default_max_startups(),
            login_grace_time: default_login_grace_time(),
            accept_env: default_accept_env(),
            allow_agent_forwarding: default_true(),
            x11_forwarding: false,
            x11_display_offset: default_x11_display_offset(),
        }
    }
}

impl ServerConfig {
    pub fn load() -> Self {
        let paths = [
            "/etc/ssh/sshd_config",
            "/etc/ns-ssh/sshd_config",
        ];

        for path in &paths {
            if let Ok(content) = fs::read_to_string(path) {
                return Self::parse(&content);
            }
        }

        Self::default()
    }

    pub fn load_from(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(content) => Self::parse(&content),
            Err(_) => Self::default(),
        }
    }

    pub fn parse(content: &str) -> Self {
        let mut config = ServerConfig::default();
        let mut includes = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut parts = line.splitn(2, |c: char| c.is_whitespace());
            let key = parts.next().unwrap_or("").to_lowercase();
            let value = parts.next().unwrap_or("").trim();

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
                "pubkeyauthentication" | "pubkey_auth" => {
                    config.pubkey_auth = value == "yes";
                }
                "permitrootlogin" | "permit_root_login" => {
                    config.permit_root_login = value == "yes";
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
                "include" => {
                    includes.push(value.to_string());
                }
                _ => {}
            }
        }

        for include_path in includes {
            let expanded = if include_path.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    home.join(&include_path[2..])
                } else {
                    continue;
                }
            } else {
                PathBuf::from(&include_path)
            };

            if let Ok(content) = fs::read_to_string(&expanded) {
                let included = Self::parse(&content);
                config.host_key_files.extend(included.host_key_files);
                config.authorized_keys_files.extend(included.authorized_keys_files);
                config.subsystems.extend(included.subsystems);
            }
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
