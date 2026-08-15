use crate::error::{Result, SshError};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{Write, BufRead, BufReader};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct KnownHostEntry {
    pub hosts: Vec<String>,
    pub key_type: String,
    pub public_key: Vec<u8>,
    pub comment: Option<String>,
}

pub struct KnownHosts {
    entries: Vec<KnownHostEntry>,
    file_path: PathBuf,
}

impl KnownHosts {
    pub fn new(path: PathBuf) -> Self {
        let entries = Self::load_from_file(&path).unwrap_or_default();
        KnownHosts { entries, file_path: path }
    }

    pub fn default_client_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ssh")
            .join("known_hosts")
    }

    pub fn default_server_path() -> PathBuf {
        PathBuf::from("/etc/ssh/known_hosts")
    }

    fn load_from_file(path: &Path) -> Result<Vec<KnownHostEntry>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(path)
            .map_err(|e| SshError::KnownHosts(format!("cannot open {}: {}", path.display(), e)))?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| SshError::KnownHosts(e.to_string()))?;
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(entry) = Self::parse_line(&line) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    fn parse_line(line: &str) -> Option<KnownHostEntry> {
        let mut parts = line.split_whitespace();
        let hosts_str = parts.next()?;
        let key_type = parts.next()?;
        let key_b64 = parts.next()?;
        let comment = parts.next().map(|s| s.to_string());

        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            key_b64,
        ).ok()?;

        let hosts = hosts_str.split(',').map(|s| s.to_string()).collect();

        Some(KnownHostEntry {
            hosts,
            key_type: key_type.to_string(),
            public_key: key_bytes,
            comment,
        })
    }

    pub fn check(&self, hostname: &str, port: u16, key_type: &str, public_key: &[u8]) -> HostKeyStatus {
        let host_port = format!("[{}]:{}", hostname, port);
        let hostname_only = hostname.to_string();

        for entry in &self.entries {
            let host_matches = entry.hosts.iter().any(|h| {
                h == &host_port || h == &hostname_only || h == "*"
            });

            if host_matches {
                if entry.key_type == key_type && entry.public_key == public_key {
                    return HostKeyStatus::Known;
                } else if entry.key_type == key_type {
                    return HostKeyStatus::Changed;
                }
            }
        }

        HostKeyStatus::Unknown
    }

    pub fn add_host(&mut self, hostname: &str, port: u16, key_type: &str, public_key: &[u8]) -> Result<()> {
        let marker = if port != 22 {
            format!("[{}]:{}", hostname, port)
        } else {
            hostname.to_string()
        };

        let key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key,
        );

        let line = format!("{} {} {}", marker, key_type, key_b64);

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|e| SshError::KnownHosts(format!("cannot open {}: {}", self.file_path.display(), e)))?;

        writeln!(file, "{}", line)
            .map_err(|e| SshError::KnownHosts(format!("write error: {}", e)))?;

        self.entries.push(KnownHostEntry {
            hosts: vec![marker],
            key_type: key_type.to_string(),
            public_key: public_key.to_vec(),
            comment: None,
        });

        Ok(())
    }

    pub fn remove_host(&mut self, hostname: &str) -> Result<bool> {
        let initial_len = self.entries.len();
        self.entries.retain(|e| !e.hosts.iter().any(|h| h == hostname));

        if self.entries.len() == initial_len {
            return Ok(false);
        }

        self.save()?;
        Ok(true)
    }

    fn save(&self) -> Result<()> {
        let mut file = fs::File::create(&self.file_path)
            .map_err(|e| SshError::KnownHosts(format!("cannot create {}: {}", self.file_path.display(), e)))?;

        for entry in &self.entries {
            let hosts = entry.hosts.join(",");
            let key_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &entry.public_key,
            );
            writeln!(file, "{} {} {}", hosts, entry.key_type, key_b64)
                .map_err(|e| SshError::KnownHosts(format!("write error: {}", e)))?;
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HostKeyStatus {
    Known,
    Unknown,
    Changed,
}

pub fn hash_host_key(hostname: &str, port: u16, key_type: &str, public_key: &[u8]) -> String {
    use sha2::{Sha256, Digest};

    let host_salt = format!("{}|{}", hostname, port);
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(host_salt.as_bytes());
    let salt = salt_hasher.finalize();

    let mut key_data = Vec::new();
    key_data.extend_from_slice(&salt);
    key_data.extend_from_slice(public_key);

    if key_type.contains("sha256") {
        let mut hasher = Sha256::new();
        hasher.update(&key_data);
        let hash = hasher.finalize();
        format!("SHA256:{}", base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &hash,
        ))
    } else {
        let mut hasher = Sha256::new();
        hasher.update(&key_data);
        let hash = hasher.finalize();
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}:{}", key_type, hex)
    }
}
