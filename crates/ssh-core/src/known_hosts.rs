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
    /// OpenSSH hashed-host fields: `|1|base64(salt)|base64(HMAC-SHA1)`.
    pub host_salt: Option<Vec<u8>>,
    pub host_hash: Option<Vec<u8>>,
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

        let (hosts, host_salt, host_hash) = if hosts_str.starts_with("|1|") {
            let fields: Vec<&str> = hosts_str.split('|').collect();
            // fields: ["", "1", salt, hash]
            if fields.len() < 4 {
                (Vec::new(), None, None)
            } else {
                let salt = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    fields[2],
                ).ok()?;
                let hash = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    fields[3],
                ).ok()?;
                (Vec::new(), Some(salt), Some(hash))
            }
        } else {
            let hosts = hosts_str.split(',').map(|s| s.to_string()).collect();
            (hosts, None, None)
        };

        Some(KnownHostEntry {
            hosts,
            key_type: key_type.to_string(),
            public_key: key_bytes,
            comment,
            host_salt,
            host_hash,
        })
    }

    pub fn check(&self, hostname: &str, port: u16, key_type: &str, public_key: &[u8]) -> HostKeyStatus {
        let host_port = format!("[{}]:{}", hostname, port);
        let hostname_only = hostname.to_string();

        for entry in &self.entries {
            let host_matches = entry.hosts.iter().any(|h| {
                h == &host_port || h == &hostname_only || h == "*"
            }) || match (&entry.host_salt, &entry.host_hash) {
                (Some(salt), Some(hash)) => {
                    let candidate = format!("[{}]:{}", hostname, port);
                    let computed = hash_hostname(salt, &candidate);
                    constant_time_eq(computed.as_slice(), hash)
                        || {
                            let candidate2 = hostname.to_string();
                            let computed2 = hash_hostname(salt, &candidate2);
                            constant_time_eq(computed2.as_slice(), hash)
                        }
                }
                _ => false,
            };

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
        self.add_host_hashed(hostname, port, key_type, public_key, false)
    }

    pub fn add_host_hashed(
        &mut self,
        hostname: &str,
        port: u16,
        key_type: &str,
        public_key: &[u8],
        hashed: bool,
    ) -> Result<()> {
        let marker = if port != 22 {
            format!("[{}]:{}", hostname, port)
        } else {
            hostname.to_string()
        };

        let key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key,
        );

        let (line, salt_out, hash_out) = if hashed {
            let salt = random_salt();
            let digest = hash_hostname(&salt, &marker);
            let salt_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &salt,
            );
            let hash_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &digest,
            );
            (format!("|1|{}|{} {} {}", salt_b64, hash_b64, key_type, key_b64), Some(salt), Some(digest))
        } else {
            (format!("{} {} {}", marker, key_type, key_b64), None, None)
        };

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|e| SshError::KnownHosts(format!("cannot open {}: {}", self.file_path.display(), e)))?;

        writeln!(file, "{}", line)
            .map_err(|e| SshError::KnownHosts(format!("write error: {}", e)))?;

        if hashed {
            self.entries.push(KnownHostEntry {
                hosts: Vec::new(),
                key_type: key_type.to_string(),
                public_key: public_key.to_vec(),
                comment: None,
                host_salt: salt_out,
                host_hash: hash_out,
            });
        } else {
            self.entries.push(KnownHostEntry {
                hosts: vec![marker],
                key_type: key_type.to_string(),
                public_key: public_key.to_vec(),
                comment: None,
                host_salt: None,
                host_hash: None,
            });
        }

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
            let key_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &entry.public_key,
            );
            let hosts_field = if let (Some(salt), Some(hash)) = (&entry.host_salt, &entry.host_hash) {
                let salt_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    salt,
                );
                let hash_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    hash,
                );
                format!("|1|{}|{}", salt_b64, hash_b64)
            } else {
                entry.hosts.join(",")
            };
            writeln!(file, "{} {} {}", hosts_field, entry.key_type, key_b64)
                .map_err(|e| SshError::KnownHosts(format!("write error: {}", e)))?;
        }

        Ok(())
    }
}

/// Compute the OpenSSH hashed-hostname digest: HMAC-SHA1(key=salt, msg=hostname).
fn hash_hostname(salt: &[u8], hostname: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(hostname.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn random_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt.to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_hostname_matches_openssh_format() {
        // Known vector: openssl kdf or openssh-computed value.
        let salt = [0x4du8; 16];
        let digest = hash_hostname(&salt, "example.com");
        assert_eq!(digest.len(), 20);
        // Format used by openssh: |1|b64(salt)|b64(digest)
        let salt_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &salt,
        );
        let hash_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &digest,
        );
        assert_eq!(salt_b64, "TU1NTU1NTU1NTU1NTU1NTQ==");
        assert_eq!(hash_b64, "eU8R+iPCJXOoU+SRxVW4gO3fBsY=");
    }

    #[test]
    fn check_matches_hashed_entry() {
        let dir = std::env::temp_dir().join(format!("ns_kh_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");

        let mut kh = KnownHosts::new(path.clone());
        let key = vec![1u8, 2, 3, 4, 5];
        kh.add_host_hashed("myserver.example.com", 22, "ssh-ed25519", &key, true).unwrap();
        drop(kh);

        let reloaded = KnownHosts::new(path);
        assert_eq!(
            reloaded.check("myserver.example.com", 22, "ssh-ed25519", &key),
            HostKeyStatus::Known
        );
        assert_eq!(
            reloaded.check("other.example.com", 22, "ssh-ed25519", &key),
            HostKeyStatus::Unknown
        );
        let other_key = vec![6u8, 7, 8, 9, 10];
        assert_eq!(
            reloaded.check("myserver.example.com", 22, "ssh-ed25519", &other_key),
            HostKeyStatus::Changed
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_plain_entries_still_work() {
        let dir = std::env::temp_dir().join(format!("ns_kh_plain_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");

        let mut kh = KnownHosts::new(path.clone());
        let key = vec![9u8, 8, 7];
        kh.add_host("plain.example.com", 22, "ssh-ed25519", &key).unwrap();
        drop(kh);

        let reloaded = KnownHosts::new(path);
        assert_eq!(
            reloaded.check("plain.example.com", 22, "ssh-ed25519", &key),
            HostKeyStatus::Known
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
