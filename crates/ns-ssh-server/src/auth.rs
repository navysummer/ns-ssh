use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::hostkey::*;
use ssh_core::known_hosts::*;
use std::path::PathBuf;
use std::fs;
use std::collections::HashMap;
use base64::Engine;

pub struct AuthorizedKeyEntry {
    pub key_type: String,
    pub public_key: Vec<u8>,
    pub comment: Option<String>,
}

pub struct ServerAuth {
    authorized_keys: Vec<AuthorizedKeyEntry>,
    password_hashes: HashMap<String, String>,
}

impl ServerAuth {
    pub fn new() -> Self {
        ServerAuth {
            authorized_keys: Vec::new(),
            password_hashes: HashMap::new(),
        }
    }

    pub fn load_authorized_keys(&mut self, paths: &[PathBuf]) -> Result<()> {
        for path in paths {
            let expanded = if path.starts_with("~/") {
                let path_str = path.to_string_lossy();
                let rest = &path_str[2..];
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(rest)
            } else {
                path.clone()
            };

            if let Ok(content) = fs::read_to_string(&expanded) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    if let Some(entry) = Self::parse_authorized_key(line) {
                        self.authorized_keys.push(entry);
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_authorized_key(line: &str) -> Option<AuthorizedKeyEntry> {
        let mut parts = line.split_whitespace();
        let key_type = parts.next()?;
        let key_b64 = parts.next()?;
        let comment = parts.next().map(|s| s.to_string());

        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .ok()?;

        Some(AuthorizedKeyEntry {
            key_type: key_type.to_string(),
            public_key: key_bytes,
            comment,
        })
    }

    pub fn verify_public_key(
        &self,
        key_type: &str,
        public_key: &[u8],
    ) -> bool {
        self.authorized_keys.iter().any(|entry| {
            entry.key_type == key_type && entry.public_key == public_key
        })
    }

    pub fn verify_public_key_with_comment(
        &self,
        key_type: &str,
        public_key: &[u8],
        username: &str,
    ) -> bool {
        self.authorized_keys.iter().any(|entry| {
            if entry.key_type == key_type && entry.public_key == public_key {
                if let Some(ref comment) = entry.comment {
                    return comment.contains(username) || comment.is_empty();
                }
                true
            } else {
                false
            }
        })
    }

    pub fn create_signer_for_key(&self, key_type: &str, public_key: &[u8]) -> Option<Box<dyn ssh_core::hostkey::HostKeySigner>> {
        match key_type {
            "ssh-ed25519" => {
                let mut r = public_key;
                let kt = SshString::decode(&mut r).ok()?;
                if kt.as_str().ok()? != "ssh-ed25519" { return None; }
                let pk = SshBytes::decode(&mut r).ok()?;
                if pk.0.len() != 32 { return None; }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&pk.0);
                ssh_core::hostkey::Ed25519HostKey::from_public_bytes(&arr)
                    .ok().map(|k| Box::new(k) as Box<dyn ssh_core::hostkey::HostKeySigner>)
            }
            "ecdsa-sha2-nistp256" => {
                let mut r = public_key;
                let kt = SshString::decode(&mut r).ok()?;
                if kt.as_str().ok()? != "ecdsa-sha2-nistp256" { return None; }
                let curve = SshString::decode(&mut r).ok()?;
                if curve.as_str().ok()? != "nistp256" { return None; }
                let pk = SshBytes::decode(&mut r).ok()?;
                ssh_core::hostkey::EcdsaP256HostKey::from_public_bytes(&pk.0)
                    .ok().map(|k| Box::new(k) as Box<dyn ssh_core::hostkey::HostKeySigner>)
            }
            "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => {
                let mut r = public_key;
                let kt = SshString::decode(&mut r).ok()?;
                let kt_str = kt.as_str().ok()?;
                if kt_str != "ssh-rsa" { return None; }
                let e_bytes = SshBytes::decode(&mut r).ok()?;
                let n_bytes = SshBytes::decode(&mut r).ok()?;
                let n = rsa::BigUint::from_bytes_be(&n_bytes.0);
                let e = rsa::BigUint::from_bytes_be(&e_bytes.0);
                let public_key = rsa::RsaPublicKey::new(n, e).ok()?;
                Some(Box::new(ssh_core::hostkey::RsaHostKey::new(None, public_key, 2048))
                    as Box<dyn ssh_core::hostkey::HostKeySigner>)
            }
            _ => None,
        }
    }

    pub fn verify_signature(
        &self,
        session_id: &[u8],
        username: &str,
        key_type: &str,
        public_key: &[u8],
        signature_blob: &[u8],
    ) -> bool {
        let signer = match self.create_signer_for_key(key_type, public_key) {
            Some(s) => s,
            None => return false,
        };

        let mut data = Vec::new();
        data.extend_from_slice(&(session_id.len() as u32).to_be_bytes());
        data.extend_from_slice(session_id);
        data.push(50);
        data.extend_from_slice(&(username.len() as u32).to_be_bytes());
        data.extend_from_slice(username.as_bytes());
        let service = "ssh-connection";
        data.extend_from_slice(&(service.len() as u32).to_be_bytes());
        data.extend_from_slice(service.as_bytes());
        data.extend_from_slice(&(4u32).to_be_bytes());
        data.extend_from_slice(b"none");
        data.push(1);
        data.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        data.extend_from_slice(key_type.as_bytes());
        data.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
        data.extend_from_slice(public_key);

        signer.verify(&data, signature_blob).unwrap_or(false)
    }

    pub fn load_shadow_password(&self, username: &str) -> Result<Option<String>> {
        let shadow_path = "/etc/shadow";
        if let Ok(content) = fs::read_to_string(shadow_path) {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 && parts[0] == username {
                    return Ok(Some(parts[1].to_string()));
                }
            }
        }
        Ok(None)
    }

    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        if let Some(hash) = self.password_hashes.get(username) {
            return verify_unix_password(password, hash);
        }

        if let Ok(Some(hash)) = self.load_shadow_password(username) {
            return verify_unix_password(password, &hash);
        }

        false
    }

    pub fn add_password_user(&mut self, username: &str, hash: &str) {
        self.password_hashes.insert(username.to_string(), hash.to_string());
    }

    pub fn get_authorized_keys_for_user(&self, username: &str) -> Vec<&AuthorizedKeyEntry> {
        self.authorized_keys.iter().filter(|entry| {
            if let Some(ref comment) = entry.comment {
                comment.contains(username)
            } else {
                true
            }
        }).collect()
    }
}

fn verify_unix_password(password: &str, hash: &str) -> bool {
    if hash.starts_with("$") {
        let parts: Vec<&str> = hash.split('$').collect();
        if parts.len() >= 4 {
            let algo_id = parts[1];
            let salt = parts[2];
            let expected = parts[3];

            let computed = match algo_id {
                "1" => {
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(format!("{}${}", salt, password));
                    let result = hasher.finalize();
                    base64::engine::general_purpose::STANDARD.encode(result)
                }
                "5" | "6" => {
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(format!("{}{}", salt, password));
                    let result = hasher.finalize();
                    base64::engine::general_purpose::STANDARD.encode(result)
                }
                _ => return false,
            };

            return computed.starts_with(expected);
        }
    }

    password == hash
}

pub fn check_user_authorized(username: &str) -> bool {
    let denied_users = ["/etc/ssh/sshd_config"];
    for path in &denied_users {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.to_lowercase().starts_with("denyusers") {
                    let users: Vec<&str> = line.split_whitespace().skip(1).collect();
                    if users.contains(&username) {
                        return false;
                    }
                }
                if line.to_lowercase().starts_with("allowusers") {
                    let users: Vec<&str> = line.split_whitespace().skip(1).collect();
                    if !users.contains(&username) && !users.is_empty() {
                        return false;
                    }
                }
            }
        }
    }

    true
}

pub fn check_group_membership(username: &str, allow_groups: &[String], deny_groups: &[String]) -> bool {
    if !deny_groups.is_empty() {
        if let Ok(groups) = get_user_groups(username) {
            for group in &groups {
                if deny_groups.contains(group) {
                    return false;
                }
            }
        }
    }

    if !allow_groups.is_empty() {
        if let Ok(groups) = get_user_groups(username) {
            for group in &groups {
                if allow_groups.contains(group) {
                    return true;
                }
            }
        }
        return false;
    }

    true
}

fn get_user_groups(username: &str) -> Result<Vec<String>> {
    let output = std::process::Command::new("groups")
        .arg(username)
        .output()
        .map_err(|e| SshError::Io(e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let groups: Vec<String> = stdout.split_whitespace()
            .skip(1)
            .map(|s| s.to_string())
            .collect();
        Ok(groups)
    } else {
        Ok(Vec::new())
    }
}
