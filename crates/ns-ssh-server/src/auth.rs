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
    authorized_keys_patterns: Vec<String>,
}

impl ServerAuth {
    pub fn new() -> Self {
        ServerAuth {
            authorized_keys: Vec::new(),
            password_hashes: HashMap::new(),
            authorized_keys_patterns: Vec::new(),
        }
    }

    /// Record the raw AuthorizedKeysFile patterns (may contain `%h`/`%u` and `~`).
    pub fn set_authorized_keys_patterns(&mut self, patterns: Vec<String>) {
        self.authorized_keys_patterns = patterns;
    }

    /// Resolve a user's home directory from /etc/passwd.
    fn home_dir_for_user(username: &str) -> Option<String> {
        let content = fs::read_to_string("/etc/passwd").ok()?;
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 && parts[0] == username {
                return Some(parts[5].to_string());
            }
        }
        // Fallback to the server's own home for the current user.
        if username == std::env::var("USER").ok().as_deref().unwrap_or("") {
            return dirs::home_dir().map(|p| p.to_string_lossy().to_string());
        }
        None
    }

    /// Expand a single AuthorizedKeysFile pattern for the given user.
    fn expand_pattern(pattern: &str, username: &str) -> Option<PathBuf> {
        let home = Self::home_dir_for_user(username)?;
        let expanded = pattern
            .replace("%h", &home)
            .replace("%u", username);
        let path = if expanded.starts_with("~/") {
            PathBuf::from(&home).join(&expanded[2..])
        } else {
            PathBuf::from(expanded)
        };
        Some(path)
    }

    /// Load authorized keys from the user's own authorized_keys files.
    pub fn load_user_authorized_keys(&mut self, username: &str) {
        let patterns = if self.authorized_keys_patterns.is_empty() {
            vec!["~/.ssh/authorized_keys".to_string(), "~/.ssh/authorized_keys2".to_string()]
        } else {
            self.authorized_keys_patterns.clone()
        };

        let mut entries: Vec<AuthorizedKeyEntry> = Vec::new();
        for pattern in &patterns {
            if let Some(path) = Self::expand_pattern(pattern, username) {
                if let Ok(content) = fs::read_to_string(&path) {
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        if let Some(entry) = Self::parse_authorized_key(line) {
                            entries.push(entry);
                        }
                    }
                }
            }
        }
        self.authorized_keys = entries;
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
        data.extend_from_slice(&(9u32).to_be_bytes());
        data.extend_from_slice(b"publickey");
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
    if hash.starts_with("$6$") || hash.starts_with("$5$") {
        return verify_sha_crypt(password, hash);
    }
    if hash.starts_with("$1$") {
        return verify_md5_crypt(password, hash);
    }
    if hash.starts_with("$2") {
        // bcrypt ($2a$/$2b$/$2y$) and yescrypt ($y$) not supported in pure Rust core
        return false;
    }

    password == hash
}

fn verify_sha_crypt(password: &str, hash: &str) -> bool {
    use sha_crypt::password_hash::PasswordVerifier;
    use sha_crypt::{PasswordHashRef, ShaCrypt};

    let parsed = match PasswordHashRef::new(hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let verifier = if hash.starts_with("$6$") {
        ShaCrypt::SHA512
    } else {
        ShaCrypt::SHA256
    };
    verifier.verify_password(password.as_bytes(), parsed).is_ok()
}

fn verify_md5_crypt(password: &str, hash: &str) -> bool {
    use md5::{Digest, Md5};

    // Format: $1$<salt up to 8 chars>$<encoded hash>
    let rest = &hash[3..];
    let (salt, expected) = match rest.split_once('$') {
        Some((s, e)) => (s, e),
        None => return false,
    };
    let salt = &salt[..salt.len().min(8)];
    let pw = password.as_bytes();

    // ctx = MD5(pw || "$1$" || salt) buffered
    let mut ctx = Md5::new();
    ctx.update(pw);
    ctx.update(b"$1$");
    ctx.update(salt.as_bytes());

    // alt_result = MD5(pw || salt || pw)
    let mut alt = Md5::new();
    alt.update(pw);
    alt.update(salt.as_bytes());
    alt.update(pw);
    let alt_result = alt.finalize();

    // Add chunks of alt_result to ctx while key_len > 0
    let mut pl = pw.len();
    while pl > 0 {
        let chunk = if pl > 16 { 16 } else { pl };
        ctx.update(&alt_result[..chunk]);
        pl -= chunk;
    }

    // The "weird" compatibility step: for every bit of key_len, add one
    // byte: NUL if the bit is set, otherwise the first byte of the key.
    let mut cnt = pw.len();
    while cnt > 0 {
        if cnt & 1 == 1 {
            ctx.update(&[0u8]);
        } else {
            ctx.update(&pw[..1]);
        }
        cnt >>= 1;
    }
    let mut final_digest = ctx.finalize();

    for i in 0..1000 {
        let mut c = Md5::new();
        if i & 1 == 1 {
            c.update(pw);
        } else {
            c.update(&final_digest);
        }
        if i % 3 != 0 {
            c.update(salt.as_bytes());
        }
        if i % 7 != 0 {
            c.update(pw);
        }
        if i & 1 == 1 {
            c.update(&final_digest);
        } else {
            c.update(pw);
        }
        final_digest = c.finalize();
    }

    let computed = md5_crypt_encode(&final_digest);
    constant_time_eq(computed.as_bytes(), expected.as_bytes())
}

fn md5_crypt_encode(digest: &[u8]) -> String {
    if digest.len() < 16 {
        return String::new();
    }
    const ALPHABET: &[u8; 64] =
        b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    let mut out = String::with_capacity(22);

    let mut b64_24 = |a: u8, b: u8, c: u8, out: &mut String| {
        let v = ((a as u32) << 16) | ((b as u32) << 8) | (c as u32);
        out.push(ALPHABET[(v & 0x3f) as usize] as char);
        out.push(ALPHABET[((v >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[((v >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((v >> 18) & 0x3f) as usize] as char);
    };

    b64_24(digest[0], digest[6], digest[12], &mut out);
    b64_24(digest[1], digest[7], digest[13], &mut out);
    b64_24(digest[2], digest[8], digest[14], &mut out);
    b64_24(digest[3], digest[9], digest[15], &mut out);
    b64_24(digest[4], digest[10], digest[5], &mut out);

    let v = digest[11] as u32;
    out.push(ALPHABET[(v & 0x3f) as usize] as char);
    out.push(ALPHABET[((v >> 6) & 0x3f) as usize] as char);

    out
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
    fn md5_crypt_known_vector() {
        // Reference: "password" with salt "12345678"
        // Generated by: openssl passwd -1 -salt 12345678 password
        assert!(verify_unix_password("password", "$1$12345678$o2n/JiO/h5VviOInWJ4OQ/"));
    }

    #[test]
    fn md5_crypt_wrong_password() {
        assert!(!verify_unix_password("wrongpass", "$1$12345678$o2n/JiO/h5VviOInWJ4OQ/"));
    }

    #[test]
    fn sha512_crypt_known_vector() {
        // Reference: "password" with salt "12345678", default rounds
        // Generated by: openssl passwd -6 -salt 12345678 password
        assert!(verify_unix_password("password", "$6$12345678$I8tr4xFAC6/TtjYWdp0LWEjQre2LcYm2jdSMNLQDIyqRv.cKo7KMD5/HpzVVFKpUQlIekr/Vw.OdImtRM85fg/"));
    }

    #[test]
    fn sha256_crypt_known_vector() {
        // Reference: "password" with salt "12345678"
        // Generated by: openssl passwd -5 -salt 12345678 password
        assert!(verify_unix_password("password", "$5$12345678$HxSvzMyVSg03Aq96z9E/GySiT7BkyOSTDjfKSua5oY2"));
    }

    #[test]
    fn plaintext_password() {
        assert!(verify_unix_password("secret", "secret"));
        assert!(!verify_unix_password("secret", "other"));
    }
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
