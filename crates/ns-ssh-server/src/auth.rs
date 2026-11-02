use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::hostkey::*;
use ssh_core::known_hosts::*;
use std::path::PathBuf;
use std::path::Path;
use std::fs;
use std::collections::HashMap;
use base64::Engine;

/// Parsed options from an authorized_keys line prefix (before key-type/key-data).
#[derive(Debug, Clone, Default)]
pub struct AuthorizedKeyOptions {
    pub command: Option<String>,
    pub environment: Vec<(String, String)>,
    pub from_pattern: Option<String>,
    pub no_pty: bool,
    pub no_port_forwarding: bool,
    pub no_x11_forwarding: bool,
    pub no_agent_forwarding: bool,
    pub no_user_ptm: bool,
    pub permit_open: Vec<String>,
    pub permit_listen: Vec<String>,
    pub restrictions_only: bool,
}

impl AuthorizedKeyOptions {
    /// Parse sshd-compatible options from the prefix of an authorized_keys line.
    /// Returns (options, remaining_key_type_or_data) or None if parsing fails at a key boundary.
    pub fn parse(line: &str) -> Option<(Self, &'_ str)> {
        let mut opts = AuthorizedKeyOptions::default();
        let mut rest = line;

        loop {
            // Skip whitespace between options
            rest = rest.trim_start();
            if rest.is_empty() {
                break;
            }

            let (token, remaining) = Self::next_token(rest)?;

            if token == "ssh-ed25519" || token == "ecdsa-sha2-nistp256"
                || token == "ecdsa-sha2-nistp384" || token == "ecdsa-sha2-nistp521"
                || token == "ssh-rsa" || token == "sk-ssh-ed25519@openssh.com"
                || token == "sk-ecdsa-sha2-nistp256@openssh.com"
            {
                // We've reached the key type — stop parsing options. `rest` points at it.
                return Some((opts, rest));
            }
            rest = remaining;

            // A single whitespace-delimited token may hold several comma-separated options.
            for sub in Self::split_options(&token) {
                if sub.is_empty() {
                    continue;
                }
                if let Some(eq_pos) = sub.find('=') {
                    let key = &sub[..eq_pos];
                    let value = Self::unquote(&sub[eq_pos + 1..]);
                    match key {
                        "command" => opts.command = Some(value),
                        "environment" => {
                            if let Some((k, v)) = value.split_once('=') {
                                opts.environment.push((k.to_string(), v.to_string()));
                            }
                        }
                        "from" => opts.from_pattern = Some(value),
                        "no-pty" => opts.no_pty = true,
                        "no-port-forwarding" => opts.no_port_forwarding = true,
                        "no-x11-forwarding" => opts.no_x11_forwarding = true,
                        "no-agent-forwarding" => opts.no_agent_forwarding = true,
                        "no-user-pty" => opts.no_user_ptm = true,
                        "permitopen" => {
                            for entry in value.split(',') {
                                let entry = entry.trim();
                                if !entry.is_empty() {
                                    opts.permit_open.push(entry.to_string());
                                }
                            }
                        }
                        "permitlisten" => {
                            for entry in value.split(',') {
                                let entry = entry.trim();
                                if !entry.is_empty() {
                                    opts.permit_listen.push(entry.to_string());
                                }
                            }
                        }
                        "restrict" => opts.restrictions_only = true,
                        _ => {} // ignore unknown options
                    }
                } else if sub == "no-pty" {
                    opts.no_pty = true;
                } else if sub == "no-port-forwarding" {
                    opts.no_port_forwarding = true;
                } else if sub == "no-x11-forwarding" {
                    opts.no_x11_forwarding = true;
                } else if sub == "no-agent-forwarding" {
                    opts.no_agent_forwarding = true;
                } else if sub == "no-user-pty" {
                    opts.no_user_ptm = true;
                } else if sub == "restrict" {
                    opts.restrictions_only = true;
                } else {
                    // Unknown option — ignore it.
                }
            }
        }

        None
    }

    /// Split a whitespace-delimited options token on top-level commas, respecting
    /// double quotes and backslash escapes.
    fn split_options(token: &str) -> Vec<&str> {
        let bytes = token.as_bytes();
        let mut parts = Vec::new();
        let mut start = 0;
        let mut i = 0;
        let mut in_quote = false;
        let mut escaped = false;
        while i < bytes.len() {
            let b = bytes[i];
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if b == b'"' {
                in_quote = !in_quote;
                i += 1;
                continue;
            }
            if b == b',' && !in_quote {
                parts.push(&token[start..i]);
                start = i + 1;
            }
            i += 1;
        }
        parts.push(&token[start..]);
        parts
    }

    /// Extract the next whitespace-delimited token, respecting double quotes and
    /// backslash escapes. Returns (token, remaining).
    fn next_token(s: &str) -> Option<(&str, &str)> {
        let s = s.trim_start();
        if s.is_empty() {
            return None;
        }
        let bytes = s.as_bytes();
        let mut i = 0;
        let mut in_quote = false;
        let mut escaped = false;
        while i < bytes.len() {
            let b = bytes[i];
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if b == b'"' {
                in_quote = !in_quote;
                i += 1;
                continue;
            }
            if b.is_ascii_whitespace() && !in_quote {
                break;
            }
            i += 1;
        }
        Some((&s[..i], &s[i..]))
    }

    /// Strip one layer of surrounding double quotes and decode sshd escapes.
    fn unquote(s: &str) -> String {
        let inner = if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
            &s[1..s.len() - 1]
        } else {
            s
        };
        inner.replace("\\s", " ").replace("\\n", "\n").replace("\\\\", "\\")
    }

    /// Match a glob pattern (supporting '*' and '?') against text.
    pub fn glob_match(pattern: &str, text: &str) -> bool {
        // Standard two-pointer wildcard matcher supporting '*' and '?'.
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
}

#[derive(Debug, Clone)]
pub struct AuthorizedKeyEntry {
    pub key_type: String,
    pub public_key: Vec<u8>,
    pub comment: Option<String>,
    pub options: AuthorizedKeyOptions,
}

pub struct ServerAuth {
    authorized_keys: Vec<AuthorizedKeyEntry>,
    password_hashes: HashMap<String, String>,
    authorized_keys_patterns: Vec<String>,
    authorized_keys_command: Option<String>,
    authorized_keys_command_user: Option<String>,
    strict_modes: bool,
}

impl ServerAuth {
    pub fn new() -> Self {
        ServerAuth {
            authorized_keys: Vec::new(),
            password_hashes: HashMap::new(),
            authorized_keys_patterns: Vec::new(),
            authorized_keys_command: None,
            authorized_keys_command_user: None,
            strict_modes: true,
        }
    }

    /// Set StrictModes (authorized_keys file/directory ownership & permissions).
    pub fn set_strict_modes(&mut self, strict: bool) {
        self.strict_modes = strict;
    }

    /// Record the raw AuthorizedKeysFile patterns (may contain `%h`/`%u` and `~`).
    pub fn set_authorized_keys_patterns(&mut self, patterns: Vec<String>) {
        self.authorized_keys_patterns = patterns;
    }

    /// Set AuthorizedKeysCommand (and optional AuthorizedKeysCommandUser).
    pub fn set_authorized_keys_command(&mut self, command: Option<String>, user: Option<String>) {
        self.authorized_keys_command = command;
        self.authorized_keys_command_user = user;
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
        let mut entries: Vec<AuthorizedKeyEntry> = Vec::new();

        // AuthorizedKeysCommand takes precedence: run the command to obtain keys.
        if let Some(ref command) = self.authorized_keys_command {
            let command_user = self.authorized_keys_command_user.clone();
            if let Some(content) = Self::run_authorized_keys_command(command, username, command_user.as_deref()) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some(entry) = Self::parse_authorized_key(line) {
                        entries.push(entry);
                    }
                }
                self.authorized_keys = entries;
                return;
            }
        }

        let patterns = if self.authorized_keys_patterns.is_empty() {
            vec!["~/.ssh/authorized_keys".to_string(), "~/.ssh/authorized_keys2".to_string()]
        } else {
            self.authorized_keys_patterns.clone()
        };

        for pattern in &patterns {
            if let Some(path) = Self::expand_pattern(pattern, username) {
                if let Ok(content) = fs::read_to_string(&path) {
                    // StrictModes: reject authorized_keys that are world-writable,
                    // group-writable, or not owned by the user.
                    if self.strict_modes && !Self::check_authorized_keys_permissions(&path, username) {
                        tracing::warn!("StrictModes: rejecting overly permissive authorized_keys: {}", path.display());
                        continue;
                    }
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

    /// Run AuthorizedKeysCommand, substituting `%u`/`%h`/`%U`, and return stdout.
    /// When `command_user` is set, the command runs as that user (OpenSSH's
    /// AuthorizedKeysCommandUser; requires the server to be root).
    fn run_authorized_keys_command(command: &str, username: &str, command_user: Option<&str>) -> Option<String> {
        use std::process::Command;
        use std::os::unix::process::CommandExt;
        let home = Self::home_dir_for_user(username).unwrap_or_default();
        let uid = Self::uid_for_user(username).unwrap_or(0);
        let expanded = command
            .replace("%u", username)
            .replace("%h", &home)
            .replace("%U", &uid.to_string());

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(&expanded);

        if let Some(user) = command_user {
            let target_uid = Self::uid_for_user(user).unwrap_or(0);
            let target_gid = Self::gid_for_user(user).unwrap_or(0);
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setgid(target_gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setuid(target_uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let output = cmd.output().ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            None
        }
    }

    /// Resolve a user's numeric gid from /etc/passwd (or `id -g`).
    fn gid_for_user(username: &str) -> Option<u32> {
        let content = fs::read_to_string("/etc/passwd").ok()?;
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 && parts[0] == username {
                return parts[3].parse().ok();
            }
        }
        let out = std::process::Command::new("id")
            .arg("-g")
            .arg(username)
            .output()
            .ok()?;
        if out.status.success() {
            String::from_utf8_lossy(&out.stdout).trim().parse().ok()
        } else {
            None
        }
    }

    /// Resolve a user's numeric uid from /etc/passwd (or `id -u` on systems
    /// where the user is not listed, e.g. macOS DirectoryService).
    fn uid_for_user(username: &str) -> Option<u32> {
        let content = fs::read_to_string("/etc/passwd").ok()?;
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 && parts[0] == username {
                return parts[2].parse().ok();
            }
        }
        // Fallback: `id -u <username>` (handles LDAP/DirectoryService users).
        let out = std::process::Command::new("id")
            .arg("-u")
            .arg(username)
            .output()
            .ok()?;
        if out.status.success() {
            String::from_utf8_lossy(&out.stdout).trim().parse().ok()
        } else {
            None
        }
    }

    /// StrictModes check: the authorized_keys file must not be writable by
    /// group/others and must be owned by the user (or root).
    fn check_authorized_keys_permissions(path: &Path, username: &str) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(meta) = fs::metadata(path) else { return false; };
            let mode = meta.mode();
            // Group/other write bits must be clear (0o022).
            if mode & 0o022 != 0 {
                return false;
            }
            let uid = Self::uid_for_user(username).unwrap_or(u32::MAX);
            // Owned by the user or root.
            if meta.uid() != uid && meta.uid() != 0 {
                return false;
            }
            true
        }
        #[cfg(not(unix))]
        {
            let _ = (path, username);
            true
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
        // Try to parse options first (they appear before the key type)
        let (options, rest) = match AuthorizedKeyOptions::parse(line) {
            Some((opts, r)) => (opts, r),
            None => (AuthorizedKeyOptions::default(), line),
        };

        let mut parts = rest.split_whitespace();
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
            options,
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

    /// Find the matching authorized key entry for a given key blob.
    pub fn find_matching_key(&self, key_type: &str, public_key: &[u8]) -> Option<&AuthorizedKeyEntry> {
        self.authorized_keys.iter().find(|entry| {
            entry.key_type == key_type && entry.public_key == public_key
        })
    }

    /// Check if a user is allowed by from= pattern in their authorized key.
    pub fn check_from_pattern(&self, entry: &AuthorizedKeyEntry, peer_addr: &str) -> bool {
        if let Some(ref pattern) = entry.options.from_pattern {
            // from="host1,host2,!denyhost" — comma-separated patterns with ! negation
            let mut has_positive = false;
            for pat in pattern.split(',') {
                let pat = pat.trim();
                if pat.is_empty() {
                    continue;
                }
                if let Some(rest) = pat.strip_prefix('!') {
                    if AuthorizedKeyOptions::glob_match(rest, peer_addr) {
                        return false;
                    }
                } else {
                    has_positive = true;
                    if AuthorizedKeyOptions::glob_match(pat, peer_addr) {
                        return true;
                    }
                }
            }
            // If only negation patterns were present, default to allow.
            return !has_positive;
        }
        true
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
                let public_key = rsa::RsaPublicKey::new(n.clone(), e).ok()?;
                // Dynamically compute RSA key bits from n
                let bits = n.bits() as usize;
                Some(Box::new(ssh_core::hostkey::RsaHostKey::new(None, public_key, bits))
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

        // Build sign data using SshBytes encoding for session_id (matching client side)
        let mut data = Vec::new();
        SshBytes(session_id.to_vec()).encode(&mut data).unwrap();
        data.push(50); // SSH_MSG_USERAUTH_REQUEST
        SshString::new(username).encode(&mut data).unwrap();
        let service = "ssh-connection";
        SshString::new(service).encode(&mut data).unwrap();
        SshString::new("publickey").encode(&mut data).unwrap();
        data.push(1); // have_sig = true
        SshString::new(key_type).encode(&mut data).unwrap();
        SshBytes(public_key.to_vec()).encode(&mut data).unwrap();

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
    fn authorized_key_options_parse_command_with_spaces() {
        let line = "command=\"ls -la /tmp\",no-pty ssh-ed25519 AAAA comment";
        let (opts, rest) = AuthorizedKeyOptions::parse(line).expect("should parse");
        assert_eq!(opts.command.as_deref(), Some("ls -la /tmp"));
        assert!(opts.no_pty);
        assert!(rest.starts_with("ssh-ed25519"));
    }

    #[test]
    fn authorized_key_options_parse_from_and_environment() {
        let line = "from=\"192.168.1.*,!10.0.0.1\",environment=\"FOO=bar baz\" ssh-rsa AAAA";
        let (opts, rest) = AuthorizedKeyOptions::parse(line).expect("should parse");
        assert_eq!(opts.from_pattern.as_deref(), Some("192.168.1.*,!10.0.0.1"));
        assert_eq!(opts.environment, vec![("FOO".to_string(), "bar baz".to_string())]);
        assert!(rest.starts_with("ssh-rsa"));
    }

    #[test]
    fn authorized_key_options_none() {
        let line = "ssh-ed25519 AAAA comment";
        let (opts, rest) = AuthorizedKeyOptions::parse(line).expect("should parse");
        assert!(opts.command.is_none());
        assert!(rest.starts_with("ssh-ed25519"));
    }

    #[test]
    fn from_pattern_glob_matching() {
        // * matches any sequence, ? matches a single character
        assert!(AuthorizedKeyOptions::glob_match("192.168.*", "192.168.1.5"));
        assert!(!AuthorizedKeyOptions::glob_match("192.168.*", "10.0.0.1"));
        assert!(AuthorizedKeyOptions::glob_match("host?01", "hostA01"));
        assert!(!AuthorizedKeyOptions::glob_match("host?01", "hostAA01"));
    }

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

    #[test]
    fn user_pattern_wildcard() {
        // Bare patterns match the username with wildcards.
        assert!(wildcard_match("alice", "alice"));
        assert!(wildcard_match("al*", "alice"));
        assert!(wildcard_match("a?ice", "alice"));
        assert!(!wildcard_match("a?ice", "axxice"));
        assert!(!wildcard_match("bob", "alice"));
    }

    #[test]
    fn user_pattern_user_host() {
        // user@host patterns match both components.
        assert!(user_pattern_matches("alice", "web.example.com", "alice@*.example.com"));
        assert!(user_pattern_matches("alice", "web.example.com", "alice@web.*"));
        assert!(!user_pattern_matches("alice", "db.example.com", "alice@web.*"));
        assert!(!user_pattern_matches("bob", "web.example.com", "alice@*"));
    }

    #[test]
    fn check_user_authorized_patterns() {
        let allow = vec!["alice@*".to_string(), "bob".to_string()];
        let deny: Vec<String> = Vec::new();
        assert!(check_user_authorized("alice", "host", &allow, &deny));
        assert!(check_user_authorized("bob", "host", &allow, &deny));
        assert!(!check_user_authorized("carol", "host", &allow, &deny));

        // DenyUsers takes precedence.
        let deny = vec!["alice@*".to_string()];
        assert!(!check_user_authorized("alice", "host", &allow, &deny));
        assert!(check_user_authorized("bob", "host", &allow, &deny));

        // Negated AllowUsers entry denies.
        let allow = vec!["!alice@*".to_string(), "*".to_string()];
        assert!(!check_user_authorized("alice", "host", &allow, &deny));
    }

    #[test]
    fn strict_modes_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ns-ssh-auth-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("authorized_keys");
        std::fs::write(&path, "ssh-ed25519 AAAA\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let me = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        // 644, owned by current user: accepted.
        assert!(ServerAuth::check_authorized_keys_permissions(&path, &me));
        // World-writable: rejected.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!ServerAuth::check_authorized_keys_permissions(&path, &me));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

pub fn check_user_authorized(username: &str, hostname: &str, allow_users: &[String], deny_users: &[String]) -> bool {
    // DenyUsers takes precedence (supports wildcards and `user@host` patterns).
    for pat in deny_users {
        if user_pattern_matches(username, hostname, pat) {
            return false;
        }
    }
    // AllowUsers: if the list is non-empty, the user must match a positive
    // pattern (a leading `!` excludes the user).
    if !allow_users.is_empty() {
        for pat in allow_users {
            if let Some(neg) = pat.strip_prefix('!') {
                if user_pattern_matches(username, hostname, neg) {
                    return false;
                }
            }
        }
        if allow_users.iter().any(|p| !p.starts_with('!') && user_pattern_matches(username, hostname, p)) {
            return true;
        }
        return false;
    }
    true
}

/// Match an AllowUsers/DenyUsers entry against `user@host`. Bare patterns match
/// the username; `user@host` patterns match both (wildcards supported).
fn user_pattern_matches(username: &str, hostname: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if let Some((u, h)) = pattern.rsplit_once('@') {
        wildcard_match(u, username) && wildcard_match(h, hostname)
    } else {
        wildcard_match(pattern, username)
    }
}

/// Classic iterative glob matcher: `*` matches any sequence, `?` matches one char.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut match_idx = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
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

pub fn get_user_groups(username: &str) -> Result<Vec<String>> {
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
