use ssh_core::error::{Result, SshError};
use ssh_core::hostkey::*;
use std::path::{Path, PathBuf};
use std::fs;
use base64::Engine;

pub struct HostKeyManager {
    keys: Vec<Box<dyn HostKeySigner>>,
}

impl HostKeyManager {
    pub fn new() -> Self {
        HostKeyManager { keys: Vec::new() }
    }

    pub fn load_or_generate(&mut self, key_files: &[PathBuf]) -> Result<()> {
        for key_path in key_files {
            match self.load_key(key_path) {
                Ok(key) => {
                    self.keys.push(key);
                }
                Err(_) => {
                    match self.generate_key(key_path) {
                        Ok(key) => {
                            self.keys.push(key);
                        }
                        Err(e) => {
                            eprintln!("Warning: failed to load or generate host key {}: {}", key_path.display(), e);
                        }
                    }
                }
            }
        }

        if self.keys.is_empty() {
            return Err(SshError::Protocol("no host keys available".into()));
        }

        Ok(())
    }

    fn load_key(&self, path: &Path) -> Result<Box<dyn HostKeySigner>> {
        let content = fs::read_to_string(path)
            .map_err(|e| SshError::Io(e))?;

        let content = content.trim();

        if content.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
            load_openssh_key(content)
        } else {
            Err(SshError::InvalidKey("unsupported key format".into()))
        }
    }

    fn generate_key(&self, path: &Path) -> Result<Box<dyn HostKeySigner>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| SshError::Io(e))?;
        }

        let key_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let key: Box<dyn HostKeySigner> = if key_name.contains("ed25519") {
            Box::new(Ed25519HostKey::generate()?)
        } else if key_name.contains("ecdsa") {
            if key_name.contains("384") {
                Box::new(EcdsaP384HostKey::generate()?)
            } else if key_name.contains("521") {
                Box::new(EcdsaP521HostKey::generate()?)
            } else {
                Box::new(EcdsaP256HostKey::generate()?)
            }
        } else if key_name.contains("rsa") {
            Box::new(RsaHostKey::generate(2048)?)
        } else {
            Box::new(Ed25519HostKey::generate()?)
        };

        self.save_key(path, key.as_ref())?;
        Ok(key)
    }

    fn save_key(&self, path: &Path, key: &dyn HostKeySigner) -> Result<()> {
        let key_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let content = if key_name.contains("ed25519") {
            let ed_key = key.as_any().downcast_ref::<Ed25519HostKey>()
                .ok_or_else(|| SshError::Protocol("ed25519 key type mismatch".into()))?;
            ssh_core::keygen::format_openssh_ed25519(&ed_key.secret_bytes())
        } else if key_name.contains("ecdsa") {
            let secret = if let Some(k) = key.as_any().downcast_ref::<EcdsaP256HostKey>() {
                k.secret_bytes()
            } else if let Some(k) = key.as_any().downcast_ref::<EcdsaP384HostKey>() {
                k.secret_bytes()
            } else if let Some(k) = key.as_any().downcast_ref::<EcdsaP521HostKey>() {
                k.secret_bytes()
            } else {
                return Err(SshError::Protocol("ecdsa key type mismatch".into()));
            };
            ssh_core::keygen::format_openssh_ecdsa(&secret)?
        } else {
            return Err(SshError::Protocol("unsupported key type for generation".into()));
        };

        fs::write(path, &content)
            .map_err(|e| SshError::Io(e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|e| SshError::Io(e))?;
        }

        Ok(())
    }

    /// Load `HostCertificate` files and additionally present the certified
    /// variants of the matching host keys (as OpenSSH does).
    pub fn load_certificates(&mut self, cert_files: &[String]) -> Result<()> {
        use ssh_core::cert::{
            is_certificate_key_type, parse_public_key_line, Certificate, CertificateSigner,
            CERT_TYPE_HOST,
        };

        for path in cert_files {
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Warning: cannot read host certificate {}: {}", path, e);
                    continue;
                }
            };
            let line = match content
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with('#'))
            {
                Some(l) => l,
                None => {
                    eprintln!("Warning: host certificate {} is empty", path);
                    continue;
                }
            };
            let Some((key_type, blob)) = parse_public_key_line(line) else {
                eprintln!("Warning: malformed host certificate {}", path);
                continue;
            };
            if !is_certificate_key_type(&key_type) {
                eprintln!("Warning: {} is not a certificate", path);
                continue;
            }
            let cert = match Certificate::parse(&blob) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Warning: cannot parse host certificate {}: {}", path, e);
                    continue;
                }
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if cert.cert_type != CERT_TYPE_HOST || !cert.is_valid_at(now) {
                eprintln!("Warning: host certificate {} is not a valid host certificate", path);
                continue;
            }
            let Some(inner) = self
                .keys
                .iter()
                .find(|k| k.public_key_bytes() == cert.raw_key_blob)
            else {
                eprintln!(
                    "Warning: no host key matches certificate {}",
                    path
                );
                continue;
            };
            let inner = inner.clone_box();

            // Certificate key types follow the plain key type, except for RSA
            // which advertises one variant per signature algorithm.
            let algorithms: Vec<String> = match cert.base_key_type.as_str() {
                "ssh-rsa" => vec![
                    "rsa-sha2-512-cert-v01@openssh.com".to_string(),
                    "rsa-sha2-256-cert-v01@openssh.com".to_string(),
                ],
                base => vec![format!("{}-cert-v01@openssh.com", base)],
            };
            for algorithm in algorithms {
                if self.keys.iter().any(|k| k.algorithm_name() == algorithm) {
                    continue;
                }
                self.keys.push(Box::new(CertificateSigner::new(
                    inner.clone_box(),
                    algorithm,
                    blob.clone(),
                )));
            }
        }
        Ok(())
    }

    pub fn get_key_for_algorithm(&self, algorithm: &str) -> Option<&dyn HostKeySigner> {
        self.keys
            .iter()
            .find(|k| k.algorithm_name() == algorithm || k.supports(algorithm))
            .map(|k| k.as_ref())
    }

    pub fn get_all_keys(&self) -> &[Box<dyn HostKeySigner>] {
        &self.keys
    }

}

fn load_openssh_key(content: &str) -> Result<Box<dyn HostKeySigner>> {
    let base64_content: String = content.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&base64_content)
        .map_err(|e| SshError::InvalidKey(format!("base64 decode: {}", e)))?;

    if decoded.len() < 15 {
        return Err(SshError::InvalidKey("key too short".into()));
    }

    let magic = &decoded[..15];
    if magic != b"openssh-key-v1\0" {
        return Err(SshError::InvalidKey("invalid openssh key magic".into()));
    }

    let mut r = &decoded[15..];
    let _ciphername = read_simplified_string(&mut r)?;
    let _kdfname = read_simplified_string(&mut r)?;
    let _kdfoptions = read_simplified_string(&mut r)?;
    let _num_keys = read_simplified_uint32(&mut r)?;

    let _pub_len = read_simplified_uint32(&mut r)? as usize;
    r = &r[_pub_len..];

    let priv_len = read_simplified_uint32(&mut r)? as usize;
    if r.len() < priv_len {
        return Err(SshError::InvalidKey("truncated private key".into()));
    }
    let priv_data = &r[..priv_len];

    let mut pr = priv_data;
    let _check1 = read_simplified_uint32(&mut pr)?;
    let _check2 = read_simplified_uint32(&mut pr)?;
    let key_type = read_simplified_string(&mut pr)?;

    match key_type.as_str() {
        "ssh-ed25519" => {
            let _pub_len = read_simplified_uint32(&mut pr)? as usize;
            pr = &pr[_pub_len..];
            let _secret_len = read_simplified_uint32(&mut pr)? as usize;
            let secret_bytes = read_simplified_raw(&mut pr, 32)?;
            let _pub_after = read_simplified_raw(&mut pr, 32)?;

            Ok(Box::new(Ed25519HostKey::from_bytes(
                &secret_bytes.try_into().map_err(|_| SshError::InvalidKey("wrong ed25519 key size".into()))?
            )?))
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let _pub_curve = read_simplified_string(&mut pr)?;
            let _pub_len = read_simplified_uint32(&mut pr)? as usize;
            pr = &pr[_pub_len..];
            let secret_bytes = read_simplified_string_bytes(&mut pr)?;
            let (field_len, name) = match key_type.as_str() {
                "ecdsa-sha2-nistp256" => (32, "nistp256"),
                "ecdsa-sha2-nistp384" => (48, "nistp384"),
                _ => (66, "nistp521"),
            };
            let secret = normalize_scalar(&secret_bytes, field_len)?;
            match name {
                "nistp256" => Ok(Box::new(EcdsaP256HostKey::from_secret_bytes(&secret)?)),
                "nistp384" => Ok(Box::new(EcdsaP384HostKey::from_secret_bytes(&secret)?)),
                _ => Ok(Box::new(EcdsaP521HostKey::from_secret_bytes(&secret)?)),
            }
        }
        "ssh-rsa" => {
            let n_bytes = read_simplified_string_bytes(&mut pr)?;
            let e_bytes = read_simplified_string_bytes(&mut pr)?;
            let _d_bytes = read_simplified_string_bytes(&mut pr)?;
            let _iqmp_bytes = read_simplified_string_bytes(&mut pr)?;
            let _p_bytes = read_simplified_string_bytes(&mut pr)?;
            let _q_bytes = read_simplified_string_bytes(&mut pr)?;

            let n = rsa::BigUint::from_bytes_be(&n_bytes);
            let e = rsa::BigUint::from_bytes_be(&e_bytes);
            let d = rsa::BigUint::from_bytes_be(&_d_bytes);

            let rsa_key = rsa::RsaPrivateKey::from_components(n, e, d, vec![])
                .map_err(|e| SshError::InvalidKey(format!("RSA: {}", e)))?;
            let public_key = rsa::RsaPublicKey::from(&rsa_key);

            Ok(Box::new(RsaHostKey::new(Some(rsa_key), public_key, 2048)))
        }
        _ => Err(SshError::InvalidKey(format!("unsupported key type: {}", key_type))),
    }
}

fn read_simplified_string(r: &mut &[u8]) -> Result<String> {
    let len = read_simplified_uint32(r)? as usize;
    if r.len() < len {
        return Err(SshError::InvalidKey("truncated string".into()));
    }
    let s = String::from_utf8_lossy(&r[..len]).to_string();
    *r = &r[len..];
    Ok(s)
}

fn read_simplified_string_bytes(r: &mut &[u8]) -> Result<Vec<u8>> {
    let len = read_simplified_uint32(r)? as usize;
    if r.len() < len {
        return Err(SshError::InvalidKey("truncated string".into()));
    }
    let bytes = r[..len].to_vec();
    *r = &r[len..];
    Ok(bytes)
}

fn read_simplified_uint32(r: &mut &[u8]) -> Result<u32> {
    if r.len() < 4 {
        return Err(SshError::InvalidKey("truncated uint32".into()));
    }
    let val = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
    *r = &r[4..];
    Ok(val)
}

/// OpenSSH stores the ECDSA private scalar as an mpint, which may carry a
/// leading 0x00 sign byte and may omit leading zeros. Normalise it to the
/// curve's field width before handing it to the crypto crate.
fn normalize_scalar(bytes: &[u8], field_len: usize) -> Result<Vec<u8>> {
    if bytes.len() > field_len + 1 {
        return Err(SshError::InvalidKey("ECDSA secret longer than field".into()));
    }
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let scalar = &bytes[first..];
    if scalar.len() > field_len {
        return Err(SshError::InvalidKey("ECDSA secret longer than field".into()));
    }
    let mut out = vec![0u8; field_len];
    out[field_len - scalar.len()..].copy_from_slice(scalar);
    Ok(out)
}

fn read_simplified_raw(r: &mut &[u8], len: usize) -> Result<Vec<u8>> {
    if r.len() < len {
        return Err(SshError::InvalidKey("truncated raw data".into()));
    }
    let bytes = r[..len].to_vec();
    *r = &r[len..];
    Ok(bytes)
}
