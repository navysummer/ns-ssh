//! OpenSSH certificate support (PROTOCOL.certkeys).
//!
//! A certificate is a public key blob with extra signed fields: serial,
//! type (user/host), principals, validity window, critical options and
//! extensions. The whole certificate (minus the trailing signature) is signed
//! by a certificate authority (CA) key.

use crate::encoding::*;
use crate::error::{Result, SshError};
use crate::hostkey::*;

pub const CERT_TYPE_USER: u32 = 1;
pub const CERT_TYPE_HOST: u32 = 2;

#[derive(Debug, Clone)]
pub struct Certificate {
    /// Full certificate key type, e.g. `ssh-ed25519-cert-v01@openssh.com`.
    pub key_type: String,
    /// Underlying plain key type, e.g. `ssh-ed25519`.
    pub base_key_type: String,
    pub nonce: Vec<u8>,
    /// Plain public key blob reconstructed from the certificate fields.
    pub raw_key_blob: Vec<u8>,
    pub serial: u64,
    pub cert_type: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical_options: Vec<(String, Vec<u8>)>,
    pub extensions: Vec<(String, Vec<u8>)>,
    /// CA public key blob.
    pub signature_key: Vec<u8>,
    pub signature: Vec<u8>,
    /// Certificate bytes covered by the CA signature.
    signed_data: Vec<u8>,
}

/// Whether a key type names an OpenSSH certificate.
pub fn is_certificate_key_type(key_type: &str) -> bool {
    key_type.ends_with("-cert-v01@openssh.com")
}

/// Map a certificate key type to the plain key type it wraps.
pub fn base_key_type_for(key_type: &str) -> Option<&'static str> {
    match key_type {
        "ssh-ed25519-cert-v01@openssh.com" => Some("ssh-ed25519"),
        "ssh-rsa-cert-v01@openssh.com"
        | "rsa-sha2-256-cert-v01@openssh.com"
        | "rsa-sha2-512-cert-v01@openssh.com" => Some("ssh-rsa"),
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp256"),
        "ecdsa-sha2-nistp384-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp384"),
        "ecdsa-sha2-nistp521-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp521"),
        _ => None,
    }
}

/// Map a certificate signature algorithm name to the plain algorithm the
/// underlying key signs with (e.g. `rsa-sha2-512-cert-v01@openssh.com` ->
/// `rsa-sha2-512`). Non-certificate names are returned unchanged.
pub fn base_signature_algorithm(algorithm: &str) -> &str {
    match algorithm {
        "ssh-ed25519-cert-v01@openssh.com" => "ssh-ed25519",
        "ssh-rsa-cert-v01@openssh.com" => "ssh-rsa",
        "rsa-sha2-256-cert-v01@openssh.com" => "rsa-sha2-256",
        "rsa-sha2-512-cert-v01@openssh.com" => "rsa-sha2-512",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com" => "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com" => "ecdsa-sha2-nistp521",
        other => other,
    }
}

/// Match a principal pattern (`*` and `?` wildcards, as OpenSSH allows in
/// certificate principals) against a concrete name.
fn principal_pattern_matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut star_ni) = (None, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ni = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn parse_options(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut r = bytes;
    let mut out = Vec::new();
    while !r.is_empty() {
        let name = SshString::decode(&mut r)?.0;
        let data = SshBytes::decode(&mut r)?.0;
        out.push((String::from_utf8_lossy(&name).into_owned(), data));
    }
    Ok(out)
}

impl Certificate {
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut r = blob;
        let key_type = SshString::decode(&mut r)?.as_str()?.to_string();
        let base = base_key_type_for(&key_type)
            .ok_or_else(|| SshError::InvalidKey(format!("unsupported certificate type: {}", key_type)))?
            .to_string();
        let nonce = SshBytes::decode(&mut r)?.0;

        // Key-type specific public fields, used to reconstruct a plain key blob.
        let mut raw = Vec::new();
        SshString::new(&base).encode(&mut raw)?;
        match base.as_str() {
            "ssh-ed25519" => {
                let pk = SshBytes::decode(&mut r)?;
                if pk.0.len() != 32 {
                    return Err(SshError::InvalidKey("ed25519 certificate key length".into()));
                }
                SshBytes(pk.0.clone()).encode(&mut raw)?;
            }
            "ssh-rsa" => {
                let e = SshMpInt::decode(&mut r)?;
                let n = SshMpInt::decode(&mut r)?;
                e.encode(&mut raw)?;
                n.encode(&mut raw)?;
            }
            _ => {
                // ECDSA: curve name plus the public point.
                let curve = SshString::decode(&mut r)?;
                let point = SshBytes::decode(&mut r)?;
                curve.encode(&mut raw)?;
                point.encode(&mut raw)?;
            }
        }

        let serial = u64::decode(&mut r)?;
        let cert_type = u32::decode(&mut r)?;
        let key_id = SshString::decode(&mut r)?.as_str()?.to_string();
        // OpenSSH encodes the principals as a string containing zero or more
        // nested strings, one principal each (not a comma-separated list).
        let principals_raw = SshBytes::decode(&mut r)?.0;
        let mut principals = Vec::new();
        let mut pr = &principals_raw[..];
        while !pr.is_empty() {
            principals.push(SshString::decode(&mut pr)?.as_str()?.to_string());
        }
        let valid_after = u64::decode(&mut r)?;
        let valid_before = u64::decode(&mut r)?;
        let critical = parse_options(&SshBytes::decode(&mut r)?.0)?;
        let extensions = parse_options(&SshBytes::decode(&mut r)?.0)?;
        let _reserved = SshBytes::decode(&mut r)?.0;
        let signature_key = SshBytes::decode(&mut r)?.0;
        // Everything up to (but excluding) the signature field is signed.
        let signed_data = blob[..blob.len() - r.len()].to_vec();
        let signature = SshBytes::decode(&mut r)?.0;

        Ok(Certificate {
            key_type,
            base_key_type: base,
            nonce,
            raw_key_blob: raw,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options: critical,
            extensions,
            signature_key,
            signature,
            signed_data,
        })
    }

    /// Validity window check, as OpenSSH does it (0 means unbounded).
    pub fn is_valid_at(&self, now: u64) -> bool {
        (self.valid_after == 0 || now >= self.valid_after)
            && (self.valid_before == 0 || now < self.valid_before)
    }

    pub fn principal_matches(&self, name: &str) -> bool {
        self.principals
            .iter()
            .any(|p| principal_pattern_matches(p, name))
    }

    /// Whether any of `allowed` appears in the certificate principals.
    pub fn any_principal_in(&self, allowed: &[String]) -> bool {
        self.principals.iter().any(|p| allowed.iter().any(|a| a == p))
    }

    pub fn critical_option(&self, name: &str) -> Option<&[u8]> {
        self.critical_options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.as_slice())
    }

    pub fn has_extension(&self, name: &str) -> bool {
        self.extensions.iter().any(|(n, _)| n == name)
    }

    /// Verify the CA signature over the certificate.
    pub fn verify_ca_signature(&self, allowed_ca_types: Option<&[String]>) -> bool {
        let mut r = &self.signature_key[..];
        let ca_key_type = match SshString::decode(&mut r) {
            Ok(s) => match s.as_str() {
                Ok(v) => v.to_string(),
                Err(_) => return false,
            },
            Err(_) => return false,
        };
        if let Some(allowed) = allowed_ca_types {
            if !allowed.iter().any(|a| a == &ca_key_type) {
                return false;
            }
        }
        let verifier = match verifier_for_plain_key(&ca_key_type, &self.signature_key) {
            Some(v) => v,
            None => return false,
        };
        verifier.verify(&self.signed_data, &self.signature).unwrap_or(false)
    }

    /// Whether the certificate's underlying key is listed in `revoked`
    /// (public key blobs from a RevokedKeys file).
    pub fn is_revoked_by(&self, revoked: &[Vec<u8>]) -> bool {
        revoked.iter().any(|blob| blob == &self.raw_key_blob || blob == &self.signature_key)
    }
}

/// Build an Ed25519/RSA/ECDSA verifier from a plain public key blob that
/// starts with its key-type string.
pub fn verifier_for_plain_key(key_type: &str, key_blob: &[u8]) -> Option<Box<dyn HostKeyVerifier>> {
    let mut r = key_blob;
    let declared = SshString::decode(&mut r).ok()?.as_str().ok()?.to_string();
    if declared != key_type && !(key_type.starts_with("rsa-sha2-") && declared == "ssh-rsa") {
        return None;
    }
    match declared.as_str() {
        "ssh-ed25519" => {
            let pk = SshBytes::decode(&mut r).ok()?;
            if pk.0.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk.0);
            Ed25519HostKey::from_public_bytes(&arr)
                .ok()
                .map(|k| Box::new(k) as Box<dyn HostKeyVerifier>)
        }
        "ecdsa-sha2-nistp256" => {
            let _curve = SshString::decode(&mut r).ok()?;
            let q = SshBytes::decode(&mut r).ok()?;
            EcdsaP256HostKey::from_public_bytes(&q.0)
                .ok()
                .map(|k| Box::new(k) as Box<dyn HostKeyVerifier>)
        }
        "ecdsa-sha2-nistp384" => {
            let _curve = SshString::decode(&mut r).ok()?;
            let q = SshBytes::decode(&mut r).ok()?;
            EcdsaP384HostKey::from_public_bytes(&q.0)
                .ok()
                .map(|k| Box::new(k) as Box<dyn HostKeyVerifier>)
        }
        "ecdsa-sha2-nistp521" => {
            let _curve = SshString::decode(&mut r).ok()?;
            let q = SshBytes::decode(&mut r).ok()?;
            EcdsaP521HostKey::from_public_bytes(&q.0)
                .ok()
                .map(|k| Box::new(k) as Box<dyn HostKeyVerifier>)
        }
        "ssh-rsa" => {
            // RsaHostKey::from_public_bytes expects the blob without the key type.
            let e = SshMpInt::decode(&mut r).ok()?;
            let n = SshMpInt::decode(&mut r).ok()?;
            let mut inner = Vec::new();
            e.encode(&mut inner).ok()?;
            n.encode(&mut inner).ok()?;
            RsaHostKey::from_public_bytes(&inner)
                .ok()
                .map(|k| Box::new(k) as Box<dyn HostKeyVerifier>)
        }
        _ => None,
    }
}

/// Read a single-line public key file and return `(key_type, blob)`.
pub fn read_public_key_file(path: &std::path::Path) -> Result<(String, Vec<u8>)> {
    let content = std::fs::read_to_string(path).map_err(SshError::Io)?;
    parse_public_key_line(content.trim())
        .ok_or_else(|| SshError::InvalidKey(format!("invalid public key file: {}", path.display())))
}

pub fn parse_public_key_line(line: &str) -> Option<(String, Vec<u8>)> {
    let mut parts = line.split_whitespace();
    let key_type = parts.next()?.to_string();
    let b64 = parts.next()?;
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some((key_type, blob))
}

/// A signer that advertises a certificate blob while signing with the
/// certificate's underlying private key.
pub struct CertificateSigner {
    inner: Box<dyn HostKeySigner>,
    cert_type: String,
    cert_blob: Vec<u8>,
}

impl CertificateSigner {
    pub fn new(inner: Box<dyn HostKeySigner>, cert_type: String, cert_blob: Vec<u8>) -> Self {
        CertificateSigner { inner, cert_type, cert_blob }
    }
}

impl HostKeySigner for CertificateSigner {
    fn algorithm_name(&self) -> &str {
        &self.cert_type
    }
    fn key_type(&self) -> &str {
        &self.cert_type
    }
    fn public_key_bytes(&self) -> Vec<u8> {
        self.cert_blob.clone()
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.inner.sign(data)
    }
    fn sign_with(&self, algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .sign_with(base_signature_algorithm(algorithm), data)
    }
    fn supports(&self, algorithm: &str) -> bool {
        algorithm == self.cert_type || self.inner.supports(algorithm)
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        self.inner.verify(data, signature)
    }
    fn clone_box(&self) -> Box<dyn HostKeySigner> {
        Box::new(CertificateSigner {
            inner: self.inner.clone_box(),
            cert_type: self.cert_type.clone(),
            cert_blob: self.cert_blob.clone(),
        })
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_user_cert(principals: &[&str], valid_after: u64, valid_before: u64, signer: &dyn HostKeySigner) -> Vec<u8> {
        let mut cert = Vec::new();
        SshString::new("ssh-ed25519-cert-v01@openssh.com").encode(&mut cert).unwrap();
        SshBytes(vec![1, 2, 3, 4]).encode(&mut cert).unwrap();
        // ed25519 public key from the signer
        let mut r = &signer.public_key_bytes()[..];
        let _kt = SshString::decode(&mut r).unwrap();
        let pk = SshBytes::decode(&mut r).unwrap();
        pk.encode(&mut cert).unwrap();
        cert.extend_from_slice(&7u64.to_be_bytes()); // serial
        cert.extend_from_slice(&CERT_TYPE_USER.to_be_bytes());
        SshString::new("test-id").encode(&mut cert).unwrap();
        let mut pbuf = Vec::new();
        for p in principals {
            SshString::new(p).encode(&mut pbuf).unwrap();
        }
        SshBytes(pbuf).encode(&mut cert).unwrap();
        cert.extend_from_slice(&valid_after.to_be_bytes());
        cert.extend_from_slice(&valid_before.to_be_bytes());
        SshBytes(Vec::new()).encode(&mut cert).unwrap(); // critical options
        SshBytes(Vec::new()).encode(&mut cert).unwrap(); // extensions
        SshBytes(Vec::new()).encode(&mut cert).unwrap(); // reserved
        SshBytes(signer.public_key_bytes()).encode(&mut cert).unwrap();
        let sig = signer.sign(&cert).unwrap();
        SshBytes(sig).encode(&mut cert).unwrap();
        cert
    }

    #[test]
    fn parses_and_verifies_ed25519_user_certificate() {
        let ca = Ed25519HostKey::generate().unwrap();
        let blob = build_user_cert(&["alice", "bob"], 0, 0, &ca);
        let cert = Certificate::parse(&blob).unwrap();
        assert_eq!(cert.key_type, "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(cert.base_key_type, "ssh-ed25519");
        assert_eq!(cert.cert_type, CERT_TYPE_USER);
        assert_eq!(cert.serial, 7);
        assert!(cert.principal_matches("alice"));
        assert!(cert.principal_matches("bob"));
        assert!(!cert.principal_matches("carol"));
        assert!(cert.verify_ca_signature(None));
        assert!(cert.verify_ca_signature(Some(&["ssh-ed25519".to_string()])));
        assert!(!cert.verify_ca_signature(Some(&["ssh-rsa".to_string()])));
        assert!(cert.is_valid_at(u64::MAX / 2));
        // Tampering with the principals invalidates the CA signature.
        let mut tampered = blob.clone();
        let pos = blob.windows(5).position(|w| w == b"alice").unwrap();
        tampered[pos] = b'x';
        let bad = Certificate::parse(&tampered).unwrap();
        assert!(!bad.verify_ca_signature(None));
    }

    #[test]
    fn validity_window_is_enforced() {
        let ca = Ed25519HostKey::generate().unwrap();
        let blob = build_user_cert(&["alice"], 100, 200, &ca);
        let cert = Certificate::parse(&blob).unwrap();
        assert!(!cert.is_valid_at(50));
        assert!(cert.is_valid_at(100));
        assert!(cert.is_valid_at(199));
        assert!(!cert.is_valid_at(200));
    }

    #[test]
    fn certificate_algorithms_map_to_plain_algorithms() {
        assert_eq!(
            base_signature_algorithm("ssh-ed25519-cert-v01@openssh.com"),
            "ssh-ed25519"
        );
        assert_eq!(
            base_signature_algorithm("rsa-sha2-512-cert-v01@openssh.com"),
            "rsa-sha2-512"
        );
        assert_eq!(
            base_signature_algorithm("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
            "ecdsa-sha2-nistp256"
        );
        assert_eq!(base_signature_algorithm("ssh-ed25519"), "ssh-ed25519");
    }

    #[test]
    fn principals_support_wildcards() {
        let ca = Ed25519HostKey::generate().unwrap();
        let blob = build_user_cert(&["*.example.com"], 0, 0, &ca);
        let cert = Certificate::parse(&blob).unwrap();
        assert!(cert.principal_matches("a.example.com"));
        assert!(cert.principal_matches("a.b.example.com"));
        assert!(!cert.principal_matches("example.org"));
    }

    #[test]
    fn certificate_signer_advertises_cert_blob() {
        let key = Ed25519HostKey::generate().unwrap();
        let blob = build_user_cert(&["alice"], 0, 0, &key);
        let signer = CertificateSigner::new(
            Box::new(key),
            "ssh-ed25519-cert-v01@openssh.com".to_string(),
            blob.clone(),
        );
        assert_eq!(signer.algorithm_name(), "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(signer.public_key_bytes(), blob);
        assert!(signer.sign(b"data").is_ok());
    }
}
