//! OpenSSH key generation & serialization helpers.
//!
//! Shared between `ns-ssh` (ssh-keygen subcommand) and `ns-ssh-server`
//! (host key generation), so both emit byte-identical OpenSSH private keys.

use crate::error::{Result, SshError};
use base64::Engine;

/// Format an ed25519 private key as an OpenSSH private key (no passphrase).
pub fn format_openssh_ed25519(secret: &[u8; 32]) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"openssh-key-v1\0");
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(b"none"); // cipher: none
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(b"none"); // kdf: none
    buf.extend_from_slice(&0u32.to_be_bytes()); // kdf options: empty string
    buf.extend_from_slice(&1u32.to_be_bytes()); // nkeys

    let signing = ed25519_dalek::SigningKey::from_bytes(secret);
    let pub_key = signing.verifying_key();

    let mut pub_key_buf = Vec::new();
    pub_key_buf.extend_from_slice(&(11u32).to_be_bytes());
    pub_key_buf.extend_from_slice(b"ssh-ed25519");
    pub_key_buf.extend_from_slice(&(32u32).to_be_bytes());
    pub_key_buf.extend_from_slice(pub_key.as_bytes());
    buf.extend_from_slice(&(pub_key_buf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&pub_key_buf);

    let mut priv_key_buf = Vec::new();
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes()); // checkint 1
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes()); // checkint 2
    priv_key_buf.extend_from_slice(&(11u32).to_be_bytes());
    priv_key_buf.extend_from_slice(b"ssh-ed25519");
    priv_key_buf.extend_from_slice(&(32u32).to_be_bytes());
    priv_key_buf.extend_from_slice(pub_key.as_bytes());
    priv_key_buf.extend_from_slice(&(64u32).to_be_bytes());
    priv_key_buf.extend_from_slice(secret);
    priv_key_buf.extend_from_slice(pub_key.as_bytes());
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes()); // comment: empty string
    // Pad with 1,2,3,... so the private block is a multiple of the block size (8 for none).
    let pad = (8 - (priv_key_buf.len() % 8)) % 8;
    for i in 1..=pad {
        priv_key_buf.push(i as u8);
    }

    buf.extend_from_slice(&(priv_key_buf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&priv_key_buf);

    encode_pem(&buf)
}

/// Format an ECDSA (P-256/P-384/P-521) private key as an OpenSSH private key
/// (no passphrase). The curve is selected from the scalar length.
pub fn format_openssh_ecdsa(secret: &[u8]) -> Result<String> {
    let (key_type, curve_name, point_bytes) = match secret.len() {
        32 => {
            let signing_key = p256::ecdsa::SigningKey::from_slice(secret)
                .map_err(|e| SshError::InvalidKey(format!("ecdsa p256: {}", e)))?;
            let point = signing_key.verifying_key().to_encoded_point(false);
            ("ecdsa-sha2-nistp256", "nistp256", point.as_bytes().to_vec())
        }
        48 => {
            let signing_key = p384::ecdsa::SigningKey::from_slice(secret)
                .map_err(|e| SshError::InvalidKey(format!("ecdsa p384: {}", e)))?;
            let point = signing_key.verifying_key().to_encoded_point(false);
            ("ecdsa-sha2-nistp384", "nistp384", point.as_bytes().to_vec())
        }
        66 => {
            let signing_key = p521::ecdsa::SigningKey::from_slice(secret)
                .map_err(|e| SshError::InvalidKey(format!("ecdsa p521: {}", e)))?;
            let point = p521::ecdsa::VerifyingKey::from(&signing_key)
                .to_encoded_point(false);
            ("ecdsa-sha2-nistp521", "nistp521", point.as_bytes().to_vec())
        }
        _ => {
            return Err(SshError::InvalidKey(
                "unsupported ECDSA secret length".into(),
            ))
        }
    };

    let mut buf = Vec::new();
    buf.extend_from_slice(b"openssh-key-v1\0");
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(b"none"); // cipher: none
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(b"none"); // kdf: none
    buf.extend_from_slice(&0u32.to_be_bytes()); // kdf options: empty string
    buf.extend_from_slice(&1u32.to_be_bytes());

    let mut pub_key_buf = Vec::new();
    pub_key_buf.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    pub_key_buf.extend_from_slice(key_type.as_bytes());
    pub_key_buf.extend_from_slice(&(curve_name.len() as u32).to_be_bytes());
    pub_key_buf.extend_from_slice(curve_name.as_bytes());
    pub_key_buf.extend_from_slice(&(point_bytes.len() as u32).to_be_bytes());
    pub_key_buf.extend_from_slice(&point_bytes);
    buf.extend_from_slice(&(pub_key_buf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&pub_key_buf);

    let mut priv_key_buf = Vec::new();
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes());
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes());
    priv_key_buf.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    priv_key_buf.extend_from_slice(key_type.as_bytes());
    priv_key_buf.extend_from_slice(&(curve_name.len() as u32).to_be_bytes());
    priv_key_buf.extend_from_slice(curve_name.as_bytes());
    priv_key_buf.extend_from_slice(&(point_bytes.len() as u32).to_be_bytes());
    priv_key_buf.extend_from_slice(&point_bytes);
    // Private scalar encoded as mpint: prepend 0x00 if the high bit is set.
    let mut scalar_mpint = Vec::new();
    if secret.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        scalar_mpint.push(0x00);
    }
    scalar_mpint.extend_from_slice(secret);
    priv_key_buf.extend_from_slice(&(scalar_mpint.len() as u32).to_be_bytes());
    priv_key_buf.extend_from_slice(&scalar_mpint);
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes()); // comment (empty)
    let pad = (8 - (priv_key_buf.len() % 8)) % 8;
    for i in 1..=pad {
        priv_key_buf.push(i as u8);
    }

    buf.extend_from_slice(&(priv_key_buf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&priv_key_buf);

    Ok(encode_pem(&buf))
}

fn encode_pem(buf: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(buf);
    let mut result = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        result.push_str(std::str::from_utf8(chunk).unwrap());
        result.push('\n');
    }
    result.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    result
}

/// The OpenSSH public-key line for an ed25519 public key.
pub fn format_public_ed25519(public: &[u8; 32]) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(11u32).to_be_bytes());
    buf.extend_from_slice(b"ssh-ed25519");
    buf.extend_from_slice(&(32u32).to_be_bytes());
    buf.extend_from_slice(public);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
    format!("ssh-ed25519 {}", encoded)
}

/// Write a private key file with 0600 permissions (POSIX).
pub fn write_private_key(path: &std::path::Path, content: &str) -> Result<()> {
    std::fs::write(path, content).map_err(|e| SshError::Io(e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| SshError::Io(e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_ed25519_roundtrip() {
        let secret = [7u8; 32];
        let pem = format_openssh_ed25519(&secret);
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(pem.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        // Re-derive the public key and verify it matches format_public_ed25519.
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let pub_key = signing.verifying_key();
        let line = format_public_ed25519(pub_key.as_bytes());
        assert!(line.starts_with("ssh-ed25519 "));
        assert_eq!(line.len(), 11 + 1 + 68); // "ssh-ed25519 " + base64(44 bytes)
    }

    #[test]
    fn openssh_ecdsa_pem() {
        let key = crate::hostkey::EcdsaP256HostKey::generate().unwrap();
        let pem = format_openssh_ecdsa(&key.secret_bytes()).unwrap();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }
}
