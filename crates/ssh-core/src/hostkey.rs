use crate::error::{Result, SshError};
use crate::encoding::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::pkcs1v15::Signature as RsaSignature;
use rsa::traits::PublicKeyParts;
use rsa::signature::{RandomizedSigner, Verifier as RsaVerifier, SignatureEncoding};
use sha2::{Sha256, Sha512};
use sha1::Sha1;
use rand::rngs::OsRng;

pub trait HostKeySigner: Send + Sync {
    fn algorithm_name(&self) -> &str;
    fn key_type(&self) -> &str;
    fn public_key_bytes(&self) -> Vec<u8>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn sign_with(&self, algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
        let _ = algorithm;
        self.sign(data)
    }
    fn supports(&self, algorithm: &str) -> bool {
        algorithm == self.algorithm_name()
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool>;
    fn clone_box(&self) -> Box<dyn HostKeySigner>;
    /// Downcast to a concrete key type (used for agent serialization).
    fn as_any(&self) -> &dyn std::any::Any;
}

impl Clone for Box<dyn HostKeySigner> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub trait HostKeyVerifier: Send + Sync {
    fn algorithm_name(&self) -> &str;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool>;
    fn verify_with(&self, algorithm: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
        let _ = algorithm;
        self.verify(data, signature)
    }
    fn public_key_bytes(&self) -> Vec<u8>;
    fn key_type(&self) -> &str;
}

/// Encode an ECDSA signature as OpenSSH does it (RFC 5656 §3.1):
/// `string type`, then `string (string r || string s)`, where each of r and s
/// is `field_len` bytes. Encoding r||s as one flat 64-byte string (which this
/// used to do) is readable by our own code but rejected by OpenSSH, so ECDSA
/// authentication could never interoperate.
fn encode_ecdsa_signature(algorithm: &str, signature: &[u8], field_len: usize) -> Vec<u8> {
    debug_assert_eq!(signature.len(), field_len * 2);
    let (r, s) = signature.split_at(field_len);
    let mut inner = Vec::new();
    SshString(ecdsa_mpint(r)).encode(&mut inner).unwrap();
    SshString(ecdsa_mpint(s)).encode(&mut inner).unwrap();
    let mut buf = Vec::new();
    SshString::new(algorithm).encode(&mut buf).unwrap();
    SshBytes(inner).encode(&mut buf).unwrap();
    buf
}

/// OpenSSH stores the ECDSA components as SSH `mpint`s. A 32-byte (or 66-byte
/// for P-521) value whose top bit is set would be negative without a leading
/// zero byte, which the peer rejects, so add the sign byte when necessary.
fn ecdsa_mpint(component: &[u8]) -> Vec<u8> {
    let first = component.iter().position(|&b| b != 0).unwrap_or(component.len());
    let mut out = Vec::with_capacity(component.len() - first + 1);
    if first < component.len() && component[first] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&component[first..]);
    out
}

/// Parse the OpenSSH ECDSA signature layout produced by
/// [`encode_ecdsa_signature`] into the flat `r||s` form the curve crate
/// expects. Components shorter than `field_len` are left-padded with zeros
/// (OpenSSH normally emits exactly `field_len` bytes).
fn decode_ecdsa_signature(signature: &[u8], field_len: usize) -> Result<Vec<u8>> {
    let mut outer = signature;
    let _sig_type = SshString::decode(&mut outer)?;
    let inner = SshBytes::decode(&mut outer)?;
    let mut rest = &inner.0[..];
    let r = SshString::decode(&mut rest)?;
    let s = SshString::decode(&mut rest)?;
    // Strip a leading 0x00 sign byte before checking the component size.
    let strip = |v: &[u8]| -> Vec<u8> {
        let first = v.iter().position(|&b| b != 0).unwrap_or(v.len());
        v[first..].to_vec()
    };
    let r = strip(&r.0);
    let s = strip(&s.0);
    if r.len() > field_len || s.len() > field_len {
        return Err(SshError::InvalidKey("ecdsa signature component too large".into()));
    }
    let mut flat = vec![0u8; field_len * 2];
    flat[field_len - r.len()..field_len].copy_from_slice(&r);
    flat[field_len * 2 - s.len()..].copy_from_slice(&s);
    Ok(flat)
}

pub struct Ed25519HostKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519HostKey {
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok(Ed25519HostKey { signing_key, verifying_key })
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        Ok(Ed25519HostKey { signing_key, verifying_key })
    }

    pub fn from_public_bytes(public: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(public)
            .map_err(|e| SshError::InvalidKey(format!("ed25519: {}", e)))?;
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Ed25519HostKey { signing_key, verifying_key })
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Raw 32-byte ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl HostKeySigner for Ed25519HostKey {
    fn algorithm_name(&self) -> &str { "ssh-ed25519" }
    fn key_type(&self) -> &str { "ssh-ed25519" }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::new("ssh-ed25519").encode(&mut buf).unwrap();
        SshBytes(self.verifying_key.as_bytes().to_vec()).encode(&mut buf).unwrap();
        buf
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = self.signing_key.sign(data);
        let mut buf = Vec::new();
        SshString::new("ssh-ed25519").encode(&mut buf).unwrap();
        SshBytes(sig.to_bytes().to_vec()).encode(&mut buf).unwrap();
        Ok(buf)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut r = &signature[..];
        let _sig_type = SshString::decode(&mut r)?;
        let sig_bytes = SshBytes::decode(&mut r)?;
        let sig = Signature::from_slice(&sig_bytes.0)
            .map_err(|e| SshError::InvalidKey(format!("ed25519 sig: {}", e)))?;
        Ok(self.verifying_key.verify(data, &sig).is_ok())
    }

    fn clone_box(&self) -> Box<dyn HostKeySigner> {
        Box::new(Ed25519HostKey {
            signing_key: SigningKey::from_bytes(&self.signing_key.to_bytes()),
            verifying_key: self.verifying_key.clone(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

impl HostKeyVerifier for Ed25519HostKey {
    fn algorithm_name(&self) -> &str { "ssh-ed25519" }
    fn key_type(&self) -> &str { "ssh-ed25519" }
    fn public_key_bytes(&self) -> Vec<u8> { self.verifying_key.as_bytes().to_vec() }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        HostKeySigner::verify(self, data, signature)
    }
}

pub struct EcdsaP256HostKey {
    signing_key: p256::ecdsa::SigningKey,
    verifying_key: p256::ecdsa::VerifyingKey,
}

impl EcdsaP256HostKey {
    pub fn generate() -> Result<Self> {
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key().to_owned();
        Ok(EcdsaP256HostKey { signing_key, verifying_key })
    }

    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() != 32 {
            return Err(SshError::InvalidKey(format!(
                "ecdsa p256: secret must be 32 bytes, got {}", secret.len()
            )));
        }
        let signing_key = p256::ecdsa::SigningKey::from_slice(secret)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p256: {}", e)))?;
        let verifying_key = signing_key.verifying_key().to_owned();
        Ok(EcdsaP256HostKey { signing_key, verifying_key })
    }

    pub fn from_public_bytes(public: &[u8]) -> Result<Self> {
        let _point = p256::EncodedPoint::from_bytes(public)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p256: {}", e)))?;
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p256: {}", e)))?;
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        Ok(EcdsaP256HostKey { signing_key, verifying_key })
    }

    pub fn secret_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Raw uncompressed EC point (0x04 || X || Y) for the agent protocol.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }
}

impl HostKeySigner for EcdsaP256HostKey {
    fn algorithm_name(&self) -> &str { "ecdsa-sha2-nistp256" }
    fn key_type(&self) -> &str { "ecdsa-sha2-nistp256" }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::new("ecdsa-sha2-nistp256").encode(&mut buf).unwrap();
        SshString::new("nistp256").encode(&mut buf).unwrap();
        let point = self.verifying_key.to_encoded_point(false);
        SshBytes(point.as_bytes().to_vec()).encode(&mut buf).unwrap();
        buf
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let sig: p256::ecdsa::Signature = self.signing_key
            .sign_prehash(&hash)
            .map_err(|e| SshError::Protocol(format!("ecdsa sign: {}", e)))?;
        Ok(encode_ecdsa_signature(
            "ecdsa-sha2-nistp256",
            &sig.to_bytes(),
            32,
        ))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let flat = decode_ecdsa_signature(signature, 32)?;
        let sig = p256::ecdsa::Signature::from_slice(&flat)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa sig: {}", e)))?;
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        Ok(self.verifying_key.verify_prehash(&hash, &sig).is_ok())
    }

    fn clone_box(&self) -> Box<dyn HostKeySigner> {
        Box::new(EcdsaP256HostKey {
            signing_key: p256::ecdsa::SigningKey::from_bytes(&self.signing_key.to_bytes()).unwrap(),
            verifying_key: self.verifying_key.clone(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

impl HostKeyVerifier for EcdsaP256HostKey {
    fn algorithm_name(&self) -> &str { "ecdsa-sha2-nistp256" }
    fn key_type(&self) -> &str { "ecdsa-sha2-nistp256" }
    fn public_key_bytes(&self) -> Vec<u8> {
        let point = self.verifying_key.to_encoded_point(false);
        point.as_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        HostKeySigner::verify(self, data, signature)
    }
}

pub struct EcdsaP384HostKey {
    signing_key: p384::ecdsa::SigningKey,
    verifying_key: p384::ecdsa::VerifyingKey,
}

impl EcdsaP384HostKey {
    pub fn generate() -> Result<Self> {
        let signing_key = p384::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key().to_owned();
        Ok(EcdsaP384HostKey { signing_key, verifying_key })
    }

    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() != 48 {
            return Err(SshError::InvalidKey(format!(
                "ecdsa p384: secret must be 48 bytes, got {}", secret.len()
            )));
        }
        let signing_key = p384::ecdsa::SigningKey::from_slice(secret)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p384: {}", e)))?;
        let verifying_key = signing_key.verifying_key().to_owned();
        Ok(EcdsaP384HostKey { signing_key, verifying_key })
    }

    pub fn from_public_bytes(public: &[u8]) -> Result<Self> {
        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p384: {}", e)))?;
        let signing_key = p384::ecdsa::SigningKey::random(&mut OsRng);
        Ok(EcdsaP384HostKey { signing_key, verifying_key })
    }

    pub fn secret_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }
}

impl HostKeySigner for EcdsaP384HostKey {
    fn algorithm_name(&self) -> &str { "ecdsa-sha2-nistp384" }
    fn key_type(&self) -> &str { "ecdsa-sha2-nistp384" }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::new("ecdsa-sha2-nistp384").encode(&mut buf).unwrap();
        SshString::new("nistp384").encode(&mut buf).unwrap();
        let point = self.verifying_key.to_encoded_point(false);
        SshBytes(point.as_bytes().to_vec()).encode(&mut buf).unwrap();
        buf
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        // RFC 5656 §6.2.1: the hash is tied to the curve — nistp384 uses SHA-384.
        // Signing with SHA-256 produced a signature OpenSSH could never verify
        // (it always hashes with SHA-384 for this curve).
        use sha2::{Sha384, Digest};
        let mut hasher = Sha384::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let sig: p384::ecdsa::Signature = self.signing_key
            .sign_prehash(&hash)
            .map_err(|e| SshError::Protocol(format!("ecdsa p384 sign: {}", e)))?;
        Ok(encode_ecdsa_signature(
            "ecdsa-sha2-nistp384",
            &sig.to_bytes(),
            48,
        ))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let flat = decode_ecdsa_signature(signature, 48)?;
        let sig = p384::ecdsa::Signature::from_slice(&flat)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p384 sig: {}", e)))?;
        use sha2::{Sha384, Digest};
        let mut hasher = Sha384::new();
        hasher.update(data);
        let hash = hasher.finalize();
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        Ok(self.verifying_key.verify_prehash(&hash, &sig).is_ok())
    }

    fn clone_box(&self) -> Box<dyn HostKeySigner> {
        Box::new(EcdsaP384HostKey {
            signing_key: p384::ecdsa::SigningKey::from_bytes(&self.signing_key.to_bytes()).unwrap(),
            verifying_key: self.verifying_key.clone(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

impl HostKeyVerifier for EcdsaP384HostKey {
    fn algorithm_name(&self) -> &str { "ecdsa-sha2-nistp384" }
    fn key_type(&self) -> &str { "ecdsa-sha2-nistp384" }
    fn public_key_bytes(&self) -> Vec<u8> {
        let point = self.verifying_key.to_encoded_point(false);
        point.as_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        HostKeySigner::verify(self, data, signature)
    }
}

pub struct EcdsaP521HostKey {
    signing_key: p521::ecdsa::SigningKey,
    verifying_key: p521::ecdsa::VerifyingKey,
}

impl EcdsaP521HostKey {
    pub fn generate() -> Result<Self> {
        let signing_key = p521::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
        Ok(EcdsaP521HostKey { signing_key, verifying_key })
    }

    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() != 66 {
            return Err(SshError::InvalidKey(format!(
                "ecdsa p521: secret must be 66 bytes, got {}", secret.len()
            )));
        }
        let signing_key = p521::ecdsa::SigningKey::from_slice(secret)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p521: {}", e)))?;
        let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
        Ok(EcdsaP521HostKey { signing_key, verifying_key })
    }

    pub fn from_public_bytes(public: &[u8]) -> Result<Self> {
        let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(public)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p521: {}", e)))?;
        let signing_key = p521::ecdsa::SigningKey::random(&mut OsRng);
        Ok(EcdsaP521HostKey { signing_key, verifying_key })
    }

    pub fn secret_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }
}

impl HostKeySigner for EcdsaP521HostKey {
    fn algorithm_name(&self) -> &str { "ecdsa-sha2-nistp521" }
    fn key_type(&self) -> &str { "ecdsa-sha2-nistp521" }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::new("ecdsa-sha2-nistp521").encode(&mut buf).unwrap();
        SshString::new("nistp521").encode(&mut buf).unwrap();
        let point = self.verifying_key.to_encoded_point(false);
        SshBytes(point.as_bytes().to_vec()).encode(&mut buf).unwrap();
        buf
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use p521::ecdsa::signature::hazmat::PrehashSigner;
        // RFC 5656 §6.2.1: nistp521 is hashed with SHA-512, not SHA-256.
        use sha2::{Sha512, Digest};
        let mut hasher = Sha512::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let sig = self.signing_key
            .sign_prehash(&hash)
            .map_err(|e| SshError::Protocol(format!("ecdsa p521 sign: {}", e)))?;
        Ok(encode_ecdsa_signature(
            "ecdsa-sha2-nistp521",
            &sig.to_bytes(),
            66,
        ))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let flat = decode_ecdsa_signature(signature, 66)?;
        let sig = p521::ecdsa::Signature::from_slice(&flat)
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p521 sig: {}", e)))?;
        use sha2::{Sha512, Digest};
        let mut hasher = Sha512::new();
        hasher.update(data);
        let hash = hasher.finalize();
        use p521::ecdsa::signature::hazmat::PrehashVerifier;
        Ok(self.verifying_key.verify_prehash(&hash, &sig).is_ok())
    }

    fn clone_box(&self) -> Box<dyn HostKeySigner> {
        Box::new(EcdsaP521HostKey {
            signing_key: p521::ecdsa::SigningKey::from_bytes(&self.signing_key.to_bytes()).unwrap(),
            verifying_key: self.verifying_key.clone(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

impl HostKeyVerifier for EcdsaP521HostKey {
    fn algorithm_name(&self) -> &str { "ecdsa-sha2-nistp521" }
    fn key_type(&self) -> &str { "ecdsa-sha2-nistp521" }
    fn public_key_bytes(&self) -> Vec<u8> {
        let point = self.verifying_key.to_encoded_point(false);
        point.as_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        HostKeySigner::verify(self, data, signature)
    }
}

pub struct RsaHostKey {
    private_key: Option<RsaPrivateKey>,
    public_key: RsaPublicKey,
    bits: usize,
}

impl RsaHostKey {
    /// RSA modulus size in bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    pub fn generate(bits: usize) -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| SshError::InvalidKey(format!("RSA gen: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(RsaHostKey { private_key: Some(private_key), public_key, bits })
    }

    pub fn from_private_key(private_key: RsaPrivateKey, bits: usize) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        RsaHostKey { private_key: Some(private_key), public_key, bits }
    }

    pub fn new(private_key: Option<RsaPrivateKey>, public_key: RsaPublicKey, bits: usize) -> Self {
        RsaHostKey { private_key, public_key, bits }
    }

    pub fn from_public_bytes(public: &[u8]) -> Result<Self> {
        let mut r = &public[..];
        // RFC 4253 §6.6: the key blob after "ssh-rsa" is `mpint e`, then
        // `mpint n`. Getting these the wrong way around makes the modulus and
        // exponent swap, which no real peer can verify.
        let e_bytes = SshMpInt::decode(&mut r)?.0;
        let n_bytes = SshMpInt::decode(&mut r)?.0;
        let e = rsa::BigUint::from_bytes_be(&e_bytes);
        let n = rsa::BigUint::from_bytes_be(&n_bytes);
        let public_key = rsa::RsaPublicKey::new(n, e)
            .map_err(|e| SshError::InvalidKey(format!("RSA pubkey: {}", e)))?;
        let bits = public_key.size() * 8;
        Ok(RsaHostKey { private_key: None, public_key, bits })
    }
}

impl HostKeySigner for RsaHostKey {
    fn algorithm_name(&self) -> &str { "rsa-sha2-256" }
    fn key_type(&self) -> &str { "ssh-rsa" }

    fn supports(&self, algorithm: &str) -> bool {
        matches!(algorithm, "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa")
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::new("ssh-rsa").encode(&mut buf).unwrap();

        // RFC 4253 §6.6: `mpint e` first, then `mpint n`.
        let e = self.public_key.e().to_bytes_be();
        let n = self.public_key.n().to_bytes_be();
        SshMpInt(e).encode(&mut buf).unwrap();
        SshMpInt(n).encode(&mut buf).unwrap();
        buf
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign_with("rsa-sha2-256", data)
    }

    fn sign_with(&self, algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
        match algorithm {
            "rsa-sha2-512" => {
                let priv_key = self.private_key.as_ref()
                    .ok_or_else(|| SshError::InvalidKey("no private key for signing".into()))?;
                let signing_key = RsaSigningKey::<Sha512>::new(priv_key.clone());
                let sig = signing_key.sign_with_rng(&mut OsRng, data);
                let mut buf = Vec::new();
                SshString::new("rsa-sha2-512").encode(&mut buf).unwrap();
                SshBytes(sig.to_vec()).encode(&mut buf).unwrap();
                Ok(buf)
            }
            "rsa-sha2-256" => {
                let priv_key = self.private_key.as_ref()
                    .ok_or_else(|| SshError::InvalidKey("no private key for signing".into()))?;
                let signing_key = RsaSigningKey::<Sha256>::new(priv_key.clone());
                let sig = signing_key.sign_with_rng(&mut OsRng, data);
                let mut buf = Vec::new();
                SshString::new("rsa-sha2-256").encode(&mut buf).unwrap();
                SshBytes(sig.to_vec()).encode(&mut buf).unwrap();
                Ok(buf)
            }
            "ssh-rsa" => {
                let priv_key = self.private_key.as_ref()
                    .ok_or_else(|| SshError::InvalidKey("no private key for signing".into()))?;
                let signing_key = RsaSigningKey::<Sha1>::new(priv_key.clone());
                let sig = signing_key.sign_with_rng(&mut OsRng, data);
                let mut buf = Vec::new();
                SshString::new("ssh-rsa").encode(&mut buf).unwrap();
                SshBytes(sig.to_vec()).encode(&mut buf).unwrap();
                Ok(buf)
            }
            other => Err(SshError::Protocol(format!("unsupported RSA hostkey algorithm: {}", other))),
        }
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut r = &signature[..];
        let sig_type = SshString::decode(&mut r)?.0;
        let sig_type_str = String::from_utf8_lossy(&sig_type).to_string();
        let _sig_bytes = SshBytes::decode(&mut r)?.0;
        self.verify_with(&sig_type_str, data, signature)
    }

    fn clone_box(&self) -> Box<dyn HostKeySigner> {
        match self.private_key {
            Some(ref sk) => {
                use rsa::pkcs8::EncodePrivateKey;
                use rsa::pkcs8::DecodePrivateKey;
                match sk.to_pkcs8_der() {
                    Ok(doc) => {
                        match RsaPrivateKey::from_pkcs8_der(doc.as_bytes()) {
                            Ok(priv_key) => {
                                let pub_key = RsaPublicKey::from(&priv_key);
                                Box::new(RsaHostKey {
                                    private_key: Some(priv_key),
                                    public_key: pub_key,
                                    bits: self.bits,
                                })
                            }
                            Err(_) => {
                                Box::new(RsaHostKey {
                                    private_key: None,
                                    public_key: self.public_key.clone(),
                                    bits: self.bits,
                                })
                            }
                        }
                    }
                    Err(_) => {
                        Box::new(RsaHostKey {
                            private_key: None,
                            public_key: self.public_key.clone(),
                            bits: self.bits,
                        })
                    }
                }
            }
            None => {
                Box::new(RsaHostKey {
                    private_key: None,
                    public_key: self.public_key.clone(),
                    bits: self.bits,
                })
            }
        }
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

impl HostKeyVerifier for RsaHostKey {
    fn algorithm_name(&self) -> &str { "rsa-sha2-256" }
    fn key_type(&self) -> &str { "ssh-rsa" }
    fn public_key_bytes(&self) -> Vec<u8> {
        let e = self.public_key.e().to_bytes_be();
        let n = self.public_key.n().to_bytes_be();
        let mut buf = Vec::new();
        SshMpInt(e).encode(&mut buf).unwrap();
        SshMpInt(n).encode(&mut buf).unwrap();
        buf
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        HostKeySigner::verify(self, data, signature)
    }

    fn verify_with(&self, algorithm: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut r = &signature[..];
        let _sig_type = SshString::decode(&mut r)?;
        let sig_bytes = SshBytes::decode(&mut r)?.0;
        match algorithm {
            "rsa-sha2-512" => {
                let verifying_key = RsaVerifyingKey::<Sha512>::new(self.public_key.clone());
                let sig = RsaSignature::try_from(sig_bytes.as_slice())
                    .map_err(|e| SshError::InvalidKey(format!("RSA sig: {}", e)))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            "rsa-sha2-256" => {
                let verifying_key = RsaVerifyingKey::<Sha256>::new(self.public_key.clone());
                let sig = RsaSignature::try_from(sig_bytes.as_slice())
                    .map_err(|e| SshError::InvalidKey(format!("RSA sig: {}", e)))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            "ssh-rsa" => {
                let verifying_key = RsaVerifyingKey::<Sha1>::new(self.public_key.clone());
                let sig = RsaSignature::try_from(sig_bytes.as_slice())
                    .map_err(|e| SshError::InvalidKey(format!("RSA sig: {}", e)))?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            other => Err(SshError::Protocol(format!("unsupported RSA verify algorithm: {}", other))),
        }
    }
}

/// OpenSSH FIDO2 security-key host key (`sk-ssh-ed25519@openssh.com`,
/// `sk-ecdsa-sha2-nistp256@openssh.com`).
///
/// The public-key blob is
///   `string key_type || string underlying_type || string pk || string application`
/// where `pk` is the ordinary ed25519/ecdsa public key the FIDO2 authenticator
/// attests. Signatures are ordinary ed25519/ecdsa signatures over the data,
/// wrapped as `string key_type || string signature`; verification therefore
/// reduces to verifying with the underlying plain key. Hardware signing is
/// done by the authenticator and is out of scope here (no FIDO2 transport),
/// so only the verifier half is implemented.
pub struct SkHostKey {
    key_type: String,
    underlying: String,
    pk: Vec<u8>,
    /// The full public-key blob (`string key_type || ... || string application`).
    blob: Vec<u8>,
}

impl SkHostKey {
    /// Parse an SK public-key blob (the `string key_type || ...` layout).
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        let mut r = blob;
        let key_type = SshString::decode(&mut r)?.as_str()?.to_string();
        if key_type != "sk-ssh-ed25519@openssh.com"
            && key_type != "sk-ecdsa-sha2-nistp256@openssh.com"
        {
            return Err(SshError::InvalidKey(format!("not an SK key: {}", key_type)));
        }
        let underlying = SshString::decode(&mut r)?.as_str()?.to_string();
        // `pk` for ed25519 is a raw 32-byte string; for ecdsa it is
        // `string curve_name || string Q`. Keep the trailing `application`
        // string after `pk`.
        let pk = if underlying == "ssh-ed25519" {
            SshBytes::decode(&mut r)?.0
        } else if underlying.starts_with("ecdsa-sha2-nistp") {
            let _curve = SshString::decode(&mut r)?;
            SshBytes::decode(&mut r)?.0
        } else {
            return Err(SshError::InvalidKey(format!("unsupported SK underlying type: {}", underlying)));
        };
        Ok(SkHostKey {
            key_type,
            underlying,
            pk,
            blob: blob.to_vec(),
        })
    }

    /// The plain key type this SK key wraps (`ssh-ed25519`, `ecdsa-sha2-nistp256`).
    pub fn underlying_type(&self) -> &str {
        &self.underlying
    }
}

impl HostKeyVerifier for SkHostKey {
    fn algorithm_name(&self) -> &str {
        &self.key_type
    }

    fn key_type(&self) -> &str {
        &self.key_type
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.pk.clone()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        // The SK signature blob is `string key_type || string signature`; the
        // inner signature is a plain ed25519/ecdsa signature over `data`.
        let mut r = signature;
        let _sig_type = SshString::decode(&mut r)?;
        let inner = SshBytes::decode(&mut r)?.0;
        match self.underlying.as_str() {
            "ssh-ed25519" => {
                let pk: [u8; 32] = self.pk.as_slice().try_into()
                    .map_err(|_| SshError::InvalidKey("SK ed25519 pubkey length".into()))?;
                let verifying = VerifyingKey::from_bytes(&pk)
                    .map_err(|e| SshError::InvalidKey(format!("SK ed25519 pubkey: {}", e)))?;
                let sig = Signature::from_slice(&inner)
                    .map_err(|e| SshError::InvalidKey(format!("SK ed25519 sig: {}", e)))?;
                Ok(verifying.verify(data, &sig).is_ok())
            }
            "ecdsa-sha2-nistp256" => {
                // `inner` is the SSH ECDSA signature layout (`string r, string s`).
                let flat = decode_ecdsa_signature(&inner, 32)?;
                let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.pk)
                    .map_err(|e| SshError::InvalidKey(format!("SK ecdsa pubkey: {}", e)))?;
                let sig = p256::ecdsa::Signature::from_slice(&flat)
                    .map_err(|e| SshError::InvalidKey(format!("SK ecdsa sig: {}", e)))?;
                use p256::ecdsa::signature::Verifier as _;
                Ok(verifying.verify(data, &sig).is_ok())
            }
            other => Err(SshError::InvalidKey(format!(
                "unsupported SK underlying type for verify: {}",
                other
            ))),
        }
    }
}

impl HostKeySigner for SkHostKey {
    fn algorithm_name(&self) -> &str {
        &self.key_type
    }

    fn key_type(&self) -> &str {
        &self.key_type
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.blob.clone()
    }

    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Err(SshError::InvalidKey(
            "SK signing requires a FIDO2 authenticator, which is not wired up".into(),
        ))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        HostKeyVerifier::verify(self, data, signature)
    }

    fn clone_box(&self) -> Box<dyn HostKeySigner> {
        Box::new(SkHostKey {
            key_type: self.key_type.clone(),
            underlying: self.underlying.clone(),
            pk: self.pk.clone(),
            blob: self.blob.clone(),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub fn get_supported_host_key_algorithms() -> Vec<&'static str> {
    vec![
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-rsa",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flatten the OpenSSH `string type, string (string r || string s)` layout
    /// back to `r || s` for direct curve-crate verification.
    fn ssh_sig_bytes(blob: &[u8]) -> Vec<u8> {
        let mut r: &[u8] = blob;
        let ty = SshString::decode(&mut r).unwrap();
        let field_len = match ty.0.as_slice() {
            b"ecdsa-sha2-nistp256" => 32,
            b"ecdsa-sha2-nistp384" => 48,
            b"ecdsa-sha2-nistp521" => 66,
            other => panic!("unexpected ecdsa type {:?}", other),
        };
        let inner = SshBytes::decode(&mut r).unwrap().0;
        let mut ir: &[u8] = &inner;
        let mut out = Vec::with_capacity(field_len * 2);
        for _ in 0..2 {
            let v = SshString::decode(&mut ir).unwrap().0;
            let first = v.iter().position(|&b| b != 0).unwrap_or(v.len());
            out.extend(std::iter::repeat_n(0u8, field_len - (v.len() - first)));
            out.extend_from_slice(&v[first..]);
        }
        out
    }

    /// OpenSSH encodes r and s as two separate SSH strings. A flat 64-byte
    /// signature blob is self-consistent but never accepted by OpenSSH; guard
    /// the wire shape so that regression cannot silently return.
    #[test]
    fn ecdsa_signature_uses_two_string_components() {
        let key = EcdsaP256HostKey::generate().unwrap();
        let blob = key.sign(b"data").unwrap();
        let mut r: &[u8] = &blob;
        let ty = SshString::decode(&mut r).unwrap();
        assert_eq!(ty.0, b"ecdsa-sha2-nistp256");
        let inner = SshBytes::decode(&mut r).unwrap().0;
        // r and s are 32-byte mpints; each may grow to 33 bytes when the top
        // bit is set and needs a positive sign byte.
        assert!(
            (72..=74).contains(&inner.len()),
            "signature must be string r + string s, got {} bytes",
            inner.len()
        );
        assert_eq!(ssh_sig_bytes(&blob).len(), 64);
        assert!(r.is_empty());
    }

    /// RFC 5656 §6.2.1: nistp384 hashes with SHA-384. A round-trip through our
    /// own sign/verify would not catch a wrong hash (both sides would agree),
    /// so pin the digest explicitly against the verifying key.
    #[test]
    fn ecdsa_p384_signature_uses_sha384() {
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        use sha2::{Digest, Sha256, Sha384};
        let key = EcdsaP384HostKey::generate().unwrap();
        let data = b"kex exchange hash";
        let sig = ssh_sig_bytes(&key.sign(data).unwrap());

        let good = Sha384::digest(data);
        let parsed = p384::ecdsa::Signature::from_slice(&sig).unwrap();
        assert!(key.verifying_key.verify_prehash(&good, &parsed).is_ok());

        let wrong = Sha256::digest(data);
        assert!(key.verifying_key.verify_prehash(&wrong, &parsed).is_err());
    }

    #[test]
    fn ecdsa_p521_signature_uses_sha512() {
        use p521::ecdsa::signature::hazmat::PrehashVerifier;
        use sha2::{Digest, Sha256, Sha512};
        let key = EcdsaP521HostKey::generate().unwrap();
        let data = b"kex exchange hash";
        let sig = ssh_sig_bytes(&key.sign(data).unwrap());

        let good = Sha512::digest(data);
        let parsed = p521::ecdsa::Signature::from_slice(&sig).unwrap();
        assert!(key.verifying_key.verify_prehash(&good, &parsed).is_ok());

        let wrong = Sha256::digest(data);
        assert!(key.verifying_key.verify_prehash(&wrong, &parsed).is_err());
    }

    /// An SK host key's public blob embeds the underlying plain key; the
    /// verifier must recover it and verify a plain ed25519 signature wrapped
    /// in the SK signature layout.
    #[test]
    fn sk_ed25519_host_key_parses_and_verifies() {
        let base = Ed25519HostKey::generate().unwrap();
        let pk = HostKeySigner::public_key_bytes(&base);
        // `pk` from public_key_bytes() is `string "ssh-ed25519" || string pk`.
        let mut r: &[u8] = &pk;
        let _ty = SshString::decode(&mut r).unwrap();
        let raw_pk = SshBytes::decode(&mut r).unwrap().0;

        let mut blob = Vec::new();
        SshString::new("sk-ssh-ed25519@openssh.com").encode(&mut blob).unwrap();
        SshString::new("ssh-ed25519").encode(&mut blob).unwrap();
        SshBytes(raw_pk.clone()).encode(&mut blob).unwrap();
        SshString::new("ssh:").encode(&mut blob).unwrap();

        let sk = SkHostKey::from_blob(&blob).unwrap();
        assert_eq!(HostKeySigner::key_type(&sk), "sk-ssh-ed25519@openssh.com");
        assert_eq!(sk.underlying_type(), "ssh-ed25519");
        // HostKeyVerifier::public_key_bytes returns the underlying plain key.
        assert_eq!(HostKeyVerifier::public_key_bytes(&sk), raw_pk);

        // Sign with the underlying software key and wrap in the SK layout.
        let data = b"kex exchange hash";
        let plain_sig = base.sign(data).unwrap();
        let mut r: &[u8] = &plain_sig;
        let _ty = SshString::decode(&mut r).unwrap();
        let raw_sig = SshBytes::decode(&mut r).unwrap().0;
        let mut sk_sig = Vec::new();
        SshString::new("sk-ssh-ed25519@openssh.com").encode(&mut sk_sig).unwrap();
        SshBytes(raw_sig).encode(&mut sk_sig).unwrap();

        assert!(HostKeyVerifier::verify(&sk, data, &sk_sig).unwrap());
        assert!(!HostKeyVerifier::verify(&sk, b"tampered", &sk_sig).unwrap());
    }
}
