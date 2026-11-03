use crate::error::{Result, SshError};
use crate::encoding::*;
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::pkcs1v15::Signature as RsaSignature;
use rsa::traits::PublicKeyParts;
use rsa::signature::{RandomizedSigner, Verifier as RsaVerifier, SignatureEncoding};
use sha2::{Sha256, Sha512};
use sha1::Sha1;
use rand::rngs::OsRng;
use std::io::Write;

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
        let signing_key = p256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|e| SshError::InvalidKey(format!("ecdsa p256: {}", e)))?;
        let verifying_key = signing_key.verifying_key().to_owned();
        Ok(EcdsaP256HostKey { signing_key, verifying_key })
    }

    pub fn from_public_bytes(public: &[u8]) -> Result<Self> {
        let point = p256::EncodedPoint::from_bytes(public)
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
        let mut buf = Vec::new();
        SshString::new("ecdsa-sha2-nistp256").encode(&mut buf).unwrap();
        SshBytes(sig.to_bytes().to_vec()).encode(&mut buf).unwrap();
        Ok(buf)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut r = &signature[..];
        let _sig_type = SshString::decode(&mut r)?;
        let sig_bytes = SshBytes::decode(&mut r)?;
        let sig = p256::ecdsa::Signature::from_slice(&sig_bytes.0)
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
        let signing_key = p384::ecdsa::SigningKey::from_bytes(secret.into())
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
        let mut buf = Vec::new();
        SshString::new("ecdsa-sha2-nistp384").encode(&mut buf).unwrap();
        SshBytes(sig.to_bytes().to_vec()).encode(&mut buf).unwrap();
        Ok(buf)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut r = &signature[..];
        let _sig_type = SshString::decode(&mut r)?;
        let sig_bytes = SshBytes::decode(&mut r)?;
        let sig = p384::ecdsa::Signature::from_slice(&sig_bytes.0)
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
        let signing_key = p521::ecdsa::SigningKey::from_bytes(secret.into())
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
        let mut buf = Vec::new();
        SshString::new("ecdsa-sha2-nistp521").encode(&mut buf).unwrap();
        SshBytes(sig.to_bytes().to_vec()).encode(&mut buf).unwrap();
        Ok(buf)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut r = &signature[..];
        let _sig_type = SshString::decode(&mut r)?;
        let sig_bytes = SshBytes::decode(&mut r)?;
        let sig = p521::ecdsa::Signature::from_slice(&sig_bytes.0)
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
        let n_bytes = SshBytes::decode(&mut r)?.0;
        let e_bytes = SshBytes::decode(&mut r)?.0;
        let n = rsa::BigUint::from_bytes_be(&n_bytes);
        let e = rsa::BigUint::from_bytes_be(&e_bytes);
        let public_key = rsa::RsaPublicKey::new(n, e)
            .map_err(|e| SshError::InvalidKey(format!("RSA pubkey: {}", e)))?;
        let bits = public_key.size();
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

        let n = self.public_key.n().to_bytes_be();
        let e = self.public_key.e().to_bytes_be();
        SshBytes(n).encode(&mut buf).unwrap();
        SshBytes(e).encode(&mut buf).unwrap();
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
        let sig_bytes = SshBytes::decode(&mut r)?.0;
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
        let n = self.public_key.n().to_bytes_be();
        let e = self.public_key.e().to_bytes_be();
        let mut buf = Vec::new();
        SshBytes(n).encode(&mut buf).unwrap();
        SshBytes(e).encode(&mut buf).unwrap();
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

pub fn get_supported_host_key_algorithms() -> Vec<&'static str> {
    vec![
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-rsa",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strip the `string keytype` prefix from an SSH signature blob.
    fn ssh_sig_bytes(blob: &[u8]) -> Vec<u8> {
        let mut r: &[u8] = blob;
        let _ = SshString::decode(&mut r).unwrap();
        SshBytes::decode(&mut r).unwrap().0
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
}
