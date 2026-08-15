use crate::error::{Result, SshError};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
use chacha20poly1305::aead::Aead;
use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use aes::cipher::{StreamCipher, KeyIvInit};

pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;
pub const CHACHA20_POLY1305_IV_LEN: usize = 12;
pub const CHACHA20_POLY1305_TAG_LEN: usize = 16;

pub const AES128_CTR_KEY_LEN: usize = 16;
pub const AES128_CTR_IV_LEN: usize = 16;
pub const AES192_CTR_KEY_LEN: usize = 24;
pub const AES192_CTR_IV_LEN: usize = 16;
pub const AES256_CTR_KEY_LEN: usize = 32;
pub const AES256_CTR_IV_LEN: usize = 16;

pub const AES128_GCM_KEY_LEN: usize = 16;
pub const AES128_GCM_IV_LEN: usize = 12;
pub const AES128_GCM_TAG_LEN: usize = 16;
pub const AES256_GCM_KEY_LEN: usize = 32;
pub const AES256_GCM_IV_LEN: usize = 12;
pub const AES256_GCM_TAG_LEN: usize = 16;

pub trait SshCipher: Send + Sync {
    fn name(&self) -> &str;
    fn key_len(&self) -> usize;
    fn iv_len(&self) -> usize;
    fn block_size(&self) -> usize;
    fn tag_len(&self) -> usize;
    fn set_key(&mut self, key: &[u8]) -> Result<()>;
    fn set_iv(&mut self, iv: &[u8]) -> Result<()>;
    fn encrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>>;
    fn is_aead(&self) -> bool;
}

pub struct ChaCha20Poly1305Cipher {
    key: [u8; 32],
    initialized: bool,
}

impl ChaCha20Poly1305Cipher {
    pub fn new() -> Self {
        ChaCha20Poly1305Cipher {
            key: [0u8; 32],
            initialized: false,
        }
    }

    pub fn kex_name() -> &'static str {
        "chacha20-poly1305@openssh.com"
    }

    fn compute_nonce(seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&seq.to_be_bytes());
        nonce
    }
}

impl SshCipher for ChaCha20Poly1305Cipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { CHACHA20_POLY1305_KEY_LEN }
    fn iv_len(&self) -> usize { CHACHA20_POLY1305_IV_LEN }
    fn block_size(&self) -> usize { 8 }
    fn tag_len(&self) -> usize { CHACHA20_POLY1305_TAG_LEN }
    fn is_aead(&self) -> bool { true }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != CHACHA20_POLY1305_KEY_LEN {
            return Err(SshError::InvalidKey("wrong key length for chacha20-poly1305".into()));
        }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }

    fn set_iv(&mut self, _iv: &[u8]) -> Result<()> {
        Ok(())
    }

    fn encrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized {
            return Err(SshError::Protocol("cipher not initialized".into()));
        }
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let nonce = Self::compute_nonce(seq);
        let ciphertext = cipher.encrypt(&nonce.into(), data)
            .map_err(|e| SshError::Protocol(format!("encrypt error: {}", e)))?;
        Ok(ciphertext)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized {
            return Err(SshError::Protocol("cipher not initialized".into()));
        }
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let nonce = Self::compute_nonce(seq);
        let plaintext = cipher.decrypt(&nonce.into(), data)
            .map_err(|_| SshError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

pub struct Aes128CtrCipher {
    key: [u8; 16],
    iv: [u8; 16],
    initialized: bool,
}

impl Aes128CtrCipher {
    pub fn new() -> Self {
        Aes128CtrCipher {
            key: [0u8; 16],
            iv: [0u8; 16],
            initialized: false,
        }
    }

    pub fn kex_name() -> &'static str {
        "aes128-ctr"
    }
}

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

impl SshCipher for Aes128CtrCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES128_CTR_KEY_LEN }
    fn iv_len(&self) -> usize { AES128_CTR_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 0 }
    fn is_aead(&self) -> bool { false }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES128_CTR_KEY_LEN {
            return Err(SshError::InvalidKey("wrong key length for aes128-ctr".into()));
        }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }

    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES128_CTR_IV_LEN {
            return Err(SshError::InvalidKey("wrong IV length for aes128-ctr".into()));
        }
        self.iv.copy_from_slice(iv);
        Ok(())
    }

    fn encrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized {
            return Err(SshError::Protocol("cipher not initialized".into()));
        }
        let mut output = data.to_vec();
        let mut cipher = Aes128Ctr::new(&self.key.into(), &self.iv.into());
        cipher.apply_keystream(&mut output);

        let block_count = data.len() / 16;
        let mut carry = block_count as u16;
        for i in (0..self.iv.len()).rev() {
            carry += self.iv[i] as u16;
            self.iv[i] = (carry & 0xff) as u8;
            carry >>= 8;
            if carry == 0 { break; }
        }

        Ok(output)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(seq, data)
    }
}

pub struct Aes192CtrCipher {
    key: [u8; 24],
    iv: [u8; 16],
    initialized: bool,
}

impl Aes192CtrCipher {
    pub fn new() -> Self {
        Aes192CtrCipher {
            key: [0u8; 24],
            iv: [0u8; 16],
            initialized: false,
        }
    }
    pub fn kex_name() -> &'static str { "aes192-ctr" }
}

type Aes192Ctr = ctr::Ctr128BE<Aes192>;

impl SshCipher for Aes192CtrCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES192_CTR_KEY_LEN }
    fn iv_len(&self) -> usize { AES192_CTR_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 0 }
    fn is_aead(&self) -> bool { false }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES192_CTR_KEY_LEN {
            return Err(SshError::InvalidKey("wrong key length".into()));
        }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }

    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES192_CTR_IV_LEN {
            return Err(SshError::InvalidKey("wrong IV length".into()));
        }
        self.iv.copy_from_slice(iv);
        Ok(())
    }

    fn encrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        let mut output = data.to_vec();
        let mut cipher = Aes192Ctr::new(&self.key.into(), &self.iv.into());
        cipher.apply_keystream(&mut output);
        let block_count = data.len() / 16;
        let mut carry = block_count as u16;
        for i in (0..self.iv.len()).rev() {
            carry += self.iv[i] as u16;
            self.iv[i] = (carry & 0xff) as u8;
            carry >>= 8;
            if carry == 0 { break; }
        }
        Ok(output)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(seq, data)
    }
}

pub struct Aes256CtrCipher {
    key: [u8; 32],
    iv: [u8; 16],
    initialized: bool,
}

impl Aes256CtrCipher {
    pub fn new() -> Self {
        Aes256CtrCipher {
            key: [0u8; 32],
            iv: [0u8; 16],
            initialized: false,
        }
    }
    pub fn kex_name() -> &'static str { "aes256-ctr" }
}

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

impl SshCipher for Aes256CtrCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES256_CTR_KEY_LEN }
    fn iv_len(&self) -> usize { AES256_CTR_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 0 }
    fn is_aead(&self) -> bool { false }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES256_CTR_KEY_LEN {
            return Err(SshError::InvalidKey("wrong key length".into()));
        }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }

    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES256_CTR_IV_LEN {
            return Err(SshError::InvalidKey("wrong IV length".into()));
        }
        self.iv.copy_from_slice(iv);
        Ok(())
    }

    fn encrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        let mut output = data.to_vec();
        let mut cipher = Aes256Ctr::new(&self.key.into(), &self.iv.into());
        cipher.apply_keystream(&mut output);
        let block_count = data.len() / 16;
        let mut carry = block_count as u16;
        for i in (0..self.iv.len()).rev() {
            carry += self.iv[i] as u16;
            self.iv[i] = (carry & 0xff) as u8;
            carry >>= 8;
            if carry == 0 { break; }
        }
        Ok(output)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(seq, data)
    }
}

pub struct Aes128GcmCipher {
    key: [u8; 16],
    initialized: bool,
}

impl Aes128GcmCipher {
    pub fn new() -> Self { Aes128GcmCipher { key: [0u8; 16], initialized: false } }
    pub fn kex_name() -> &'static str { "aes128-gcm@openssh.com" }
}

impl SshCipher for Aes128GcmCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES128_GCM_KEY_LEN }
    fn iv_len(&self) -> usize { AES128_GCM_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { AES128_GCM_TAG_LEN }
    fn is_aead(&self) -> bool { true }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES128_GCM_KEY_LEN {
            return Err(SshError::InvalidKey("wrong key length".into()));
        }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }

    fn set_iv(&mut self, _iv: &[u8]) -> Result<()> { Ok(()) }

    fn encrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        let cipher = AesGcm::<aes_gcm::aes::Aes128, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&seq.to_be_bytes());
        let ciphertext = cipher.encrypt(&nonce.into(), data)
            .map_err(|e| SshError::Protocol(format!("encrypt error: {}", e)))?;
        Ok(ciphertext)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        let cipher = AesGcm::<aes_gcm::aes::Aes128, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&seq.to_be_bytes());
        let plaintext = cipher.decrypt(&nonce.into(), data)
            .map_err(|_| SshError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

pub struct Aes256GcmCipher {
    key: [u8; 32],
    initialized: bool,
}

impl Aes256GcmCipher {
    pub fn new() -> Self { Aes256GcmCipher { key: [0u8; 32], initialized: false } }
    pub fn kex_name() -> &'static str { "aes256-gcm@openssh.com" }
}

impl SshCipher for Aes256GcmCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES256_GCM_KEY_LEN }
    fn iv_len(&self) -> usize { AES256_GCM_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { AES256_GCM_TAG_LEN }
    fn is_aead(&self) -> bool { true }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES256_GCM_KEY_LEN {
            return Err(SshError::InvalidKey("wrong key length".into()));
        }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }

    fn set_iv(&mut self, _iv: &[u8]) -> Result<()> { Ok(()) }

    fn encrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        let cipher = AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&seq.to_be_bytes());
        let ciphertext = cipher.encrypt(&nonce.into(), data)
            .map_err(|e| SshError::Protocol(format!("encrypt error: {}", e)))?;
        Ok(ciphertext)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        let cipher = AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&seq.to_be_bytes());
        let plaintext = cipher.decrypt(&nonce.into(), data)
            .map_err(|_| SshError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

pub fn create_cipher(name: &str) -> Result<Box<dyn SshCipher>> {
    match name {
        "chacha20-poly1305@openssh.com" => Ok(Box::new(ChaCha20Poly1305Cipher::new())),
        "aes128-ctr" => Ok(Box::new(Aes128CtrCipher::new())),
        "aes192-ctr" => Ok(Box::new(Aes192CtrCipher::new())),
        "aes256-ctr" => Ok(Box::new(Aes256CtrCipher::new())),
        "aes128-gcm@openssh.com" => Ok(Box::new(Aes128GcmCipher::new())),
        "aes256-gcm@openssh.com" => Ok(Box::new(Aes256GcmCipher::new())),
        _ => Err(SshError::UnsupportedAlgorithm(format!("cipher: {}", name))),
    }
}

pub fn get_supported_ciphers() -> Vec<&'static str> {
    vec![
        "chacha20-poly1305@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
    ]
}
