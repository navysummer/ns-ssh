use crate::error::{Result, SshError};
use chacha20poly1305::aead::Aead;
use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use cipher::{
    StreamCipher, KeyIvInit,
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use chacha20::ChaCha20Legacy;
use chacha20::cipher::StreamCipherSeek as ChaChaStreamCipherSeek;
use poly1305::Poly1305;

// OpenSSH chacha20-poly1305 uses a 64-byte key: a 32-byte main key and a
// 32-byte header key (OpenSSH cipher-chachapoly.c: keylen == 32+32).
pub const CHACHA20_POLY1305_KEY_LEN: usize = 64;
pub const CHACHA20_POLY1305_IV_LEN: usize = 0;
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

/// RFC 8439 Poly1305 MAC over `data` with `key`, using OpenSSH's padding
/// convention (poly1305.c): full 16-byte blocks are processed as-is; a
/// non-empty tail is padded with `0x01` then zeros to fill the block.
/// This matches the `poly1305` crate's `compute_unpadded` (used by
/// XSalsa20Poly1305), which is exactly OpenSSH's poly1305_auth.
fn poly1305_rfc8439(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mac = Poly1305::new(GenericArray::from_slice(key));
    let tag = mac.compute_unpadded(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

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
    /// AEAD encrypt with associated data. OpenSSH's AES-GCM authenticates the
    /// cleartext 4-byte packet_length as AAD, so the cipher must see it even
    /// though it is not encrypted. Ciphers without AAD ignore `aad`.
    fn encrypt_with_aad(&mut self, seq: u64, _aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(seq, data)
    }
    /// AEAD decrypt with associated data; `data` is ciphertext || tag.
    fn decrypt_with_aad(&mut self, seq: u64, _aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.decrypt(seq, data)
    }
    fn is_aead(&self) -> bool;
    /// True for OpenSSH's chacha20-poly1305@openssh.com, which encrypts the
    /// 4-byte packet_length field (with a separate header key) rather than
    /// leaving it in the clear like other AEAD ciphers.
    fn is_chachapoly(&self) -> bool { false }
    /// Decrypt just the 4-byte packet_length field. For chacha20-poly1305 this
    /// uses the header key; for everything else the length is plaintext.
    fn decrypt_length(&self, _seq: u64, len_bytes: &[u8]) -> Result<u32> {
        if len_bytes.len() < 4 {
            return Err(SshError::InvalidPacket("short length".into()));
        }
        Ok(u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]))
    }
}

pub struct ChaCha20Poly1305Cipher {
    key: [u8; 64],
    initialized: bool,
}

impl ChaCha20Poly1305Cipher {
    pub fn new() -> Self {
        ChaCha20Poly1305Cipher {
            key: [0u8; 64],
            initialized: false,
        }
    }

    pub fn kex_name() -> &'static str {
        "chacha20-poly1305@openssh.com"
    }

    /// OpenSSH chacha20-poly1305@openssh.com construction (cipher-chachapoly.c).
    ///
    /// The 4-byte packet_length field is encrypted with the *header* key using
    /// the legacy ChaCha20 stream (64-bit nonce = big-endian sequence number,
    /// block counter 0). The body is encrypted with the *main* key using the
    /// same nonce and block counter 1. The Poly1305 tag covers the whole
    /// ciphertext (encrypted packet_length || encrypted body) and is appended.
    ///
    /// `data` is the full plaintext packet (packet_length || padding_len ||
    /// payload || padding). Returns the full wire packet (ciphertext || tag).
    fn crypt(&self, seq: u64, data: &[u8], do_encrypt: bool) -> Result<Vec<u8>> {
        if !self.initialized {
            return Err(SshError::Protocol("cipher not initialized".into()));
        }
        if data.len() < 4 {
            return Err(SshError::Protocol("chacha packet too short".into()));
        }

        let main_key = &self.key[..32];
        let header_key = &self.key[32..];

        let seqbuf: [u8; 8] = seq.to_be_bytes();
        let nonce = GenericArray::from_slice(&seqbuf);

        // Derive the Poly1305 key: ChaCha20(main_key, nonce=seq, counter=0)
        // applied to 32 zero bytes (OpenSSH chachapoly_crypt).
        let mut poly_key = [0u8; 32];
        let mut poly_cipher = ChaCha20Legacy::new(GenericArray::from_slice(main_key), nonce);
        poly_cipher.apply_keystream(&mut poly_key);

        // For decryption, split off the trailing tag and verify it over the
        // ciphertext before doing anything else (OpenSSH chachapoly_crypt).
        let (payload, tag): (&[u8], Option<&[u8]>) = if do_encrypt {
            (data, None)
        } else {
            if data.len() < CHACHA20_POLY1305_TAG_LEN {
                return Err(SshError::DecryptionFailed);
            }
            let (ct, tag_got) = data.split_at(data.len() - CHACHA20_POLY1305_TAG_LEN);
            let expected = poly1305_rfc8439(&poly_key, ct);
            if expected.as_slice() != tag_got {
                return Err(SshError::DecryptionFailed);
            }
            (ct, Some(tag_got))
        };

        let mut out = vec![0u8; payload.len()];

        // Encrypt/decrypt the 4-byte packet_length with the header key
        // (block counter 0).
        let mut header_cipher = ChaCha20Legacy::new(GenericArray::from_slice(header_key), nonce);
        let mut header_ks = [0u8; 4];
        header_cipher.apply_keystream(&mut header_ks);
        for i in 0..4 {
            out[i] = payload[i] ^ header_ks[i];
        }

        // Encrypt/decrypt the body with the main key (block counter 1).
        if payload.len() > 4 {
            let mut body_cipher = ChaCha20Legacy::new(GenericArray::from_slice(main_key), nonce);
            body_cipher.seek(64); // one 64-byte block => counter 1
            let mut body = payload[4..].to_vec();
            body_cipher.apply_keystream(&mut body);
            out[4..].copy_from_slice(&body);
        }

        if do_encrypt {
            // Append the Poly1305 tag over the whole ciphertext.
            let tag = poly1305_rfc8439(&poly_key, &out);
            out.extend_from_slice(&tag);
            Ok(out)
        } else {
            debug_assert!(tag.is_some());
            Ok(out)
        }
    }
}

impl SshCipher for ChaCha20Poly1305Cipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { CHACHA20_POLY1305_KEY_LEN }
    fn iv_len(&self) -> usize { CHACHA20_POLY1305_IV_LEN }
    fn block_size(&self) -> usize { 8 }
    fn tag_len(&self) -> usize { CHACHA20_POLY1305_TAG_LEN }
    fn is_aead(&self) -> bool { true }
    fn is_chachapoly(&self) -> bool { true }

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
        self.crypt(seq, data, true)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.crypt(seq, data, false)
    }

    fn decrypt_length(&self, seq: u64, len_bytes: &[u8]) -> Result<u32> {
        if len_bytes.len() < 4 {
            return Err(SshError::InvalidPacket("short length".into()));
        }
        let header_key = &self.key[32..];
        let seqbuf: [u8; 8] = seq.to_be_bytes();
        let nonce = GenericArray::from_slice(&seqbuf);
        let mut header_cipher = ChaCha20Legacy::new(GenericArray::from_slice(header_key), nonce);
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&len_bytes[..4]);
        header_cipher.apply_keystream(&mut buf);
        Ok(u32::from_be_bytes(buf))
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

/// OpenSSH's AES-GCM nonce (RFC 5647 §7.1): a 4-byte fixed field followed by
/// an 8-byte invocation counter. OpenSSH calls `EVP_CTRL_GCM_SET_IV_FIXED` with
/// the whole 12-byte KEX IV and then `EVP_CTRL_GCM_IV_GEN` before each packet,
/// i.e. the first packet uses the KEX IV verbatim and every later packet
/// increments the counter. The packet sequence number is *not* used, and the
/// counter resets on rekey when a new IV is installed.
fn gcm_nonce(iv_fixed: &[u8; 4], ctr: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(iv_fixed);
    nonce[4..].copy_from_slice(&ctr.to_be_bytes());
    nonce
}

pub struct Aes128GcmCipher {
    key: [u8; 16],
    iv: [u8; 4],
    ctr: u64,
    initialized: bool,
}

impl Aes128GcmCipher {
    pub fn new() -> Self {
        Aes128GcmCipher { key: [0u8; 16], iv: [0u8; 4], ctr: 0, initialized: false }
    }
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

    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES128_GCM_IV_LEN {
            return Err(SshError::InvalidKey("wrong IV length".into()));
        }
        self.iv.copy_from_slice(&iv[..4]);
        self.ctr = u64::from_be_bytes(iv[4..12].try_into().unwrap());
        Ok(())
    }

    fn encrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(seq, &[], data)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(seq, &[], data)
    }

    fn encrypt_with_aad(&mut self, _seq: u64, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        use aes_gcm::aead::Payload;
        let cipher = AesGcm::<aes_gcm::aes::Aes128, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let nonce = gcm_nonce(&self.iv, self.ctr);
        self.ctr = self.ctr.wrapping_add(1);
        let ciphertext = cipher.encrypt(&nonce.into(), Payload { msg: data, aad })
            .map_err(|e| SshError::Protocol(format!("encrypt error: {}", e)))?;
        Ok(ciphertext)
    }

    fn decrypt_with_aad(&mut self, _seq: u64, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        use aes_gcm::aead::Payload;
        let cipher = AesGcm::<aes_gcm::aes::Aes128, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let nonce = gcm_nonce(&self.iv, self.ctr);
        self.ctr = self.ctr.wrapping_add(1);
        let plaintext = cipher.decrypt(&nonce.into(), Payload { msg: data, aad })
            .map_err(|_| SshError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

pub struct Aes256GcmCipher {
    key: [u8; 32],
    iv: [u8; 4],
    ctr: u64,
    initialized: bool,
}

impl Aes256GcmCipher {
    pub fn new() -> Self {
        Aes256GcmCipher { key: [0u8; 32], iv: [0u8; 4], ctr: 0, initialized: false }
    }
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

    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES256_GCM_IV_LEN {
            return Err(SshError::InvalidKey("wrong IV length".into()));
        }
        self.iv.copy_from_slice(&iv[..4]);
        self.ctr = u64::from_be_bytes(iv[4..12].try_into().unwrap());
        Ok(())
    }

    fn encrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(seq, &[], data)
    }

    fn decrypt(&mut self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(seq, &[], data)
    }

    fn encrypt_with_aad(&mut self, _seq: u64, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        use aes_gcm::aead::Payload;
        let cipher = AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let nonce = gcm_nonce(&self.iv, self.ctr);
        self.ctr = self.ctr.wrapping_add(1);
        let ciphertext = cipher.encrypt(&nonce.into(), Payload { msg: data, aad })
            .map_err(|e| SshError::Protocol(format!("encrypt error: {}", e)))?;
        Ok(ciphertext)
    }

    fn decrypt_with_aad(&mut self, _seq: u64, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        use aes_gcm::{AesGcm, KeyInit};
        use aes_gcm::aead::Payload;
        let cipher = AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12>::new(
            (&self.key).into(),
        );
        let nonce = gcm_nonce(&self.iv, self.ctr);
        self.ctr = self.ctr.wrapping_add(1);
        let plaintext = cipher.decrypt(&nonce.into(), Payload { msg: data, aad })
            .map_err(|_| SshError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

pub const AES128_CBC_KEY_LEN: usize = 16;
pub const AES192_CBC_KEY_LEN: usize = 24;
pub const AES256_CBC_KEY_LEN: usize = 32;
pub const AES_CBC_IV_LEN: usize = 16;

pub const TDES_CBC_KEY_LEN: usize = 24;
pub const TDES_CBC_IV_LEN: usize = 8;

pub struct Aes128CbcCipher {
    key: [u8; 16],
    iv: [u8; 16],
    initialized: bool,
}

impl Aes128CbcCipher {
    pub fn new() -> Self { Aes128CbcCipher { key: [0u8; 16], iv: [0u8; 16], initialized: false } }
    pub fn kex_name() -> &'static str { "aes128-cbc" }
}

impl SshCipher for Aes128CbcCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES128_CBC_KEY_LEN }
    fn iv_len(&self) -> usize { AES_CBC_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 0 }
    fn is_aead(&self) -> bool { false }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES128_CBC_KEY_LEN { return Err(SshError::InvalidKey("wrong key length for aes128-cbc".into())); }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES_CBC_IV_LEN { return Err(SshError::InvalidKey("wrong IV length for aes128-cbc".into())); }
        self.iv.copy_from_slice(iv);
        Ok(())
    }
    fn encrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 16 != 0 { return Err(SshError::Protocol("CBC encrypt data must be block-aligned".into())); }
        let cipher = <Aes128 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut iv = self.iv;
        for chunk in out.chunks_mut(16) {
            for i in 0..16 { chunk[i] ^= iv[i]; }
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
            iv.copy_from_slice(block.as_slice());
        }
        self.iv = iv;
        Ok(out)
    }
    fn decrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 16 != 0 { return Err(SshError::Protocol("CBC decrypt data must be block-aligned".into())); }
        let cipher = <Aes128 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut prev = self.iv;
        let mut next_iv = [0u8; 16];
        for chunk in out.chunks_mut(16) {
            next_iv.copy_from_slice(chunk);
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
            for i in 0..16 { chunk[i] ^= prev[i]; }
            prev = next_iv;
        }
        self.iv = prev;
        Ok(out)
    }
}

pub struct Aes192CbcCipher {
    key: [u8; 24],
    iv: [u8; 16],
    initialized: bool,
}

impl Aes192CbcCipher {
    pub fn new() -> Self { Aes192CbcCipher { key: [0u8; 24], iv: [0u8; 16], initialized: false } }
    pub fn kex_name() -> &'static str { "aes192-cbc" }
}

impl SshCipher for Aes192CbcCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES192_CBC_KEY_LEN }
    fn iv_len(&self) -> usize { AES_CBC_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 0 }
    fn is_aead(&self) -> bool { false }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES192_CBC_KEY_LEN { return Err(SshError::InvalidKey("wrong key length".into())); }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES_CBC_IV_LEN { return Err(SshError::InvalidKey("wrong IV length".into())); }
        self.iv.copy_from_slice(iv);
        Ok(())
    }
    fn encrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 16 != 0 { return Err(SshError::Protocol("CBC encrypt data must be block-aligned".into())); }
        let cipher = <Aes192 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut iv = self.iv;
        for chunk in out.chunks_mut(16) {
            for i in 0..16 { chunk[i] ^= iv[i]; }
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
            iv.copy_from_slice(block.as_slice());
        }
        self.iv = iv;
        Ok(out)
    }
    fn decrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 16 != 0 { return Err(SshError::Protocol("CBC decrypt data must be block-aligned".into())); }
        let cipher = <Aes192 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut prev = self.iv;
        let mut next_iv = [0u8; 16];
        for chunk in out.chunks_mut(16) {
            next_iv.copy_from_slice(chunk);
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
            for i in 0..16 { chunk[i] ^= prev[i]; }
            prev = next_iv;
        }
        self.iv = prev;
        Ok(out)
    }
}

pub struct Aes256CbcCipher {
    key: [u8; 32],
    iv: [u8; 16],
    initialized: bool,
}

impl Aes256CbcCipher {
    pub fn new() -> Self { Aes256CbcCipher { key: [0u8; 32], iv: [0u8; 16], initialized: false } }
    pub fn kex_name() -> &'static str { "aes256-cbc" }
}

impl SshCipher for Aes256CbcCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { AES256_CBC_KEY_LEN }
    fn iv_len(&self) -> usize { AES_CBC_IV_LEN }
    fn block_size(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 0 }
    fn is_aead(&self) -> bool { false }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != AES256_CBC_KEY_LEN { return Err(SshError::InvalidKey("wrong key length".into())); }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != AES_CBC_IV_LEN { return Err(SshError::InvalidKey("wrong IV length".into())); }
        self.iv.copy_from_slice(iv);
        Ok(())
    }
    fn encrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 16 != 0 { return Err(SshError::Protocol("CBC encrypt data must be block-aligned".into())); }
        let cipher = <Aes256 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut iv = self.iv;
        for chunk in out.chunks_mut(16) {
            for i in 0..16 { chunk[i] ^= iv[i]; }
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
            iv.copy_from_slice(block.as_slice());
        }
        self.iv = iv;
        Ok(out)
    }
    fn decrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 16 != 0 { return Err(SshError::Protocol("CBC decrypt data must be block-aligned".into())); }
        let cipher = <Aes256 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut prev = self.iv;
        let mut next_iv = [0u8; 16];
        for chunk in out.chunks_mut(16) {
            next_iv.copy_from_slice(chunk);
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
            for i in 0..16 { chunk[i] ^= prev[i]; }
            prev = next_iv;
        }
        self.iv = prev;
        Ok(out)
    }
}

pub struct TDesCbcCipher { key: [u8; 24], iv: [u8; 8], initialized: bool }
impl TDesCbcCipher {
    pub fn new() -> Self { TDesCbcCipher { key: [0u8; 24], iv: [0u8; 8], initialized: false } }
    pub fn kex_name() -> &'static str { "3des-cbc" }
}

impl SshCipher for TDesCbcCipher {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { 24 }
    fn iv_len(&self) -> usize { 8 }
    fn block_size(&self) -> usize { 8 }
    fn tag_len(&self) -> usize { 0 }
    fn is_aead(&self) -> bool { false }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != 24 { return Err(SshError::InvalidKey("wrong key length for 3des-cbc".into())); }
        self.key.copy_from_slice(key);
        self.initialized = true;
        Ok(())
    }
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != 8 { return Err(SshError::InvalidKey("wrong IV length for 3des-cbc".into())); }
        self.iv.copy_from_slice(iv);
        Ok(())
    }
    fn encrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 8 != 0 { return Err(SshError::Protocol("3DES CBC encrypt data must be block-aligned".into())); }
        use cipher::{BlockEncrypt, KeyInit};
        let cipher = <des::TdesEde3 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut iv = self.iv;
        for chunk in out.chunks_mut(8) {
            for i in 0..8 { chunk[i] ^= iv[i]; }
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
            iv.copy_from_slice(block.as_slice());
        }
        self.iv = iv;
        Ok(out)
    }
    fn decrypt(&mut self, _seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized { return Err(SshError::Protocol("cipher not initialized".into())); }
        if data.len() % 8 != 0 { return Err(SshError::Protocol("3DES CBC decrypt data must be block-aligned".into())); }
        use cipher::{BlockDecrypt, KeyInit};
        let cipher = <des::TdesEde3 as KeyInit>::new(GenericArray::from_slice(&self.key));
        let mut out = data.to_vec();
        let mut prev = self.iv;
        let mut next_iv = [0u8; 8];
        for chunk in out.chunks_mut(8) {
            next_iv.copy_from_slice(chunk);
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
            for i in 0..8 { chunk[i] ^= prev[i]; }
            prev = next_iv;
        }
        self.iv = prev;
        Ok(out)
    }
}

pub fn create_cipher(name: &str) -> Result<Box<dyn SshCipher>> {
    match name {
        "chacha20-poly1305@openssh.com" => Ok(Box::new(ChaCha20Poly1305Cipher::new())),
        "aes128-ctr" => Ok(Box::new(Aes128CtrCipher::new())),
        "aes192-ctr" => Ok(Box::new(Aes192CtrCipher::new())),
        "aes256-ctr" => Ok(Box::new(Aes256CtrCipher::new())),
        "aes128-cbc" => Ok(Box::new(Aes128CbcCipher::new())),
        "aes192-cbc" => Ok(Box::new(Aes192CbcCipher::new())),
        "aes256-cbc" => Ok(Box::new(Aes256CbcCipher::new())),
        "3des-cbc" => Ok(Box::new(TDesCbcCipher::new())),
        "aes128-gcm@openssh.com" => Ok(Box::new(Aes128GcmCipher::new())),
        "aes256-gcm@openssh.com" => Ok(Box::new(Aes256GcmCipher::new())),
        _ => Err(SshError::UnsupportedAlgorithm(format!("cipher: {}", name))),
    }
}

pub fn get_supported_ciphers() -> Vec<&'static str> {
    vec![
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "aes256-cbc",
        "aes192-cbc",
        "aes128-cbc",
        "3des-cbc",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinctive byte values so a wrong nonce layout cannot accidentally match.
    const GCM_IV: [u8; 12] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    const GCM128_KEY: [u8; 16] = [0x11; 16];
    const GCM256_KEY: [u8; 32] = [0x22; 32];

    fn gcm128_reference(nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Vec<u8> {
        use aes_gcm::{AesGcm, KeyInit as _, aead::Payload};
        let c = AesGcm::<aes_gcm::aes::Aes128, aes_gcm::aead::consts::U12>::new(
            (&GCM128_KEY).into(),
        );
        c.encrypt(nonce.into(), Payload { msg, aad }).unwrap()
    }

    fn gcm256_reference(nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Vec<u8> {
        use aes_gcm::{AesGcm, KeyInit as _, aead::Payload};
        let c = AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12>::new(
            (&GCM256_KEY).into(),
        );
        c.encrypt(nonce.into(), Payload { msg, aad }).unwrap()
    }

    fn configured_128() -> Aes128GcmCipher {
        let mut c = Aes128GcmCipher::new();
        c.set_key(&GCM128_KEY).unwrap();
        c.set_iv(&GCM_IV).unwrap();
        c
    }

    fn configured_256() -> Aes256GcmCipher {
        let mut c = Aes256GcmCipher::new();
        c.set_key(&GCM256_KEY).unwrap();
        c.set_iv(&GCM_IV).unwrap();
        c
    }

    /// OpenSSH (cipher.c) installs the whole 12-byte KEX IV with
    /// `EVP_CTRL_GCM_SET_IV_FIXED(-1, iv)` and then calls
    /// `EVP_CTRL_GCM_IV_GEN` before every packet: the first packet uses the
    /// KEX IV verbatim, later packets increment the trailing 8-byte counter.
    #[test]
    fn aes_gcm_first_packet_uses_kex_iv_verbatim() {
        let mut c = configured_128();
        let ct = c.encrypt_with_aad(12345, &[0, 0, 0, 10], b"first packet").unwrap();
        assert_eq!(ct, gcm128_reference(&GCM_IV, &[0, 0, 0, 10], b"first packet"));

        let mut c = configured_256();
        let ct = c.encrypt_with_aad(0, &[0, 0, 0, 10], b"first packet").unwrap();
        assert_eq!(ct, gcm256_reference(&GCM_IV, &[0, 0, 0, 10], b"first packet"));
    }

    #[test]
    fn aes_gcm_counter_advances_per_packet_and_ignores_seq() {
        let mut ctr = u64::from_be_bytes(GCM_IV[4..].try_into().unwrap());
        let mut second_nonce = GCM_IV;
        second_nonce[4..].copy_from_slice(&(ctr + 1).to_be_bytes());
        ctr += 1;
        let mut third_nonce = GCM_IV;
        third_nonce[4..].copy_from_slice(&(ctr + 1).to_be_bytes());

        let mut c = configured_128();
        let _first = c.encrypt_with_aad(0, b"", b"a").unwrap();
        assert_eq!(
            c.encrypt_with_aad(999, b"", b"b").unwrap(),
            gcm128_reference(&second_nonce, b"", b"b"),
            "second packet must use IV counter + 1 regardless of seq"
        );
        assert_eq!(
            c.encrypt_with_aad(7, b"", b"c").unwrap(),
            gcm128_reference(&third_nonce, b"", b"c"),
        );

        // Same key/IV/plaintext/AAD but a different seq must produce the same
        // ciphertext: AES-GCM in OpenSSH never mixes the packet sequence number
        // into the nonce.
        let mut a = configured_128();
        let mut b = configured_128();
        assert_eq!(
            a.encrypt_with_aad(0, b"", b"same").unwrap(),
            b.encrypt_with_aad(42, b"", b"same").unwrap()
        );
    }

    #[test]
    fn aes_gcm_authenticates_aad() {
        let mut enc = configured_128();
        let ct = enc.encrypt_with_aad(0, &[0, 0, 0, 16], b"payload").unwrap();

        let mut ok = configured_128();
        assert_eq!(
            ok.decrypt_with_aad(0, &[0, 0, 0, 16], &ct).unwrap(),
            b"payload".to_vec()
        );

        // A modified cleartext packet_length (AAD) must fail authentication.
        let mut bad = configured_128();
        assert!(matches!(
            bad.decrypt_with_aad(0, &[0, 0, 0, 17], &ct),
            Err(SshError::DecryptionFailed)
        ));
    }

    #[test]
    fn aes_gcm_block_size_is_sixteen() {
        assert_eq!(configured_128().block_size(), 16);
        assert_eq!(configured_256().block_size(), 16);
    }
}


