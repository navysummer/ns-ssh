use crate::error::{Result, SshError};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use sha1::Sha1;

pub trait SshMac: Send + Sync {
    fn name(&self) -> &str;
    fn key_len(&self) -> usize;
    fn tag_len(&self) -> usize;
    fn is_etm(&self) -> bool { false }
    fn set_key(&mut self, key: &[u8]) -> Result<()>;
    fn compute_tag(&self, seq: u64, packet_data: &[u8]) -> Result<Vec<u8>>;
    fn verify_tag(&self, seq: u64, packet_data: &[u8], tag: &[u8]) -> Result<bool>;
}

// RFC 4253 §6.4: the sequence number in the MAC input is a 4-byte uint32
// (not a u64), encoded big-endian.
fn seq_bytes(seq: u64) -> [u8; 4] {
    (seq as u32).to_be_bytes()
}

/// Compare a computed tag against a peer-supplied tag in constant time.
///
/// A plain `==` on slices returns at the first differing byte, which leaks how
/// many leading bytes of a forged tag were correct and enables a byte-by-byte
/// forgery oracle. Only the equal-length case can be a match, and the length
/// itself is public (it is negotiated), so comparing it first is fine.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Keep the compiler from turning this into an early-exit comparison.
    std::hint::black_box(diff) == 0
}

fn hmac_sha256(key: &[u8], seq: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|e| SshError::Protocol(format!("HMAC: {}", e)))?;
    mac.update(&seq_bytes(seq)); mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
fn hmac_sha512(key: &[u8], seq: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|e| SshError::Protocol(format!("HMAC: {}", e)))?;
    mac.update(&seq_bytes(seq)); mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
fn hmac_sha1(key: &[u8], seq: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|e| SshError::Protocol(format!("HMAC: {}", e)))?;
    mac.update(&seq_bytes(seq)); mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

macro_rules! def_mac {
    ($s:ident, $name:expr, $keylen:expr, $taglen:expr, $etm:expr, $compute:expr) => {
        pub struct $s { key: Vec<u8> }
        impl $s { pub fn new() -> Self { $s { key: Vec::new() } } }
        impl SshMac for $s {
            fn name(&self) -> &str { $name }
            fn key_len(&self) -> usize { $keylen }
            fn tag_len(&self) -> usize { $taglen }
            fn is_etm(&self) -> bool { $etm }
            fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
            fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { ($compute)(&self.key, seq, data) }
            fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&($compute)(&self.key, seq, data)?, tag)) }
        }
    };
}

def_mac!(HmacSha256Mac, "hmac-sha2-256", 32, 32, false, hmac_sha256);
def_mac!(HmacSha256EtmMac, "hmac-sha2-256-etm@openssh.com", 32, 32, true, hmac_sha256);
def_mac!(HmacSha512Mac, "hmac-sha2-512", 64, 64, false, hmac_sha512);
def_mac!(HmacSha512EtmMac, "hmac-sha2-512-etm@openssh.com", 64, 64, true, hmac_sha512);
def_mac!(HmacSha1Mac, "hmac-sha1", 20, 20, false, hmac_sha1);
def_mac!(HmacSha1EtmMac, "hmac-sha1-etm@openssh.com", 20, 20, true, hmac_sha1);

pub struct HmacSha196Mac { key: Vec<u8> }
impl HmacSha196Mac { pub fn new() -> Self { HmacSha196Mac { key: Vec::new() } } }
impl SshMac for HmacSha196Mac {
    fn name(&self) -> &str { "hmac-sha1-96" }
    fn key_len(&self) -> usize { 20 }
    fn tag_len(&self) -> usize { 12 }
    fn is_etm(&self) -> bool { false }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { Ok(hmac_sha1(&self.key, seq, data)?[..12].to_vec()) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&hmac_sha1(&self.key, seq, data)?[..12], tag)) }
}

pub struct HmacSha196EtmMac { key: Vec<u8> }
impl HmacSha196EtmMac { pub fn new() -> Self { HmacSha196EtmMac { key: Vec::new() } } }
impl SshMac for HmacSha196EtmMac {
    fn name(&self) -> &str { "hmac-sha1-96-etm@openssh.com" }
    fn key_len(&self) -> usize { 20 }
    fn tag_len(&self) -> usize { 12 }
    fn is_etm(&self) -> bool { true }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { Ok(hmac_sha1(&self.key, seq, data)?[..12].to_vec()) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&hmac_sha1(&self.key, seq, data)?[..12], tag)) }
}

pub struct NoMac;
impl NoMac { pub fn new() -> Self { NoMac } }
impl SshMac for NoMac {
    fn name(&self) -> &str { "none" }
    fn key_len(&self) -> usize { 0 }
    fn tag_len(&self) -> usize { 0 }
    fn set_key(&mut self, _key: &[u8]) -> Result<()> { Ok(()) }
    fn compute_tag(&self, _seq: u64, _packet_data: &[u8]) -> Result<Vec<u8>> { Ok(Vec::new()) }
    fn verify_tag(&self, _seq: u64, _packet_data: &[u8], tag: &[u8]) -> Result<bool> { Ok(tag.is_empty()) }
}

pub fn create_mac(name: &str) -> Result<Box<dyn SshMac>> {
    match name {
        "hmac-sha2-256-etm@openssh.com" => Ok(Box::new(HmacSha256EtmMac::new())),
        "hmac-sha2-512-etm@openssh.com" => Ok(Box::new(HmacSha512EtmMac::new())),
        "hmac-sha1-etm@openssh.com" => Ok(Box::new(HmacSha1EtmMac::new())),
        "hmac-sha2-256" => Ok(Box::new(HmacSha256Mac::new())),
        "hmac-sha2-512" => Ok(Box::new(HmacSha512Mac::new())),
        "hmac-sha1" => Ok(Box::new(HmacSha1Mac::new())),
        "hmac-sha1-96" => Ok(Box::new(HmacSha196Mac::new())),
        "hmac-sha1-96-etm@openssh.com" => Ok(Box::new(HmacSha196EtmMac::new())),
        "none" => Ok(Box::new(NoMac::new())),
        _ => Err(SshError::UnsupportedAlgorithm(format!("mac: {}", name))),
    }
}

pub fn get_supported_macs() -> Vec<&'static str> {
    vec![
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-sha1-96-etm@openssh.com",
        "none",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_tag_accepts_exact_tag_and_rejects_any_mutation() {
        for name in ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96"] {
            let mut mac = create_mac(name).unwrap();
            mac.set_key(&vec![0x5a; mac.key_len()]).unwrap();
            let tag = mac.compute_tag(7, b"packet body").unwrap();
            assert!(mac.verify_tag(7, b"packet body", &tag).unwrap(), "{name}");

            // Wrong data, wrong seq, and a flipped tag byte must all fail.
            assert!(!mac.verify_tag(7, b"packet bodY", &tag).unwrap(), "{name}");
            assert!(!mac.verify_tag(8, b"packet body", &tag).unwrap(), "{name}");
            let mut bad = tag.clone();
            bad[0] ^= 0x01;
            assert!(!mac.verify_tag(7, b"packet body", &bad).unwrap(), "{name}");
            // Truncated tags are rejected by the length check.
            assert!(!mac.verify_tag(7, b"packet body", &tag[..tag.len() - 1]).unwrap(), "{name}");
        }
    }
}
