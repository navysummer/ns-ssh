use crate::error::{Result, SshError};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use sha1::Sha1;
use md5::Md5;
use crate::umac::UmacCtx;
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

fn hmac_md5(key: &[u8], seq: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Md5>::new_from_slice(key).map_err(|e| SshError::Protocol(format!("HMAC-MD5: {}", e)))?;
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

// Legacy MD5 HMACs (RFC 4253 / OpenSSH). Never advertised by default; only
// reachable through explicit `MACs` configuration.
def_mac!(HmacMd5Mac, "hmac-md5", 16, 16, false, hmac_md5);
def_mac!(HmacMd5EtmMac, "hmac-md5-etm@openssh.com", 16, 16, true, hmac_md5);

pub struct HmacMd596Mac { key: Vec<u8> }
impl HmacMd596Mac { pub fn new() -> Self { HmacMd596Mac { key: Vec::new() } } }
impl SshMac for HmacMd596Mac {
    fn name(&self) -> &str { "hmac-md5-96" }
    fn key_len(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 12 }
    fn is_etm(&self) -> bool { false }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { Ok(hmac_md5(&self.key, seq, data)?[..12].to_vec()) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&hmac_md5(&self.key, seq, data)?[..12], tag)) }
}

pub struct HmacMd596EtmMac { key: Vec<u8> }
impl HmacMd596EtmMac { pub fn new() -> Self { HmacMd596EtmMac { key: Vec::new() } } }
impl SshMac for HmacMd596EtmMac {
    fn name(&self) -> &str { "hmac-md5-96-etm@openssh.com" }
    fn key_len(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 12 }
    fn is_etm(&self) -> bool { true }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { Ok(hmac_md5(&self.key, seq, data)?[..12].to_vec()) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&hmac_md5(&self.key, seq, data)?[..12], tag)) }
}

// UMAC (RFC 4418) as used by OpenSSH: `umac-64@openssh.com` and
// `umac-128@openssh.com` (plus their `-etm` variants). OpenSSH feeds the
// 64-bit packet sequence number as the 8-byte big-endian UMAC nonce
// (POKE_U64 / put_u64 in mac.c). The ETM variants differ only in that the
// transport MACs the packet-length field too (is_etm).
fn umac_tag(key: &[u8], output_len: usize, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut ctx = UmacCtx::new(key, output_len)?;
    ctx.update(data);
    let mut tag = vec![0u8; output_len];
    ctx.finalize(&seq.to_be_bytes(), &mut tag);
    Ok(tag)
}

pub struct Umac64Mac { key: Vec<u8> }
impl Umac64Mac { pub fn new() -> Self { Umac64Mac { key: Vec::new() } } }
impl SshMac for Umac64Mac {
    fn name(&self) -> &str { "umac-64@openssh.com" }
    fn key_len(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 8 }
    fn is_etm(&self) -> bool { false }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { umac_tag(&self.key, 8, seq, data) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&self.compute_tag(seq, data)?, tag)) }
}

pub struct Umac64EtmMac { key: Vec<u8> }
impl Umac64EtmMac { pub fn new() -> Self { Umac64EtmMac { key: Vec::new() } } }
impl SshMac for Umac64EtmMac {
    fn name(&self) -> &str { "umac-64-etm@openssh.com" }
    fn key_len(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 8 }
    fn is_etm(&self) -> bool { true }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { umac_tag(&self.key, 8, seq, data) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&self.compute_tag(seq, data)?, tag)) }
}

pub struct Umac128Mac { key: Vec<u8> }
impl Umac128Mac { pub fn new() -> Self { Umac128Mac { key: Vec::new() } } }
impl SshMac for Umac128Mac {
    fn name(&self) -> &str { "umac-128@openssh.com" }
    fn key_len(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 16 }
    fn is_etm(&self) -> bool { false }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { umac_tag(&self.key, 16, seq, data) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&self.compute_tag(seq, data)?, tag)) }
}

pub struct Umac128EtmMac { key: Vec<u8> }
impl Umac128EtmMac { pub fn new() -> Self { Umac128EtmMac { key: Vec::new() } } }
impl SshMac for Umac128EtmMac {
    fn name(&self) -> &str { "umac-128-etm@openssh.com" }
    fn key_len(&self) -> usize { 16 }
    fn tag_len(&self) -> usize { 16 }
    fn is_etm(&self) -> bool { true }
    fn set_key(&mut self, k: &[u8]) -> Result<()> { self.key = k.to_vec(); Ok(()) }
    fn compute_tag(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> { umac_tag(&self.key, 16, seq, data) }
    fn verify_tag(&self, seq: u64, data: &[u8], tag: &[u8]) -> Result<bool> { Ok(ct_eq(&self.compute_tag(seq, data)?, tag)) }
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
        "hmac-md5" => Ok(Box::new(HmacMd5Mac::new())),
        "hmac-md5-etm@openssh.com" => Ok(Box::new(HmacMd5EtmMac::new())),
        "hmac-md5-96" => Ok(Box::new(HmacMd596Mac::new())),
        "hmac-md5-96-etm@openssh.com" => Ok(Box::new(HmacMd596EtmMac::new())),
        "umac-64@openssh.com" => Ok(Box::new(Umac64Mac::new())),
        "umac-128@openssh.com" => Ok(Box::new(Umac128Mac::new())),
        "umac-64-etm@openssh.com" => Ok(Box::new(Umac64EtmMac::new())),
        "umac-128-etm@openssh.com" => Ok(Box::new(Umac128EtmMac::new())),
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
        "hmac-md5",
        "hmac-md5-96",
        "hmac-md5-etm@openssh.com",
        "hmac-md5-96-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "none",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_tag_accepts_exact_tag_and_rejects_any_mutation() {
        for name in ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com"] {
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

    #[test]
    fn hmac_md5_matches_rfc2202_vector() {
        // RFC 2202 test case 1: key = 0x0b * 16, data = "Hi There" gives the
        // well-known HMAC-MD5 9294727a3638bb1c13f48ef8158bfc9d. SSH MACs prepend
        // the 4-byte sequence number, so the tag for seq=0 is HMAC-MD5 over
        // 00000000 || "Hi There" = 2031c68ac87159d4e01b7b40412bc931.
        let key = vec![0x0b; 16];
        let data = b"Hi There";
        let mut mac = HmacMd5Mac::new();
        mac.set_key(&key).unwrap();
        let tag = mac.compute_tag(0, data).unwrap();
        let expected = [
            0x20, 0x31, 0xc6, 0x8a, 0xc8, 0x71, 0x59, 0xd4,
            0xe0, 0x1b, 0x7b, 0x40, 0x41, 0x2b, 0xc9, 0x31,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn umac_matches_openssh_reference_vector() {
        // Reference tags produced by OpenSSH's own umac.c (compiled as a C
        // harness against OpenSSL) for:
        //   key   = 0123456789abcdeffedcba9876543210
        //   nonce = seqno 1, encoded as an 8-byte big-endian value
        // The 32-byte message exercises the L1/L3 (ip_short) path; the
        // 2048-byte message exercises the L2 polyhash + ip_long path.
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let short_msg = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ];
        let long_msg: Vec<u8> = (0..512u32).flat_map(|_| [0xaa, 0xbb, 0xcc, 0xdd]).collect();

        let mut m64 = Umac64Mac::new();
        m64.set_key(&key).unwrap();
        assert_eq!(m64.compute_tag(1, &short_msg).unwrap(), hex_to_bytes("4a1fbc94ce158caa"));
        assert_eq!(m64.compute_tag(1, &long_msg).unwrap(), hex_to_bytes("1e009bb01be8c4ff"));
        let mut m128 = Umac128Mac::new();
        m128.set_key(&key).unwrap();
        assert_eq!(m128.compute_tag(1, &short_msg).unwrap(), hex_to_bytes("f3afd5f31f9e6e86bafaa8d2a42a6887"));
        assert_eq!(m128.compute_tag(1, &long_msg).unwrap(), hex_to_bytes("a7b0f2d7ca6326d3954354f99df197ab"));
    }


    fn hex_to_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
    }
}

