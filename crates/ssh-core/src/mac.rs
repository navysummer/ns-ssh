use crate::error::{Result, SshError};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

pub trait SshMac: Send + Sync {
    fn name(&self) -> &str;
    fn key_len(&self) -> usize;
    fn tag_len(&self) -> usize;
    fn set_key(&mut self, key: &[u8]) -> Result<()>;
    fn compute_tag(&self, seq: u64, packet_data: &[u8]) -> Result<Vec<u8>>;
    fn verify_tag(&self, seq: u64, packet_data: &[u8], tag: &[u8]) -> Result<bool>;
}

pub struct HmacSha256Mac {
    key: Vec<u8>,
}

impl HmacSha256Mac {
    pub fn new() -> Self {
        HmacSha256Mac { key: Vec::new() }
    }

    pub fn kex_name() -> &'static str {
        "hmac-sha2-256"
    }
}

impl SshMac for HmacSha256Mac {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { 32 }
    fn tag_len(&self) -> usize { 32 }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        self.key = key.to_vec();
        Ok(())
    }

    fn compute_tag(&self, seq: u64, packet_data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|e| SshError::Protocol(format!("HMAC init error: {}", e)))?;
        mac.update(&seq.to_be_bytes());
        mac.update(packet_data);
        let result = mac.finalize().into_bytes().to_vec();
        Ok(result)
    }

    fn verify_tag(&self, seq: u64, packet_data: &[u8], tag: &[u8]) -> Result<bool> {
        let computed = self.compute_tag(seq, packet_data)?;
        Ok(computed == tag)
    }
}

pub struct HmacSha512Mac {
    key: Vec<u8>,
}

impl HmacSha512Mac {
    pub fn new() -> Self {
        HmacSha512Mac { key: Vec::new() }
    }

    pub fn kex_name() -> &'static str {
        "hmac-sha2-512"
    }
}

impl SshMac for HmacSha512Mac {
    fn name(&self) -> &str { Self::kex_name() }
    fn key_len(&self) -> usize { 64 }
    fn tag_len(&self) -> usize { 64 }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        self.key = key.to_vec();
        Ok(())
    }

    fn compute_tag(&self, seq: u64, packet_data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = Hmac::<Sha512>::new_from_slice(&self.key)
            .map_err(|e| SshError::Protocol(format!("HMAC init error: {}", e)))?;
        mac.update(&seq.to_be_bytes());
        mac.update(packet_data);
        let result = mac.finalize().into_bytes().to_vec();
        Ok(result)
    }

    fn verify_tag(&self, seq: u64, packet_data: &[u8], tag: &[u8]) -> Result<bool> {
        let computed = self.compute_tag(seq, packet_data)?;
        Ok(computed == tag)
    }
}

pub struct NoMac;

impl NoMac {
    pub fn new() -> Self { NoMac }
}

impl SshMac for NoMac {
    fn name(&self) -> &str { "none" }
    fn key_len(&self) -> usize { 0 }
    fn tag_len(&self) -> usize { 0 }

    fn set_key(&mut self, _key: &[u8]) -> Result<()> { Ok(()) }

    fn compute_tag(&self, _seq: u64, _packet_data: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn verify_tag(&self, _seq: u64, _packet_data: &[u8], tag: &[u8]) -> Result<bool> {
        Ok(tag.is_empty())
    }
}

pub fn create_mac(name: &str) -> Result<Box<dyn SshMac>> {
    match name {
        "hmac-sha2-256" => Ok(Box::new(HmacSha256Mac::new())),
        "hmac-sha2-512" => Ok(Box::new(HmacSha512Mac::new())),
        "none" => Ok(Box::new(NoMac::new())),
        _ => Err(SshError::UnsupportedAlgorithm(format!("mac: {}", name))),
    }
}

pub fn get_supported_macs() -> Vec<&'static str> {
    vec!["hmac-sha2-256", "hmac-sha2-512", "none"]
}
