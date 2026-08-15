use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

use crate::error::{Result, SshError};

pub trait SshEncode {
    fn encode(&self, w: &mut impl Write) -> Result<()>;
    fn encoded_len(&self) -> usize;
}

pub trait SshDecode: Sized {
    fn decode(r: &mut impl Read) -> Result<Self>;
}

impl SshEncode for bool {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&[*self as u8])?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        1
    }
}

impl SshDecode for bool {
    fn decode(r: &mut impl Read) -> Result<Self> {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }
}

impl SshEncode for u8 {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&[*self])?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        1
    }
}

impl SshDecode for u8 {
    fn decode(r: &mut impl Read) -> Result<Self> {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl SshEncode for u32 {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        w.write_u32::<BigEndian>(*self)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        4
    }
}

impl SshDecode for u32 {
    fn decode(r: &mut impl Read) -> Result<Self> {
        r.read_u32::<BigEndian>().map_err(SshError::from)
    }
}

impl SshEncode for u64 {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        w.write_u64::<BigEndian>(*self)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        8
    }
}

impl SshDecode for u64 {
    fn decode(r: &mut impl Read) -> Result<Self> {
        r.read_u64::<BigEndian>().map_err(SshError::from)
    }
}

pub struct SshString(pub Vec<u8>);

impl SshEncode for SshString {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        (self.0.len() as u32).encode(w)?;
        w.write_all(&self.0)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        4 + self.0.len()
    }
}

impl SshDecode for SshString {
    fn decode(r: &mut impl Read) -> Result<Self> {
        let len = u32::decode(r)? as usize;
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(SshString(buf))
    }
}

impl SshString {
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.0).map_err(|e| SshError::Encoding(e.to_string()))
    }

    pub fn new(s: &str) -> Self {
        SshString(s.as_bytes().to_vec())
    }
}

impl From<&str> for SshString {
    fn from(s: &str) -> Self {
        SshString::new(s)
    }
}

impl From<Vec<u8>> for SshString {
    fn from(v: Vec<u8>) -> Self {
        SshString(v)
    }
}

pub struct SshNameList(pub Vec<String>);

impl SshEncode for SshNameList {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        let s = self.0.join(",");
        SshString(s.into_bytes()).encode(w)
    }
    fn encoded_len(&self) -> usize {
        let s = self.0.join(",");
        4 + s.len()
    }
}

impl SshDecode for SshNameList {
    fn decode(r: &mut impl Read) -> Result<Self> {
        let s = SshString::decode(r)?;
        let names = if s.0.is_empty() {
            Vec::new()
        } else {
            String::from_utf8_lossy(&s.0)
                .split(',')
                .map(|s| s.to_string())
                .collect()
        };
        Ok(SshNameList(names))
    }
}

impl SshNameList {
    pub fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|n| n == name)
    }

    pub fn first_match(&self, others: &[String]) -> Option<String> {
        for candidate in &self.0 {
            if others.iter().any(|o| o == candidate) {
                return Some(candidate.clone());
            }
        }
        None
    }
}

pub struct SshMpInt(pub Vec<u8>);

impl SshEncode for SshMpInt {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        let bytes = &self.0;
        let sign = if bytes.is_empty() || bytes[0] & 0x80 != 0 {
            vec![0u8]
        } else {
            vec![]
        };
        let total_len = bytes.len() + sign.len();
        (total_len as u32).encode(w)?;
        if !sign.is_empty() {
            w.write_all(&sign)?;
        }
        w.write_all(bytes)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        let extra = if self.0.is_empty() || self.0[0] & 0x80 != 0 {
            1
        } else {
            0
        };
        4 + self.0.len() + extra
    }
}

impl SshMpInt {
    pub fn from_u32(val: u32) -> Self {
        if val == 0 {
            return SshMpInt(vec![]);
        }
        let bytes = val.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        SshMpInt(bytes[start..].to_vec())
    }

    pub fn to_u32(&self) -> Option<u32> {
        if self.0.is_empty() {
            return Some(0);
        }
        if self.0.len() > 4 {
            return None;
        }
        let mut buf = [0u8; 4];
        let offset = 4 - self.0.len();
        buf[offset..].copy_from_slice(&self.0);
        Some(u32::from_be_bytes(buf))
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        SshMpInt(bytes[start..].to_vec())
    }
}

pub fn encode_mpint(val: &num_bigint::BigUint) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let bytes = val.to_bytes_be();
    SshMpInt(bytes).encode(&mut buf)?;
    Ok(buf)
}

impl SshDecode for SshMpInt {
    fn decode(r: &mut impl Read) -> Result<Self> {
        let len = u32::decode(r)? as usize;
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(SshMpInt(buf))
    }
}

pub struct SshBytes(pub Vec<u8>);

impl SshEncode for SshBytes {
    fn encode(&self, w: &mut impl Write) -> Result<()> {
        (self.0.len() as u32).encode(w)?;
        w.write_all(&self.0)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        4 + self.0.len()
    }
}

impl SshDecode for SshBytes {
    fn decode(r: &mut impl Read) -> Result<Self> {
        let len = u32::decode(r)? as usize;
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(SshBytes(buf))
    }
}

pub fn encode_string(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    SshString::new(s).encode(&mut buf).unwrap();
    buf
}

pub fn encode_uint32(val: u32) -> Vec<u8> {
    val.to_be_bytes().to_vec()
}

pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    SshBytes(data.to_vec()).encode(&mut buf).unwrap();
    buf
}

pub fn encode_name_list(names: &[&str]) -> Vec<u8> {
    let list: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let mut buf = Vec::new();
    SshNameList(list).encode(&mut buf).unwrap();
    buf
}

pub fn read_string(r: &mut impl Read) -> Result<String> {
    let s = SshString::decode(r)?;
    s.as_str().map(|s| s.to_string())
}

pub fn read_bytes(r: &mut impl Read) -> Result<Vec<u8>> {
    let b = SshBytes::decode(r)?;
    Ok(b.0)
}

pub fn read_uint32(r: &mut impl Read) -> Result<u32> {
    u32::decode(r)
}
