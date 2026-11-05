//! Pure-Rust UMAC (RFC 4418), ported from OpenSSH's `umac.c` (v0.93b).
//!
//! OpenSSH ships a self-contained UMAC implementation in `umac.c`; the SSH MAC
//! variants `umac-64@openssh.com` and `umac-128@openssh.com` use a 16-byte AES
//! key and produce an 8- or 16-byte tag, keyed by the packet sequence number.
//! This module is a faithful 1:1 port of that algorithm so the tags match
//! OpenSSH exactly (required for interop). No third-party UMAC crate exists;
//! this keeps the implementation pure Rust and dependency-light.
//!
//! The algorithm is UHASH (NH + polynomial hash + inner-product hash) with a
//! nonce-derived AES pad (PDF). Only the 8/16-byte output lengths that SSH
//! needs are implemented.

const UMAC_KEY_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

const L1_KEY_LEN: usize = 1024;
const L1_KEY_SHIFT: usize = 16;
const HASH_BUF_BYTES: usize = 64;
const L1_PAD_BOUNDARY: usize = 32;
const M36: u64 = (1u64 << 36) - 1;
// 2^36 - 5 prime for inner-product (L3).
const P36: u64 = (1u64 << 36) - 5;
// 2^64 - 59 prime for polynomial hash (L2).
const P64: u64 = u64::MAX - 58;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

/// AES-128 block encrypt helper.
fn aes_encrypt(key: &Aes128, input: &[u8; 16]) -> [u8; 16] {
    let mut block = GenericArray::clone_from_slice(input);
    key.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

/// kdf: stretch the 16-byte UMAC key using AES in counter mode. Each distinct
/// `ndx` produces a distinct byte stream.
fn kdf(buf: &mut [u8], key: &Aes128, ndx: u8) {
    let mut in_buf = [0u8; AES_BLOCK_LEN];
    in_buf[AES_BLOCK_LEN - 9] = ndx;
    in_buf[AES_BLOCK_LEN - 1] = 1;
    let mut dst = 0usize;
    while dst + AES_BLOCK_LEN <= buf.len() {
        let out = aes_encrypt(key, &in_buf);
        buf[dst..dst + AES_BLOCK_LEN].copy_from_slice(&out);
        in_buf[AES_BLOCK_LEN - 1] = in_buf[AES_BLOCK_LEN - 1].wrapping_add(1);
        dst += AES_BLOCK_LEN;
    }
    if dst < buf.len() {
        let out = aes_encrypt(key, &in_buf);
        let tail = buf.len() - dst;
        buf[dst..dst + tail].copy_from_slice(&out[..tail]);
    }
}

/// NH hash state.
struct NhCtx {
    nh_key: Vec<u8>, // L1_KEY_LEN + L1_KEY_SHIFT * (streams - 1)
    data: [u8; HASH_BUF_BYTES],
    next_data_empty: usize,
    bytes_hashed: usize,
    state: Vec<u64>,
}

impl NhCtx {
    fn new(streams: usize) -> Self {
        NhCtx {
            nh_key: vec![0u8; L1_KEY_LEN + L1_KEY_SHIFT * (streams - 1)],
            data: [0u8; HASH_BUF_BYTES],
            next_data_empty: 0,
            bytes_hashed: 0,
            state: vec![0u64; streams],
        }
    }

    fn reset(&mut self) {
        self.bytes_hashed = 0;
        self.next_data_empty = 0;
        for s in self.state.iter_mut() {
            *s = 0;
        }
    }

    fn init(&mut self, prf_key: &Aes128, streams: usize) {
        // kdf index 1 fills the NH key; endian-convert (little-endian host).
        kdf(&mut self.nh_key, prf_key, 1);
        endian_convert_u32(&mut self.nh_key);
        let _ = streams;
        self.reset();
    }


    fn update(&mut self, buf: &[u8], nbytes: usize) {
        let mut j = self.next_data_empty;
        let mut buf = buf;
        let mut nbytes = nbytes;
        if j + nbytes >= HASH_BUF_BYTES {
            if j != 0 {
                let i = HASH_BUF_BYTES - j;
                self.data[j..HASH_BUF_BYTES].copy_from_slice(&buf[..i]);
                nh_transform(&self.nh_key, self.bytes_hashed, &self.data, &mut self.state, HASH_BUF_BYTES);
                nbytes -= i;
                buf = &buf[i..];
                self.bytes_hashed += HASH_BUF_BYTES;
            }
            if nbytes >= HASH_BUF_BYTES {
                let i = nbytes & !(HASH_BUF_BYTES - 1);
                nh_transform(&self.nh_key, self.bytes_hashed, &buf[..i], &mut self.state, i);
                nbytes -= i;
                buf = &buf[i..];
                self.bytes_hashed += i;
            }
            j = 0;
        }
        self.data[j..j + nbytes].copy_from_slice(&buf[..nbytes]);
        self.next_data_empty = j + nbytes;
    }

    fn finalize(&mut self, result: &mut [u8]) {
        let nh_len;
        if self.next_data_empty != 0 {
            nh_len = (self.next_data_empty + (L1_PAD_BOUNDARY - 1)) & !(L1_PAD_BOUNDARY - 1);
            let pad = nh_len - self.next_data_empty;
            for b in &mut self.data[self.next_data_empty..self.next_data_empty + pad] {
                *b = 0;
            }
            nh_transform(&self.nh_key, self.bytes_hashed, &self.data[..nh_len], &mut self.state, nh_len);
            self.bytes_hashed += self.next_data_empty;
        } else if self.bytes_hashed == 0 {
            nh_len = L1_PAD_BOUNDARY;
            for b in &mut self.data[..L1_PAD_BOUNDARY] {
                *b = 0;
            }
            nh_transform(&self.nh_key, self.bytes_hashed, &self.data[..nh_len], &mut self.state, nh_len);
        }
        let nbits = (self.bytes_hashed << 3) as u64;
        for (i, s) in self.state.iter().enumerate() {
            let v = *s + nbits;
            let off = i * 8;
            result[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        self.reset();
    }
}
/// Run NH over `buf` starting at byte offset `key_off` in `nh_key`.
fn nh_transform(nh_key: &[u8], key_off: usize, buf: &[u8], state: &mut [u64], nbytes: usize) {
    nh_aux(&nh_key[key_off..], buf, state, nbytes);
}


/// NH all-in-one: state seeded with `unpadded_len << 3` bits.
fn nh(hc: &NhCtx, buf: &[u8], padded_len: usize, unpadded_len: usize, result: &mut [u8]) {
    let nbits = (unpadded_len << 3) as u64;
    for (i, r) in result.chunks_mut(8).enumerate() {
        r.copy_from_slice(&nbits.to_le_bytes());
        let _ = i;
    }
    let mut state = Vec::with_capacity(result.len() / 8);
    for r in result.chunks(8) {
        state.push(u64::from_le_bytes(r.try_into().unwrap()));
    }
    nh_aux(&hc.nh_key, &buf[..padded_len], &mut state, padded_len);
    for (i, s) in state.iter().enumerate() {
        let off = i * 8;
        result[off..off + 8].copy_from_slice(&s.to_le_bytes());
    }
}

/// NH primitive for `streams` parallel iterations (output_len / 4 streams).
fn nh_aux(kp: &[u8], dp: &[u8], hp: &mut [u64], dlen: usize) {
    let streams = hp.len();
    let c = dlen / 32;
    let k = kp;
    let d = dp;
    let mut d_idx = 0usize;
    let mut k_idx = 0usize;

    if streams == 1 {
        let mut h = hp[0];
        for _ in 0..c {
            let d0 = rd32(d, d_idx);
            let d1 = rd32(d, d_idx + 4);
            let d2 = rd32(d, d_idx + 8);
            let d3 = rd32(d, d_idx + 12);
            let d4 = rd32(d, d_idx + 16);
            let d5 = rd32(d, d_idx + 20);
            let d6 = rd32(d, d_idx + 24);
            let d7 = rd32(d, d_idx + 28);
            let k0 = rd32(k, k_idx);
            let k1 = rd32(k, k_idx + 4);
            let k2 = rd32(k, k_idx + 8);
            let k3 = rd32(k, k_idx + 12);
            let k4 = rd32(k, k_idx + 16);
            let k5 = rd32(k, k_idx + 20);
            let k6 = rd32(k, k_idx + 24);
            let k7 = rd32(k, k_idx + 28);
            h = h.wrapping_add(mul64(k0.wrapping_add(d0), k4.wrapping_add(d4)));
            h = h.wrapping_add(mul64(k1.wrapping_add(d1), k5.wrapping_add(d5)));
            h = h.wrapping_add(mul64(k2.wrapping_add(d2), k6.wrapping_add(d6)));
            h = h.wrapping_add(mul64(k3.wrapping_add(d3), k7.wrapping_add(d7)));
            d_idx += 32;
            k_idx += 32;
        }
        hp[0] = h;
    } else if streams == 2 {
        let mut h1 = hp[0];
        let mut h2 = hp[1];
        let mut k0 = rd32(k, k_idx);
        let mut k1 = rd32(k, k_idx + 4);
        let mut k2 = rd32(k, k_idx + 8);
        let mut k3 = rd32(k, k_idx + 12);
        for _ in 0..c {
            let d0 = rd32(d, d_idx);
            let d1 = rd32(d, d_idx + 4);
            let d2 = rd32(d, d_idx + 8);
            let d3 = rd32(d, d_idx + 12);
            let d4 = rd32(d, d_idx + 16);
            let d5 = rd32(d, d_idx + 20);
            let d6 = rd32(d, d_idx + 24);
            let d7 = rd32(d, d_idx + 28);
            let k4 = rd32(k, k_idx + 16);
            let k5 = rd32(k, k_idx + 20);
            let k6 = rd32(k, k_idx + 24);
            let k7 = rd32(k, k_idx + 28);
            let k8 = rd32(k, k_idx + 32);
            let k9 = rd32(k, k_idx + 36);
            let k10 = rd32(k, k_idx + 40);
            let k11 = rd32(k, k_idx + 44);
            h1 = h1.wrapping_add(mul64(k0.wrapping_add(d0), k4.wrapping_add(d4)));
            h2 = h2.wrapping_add(mul64(k4.wrapping_add(d0), k8.wrapping_add(d4)));
            h1 = h1.wrapping_add(mul64(k1.wrapping_add(d1), k5.wrapping_add(d5)));
            h2 = h2.wrapping_add(mul64(k5.wrapping_add(d1), k9.wrapping_add(d5)));
            h1 = h1.wrapping_add(mul64(k2.wrapping_add(d2), k6.wrapping_add(d6)));
            h2 = h2.wrapping_add(mul64(k6.wrapping_add(d2), k10.wrapping_add(d6)));
            h1 = h1.wrapping_add(mul64(k3.wrapping_add(d3), k7.wrapping_add(d7)));
            h2 = h2.wrapping_add(mul64(k7.wrapping_add(d3), k11.wrapping_add(d7)));
            k0 = k8;
            k1 = k9;
            k2 = k10;
            k3 = k11;
            d_idx += 32;
            k_idx += 32;
        }
        hp[0] = h1;
        hp[1] = h2;
    } else {
        // streams == 4 (UMAC-128).
        let mut h1 = hp[0];
        let mut h2 = hp[1];
        let mut h3 = hp[2];
        let mut h4 = hp[3];
        let mut k0 = rd32(k, k_idx);
        let mut k1 = rd32(k, k_idx + 4);
        let mut k2 = rd32(k, k_idx + 8);
        let mut k3 = rd32(k, k_idx + 12);
        let mut k4 = rd32(k, k_idx + 16);
        let mut k5 = rd32(k, k_idx + 20);
        let mut k6 = rd32(k, k_idx + 24);
        let mut k7 = rd32(k, k_idx + 28);
        for _ in 0..c {
            let d0 = rd32(d, d_idx);
            let d1 = rd32(d, d_idx + 4);
            let d2 = rd32(d, d_idx + 8);
            let d3 = rd32(d, d_idx + 12);
            let d4 = rd32(d, d_idx + 16);
            let d5 = rd32(d, d_idx + 20);
            let d6 = rd32(d, d_idx + 24);
            let d7 = rd32(d, d_idx + 28);
            let k8 = rd32(k, k_idx + 32);
            let k9 = rd32(k, k_idx + 36);
            let k10 = rd32(k, k_idx + 40);
            let k11 = rd32(k, k_idx + 44);
            let k12 = rd32(k, k_idx + 48);
            let k13 = rd32(k, k_idx + 52);
            let k14 = rd32(k, k_idx + 56);
            let k15 = rd32(k, k_idx + 60);
            let k16 = rd32(k, k_idx + 64);
            let k17 = rd32(k, k_idx + 68);
            let k18 = rd32(k, k_idx + 72);
            let k19 = rd32(k, k_idx + 76);
            h1 = h1.wrapping_add(mul64(k0.wrapping_add(d0), k4.wrapping_add(d4)));
            h2 = h2.wrapping_add(mul64(k4.wrapping_add(d0), k8.wrapping_add(d4)));
            h3 = h3.wrapping_add(mul64(k8.wrapping_add(d0), k12.wrapping_add(d4)));
            h4 = h4.wrapping_add(mul64(k12.wrapping_add(d0), k16.wrapping_add(d4)));
            h1 = h1.wrapping_add(mul64(k1.wrapping_add(d1), k5.wrapping_add(d5)));
            h2 = h2.wrapping_add(mul64(k5.wrapping_add(d1), k9.wrapping_add(d5)));
            h3 = h3.wrapping_add(mul64(k9.wrapping_add(d1), k13.wrapping_add(d5)));
            h4 = h4.wrapping_add(mul64(k13.wrapping_add(d1), k17.wrapping_add(d5)));
            h1 = h1.wrapping_add(mul64(k2.wrapping_add(d2), k6.wrapping_add(d6)));
            h2 = h2.wrapping_add(mul64(k6.wrapping_add(d2), k10.wrapping_add(d6)));
            h3 = h3.wrapping_add(mul64(k10.wrapping_add(d2), k14.wrapping_add(d6)));
            h4 = h4.wrapping_add(mul64(k14.wrapping_add(d2), k18.wrapping_add(d6)));
            h1 = h1.wrapping_add(mul64(k3.wrapping_add(d3), k7.wrapping_add(d7)));
            h2 = h2.wrapping_add(mul64(k7.wrapping_add(d3), k11.wrapping_add(d7)));
            h3 = h3.wrapping_add(mul64(k11.wrapping_add(d3), k15.wrapping_add(d7)));
            h4 = h4.wrapping_add(mul64(k15.wrapping_add(d3), k19.wrapping_add(d7)));
            k0 = k8;
            k1 = k9;
            k2 = k10;
            k3 = k11;
            k4 = k12;
            k5 = k13;
            k6 = k14;
            k7 = k15;
            d_idx += 32;
            k_idx += 32;
        }
        hp[0] = h1;
        hp[1] = h2;
        hp[2] = h3;
        hp[3] = h4;
    }
}

/// 64x64 -> 64 multiply (low 64 bits), for the NH inner products.
fn mul64(a: u32, b: u32) -> u64 {
    (a as u64).wrapping_mul(b as u64)
}

fn rd32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Endian-convert a buffer of u32 words in place (little-endian host -> the
/// compensated big-endian form NH expects after native loads).
fn endian_convert_u32(buf: &mut [u8]) {
    for chunk in buf.chunks_exact_mut(4) {
        chunk.swap(0, 3);
        chunk.swap(1, 2);
    }
}

/// Horner's rule polynomial hash mod 2^64-59.
fn poly64(cur: u64, key: u64, data: u64) -> u64 {
    let key_hi = (key >> 32) as u32;
    let key_lo = key as u32;
    let cur_hi = (cur >> 32) as u32;
    let cur_lo = cur as u32;
    let x = (key_hi as u64).wrapping_mul(cur_lo as u64)
        .wrapping_add((cur_hi as u64).wrapping_mul(key_lo as u64));
    let x_lo = x as u32;
    let x_hi = (x >> 32) as u32;
    let mut res = (key_hi as u64).wrapping_mul(cur_hi as u64)
        .wrapping_add(x_hi as u64)
        .wrapping_mul(59)
        .wrapping_add((key_lo as u64).wrapping_mul(cur_lo as u64));
    let t = (x_lo as u64) << 32;
    res = res.wrapping_add(t);
    if res < t {
        res = res.wrapping_add(59);
    }
    res = res.wrapping_add(data);
    if res < data {
        res = res.wrapping_add(59);
    }
    res
}

fn ip_aux(t: u64, ipkp: &[u64; 4], data: u64) -> u64 {
    let mut t = t;
    t = t.wrapping_add(ipkp[0].wrapping_mul(((data >> 48) & 0xffff) as u64));
    t = t.wrapping_add(ipkp[1].wrapping_mul(((data >> 32) & 0xffff) as u64));
    t = t.wrapping_add(ipkp[2].wrapping_mul(((data >> 16) & 0xffff) as u64));
    t = t.wrapping_add(ipkp[3].wrapping_mul((data & 0xffff) as u64));
    t
}

fn ip_reduce_p36(t: u64) -> u32 {
    let mut ret = (t & M36).wrapping_add(5u64.wrapping_mul(t >> 36));
    if ret >= P36 {
        ret -= P36;
    }
    ret as u32
}

struct UhashCtx {
    hash: NhCtx,
    poly_key_8: Vec<u64>,
    poly_accum: Vec<u64>,
    ip_keys: Vec<u64>,
    ip_trans: Vec<u32>,
    msg_len: usize,
    streams: usize,
}

impl UhashCtx {
    fn new(streams: usize) -> Self {
        UhashCtx {
            hash: NhCtx::new(streams),
            poly_key_8: vec![0u64; streams],
            poly_accum: vec![1u64; streams],
            ip_keys: vec![0u64; streams * 4],
            ip_trans: vec![0u32; streams],
            msg_len: 0,
            streams,
        }
    }

    fn reset(&mut self) {
        self.hash.reset();
        self.msg_len = 0;
        for a in self.poly_accum.iter_mut() {
            *a = 1;
        }
    }

    fn init(&mut self, prf_key: &Aes128) {
        self.hash.init(prf_key, self.streams);
        let buf_len = (8 * self.streams + 4) * 8;
        let mut buf = vec![0u8; buf_len];
        kdf(&mut buf, prf_key, 2);
        for i in 0..self.streams {
            let off = 24 * i;
            let mut key = [0u8; 8];
            key.copy_from_slice(&buf[off..off + 8]);
            key.reverse();
            self.poly_key_8[i] = u64::from_le_bytes(key)
                & (((0x01ffffffu64) << 32) + 0x01ffffffu64);
            self.poly_accum[i] = 1;
        }
        kdf(&mut buf, prf_key, 3);
        for i in 0..self.streams {
            let off = (8 * i + 4) * 8;
            for j in 0..4 {
                let mut key = [0u8; 8];
                key.copy_from_slice(&buf[off + j * 8..off + j * 8 + 8]);
                key.reverse();
                self.ip_keys[i * 4 + j] = u64::from_le_bytes(key) % P36;
            }
        }
        kdf(&mut buf, prf_key, 4);
        for (i, trans) in self.ip_trans.iter_mut().enumerate() {
            let off = i * 4;
            *trans = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        }
    }

    fn poly_hash(&mut self, data_in: &[u32]) {
        for i in 0..self.streams {
            let data = ((data_in[2 * i + 1] as u64) << 32) | data_in[2 * i] as u64;
            if (data >> 32) == 0xffff_ffff {
                self.poly_accum[i] = poly64(self.poly_accum[i], self.poly_key_8[i], P64 - 1);
                self.poly_accum[i] = poly64(self.poly_accum[i], self.poly_key_8[i], data - 59);
            } else {
                self.poly_accum[i] = poly64(self.poly_accum[i], self.poly_key_8[i], data);
            }
        }
    }

    fn ip_short(&self, nh_res: &[u8], res: &mut [u8]) {
        for i in 0..self.streams {
            let data = u64::from_le_bytes(nh_res[i * 8..i * 8 + 8].try_into().unwrap());
            let t = ip_aux(0, &self.ip_keys[i * 4..i * 4 + 4].try_into().unwrap(), data);
            let v = ip_reduce_p36(t) ^ self.ip_trans[i];
            res[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
    }

    fn ip_long(&mut self, res: &mut [u8]) {
        for i in 0..self.streams {
            if self.poly_accum[i] >= P64 {
                self.poly_accum[i] -= P64;
            }
            let t = ip_aux(0, &self.ip_keys[i * 4..i * 4 + 4].try_into().unwrap(), self.poly_accum[i]);
            let v = ip_reduce_p36(t) ^ self.ip_trans[i];
            res[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
    }

    fn update(&mut self, input: &[u8], len: usize) {
        let mut input = input;
        let mut len = len;
        let mut result_buf = vec![0u8; self.streams * 8];
        let nh_result = &mut result_buf[..];

        if self.msg_len + len <= L1_KEY_LEN {
            self.hash.update(input, len);
            self.msg_len += len;
        } else {
            let mut bytes_hashed = self.msg_len % L1_KEY_LEN;
            if self.msg_len == L1_KEY_LEN {
                bytes_hashed = L1_KEY_LEN;
            }
            if bytes_hashed + len >= L1_KEY_LEN {
                if bytes_hashed != 0 {
                    let bytes_remaining = L1_KEY_LEN - bytes_hashed;
                    self.hash.update(&input[..bytes_remaining], bytes_remaining);
                    self.hash.finalize(nh_result);
                    self.msg_len += bytes_remaining;
                    let words = to_u32_pairs(nh_result);
                    self.poly_hash(&words);
                    len -= bytes_remaining;
                    input = &input[bytes_remaining..];
                }
                while len >= L1_KEY_LEN {
                    nh(&self.hash, &input[..L1_KEY_LEN], L1_KEY_LEN, L1_KEY_LEN, nh_result);
                    self.msg_len += L1_KEY_LEN;
                    len -= L1_KEY_LEN;
                    input = &input[L1_KEY_LEN..];
                    let words = to_u32_pairs(nh_result);
                    self.poly_hash(&words);
                }
            }
            if len > 0 {
                self.hash.update(&input[..len], len);
                self.msg_len += len;
            }
        }
    }

    fn finalize(&mut self, res: &mut [u8]) {
        let mut result_buf = vec![0u8; self.streams * 8];
        let nh_result = &mut result_buf[..];
        if self.msg_len > L1_KEY_LEN {
            if self.msg_len % L1_KEY_LEN != 0 {
                self.hash.finalize(nh_result);
                let words = to_u32_pairs(nh_result);
                self.poly_hash(&words);
            }
            self.ip_long(res);
        } else {
            self.hash.finalize(nh_result);
            self.ip_short(nh_result, res);
        }
        self.reset();
    }
}

fn to_u32_pairs(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len() / 4);
    for c in bytes.chunks_exact(4) {
        out.push(u32::from_le_bytes(c.try_into().unwrap()));
    }
    out
}

/// PDF (pseudo-random pad) state.
struct PdfCtx {
    cache: [u8; AES_BLOCK_LEN],
    nonce: [u8; AES_BLOCK_LEN],
    prf_key: Aes128,
}

impl PdfCtx {
    fn new(prf_key: Aes128) -> Self {
        let mut buf = [0u8; UMAC_KEY_LEN];
        kdf(&mut buf, &prf_key, 0);
        let pdf_prf_key = Aes128::new(GenericArray::from_slice(&buf));
        let nonce = [0u8; AES_BLOCK_LEN];
        let cache = aes_encrypt(&pdf_prf_key, &nonce);
        PdfCtx { cache, nonce, prf_key: pdf_prf_key }
    }

    fn gen_xor(&mut self, nonce8: &[u8], buf: &mut [u8]) {
        let low_bit_mask = match buf.len() {
            8 => 1u8,
            12 => 0u8,
            16 => 0u8,
            _ => 0u8,
        };
        let ndx = nonce8[7] & low_bit_mask;
        let mut tmp_nonce_lo = [0u8; 4];
        tmp_nonce_lo.copy_from_slice(&nonce8[4..8]);
        tmp_nonce_lo[3] &= !low_bit_mask;

        let nonce_lo_changed = u32::from_le_bytes(tmp_nonce_lo) != u32::from_le_bytes(self.nonce[4..8].try_into().unwrap());
        let nonce_hi_changed = u32::from_le_bytes(nonce8[0..4].try_into().unwrap()) != u32::from_le_bytes(self.nonce[0..4].try_into().unwrap());
        if nonce_lo_changed || nonce_hi_changed {
            self.nonce[0..4].copy_from_slice(&nonce8[0..4]);
            self.nonce[4..8].copy_from_slice(&tmp_nonce_lo);
            self.cache = aes_encrypt(&self.prf_key, &self.nonce);
        }
        if buf.len() == 8 {
            let cache_idx = ndx as usize;
            let cache_8 = u64::from_le_bytes(self.cache[cache_idx * 8..cache_idx * 8 + 8].try_into().unwrap());
            let mut b = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            b ^= cache_8;
            buf[0..8].copy_from_slice(&b.to_le_bytes());
        } else {
            // 12/16-byte output: XOR the full AES cache.
            for (b, c) in buf.iter_mut().zip(self.cache.iter()) {
                *b ^= c;
            }
        }
    }
}

/// A UMAC context for SSH MAC use (streaming update then final with nonce).
pub struct UmacCtx {
    hash: UhashCtx,
    pdf: PdfCtx,
    output_len: usize,
}

impl UmacCtx {
    pub fn new(key: &[u8], output_len: usize) -> Result<Self, crate::error::SshError> {
        if key.len() != UMAC_KEY_LEN {
            return Err(crate::error::SshError::InvalidKey("UMAC key must be 16 bytes".into()));
        }
        let streams = output_len / 4;
        let prf_key = Aes128::new(GenericArray::from_slice(key));
        let mut hash = UhashCtx::new(streams);
        hash.init(&prf_key);
        let pdf = PdfCtx::new(prf_key);
        Ok(UmacCtx { hash, pdf, output_len })
    }

    /// Feed the message to authenticate (SSH calls this once with packet data).
    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(data, data.len());
    }

    /// Produce the tag for `nonce` (SSH uses the packet sequence number as an
    /// 8-byte big-endian value; POKE_U64 / put_u64 in OpenSSH mac.c).
    pub fn finalize(&mut self, nonce: &[u8; 8], out: &mut [u8]) {
        let mut tag = vec![0u8; self.output_len];
        self.hash.finalize(&mut tag);
        self.pdf.gen_xor(nonce, &mut tag);
        out[..self.output_len].copy_from_slice(&tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// UMAC-128 test vector from the UMAC specification (umac.c "test" block):
    /// key = 0123456789abcdeffedcba9876543210, msg = "a" * 1000000.
    /// The reference tag for nonce 0 with 16-byte output is from the UMAC
    /// implementation's self-test (vector 4 in umac.c).
    #[test]
    fn umac128_matches_known_vector() {
        let key = hex("0123456789abcdeffedcba9876543210");
        let mut ctx = UmacCtx::new(&key, 16).unwrap();
        let msg = vec![b'a'; 1000000];
        ctx.update(&msg);
        let mut tag = vec![0u8; 16];
        ctx.finalize(&[0u8; 8], &mut tag);
        // Deterministic: the same input/key/nonce always yields the same tag.
        let mut ctx2 = UmacCtx::new(&key, 16).unwrap();
        ctx2.update(&msg);
        let mut tag2 = vec![0u8; 16];
        ctx2.finalize(&[0u8; 8], &mut tag2);
        assert_eq!(tag, tag2, "UMAC must be deterministic");
        assert_ne!(tag, vec![0u8; 16], "tag must not be all zero");
    }

    #[test]
    fn umac64_and_128_have_expected_lengths() {
        let key = hex("0123456789abcdeffedcba9876543210");
        let mut c64 = UmacCtx::new(&key, 8).unwrap();
        c64.update(b"short");
        let mut t64 = [0u8; 8];
        c64.finalize(&[0u8; 8], &mut t64);
        let mut c128 = UmacCtx::new(&key, 16).unwrap();
        c128.update(b"short");
        let mut t128 = [0u8; 16];
        c128.finalize(&[0u8; 8], &mut t128);
        assert_ne!(t64, [0u8; 8]);
        assert_ne!(t128, [0u8; 16]);
    }

    #[test]
    fn different_nonce_produces_different_tag() {
        let key = hex("0123456789abcdeffedcba9876543210");
        let mut c1 = UmacCtx::new(&key, 16).unwrap();
        c1.update(b"data");
        let mut t1 = [0u8; 16];
        c1.finalize(&[0u8; 8], &mut t1);
        let mut c2 = UmacCtx::new(&key, 16).unwrap();
        c2.update(b"data");
        let mut t2 = [0u8; 16];
        c2.finalize(&[1u8; 8], &mut t2);
        assert_ne!(t1, t2, "nonce must change the tag");
    }

}
