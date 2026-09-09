use crate::error::{Result, SshError};
use crate::encoding::*;
use crate::cipher::SshCipher;
use crate::mac::SshMac;
use crate::kex::*;
use crate::msg;
use std::io::{Read, Write};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

pub const MAX_PACKET_SIZE: usize = 256 * 1024;

const DEFAULT_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group-exchange-sha1",
    "ext-info-c",
    "ext-info-s",
];

const DEFAULT_HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

const DEFAULT_CIPHERS: &[&str] = &[
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
    "3des-cbc",
];

const DEFAULT_MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-sha1-96",
    "none",
];

fn filter_algos<'a>(defaults: &'a [&'a str], config: Option<&[String]>) -> Vec<&'a str> {
    match config {
        Some(list) if !list.is_empty() => defaults
            .iter()
            .copied()
            .filter(|d| list.iter().any(|c| c.as_str() == *d))
            .collect(),
        _ => defaults.to_vec(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexState {
    Initial,
    KexInitSent,
    KexInitReceived,
    KexDhInitSent,
    KexDhReplyReceived,
    NewKeysSent,
    NewKeysReceived,
    RekeyInProgress,
    Established,
}

#[derive(Clone, Debug)]
pub struct AlgorithmNegotiation {
    pub kex_algorithm: String,
    pub host_key_algorithm: String,
    pub client_to_server_cipher: String,
    pub server_to_client_cipher: String,
    pub client_to_server_mac: String,
    pub server_to_client_mac: String,
    pub client_to_server_compression: String,
    pub server_to_client_compression: String,
}

pub struct SshTransport {
    pub state: KexState,
    pub session_id: Option<Vec<u8>>,
    pub kex_algorithm: Option<Box<dyn KexAlgorithm>>,
    pub client_to_server_cipher: Option<Box<dyn SshCipher>>,
    pub server_to_client_cipher: Option<Box<dyn SshCipher>>,
    pub client_to_server_mac: Option<Box<dyn SshMac>>,
    pub server_to_client_mac: Option<Box<dyn SshMac>>,
    pub client_to_server_compression: String,
    pub server_to_client_compression: String,
    pub compression_active_c2s: bool,
    pub compression_active_s2c: bool,
    pub compression_enabled: bool,
    pub client_version: Vec<u8>,
    pub server_version: Vec<u8>,
    pub client_kex_init: Vec<u8>,
    pub server_kex_init: Vec<u8>,
    pub outgoing_seq: u64,
    pub incoming_seq: u64,
    pub exchange: Option<KexExchange>,
    pub last_rekey_bytes: u64,
    pub last_rekey_instant: std::time::Instant,
}

impl SshTransport {
    pub fn new() -> Self {
        SshTransport {
            state: KexState::Initial,
            session_id: None,
            kex_algorithm: None,
            client_to_server_cipher: None,
            server_to_client_cipher: None,
            client_to_server_mac: None,
            server_to_client_mac: None,
            client_to_server_compression: "none".to_string(),
            server_to_client_compression: "none".to_string(),
            compression_active_c2s: false,
            compression_active_s2c: false,
            compression_enabled: true,
            client_version: msg::SSH_VERSION.as_bytes().to_vec(),
            server_version: Vec::new(),
            client_kex_init: Vec::new(),
            server_kex_init: Vec::new(),
            outgoing_seq: 0,
            incoming_seq: 0,
            exchange: None,
            last_rekey_bytes: 0,
            last_rekey_instant: std::time::Instant::now(),
        }
    }

    pub fn build_kex_init(
        &mut self,
        host_key_algorithms: Option<&[String]>,
        kex_algorithms: Option<&[String]>,
        ciphers: Option<&[String]>,
        macs: Option<&[String]>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(msg::SSH_MSG_KEXINIT);
        let mut cookie = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cookie);
        payload.extend_from_slice(&cookie);

        let kex_list: Vec<&str> = filter_algos(DEFAULT_KEX, kex_algorithms);
        payload.extend(encode_name_list(&kex_list));

        let host_key_list: Vec<&str> = match host_key_algorithms {
            Some(algs) if !algs.is_empty() => algs.iter().map(|s| s.as_str()).collect(),
            _ => DEFAULT_HOST_KEYS.to_vec(),
        };
        payload.extend(encode_name_list(&host_key_list));

        let cipher_list: Vec<&str> = filter_algos(DEFAULT_CIPHERS, ciphers);
        payload.extend(encode_name_list(&cipher_list));
        payload.extend(encode_name_list(&cipher_list));

        let mac_list: Vec<&str> = filter_algos(DEFAULT_MACS, macs);
        payload.extend(encode_name_list(&mac_list));
        payload.extend(encode_name_list(&mac_list));

        let comp_list: Vec<&str> = if self.compression_enabled {
            vec!["none", "zlib@openssh.com"]
        } else {
            vec!["none"]
        };
        payload.extend(encode_name_list(&comp_list));
        payload.extend(encode_name_list(&comp_list));

        payload.extend(encode_name_list(&[]));
        payload.extend(encode_name_list(&[]));

        payload.extend_from_slice(&[0u8; 5]);

        self.client_kex_init = payload.clone();
        payload
    }

    pub fn prepare_rekey(&mut self) -> Vec<u8> {
        let mut cookie = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cookie);
        let mut payload = Vec::new();
        payload.push(msg::SSH_MSG_KEXINIT);
        payload.extend_from_slice(&cookie);
        payload.extend(self.client_kex_init[17..].to_vec());
        self.client_kex_init = payload.clone();
        payload
    }

    pub const REKEY_BYTES: u64 = 1 << 30;
    pub const REKEY_SECONDS: u64 = 3600;

    pub fn needs_rekey(&self, total_bytes: u64, elapsed_secs: u64) -> bool {
        total_bytes.saturating_sub(self.last_rekey_bytes) >= Self::REKEY_BYTES
            || elapsed_secs >= Self::REKEY_SECONDS
    }

    pub fn total_bytes(&self) -> u64 {
        self.outgoing_seq.saturating_add(self.incoming_seq).saturating_mul(1400)
    }

    pub fn negotiate_algorithms(
        client_kex: &[u8],
        server_kex: &[u8],
    ) -> Result<AlgorithmNegotiation> {
        let mut cr = &client_kex[17..];

        let client_kex_algos = SshNameList::decode(&mut cr)?;
        let client_host_key = SshNameList::decode(&mut cr)?;
        let client_ciphers_cs = SshNameList::decode(&mut cr)?;
        let client_ciphers_sc = SshNameList::decode(&mut cr)?;
        let client_macs_cs = SshNameList::decode(&mut cr)?;
        let client_macs_sc = SshNameList::decode(&mut cr)?;
        let client_comps_cs = SshNameList::decode(&mut cr)?;
        let client_comps_sc = SshNameList::decode(&mut cr)?;

        let mut sr = &server_kex[17..];

        let server_kex_algos = SshNameList::decode(&mut sr)?;
        let server_host_key = SshNameList::decode(&mut sr)?;
        let server_ciphers_cs = SshNameList::decode(&mut sr)?;
        let server_ciphers_sc = SshNameList::decode(&mut sr)?;
        let server_macs_cs = SshNameList::decode(&mut sr)?;
        let server_macs_sc = SshNameList::decode(&mut sr)?;
        let server_comps_cs = SshNameList::decode(&mut sr)?;
        let server_comps_sc = SshNameList::decode(&mut sr)?;

        let kex = choose_algorithm(&client_kex_algos.0, &server_kex_algos.0)
            .ok_or_else(|| SshError::KexFailed("no common key exchange algorithm".into()))?;
        let host_key = choose_algorithm(&client_host_key.0, &server_host_key.0)
            .ok_or_else(|| SshError::KexFailed("no common host key algorithm".into()))?;
        let cipher_cs = choose_algorithm(&client_ciphers_cs.0, &server_ciphers_cs.0)
            .ok_or_else(|| SshError::KexFailed("no common client-to-server cipher".into()))?;
        let cipher_sc = choose_algorithm(&client_ciphers_sc.0, &server_ciphers_sc.0)
            .ok_or_else(|| SshError::KexFailed("no common server-to-client cipher".into()))?;
        let mac_cs = choose_algorithm(&client_macs_cs.0, &server_macs_cs.0)
            .ok_or_else(|| SshError::KexFailed("no common client-to-server mac".into()))?;
        let mac_sc = choose_algorithm(&client_macs_sc.0, &server_macs_sc.0)
            .ok_or_else(|| SshError::KexFailed("no common server-to-client mac".into()))?;
        let comp_cs = choose_algorithm(&client_comps_cs.0, &server_comps_cs.0)
            .unwrap_or_else(|| "none".to_string());
        let comp_sc = choose_algorithm(&client_comps_sc.0, &server_comps_sc.0)
            .unwrap_or_else(|| "none".to_string());

        Ok(AlgorithmNegotiation {
            kex_algorithm: kex,
            host_key_algorithm: host_key,
            client_to_server_cipher: cipher_cs,
            server_to_client_cipher: cipher_sc,
            client_to_server_mac: mac_cs,
            server_to_client_mac: mac_sc,
            client_to_server_compression: comp_cs,
            server_to_client_compression: comp_sc,
        })
    }

    pub fn create_kex_algorithm(name: &str) -> Result<Box<dyn KexAlgorithm>> {
        match name {
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
                Ok(Box::new(Curve25519Kex::new()))
            }
            "ecdh-sha2-nistp256" => {
                Ok(Box::new(EcdhP256Kex::new()))
            }
            "ecdh-sha2-nistp384" => {
                Ok(Box::new(EcdhP384Kex::new()))
            }
            "ecdh-sha2-nistp521" => {
                Ok(Box::new(EcdhP521Kex::new()))
            }
            "diffie-hellman-group14-sha256" => {
                Ok(Box::new(ModpKex::group14_sha256()))
            }
            "diffie-hellman-group14-sha1" => {
                Ok(Box::new(ModpKex::group14_sha1()))
            }
            "diffie-hellman-group16-sha512" => {
                Ok(Box::new(ModpKex::group16_sha512()))
            }
            "diffie-hellman-group18-sha512" => {
                Ok(Box::new(ModpKex::group18_sha512()))
            }
            "diffie-hellman-group-exchange-sha256" => {
                Ok(Box::new(ModpKex::gex_sha256()))
            }
            "diffie-hellman-group-exchange-sha1" => {
                Ok(Box::new(ModpKex::gex_sha1()))
            }
            "ext-info-c" | "ext-info-s" => {
                Err(SshError::UnsupportedAlgorithm("ext-info is a pseudo-kex, not negotiable alone".into()))
            }
            _ => Err(SshError::UnsupportedAlgorithm(format!("kex: {}", name))),
        }
    }

    pub fn install_new_keys(
        &mut self,
        negotiation: &AlgorithmNegotiation,
        hash_name: &str,
        shared_secret: &[u8],
        exchange_hash: &[u8],
        session_id: &[u8],
    ) -> Result<()> {
        self.client_to_server_compression = negotiation.client_to_server_compression.clone();
        self.server_to_client_compression = negotiation.server_to_client_compression.clone();

        let key_len = crate::cipher::create_cipher(&negotiation.client_to_server_cipher)?.key_len();
        let iv_len = crate::cipher::create_cipher(&negotiation.client_to_server_cipher)?.iv_len();
        let mac_len = crate::mac::create_mac(&negotiation.client_to_server_mac)?.key_len();

        let c2s_iv = derive_initial_iv(hash_name, shared_secret, exchange_hash, session_id, iv_len);
        let c2s_key = derive_encryption_key(hash_name, shared_secret, exchange_hash, session_id, key_len);
        let c2s_mac_key = derive_integrity_key(hash_name, shared_secret, exchange_hash, session_id, mac_len);

        let s2c_key_len = crate::cipher::create_cipher(&negotiation.server_to_client_cipher)?.key_len();
        let s2c_iv_len = crate::cipher::create_cipher(&negotiation.server_to_client_cipher)?.iv_len();
        let s2c_mac_len = crate::mac::create_mac(&negotiation.server_to_client_mac)?.key_len();

        let s2c_iv = derive_initial_iv(hash_name, shared_secret, exchange_hash, session_id, s2c_iv_len);
        let s2c_key = derive_encryption_key(hash_name, shared_secret, exchange_hash, session_id, s2c_key_len);
        let s2c_mac_key = derive_integrity_key(hash_name, shared_secret, exchange_hash, session_id, s2c_mac_len);

        let mut c2s_cipher = crate::cipher::create_cipher(&negotiation.client_to_server_cipher)?;
        c2s_cipher.set_key(&c2s_key)?;
        c2s_cipher.set_iv(&c2s_iv)?;
        self.client_to_server_cipher = Some(c2s_cipher);

        let mut s2c_cipher = crate::cipher::create_cipher(&negotiation.server_to_client_cipher)?;
        s2c_cipher.set_key(&s2c_key)?;
        s2c_cipher.set_iv(&s2c_iv)?;
        self.server_to_client_cipher = Some(s2c_cipher);

        let mut c2s_mac = crate::mac::create_mac(&negotiation.client_to_server_mac)?;
        c2s_mac.set_key(&c2s_mac_key)?;
        self.client_to_server_mac = Some(c2s_mac);

        let mut s2c_mac = crate::mac::create_mac(&negotiation.server_to_client_mac)?;
        s2c_mac.set_key(&s2c_mac_key)?;
        self.server_to_client_mac = Some(s2c_mac);

        Ok(())
    }
}

fn choose_algorithm(client: &[String], server: &[String]) -> Option<String> {
    for c in client {
        if server.contains(c) {
            return Some(c.clone());
        }
    }
    None
}

pub async fn send_version_string(stream: &mut (impl AsyncWrite + Unpin), version: &[u8]) -> Result<()> {
    stream.write_all(version).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_version_string(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut version = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await?;
        if buf[0] == b'\n' {
            break;
        }
        if buf[0] != b'\r' {
            version.push(buf[0]);
        }
        if version.len() > 255 {
            return Err(SshError::Protocol("version string too long".into()));
        }
    }
    Ok(version)
}

pub async fn send_raw_packet(stream: &mut (impl AsyncWrite + Unpin), payload: &[u8]) -> Result<()> {
    let base = 1 + payload.len();
    let remainder = base % 8;
    let mut padding_len = if remainder == 0 { 0 } else { 8 - remainder };
    if padding_len < 4 { padding_len += 8; }
    let mut padding = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
    let body_len = base + padding_len;
    let packet_len_field = (4 + body_len) as u32;

    let mut packet = Vec::new();
    packet.extend(&packet_len_field.to_be_bytes());
    packet.push(padding_len as u8);
    packet.extend(payload);
    packet.extend(&padding[..padding_len]);

    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn receive_raw_packet(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;

    if total_len > MAX_PACKET_SIZE || total_len < 12 {
        return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
    }
    let body_len = total_len - 4;

    let mut rest = vec![0u8; body_len];
    stream.read_exact(&mut rest).await?;

    let padding_len = rest[0] as usize;
    let payload_len = body_len - 1 - padding_len;

    if payload_len == 0 {
        return Err(SshError::InvalidPacket("empty payload".into()));
    }

    let payload = rest[1..1 + payload_len].to_vec();
    Ok(payload)
}

pub async fn send_encrypted_packet(
    stream: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
    transport: &mut SshTransport,
    is_newkeys: bool,
    is_aead: bool,
) -> Result<()> {
    if transport.client_to_server_cipher.is_none() || transport.client_to_server_mac.is_none() {
        return send_raw_packet(stream, payload).await;
    }

    let payload: Vec<u8> = if !is_newkeys
        && (transport.client_to_server_compression == "zlib"
            || (transport.client_to_server_compression == "zlib@openssh.com"
                && transport.compression_active_c2s))
    {
        zlib_compress(payload)?
    } else {
        payload.to_vec()
    };

    let cipher = transport.client_to_server_cipher.as_mut().unwrap();
    let mac = transport.client_to_server_mac.as_ref().unwrap();
    let block_size = cipher.block_size().max(8);
    let seq = transport.outgoing_seq;

    if is_aead {
        let tag_len = cipher.tag_len();
        let base = 1 + payload.len();
        let remainder = base % block_size;
        let mut padding_len = if remainder == 0 { 0 } else { block_size - remainder };
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = (4 + body_len) as u32;

        let mut packet = Vec::new();
        packet.extend(&packet_len_field.to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend(&payload);
        packet.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet[4..])?;
        packet.truncate(4);
        packet.extend(&ciphertext);

        stream.write_all(&packet).await?;
    } else {
        let base = 1 + payload.len();
        let remainder = base % block_size;
        let mut padding_len = if remainder == 0 { 0 } else { block_size - remainder };
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = (4 + body_len) as u32;
        let len_bytes = packet_len_field.to_be_bytes();

        let mut packet_data = Vec::new();
        packet_data.push(padding_len as u8);
        packet_data.extend(&payload);
        packet_data.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet_data)?;
        let mac_tag = if mac.as_ref().is_etm() {
            let mut etm_input = Vec::with_capacity(4 + ciphertext.len());
            etm_input.extend_from_slice(&len_bytes);
            etm_input.extend_from_slice(&ciphertext);
            mac.as_ref().compute_tag(seq, &etm_input)?
        } else {
            mac.as_ref().compute_tag(seq, &packet_data)?
        };

        let mut packet = Vec::new();
        packet.extend_from_slice(&len_bytes);
        packet.extend(&ciphertext);
        packet.extend(&mac_tag);

        stream.write_all(&packet).await?;
    }

    if !is_newkeys {
        transport.outgoing_seq += 1;
    }
    stream.flush().await?;
    Ok(())
}

pub async fn receive_encrypted_packet(
    stream: &mut (impl AsyncRead + Unpin),
    transport: &mut SshTransport,
    is_newkeys: bool,
    is_aead: bool,
) -> Result<Vec<u8>> {
    if transport.server_to_client_cipher.is_none() || transport.server_to_client_mac.is_none() {
        return receive_raw_packet(stream).await;
    }

    let cipher = transport.server_to_client_cipher.as_mut().unwrap();
    let mac = transport.server_to_client_mac.as_ref().unwrap();
    let seq = transport.incoming_seq;

    let payload = if is_aead {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let tag_len = cipher.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < 12 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }
        let body_len = total_len - 4;

        let mut ciphertext = vec![0u8; body_len + tag_len];
        stream.read_exact(&mut ciphertext).await?;

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        let padding_len = plaintext[0] as usize;
        let payload_len = body_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
        payload
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let block_size = cipher.block_size().max(8);
        let mac_len = mac.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < 12 || (total_len - 4) % block_size != 0 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }
        let body_len = total_len - 4;

        let mut ciphertext = vec![0u8; body_len];
        stream.read_exact(&mut ciphertext).await?;
        let mut mac_buf = vec![0u8; mac_len];
        stream.read_exact(&mut mac_buf).await?;

        let mac_ok = if mac.as_ref().is_etm() {
            let mut etm_input = Vec::with_capacity(4 + ciphertext.len());
            etm_input.extend_from_slice(&len_buf);
            etm_input.extend_from_slice(&ciphertext);
            mac.as_ref().verify_tag(seq, &etm_input, &mac_buf)?
        } else {
            true
        };
        if mac.as_ref().is_etm() && !mac_ok {
            return Err(SshError::DecryptionFailed);
        }

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        if !mac.as_ref().is_etm() {
            let mac_ok = mac.as_ref().verify_tag(seq, &plaintext, &mac_buf)?;
            if !mac_ok {
                return Err(SshError::DecryptionFailed);
            }
        }

        let padding_len = plaintext[0] as usize;
        let payload_len = body_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
        payload
    };

    if !is_newkeys
        && (transport.server_to_client_compression == "zlib"
            || (transport.server_to_client_compression == "zlib@openssh.com"
                && transport.compression_active_s2c))
    {
        Ok(zlib_decompress(&payload)?)
    } else {
        Ok(payload)
    }
}

pub async fn send_encrypted_packet_server(
    stream: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
    transport: &mut SshTransport,
    is_newkeys: bool,
    is_aead: bool,
) -> Result<()> {
    if transport.server_to_client_cipher.is_none() || transport.server_to_client_mac.is_none() {
        return send_raw_packet(stream, payload).await;
    }

    let payload: Vec<u8> = if !is_newkeys
        && (transport.server_to_client_compression == "zlib"
            || (transport.server_to_client_compression == "zlib@openssh.com"
                && transport.compression_active_s2c))
    {
        zlib_compress(payload)?
    } else {
        payload.to_vec()
    };

    let cipher = transport.server_to_client_cipher.as_mut().unwrap();
    let mac = transport.server_to_client_mac.as_ref().unwrap();
    let block_size = cipher.block_size().max(8);
    let seq = transport.outgoing_seq;

    if is_aead {
        let tag_len = cipher.tag_len();
        let base = 1 + payload.len();
        let remainder = base % block_size;
        let mut padding_len = if remainder == 0 { 0 } else { block_size - remainder };
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = (4 + body_len) as u32;

        let mut packet = Vec::new();
        packet.extend(&packet_len_field.to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend(&payload);
        packet.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet[4..])?;
        packet.truncate(4);
        packet.extend(&ciphertext);

        stream.write_all(&packet).await?;
    } else {
        let base = 1 + payload.len();
        let remainder = base % block_size;
        let mut padding_len = if remainder == 0 { 0 } else { block_size - remainder };
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = (4 + body_len) as u32;
        let len_bytes = packet_len_field.to_be_bytes();

        let mut packet_data = Vec::new();
        packet_data.push(padding_len as u8);
        packet_data.extend(&payload);
        packet_data.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet_data)?;
        let mac_tag = if mac.as_ref().is_etm() {
            let mut etm_input = Vec::with_capacity(4 + ciphertext.len());
            etm_input.extend_from_slice(&len_bytes);
            etm_input.extend_from_slice(&ciphertext);
            mac.as_ref().compute_tag(seq, &etm_input)?
        } else {
            mac.as_ref().compute_tag(seq, &packet_data)?
        };

        let mut packet = Vec::new();
        packet.extend_from_slice(&len_bytes);
        packet.extend(&ciphertext);
        packet.extend(&mac_tag);

        stream.write_all(&packet).await?;
    }

    if !is_newkeys {
        transport.outgoing_seq += 1;
    }
    stream.flush().await?;
    Ok(())
}

pub async fn receive_encrypted_packet_server(
    stream: &mut (impl AsyncRead + Unpin),
    transport: &mut SshTransport,
    is_newkeys: bool,
    is_aead: bool,
) -> Result<Vec<u8>> {
    if transport.client_to_server_cipher.is_none() || transport.client_to_server_mac.is_none() {
        return receive_raw_packet(stream).await;
    }

    let cipher = transport.client_to_server_cipher.as_mut().unwrap();
    let mac = transport.client_to_server_mac.as_ref().unwrap();
    let seq = transport.incoming_seq;

    let payload = if is_aead {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let tag_len = cipher.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < 12 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }
        let body_len = total_len - 4;

        let mut ciphertext = vec![0u8; body_len + tag_len];
        stream.read_exact(&mut ciphertext).await?;

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        let padding_len = plaintext[0] as usize;
        let payload_len = body_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
        payload
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let block_size = cipher.block_size().max(8);
        let mac_len = mac.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < 12 || (total_len - 4) % block_size != 0 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }
        let body_len = total_len - 4;

        let mut ciphertext = vec![0u8; body_len];
        stream.read_exact(&mut ciphertext).await?;
        let mut mac_buf = vec![0u8; mac_len];
        stream.read_exact(&mut mac_buf).await?;

        let mac_ok = if mac.as_ref().is_etm() {
            let mut etm_input = Vec::with_capacity(4 + ciphertext.len());
            etm_input.extend_from_slice(&len_buf);
            etm_input.extend_from_slice(&ciphertext);
            mac.as_ref().verify_tag(seq, &etm_input, &mac_buf)?
        } else {
            true
        };
        if mac.as_ref().is_etm() && !mac_ok {
            return Err(SshError::DecryptionFailed);
        }

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        if !mac.as_ref().is_etm() {
            let mac_ok = mac.as_ref().verify_tag(seq, &plaintext, &mac_buf)?;
            if !mac_ok {
                return Err(SshError::DecryptionFailed);
            }
        }

        let padding_len = plaintext[0] as usize;
        let payload_len = body_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
        payload
    };

    if !is_newkeys
        && (transport.client_to_server_compression == "zlib"
            || (transport.client_to_server_compression == "zlib@openssh.com"
                && transport.compression_active_c2s))
    {
        Ok(zlib_decompress(&payload)?)
    } else {
        Ok(payload)
    }
}

fn zlib_compress(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(|e| SshError::Compression(e.to_string()))?;
    encoder.finish().map_err(|e| SshError::Compression(e.to_string()))
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| SshError::Compression(e.to_string()))?;
    Ok(out)
}
