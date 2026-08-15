use crate::error::{Result, SshError};
use crate::encoding::*;
use crate::cipher::SshCipher;
use crate::mac::SshMac;
use crate::kex::*;
use crate::msg;
use std::io::{Read, Write};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

pub const MAX_PACKET_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexState {
    Initial,
    KexInitSent,
    KexInitReceived,
    KexDhInitSent,
    KexDhReplyReceived,
    NewKeysSent,
    NewKeysReceived,
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
    pub client_version: Vec<u8>,
    pub server_version: Vec<u8>,
    pub client_kex_init: Vec<u8>,
    pub server_kex_init: Vec<u8>,
    pub outgoing_seq: u64,
    pub incoming_seq: u64,
    pub exchange: Option<KexExchange>,
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
            client_version: msg::SSH_VERSION.as_bytes().to_vec(),
            server_version: Vec::new(),
            client_kex_init: Vec::new(),
            server_kex_init: Vec::new(),
            outgoing_seq: 0,
            incoming_seq: 0,
            exchange: None,
        }
    }

    pub fn build_kex_init(&mut self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(msg::SSH_MSG_KEXINIT);
        let mut cookie = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cookie);
        payload.extend_from_slice(&cookie);

        payload.extend(encode_name_list(&[
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group14-sha256",
        ]));

        payload.extend(encode_name_list(&[
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "rsa-sha2-256",
            "ssh-rsa",
        ]));

        payload.extend(encode_name_list(&[
            "chacha20-poly1305@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
        ]));

        payload.extend(encode_name_list(&[
            "chacha20-poly1305@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
        ]));

        payload.extend(encode_name_list(&["hmac-sha2-256", "hmac-sha2-512"]));
        payload.extend(encode_name_list(&["hmac-sha2-256", "hmac-sha2-512"]));

        payload.extend(encode_name_list(&["none"]));
        payload.extend(encode_name_list(&["none"]));

        payload.extend(encode_name_list(&[]));
        payload.extend(encode_name_list(&[]));

        payload.extend_from_slice(&[0u8; 4]);

        self.client_kex_init = payload.clone();
        payload
    }

    pub fn negotiate_algorithms(
        client_kex: &[u8],
        server_kex: &[u8],
    ) -> Result<AlgorithmNegotiation> {
        let mut cr = &client_kex[17..];
        cr = &cr[16..];

        let client_kex_algos = SshNameList::decode(&mut cr)?;
        let client_host_key = SshNameList::decode(&mut cr)?;
        let client_ciphers_cs = SshNameList::decode(&mut cr)?;
        let client_ciphers_sc = SshNameList::decode(&mut cr)?;
        let client_macs_cs = SshNameList::decode(&mut cr)?;
        let client_macs_sc = SshNameList::decode(&mut cr)?;
        let _client_comps_cs = SshNameList::decode(&mut cr)?;
        let _client_comps_sc = SshNameList::decode(&mut cr)?;

        let mut sr = &server_kex[17..];
        sr = &sr[16..];

        let server_kex_algos = SshNameList::decode(&mut sr)?;
        let server_host_key = SshNameList::decode(&mut sr)?;
        let server_ciphers_cs = SshNameList::decode(&mut sr)?;
        let server_ciphers_sc = SshNameList::decode(&mut sr)?;
        let server_macs_cs = SshNameList::decode(&mut sr)?;
        let server_macs_sc = SshNameList::decode(&mut sr)?;
        let _server_comps_cs = SshNameList::decode(&mut sr)?;
        let _server_comps_sc = SshNameList::decode(&mut sr)?;

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

        Ok(AlgorithmNegotiation {
            kex_algorithm: kex,
            host_key_algorithm: host_key,
            client_to_server_cipher: cipher_cs,
            server_to_client_cipher: cipher_sc,
            client_to_server_mac: mac_cs,
            server_to_client_mac: mac_sc,
            client_to_server_compression: "none".to_string(),
            server_to_client_compression: "none".to_string(),
        })
    }

    pub fn create_kex_algorithm(name: &str) -> Result<Box<dyn KexAlgorithm>> {
        match name {
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
                Ok(Box::new(Curve25519Kex::new()))
            }
            "diffie-hellman-group14-sha256" => {
                Ok(Box::new(DhGroup14Kex::new()))
            }
            "ecdh-sha2-nistp256" => {
                Ok(Box::new(EcdhP256Kex::new()))
            }
            _ => Err(SshError::UnsupportedAlgorithm(format!("kex: {}", name))),
        }
    }

    pub fn install_new_keys(
        &mut self,
        negotiation: &AlgorithmNegotiation,
        shared_secret: &[u8],
        exchange_hash: &[u8],
        session_id: &[u8],
    ) -> Result<()> {
        let key_len = crate::cipher::create_cipher(&negotiation.client_to_server_cipher)?.key_len();
        let iv_len = crate::cipher::create_cipher(&negotiation.client_to_server_cipher)?.iv_len();
        let mac_len = crate::mac::create_mac(&negotiation.client_to_server_mac)?.key_len();

        let c2s_iv = derive_initial_iv(shared_secret, exchange_hash, session_id, iv_len);
        let c2s_key = derive_encryption_key(shared_secret, exchange_hash, session_id, key_len);
        let c2s_mac_key = derive_integrity_key(shared_secret, exchange_hash, session_id, mac_len);

        let s2c_key_len = crate::cipher::create_cipher(&negotiation.server_to_client_cipher)?.key_len();
        let s2c_iv_len = crate::cipher::create_cipher(&negotiation.server_to_client_cipher)?.iv_len();
        let s2c_mac_len = crate::mac::create_mac(&negotiation.server_to_client_mac)?.key_len();

        let s2c_iv = derive_initial_iv(shared_secret, exchange_hash, session_id, s2c_iv_len);
        let s2c_key = derive_encryption_key(shared_secret, exchange_hash, session_id, s2c_key_len);
        let s2c_mac_key = derive_integrity_key(shared_secret, exchange_hash, session_id, s2c_mac_len);

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
    let padding_len = if payload.len() <= 4 {
        8 - (payload.len() % 8)
    } else {
        8 - ((payload.len() + 4) % 8)
    };
    let padding_len = if padding_len < 4 { padding_len + 8 } else { padding_len };
    let mut padding = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
    let total_len = 1 + payload.len() + padding_len;

    let mut packet = Vec::new();
    packet.extend(&(total_len as u32).to_be_bytes());
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

    let mut rest = vec![0u8; total_len];
    stream.read_exact(&mut rest).await?;

    let padding_len = rest[0] as usize;
    let payload_len = total_len - 1 - padding_len;

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

    let cipher = transport.client_to_server_cipher.as_mut().unwrap();
    let mac = transport.client_to_server_mac.as_ref().unwrap();
    let block_size = cipher.block_size().max(8);
    let seq = transport.outgoing_seq;

    if is_aead {
        let tag_len = cipher.tag_len();
        let overhead = 5 + tag_len;
        let mut padding_len = block_size - ((payload.len() + overhead) % block_size);
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
        let total_len = 1 + payload.len() + padding_len;

        let mut packet = Vec::new();
        packet.extend(&(total_len as u32).to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend(payload);
        packet.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet[4..])?;
        packet.truncate(4);
        packet.extend(&ciphertext);

        stream.write_all(&packet).await?;
    } else {
        let overhead = 5;
        let mut padding_len = block_size - ((payload.len() + overhead) % block_size);
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
        let total_len = 1 + payload.len() + padding_len;

        let mut packet_data = Vec::new();
        packet_data.push(padding_len as u8);
        packet_data.extend(payload);
        packet_data.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet_data)?;
        let mac_tag = mac.as_ref().compute_tag(seq, &packet_data)?;

        let mut packet = Vec::new();
        packet.extend(&(total_len as u32).to_be_bytes());
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

    if is_aead {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let tag_len = cipher.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < 12 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }

        let mut ciphertext = vec![0u8; total_len + tag_len];
        stream.read_exact(&mut ciphertext).await?;

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        let padding_len = plaintext[0] as usize;
        let payload_len = total_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
        Ok(payload)
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let block_size = cipher.block_size().max(8);
        let mac_len = mac.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < block_size || total_len % block_size != 0 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }

        let mut ciphertext = vec![0u8; total_len];
        stream.read_exact(&mut ciphertext).await?;
        let mut mac_buf = vec![0u8; mac_len];
        stream.read_exact(&mut mac_buf).await?;

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        let mac_ok = mac.as_ref().verify_tag(seq, &plaintext, &mac_buf)?;
        if !mac_ok {
            return Err(SshError::DecryptionFailed);
        }

        let padding_len = plaintext[0] as usize;
        let payload_len = total_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
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

    let cipher = transport.server_to_client_cipher.as_mut().unwrap();
    let mac = transport.server_to_client_mac.as_ref().unwrap();
    let block_size = cipher.block_size().max(8);
    let seq = transport.outgoing_seq;

    if is_aead {
        let tag_len = cipher.tag_len();
        let overhead = 5 + tag_len;
        let mut padding_len = block_size - ((payload.len() + overhead) % block_size);
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
        let total_len = 1 + payload.len() + padding_len;

        let mut packet = Vec::new();
        packet.extend(&(total_len as u32).to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend(payload);
        packet.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet[4..])?;
        packet.truncate(4);
        packet.extend(&ciphertext);

        stream.write_all(&packet).await?;
    } else {
        let overhead = 5;
        let mut padding_len = block_size - ((payload.len() + overhead) % block_size);
        if padding_len < 4 { padding_len += block_size; }
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
        let total_len = 1 + payload.len() + padding_len;

        let mut packet_data = Vec::new();
        packet_data.push(padding_len as u8);
        packet_data.extend(payload);
        packet_data.extend(&padding[..padding_len]);

        let ciphertext = cipher.encrypt(seq, &packet_data)?;
        let mac_tag = mac.as_ref().compute_tag(seq, &packet_data)?;

        let mut packet = Vec::new();
        packet.extend(&(total_len as u32).to_be_bytes());
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

    if is_aead {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let tag_len = cipher.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < 12 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }

        let mut ciphertext = vec![0u8; total_len + tag_len];
        stream.read_exact(&mut ciphertext).await?;

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        let padding_len = plaintext[0] as usize;
        let payload_len = total_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
        Ok(payload)
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let block_size = cipher.block_size().max(8);
        let mac_len = mac.tag_len();

        if total_len > MAX_PACKET_SIZE || total_len < block_size || total_len % block_size != 0 {
            return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
        }

        let mut ciphertext = vec![0u8; total_len];
        stream.read_exact(&mut ciphertext).await?;
        let mut mac_buf = vec![0u8; mac_len];
        stream.read_exact(&mut mac_buf).await?;

        let plaintext = cipher.decrypt(seq, &ciphertext)
            .map_err(|_| SshError::DecryptionFailed)?;

        let mac_ok = mac.as_ref().verify_tag(seq, &plaintext, &mac_buf)?;
        if !mac_ok {
            return Err(SshError::DecryptionFailed);
        }

        let padding_len = plaintext[0] as usize;
        let payload_len = total_len - 1 - padding_len;
        let payload = plaintext[1..1 + payload_len].to_vec();

        if !is_newkeys { transport.incoming_seq += 1; }
        Ok(payload)
    }
}

pub const REKEY_DATA_THRESHOLD: u64 = 1024 * 1024 * 1024;
pub const REKEY_TIME_THRESHOLD_SECS: u64 = 3600;

pub fn needs_rekey(transport: &SshTransport, bytes_transferred: u64, elapsed_secs: u64) -> bool {
    if transport.state != KexState::Established {
        return false;
    }
    bytes_transferred >= REKEY_DATA_THRESHOLD || elapsed_secs >= REKEY_TIME_THRESHOLD_SECS
}

impl SshTransport {
    pub fn total_bytes(&self) -> u64 {
        (self.outgoing_seq + self.incoming_seq) * 32768
    }

    pub fn prepare_rekey(&mut self) -> Vec<u8> {
        let kex_init = self.build_kex_init();
        self.state = KexState::KexInitSent;
        kex_init
    }
}
