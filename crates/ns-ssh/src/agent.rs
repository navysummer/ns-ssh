use crate::config::ResolvedConfig;
use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::hostkey::*;
use ssh_core::msg;
use rsa::traits::PublicKeyParts;
use std::path::PathBuf;
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;

pub struct SshAgent {
    socket_path: Option<PathBuf>,
}

impl SshAgent {
    pub fn new() -> Self {
        let socket_path = std::env::var("SSH_AUTH_SOCK")
            .ok()
            .map(PathBuf::from);

        SshAgent { socket_path }
    }

    pub fn is_available(&self) -> bool {
        self.socket_path.is_some() && self.socket_path.as_ref().map(|p| p.exists()).unwrap_or(false)
    }

    pub async fn request_identities(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let socket_path = self.socket_path.as_ref()
            .ok_or_else(|| SshError::Protocol("SSH agent not available".into()))?;

        let mut stream = UnixStream::connect(socket_path).await?;

        let mut request = Vec::new();
        let payload_len = 1u32; // just the request type
        request.extend(payload_len.to_be_bytes());
        request.push(SSH_AGENTC_REQUEST_IDENTITIES);

        stream.write_all(&request).await?;

        let mut response_len_buf = [0u8; 4];
        stream.read_exact(&mut response_len_buf).await?;
        let response_len = u32::from_be_bytes(response_len_buf) as usize;

        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await?;

        if response.is_empty() || response[0] == SSH_AGENT_FAILURE {
            return Ok(Vec::new());
        }

        if response[0] != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(SshError::Protocol("unexpected agent response".into()));
        }

        let mut r = &response[1..];
        let count = u32::decode(&mut r)? as usize;
        let mut identities = Vec::new();

        for _ in 0..count {
            let blob = SshBytes::decode(&mut r)?.0;
            let comment = SshString::decode(&mut r)?.as_str()?.to_string();
            identities.push((comment, blob));
        }

        Ok(identities)
    }

    pub async fn sign_request(
        &self,
        public_key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>> {
        let socket_path = self.socket_path.as_ref()
            .ok_or_else(|| SshError::Protocol("SSH agent not available".into()))?;

        let mut stream = UnixStream::connect(socket_path).await?;

        let mut payload = Vec::new();
        payload.push(SSH_AGENTC_SIGN_REQUEST);
        payload.extend(SshBytes(public_key_blob.to_vec()).0);
        payload.extend(SshBytes(data.to_vec()).0);
        payload.extend(flags.to_be_bytes());

        let mut request = Vec::new();
        request.extend((payload.len() as u32).to_be_bytes());
        request.extend_from_slice(&payload);

        stream.write_all(&request).await?;

        let mut response_len_buf = [0u8; 4];
        stream.read_exact(&mut response_len_buf).await?;
        let response_len = u32::from_be_bytes(response_len_buf) as usize;

        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await?;

        if response.is_empty() || response[0] == SSH_AGENT_FAILURE {
            return Err(SshError::AuthFailed("agent sign request failed".into()));
        }

        if response[0] != SSH_AGENT_SIGN_RESPONSE {
            return Err(SshError::Protocol("unexpected agent sign response".into()));
        }

        let mut r = &response[1..];
        let signature = SshBytes::decode(&mut r)?.0;
        Ok(signature)
    }
}

pub fn get_identity_files() -> Vec<PathBuf> {
    let mut files = Vec::new();

    if let Some(home) = dirs::home_dir() {
        let ssh_dir = home.join(".ssh");
        if ssh_dir.exists() {
            let candidates = [
                "id_ed25519",
                "id_ecdsa",
                "id_rsa",
                "id_dsa",
                "id_xmss",
            ];
            for name in &candidates {
                let path = ssh_dir.join(name);
                if path.exists() {
                    files.push(path);
                }
            }
        }
    }

    files
}

pub fn load_private_key(path: &std::path::Path) -> Result<Box<dyn HostKeySigner>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| SshError::InvalidKey(format!("cannot read {}: {}", path.display(), e)))?;

    let content = content.trim();

    let needs_password = content.contains("ENCRYPTED")
        || content.contains("Proc-Type: 4,ENCRYPTED")
        || (content.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
            && !content.contains("none"));

    let password: Option<String> = if needs_password {
        eprintln!("Key {} is encrypted", path.display());
        Some(prompt_password()?)
    } else {
        None
    };

    if content.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        load_openssh_key(content, password.as_deref())
    } else if content.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        load_pkcs1_key(content, password.as_deref())
    } else if content.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        load_ec_key(content, password.as_deref())
    } else if content.starts_with("-----BEGIN PRIVATE KEY-----") {
        load_pkcs8_key(content, password.as_deref())
    } else if content.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        load_pkcs8_key(content, password.as_deref())
    } else {
        Err(SshError::InvalidKey("unsupported key format".into()))
    }
}

fn prompt_password() -> Result<String> {
    use std::io::Write;
    eprint!("Enter passphrase: ");
    let _ = std::io::stderr().flush();
    let pass = rpassword::read_password()
        .map_err(|e| SshError::InvalidKey(format!("cannot read password: {}", e)))?;
    Ok(pass)
}

fn pem_decode(content: &str) -> Result<Vec<u8>> {
    let b64: String = content.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
        .map_err(|e| SshError::InvalidKey(format!("base64 decode: {}", e)))
}

fn aes_ctr_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    let mut out = ciphertext.to_vec();
    match key.len() {
        16 => {
            type A128Ctr = ctr::Ctr128BE<aes::Aes128>;
            let mut c = A128Ctr::new(key.into(), iv.into());
            c.apply_keystream(&mut out);
        }
        24 => {
            type A192Ctr = ctr::Ctr128BE<aes::Aes192>;
            let mut c = A192Ctr::new(key.into(), iv.into());
            c.apply_keystream(&mut out);
        }
        32 => {
            type A256Ctr = ctr::Ctr128BE<aes::Aes256>;
            let mut c = A256Ctr::new(key.into(), iv.into());
            c.apply_keystream(&mut out);
        }
        _ => return Err(SshError::InvalidKey(format!("unsupported AES key length: {}", key.len()))),
    }
    Ok(out)
}

fn bcrypt_pbkdf_derive(password: &[u8], salt: &[u8], rounds: u32, out_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut out)
        .map_err(|e| SshError::InvalidKey(format!("bcrypt pbkdf: {:?}", e)))?;
    Ok(out)
}

fn openssh_kdf_derive(kdf: &str, kdf_opts: &[u8], password: &str, out_len: usize) -> Result<Vec<u8>> {
    match kdf {
        "none" => Ok(vec![0u8; out_len]),
        "bcrypt" => {
            let mut r = kdf_opts;
            let salt = read_simplified_string_bytes(&mut r)?;
            let rounds = read_simplified_uint32(&mut r)?;
            bcrypt_pbkdf_derive(password.as_bytes(), &salt, rounds, out_len)
        }
        other => Err(SshError::InvalidKey(format!("unsupported KDF: {}", other))),
    }
}

fn openssh_decrypt_private_block(
    cipher_name: &str,
    key_and_iv: &[u8],
    priv_data_enc: &[u8],
) -> Result<Vec<u8>> {
    match cipher_name {
        "none" => Ok(priv_data_enc.to_vec()),
        "aes128-ctr" | "aes128-cbc" => {
            let (key, iv) = key_and_iv.split_at(16);
            aes_ctr_decrypt(key, iv, priv_data_enc)
        }
        "aes192-ctr" | "aes192-cbc" => {
            let (key, iv) = key_and_iv.split_at(24);
            let iv = if iv.len() >= 16 { &iv[..16] } else { iv };
            aes_ctr_decrypt(key, iv, priv_data_enc)
        }
        "aes256-ctr" | "aes256-cbc" => {
            let (key, rest) = key_and_iv.split_at(32);
            let iv = if rest.len() >= 16 { &rest[..16] } else { rest };
            aes_ctr_decrypt(key, iv, priv_data_enc)
        }
        other => Err(SshError::InvalidKey(format!("unsupported cipher: {}", other))),
    }
}

fn load_openssh_key(content: &str, password: Option<&str>) -> Result<Box<dyn HostKeySigner>> {
    let decoded = pem_decode(content)?;

    if decoded.len() < 15 {
        return Err(SshError::InvalidKey("key too short".into()));
    }

    let magic = &decoded[..15];
    if magic != b"openssh-key-v1\0" {
        return Err(SshError::InvalidKey("invalid openssh key magic".into()));
    }

    let mut r = &decoded[15..];
    let cipher_name = read_simplified_string(&mut r)?;
    let kdf_name = read_simplified_string(&mut r)?;
    let kdf_options_raw = read_simplified_string_bytes(&mut r)?;
    let _num_keys = read_simplified_uint32(&mut r)?;

    let pub_len = read_simplified_uint32(&mut r)? as usize;
    r = &r[pub_len..];

    let priv_enc_len = read_simplified_uint32(&mut r)? as usize;
    if r.len() < priv_enc_len {
        return Err(SshError::InvalidKey("truncated encrypted private block".into()));
    }
    let priv_data_enc = &r[..priv_enc_len];

    let priv_data = if cipher_name == "none" {
        priv_data_enc.to_vec()
    } else {
        let pass = password.ok_or_else(|| SshError::InvalidKey("key is encrypted, need passphrase".into()))?;
        let key_iv_len = match cipher_name.as_str() {
            "aes128-ctr" | "aes128-cbc" => 32,
            "aes192-ctr" | "aes192-cbc" => 40,
            "aes256-ctr" | "aes256-cbc" => 48,
            other => return Err(SshError::InvalidKey(format!("unsupported cipher: {}", other))),
        };
        let key_and_iv = openssh_kdf_derive(&kdf_name, &kdf_options_raw, pass, key_iv_len)?;
        let decrypted = openssh_decrypt_private_block(&cipher_name, &key_and_iv, priv_data_enc)?;
        let check1 = u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
        let check2 = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);
        if check1 != check2 {
            return Err(SshError::InvalidKey("wrong passphrase or corrupt key".into()));
        }
        decrypted
    };

    let mut pr = &priv_data[8..];
    let key_type = read_simplified_string(&mut pr)?;

    match key_type.as_str() {
        "ssh-ed25519" => {
            let _pub_len = read_simplified_uint32(&mut pr)? as usize;
            pr = &pr[_pub_len..];
            let _secret_len = read_simplified_uint32(&mut pr)? as usize;
            let secret_bytes = read_simplified_raw(&mut pr, 32)?;

            Ok(Box::new(Ed25519HostKey::from_bytes(
                &secret_bytes.try_into().map_err(|_| SshError::InvalidKey("wrong ed25519 key size".into()))?
            )?))
        }
        "ecdsa-sha2-nistp256" => {
            let _pub_curve = read_simplified_string(&mut pr)?;
            let _pub_len = read_simplified_uint32(&mut pr)? as usize;
            pr = &pr[_pub_len..];
            let secret_len = read_simplified_uint32(&mut pr)? as usize;
            let avail = pr.len();
            let take = secret_len.min(avail);
            let secret_bytes = read_simplified_raw(&mut pr, take)?;
            let mut sb = secret_bytes;
            if sb.len() > 32 { sb = sb[sb.len()-32..].to_vec(); }
            Ok(Box::new(EcdsaP256HostKey::from_secret_bytes(&sb)?))
        }
        "ssh-rsa" => {
            let n_bytes = read_simplified_string_bytes(&mut pr)?;
            let e_bytes = read_simplified_string_bytes(&mut pr)?;
            let d_bytes = read_simplified_string_bytes(&mut pr)?;
            let _iqmp_bytes = read_simplified_string_bytes(&mut pr)?;
            let p_bytes = read_simplified_string_bytes(&mut pr)?;
            let q_bytes = read_simplified_string_bytes(&mut pr)?;

            let n = rsa::BigUint::from_bytes_be(&n_bytes);
            let e = rsa::BigUint::from_bytes_be(&e_bytes);
            let d = rsa::BigUint::from_bytes_be(&d_bytes);
            let p = rsa::BigUint::from_bytes_be(&p_bytes);
            let q = rsa::BigUint::from_bytes_be(&q_bytes);

            let rsa_key = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
                .map_err(|e| SshError::InvalidKey(format!("RSA: {}", e)))?;
            let public_key = rsa::RsaPublicKey::from(&rsa_key);
            Ok(Box::new(RsaHostKey::new(Some(rsa_key), public_key, 2048)))
        }
        _ => Err(SshError::InvalidKey(format!("unsupported key type: {}", key_type))),
    }
}

fn read_der_int(r: &mut &[u8]) -> Result<Vec<u8>> {
    if r.len() < 2 || r[0] != 0x02 {
        return Err(SshError::InvalidKey("der: expected INTEGER tag".into()));
    }
    let mut len = r[1] as usize;
    let mut off = 2;
    if len & 0x80 != 0 {
        let n = len & 0x7F;
        if r.len() < 2 + n { return Err(SshError::InvalidKey("der: long len truncated".into())); }
        let mut lb: usize = 0;
        for _ in 0..n { lb = (lb << 8) | r[off] as usize; off += 1; }
        len = lb;
    }
    if r.len() < off + len { return Err(SshError::InvalidKey("der: int truncated".into())); }
    let body = r[off..off + len].to_vec();
    *r = &r[off + len..];
    Ok(body)
}

fn read_der_tag_len<'a>(r: &mut &'a [u8], expected_tag: u8) -> Result<usize> {
    if r.is_empty() || r[0] != expected_tag {
        return Err(SshError::InvalidKey(format!("der: expected tag 0x{:02x}", expected_tag)));
    }
    let mut len = r[1] as usize;
    let mut off = 2;
    if len & 0x80 != 0 {
        let n = len & 0x7F;
        if r.len() < 2 + n { return Err(SshError::InvalidKey("der: long len truncated".into())); }
        let mut lb: usize = 0;
        for _ in 0..n { lb = (lb << 8) | r[off] as usize; off += 1; }
        len = lb;
    }
    if r.len() < off + len { return Err(SshError::InvalidKey("der: body truncated".into())); }
    *r = &r[off..];
    Ok(len)
}

fn load_pkcs1_key(content: &str, password: Option<&str>) -> Result<Box<dyn HostKeySigner>> {
    let der = pem_decode(content)?;
    let decrypted = if content.contains("Proc-Type: 4,ENCRYPTED") {
        let pass = password.ok_or_else(|| SshError::InvalidKey("PKCS#1 encrypted needs passphrase".into()))?;
        if der.len() < 16 { return Err(SshError::InvalidKey("encrypted PKCS#1 too short".into())); }
        let salt = &der[0..8];
        let ct = &der[8..];
        use sha1::Digest;
        let mut key_iv = Vec::new();
        let mut prev: Vec<u8> = Vec::new();
        while key_iv.len() < 48 {
            let mut h = sha1::Sha1::new();
            if !prev.is_empty() { h.update(&prev); }
            h.update(pass.as_bytes());
            h.update(salt);
            prev = h.finalize().to_vec();
            key_iv.extend_from_slice(&prev);
        }
        let key = &key_iv[0..32];
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(salt);
        aes_ctr_decrypt(key, &iv, ct).unwrap_or_else(|_| ct.to_vec())
    } else {
        der
    };
    let mut r = decrypted.as_slice();
    let body_len = read_der_tag_len(&mut r, 0x30)?;
    if r.len() < body_len { return Err(SshError::InvalidKey("PKCS#1 SEQ truncated".into())); }
    let mut inner = &r[..body_len];
    let _version = read_der_int(&mut inner)?;
    let n_bytes = read_der_int(&mut inner)?.to_vec();
    let e_bytes = read_der_int(&mut inner)?.to_vec();
    let d_bytes = read_der_int(&mut inner)?.to_vec();
    let _p_bytes = read_der_int(&mut inner)?.to_vec();
    let _q_bytes = read_der_int(&mut inner)?.to_vec();
    let _exp1 = read_der_int(&mut inner)?.to_vec();
    let _exp2 = read_der_int(&mut inner)?.to_vec();
    let _coef = read_der_int(&mut inner)?.to_vec();

    let n = rsa::BigUint::from_bytes_be(&n_bytes);
    let e = rsa::BigUint::from_bytes_be(&e_bytes);
    let d = rsa::BigUint::from_bytes_be(&d_bytes);
    let rsa_key = rsa::RsaPrivateKey::from_components(n, e, d, vec![])
        .map_err(|e| SshError::InvalidKey(format!("RSA: {}", e)))?;
    let public_key = rsa::RsaPublicKey::from(&rsa_key);
    let bits = public_key.n().bits();
    Ok(Box::new(RsaHostKey::new(Some(rsa_key), public_key, bits)))
}

fn load_ec_key(content: &str, password: Option<&str>) -> Result<Box<dyn HostKeySigner>> {
    let der = pem_decode(content)?;
    let decrypted = if content.contains("Proc-Type: 4,ENCRYPTED") {
        let pass = password.ok_or_else(|| SshError::InvalidKey("EC encrypted needs passphrase".into()))?;
        if der.len() < 16 { return Err(SshError::InvalidKey("encrypted EC too short".into())); }
        let salt = &der[0..8];
        let ct = &der[8..];
        use sha1::Digest;
        let mut key_iv = Vec::new();
        let mut prev: Vec<u8> = Vec::new();
        while key_iv.len() < 48 {
            let mut h = sha1::Sha1::new();
            if !prev.is_empty() { h.update(&prev); }
            h.update(pass.as_bytes());
            h.update(salt);
            prev = h.finalize().to_vec();
            key_iv.extend_from_slice(&prev);
        }
        let key = &key_iv[0..32];
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(salt);
        aes_ctr_decrypt(key, &iv, ct).unwrap_or_else(|_| ct.to_vec())
    } else {
        der
    };
    let mut r = decrypted.as_slice();
    let body_len = read_der_tag_len(&mut r, 0x30)?;
    if r.len() < body_len { return Err(SshError::InvalidKey("EC SEQ truncated".into())); }
    let mut inner = &r[..body_len];
    let _ver = read_der_int(&mut inner)?;
    if inner.is_empty() { return Err(SshError::InvalidKey("EC missing octet".into())); }
    if inner[0] != 0x04 { return Err(SshError::InvalidKey("EC private: expected OCTET STRING 0x04".into())); }
    let mut r2 = inner;
    let priv_len = read_der_tag_len(&mut r2, 0x04)?;
    if r2.len() < priv_len { return Err(SshError::InvalidKey("EC priv truncated".into())); }
    let priv_bytes = if priv_len >= 32 { &r2[r2.len().saturating_sub(priv_len)..][..priv_len] } else { r2 };
    let mut key = vec![0u8; 32];
    if priv_bytes.len() >= 32 {
        key.copy_from_slice(&priv_bytes[priv_bytes.len()-32..priv_bytes.len()]);
    } else {
        key[32-priv_bytes.len()..].copy_from_slice(priv_bytes);
    }
    Ok(Box::new(EcdsaP256HostKey::from_secret_bytes(&key)?))
}

fn load_pkcs8_key(content: &str, password: Option<&str>) -> Result<Box<dyn HostKeySigner>> {
    if content.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        let _ = password;
        return Err(SshError::InvalidKey("encrypted PKCS#8 not yet supported, use openssh-key format".into()));
    }
    let der = pem_decode(content)?;
    let mut r = der.as_slice();
    let body_len = read_der_tag_len(&mut r, 0x30)?;
    if r.len() < body_len { return Err(SshError::InvalidKey("PKCS#8 outer SEQ truncated".into())); }
    let mut outer = &r[..body_len];
    let _ver = read_der_int(&mut outer)?;
    if outer.is_empty() || outer[0] != 0x30 {
        return Err(SshError::InvalidKey("PKCS#8 missing inner algid SEQ".into()));
    }
    let alg_len = read_der_tag_len(&mut outer, 0x30)?;
    if outer.len() < alg_len { return Err(SshError::InvalidKey("PKCS#8 algid truncated".into())); }
    let alg_body = &outer[..alg_len];
    outer = &outer[alg_len..];
    let oid = if alg_body.len() > 10 && alg_body[0] == 0x06 {
        let len = alg_body[1] as usize;
        if len < 10 && alg_body.len() >= 2 + len {
            Some(&alg_body[2..2+len])
        } else { None }
    } else { None };
    if outer.is_empty() || outer[0] != 0x04 {
        return Err(SshError::InvalidKey("PKCS#8 missing privkey OCTET".into()));
    }
    let priv_der_len = read_der_tag_len(&mut outer, 0x04)?;
    if outer.len() < priv_der_len { return Err(SshError::InvalidKey("PKCS#8 priv truncated".into())); }
    let priv_der = &outer[..priv_der_len];

    match oid {
        // RSA OID: 2a 86 48 86 f7 0d 01 01 01
        Some(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, ..]) | None => {
            if priv_der.len() < 4 || priv_der[0] != 0x30 {
                return Err(SshError::InvalidKey("PKCS#8 RSA embedded malformed".into()));
            }
            let mut r3 = priv_der;
            let inner_len = read_der_tag_len(&mut r3, 0x30)?;
            if r3.len() < inner_len { return Err(SshError::InvalidKey("PKCS#8 RSA inner trunc".into())); }
            let mut inner = &r3[..inner_len];
            let _ = read_der_int(&mut inner)?;
            let n_bytes = read_der_int(&mut inner)?.to_vec();
            let e_bytes = read_der_int(&mut inner)?.to_vec();
            let d_bytes = read_der_int(&mut inner)?.to_vec();
            let _ = read_der_int(&mut inner).ok();
            let _ = read_der_int(&mut inner).ok();
            let n = rsa::BigUint::from_bytes_be(&n_bytes);
            let e = rsa::BigUint::from_bytes_be(&e_bytes);
            let d = rsa::BigUint::from_bytes_be(&d_bytes);
            let rsa_key = rsa::RsaPrivateKey::from_components(n, e, d, vec![])
                .map_err(|e| SshError::InvalidKey(format!("RSA: {}", e)))?;
            let public_key = rsa::RsaPublicKey::from(&rsa_key);
            let bits = public_key.n().bits();
            Ok(Box::new(RsaHostKey::new(Some(rsa_key), public_key, bits)))
        }
        // P-256 OID: 2a 86 48 ce 3d 03 01 07
        Some(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]) => {
            let mut r3 = priv_der;
            let inner_len = read_der_tag_len(&mut r3, 0x30)?;
            if r3.len() < inner_len { return Err(SshError::InvalidKey("PKCS#8 EC inner trunc".into())); }
            let mut inner = &r3[..inner_len];
            let _ver = read_der_int(&mut inner)?;
            if inner.is_empty() || inner[0] != 0x04 {
                return Err(SshError::InvalidKey("PKCS#8 EC missing priv octet".into()));
            }
            let plen = read_der_tag_len(&mut inner, 0x04)?;
            if inner.len() < plen { return Err(SshError::InvalidKey("PKCS#8 EC priv trunc".into())); }
            let pb = &inner[..plen];
            let mut key = vec![0u8; 32];
            if pb.len() >= 32 {
                key.copy_from_slice(&pb[pb.len()-32..]);
            } else {
                key[32-pb.len()..].copy_from_slice(pb);
            }
            Ok(Box::new(EcdsaP256HostKey::from_secret_bytes(&key)?))
        }
        // Ed25519 OID: 2b 65 70
        Some(&[0x2b, 0x65, 0x70]) => {
            if priv_der.len() >= 34 {
                let mut off = 0;
                while off + 34 <= priv_der.len() {
                    if priv_der[off] == 0x04 && priv_der[off+1] == 0x20 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&priv_der[off+2..off+34]);
                        return Ok(Box::new(Ed25519HostKey::from_bytes(&key)?));
                    }
                    off += 1;
                }
            }
            Err(SshError::InvalidKey("PKCS#8 Ed25519: cannot extract 32-byte seed".into()))
        }
        _ => Err(SshError::InvalidKey("PKCS#8: unsupported OID algorithm".into())),
    }
}

fn read_simplified_string(r: &mut &[u8]) -> Result<String> {
    let len = read_simplified_uint32(r)? as usize;
    if r.len() < len {
        return Err(SshError::InvalidKey("truncated string".into()));
    }
    let s = String::from_utf8_lossy(&r[..len]).to_string();
    *r = &r[len..];
    Ok(s)
}

fn read_simplified_string_bytes(r: &mut &[u8]) -> Result<Vec<u8>> {
    let len = read_simplified_uint32(r)? as usize;
    if r.len() < len {
        return Err(SshError::InvalidKey("truncated string".into()));
    }
    let bytes = r[..len].to_vec();
    *r = &r[len..];
    Ok(bytes)
}

fn read_simplified_uint32(r: &mut &[u8]) -> Result<u32> {
    if r.len() < 4 {
        return Err(SshError::InvalidKey("truncated uint32".into()));
    }
    let val = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
    *r = &r[4..];
    Ok(val)
}

fn read_simplified_raw(r: &mut &[u8], len: usize) -> Result<Vec<u8>> {
    if r.len() < len {
        return Err(SshError::InvalidKey("truncated raw data".into()));
    }
    let bytes = r[..len].to_vec();
    *r = &r[len..];
    Ok(bytes)
}
