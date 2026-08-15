use crate::error::{Result, SshError};
use crate::encoding::*;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use num_traits::Num;

pub trait KexAlgorithm: Send + Sync {
    fn name(&self) -> &str;
    fn generate_keypair(&mut self) -> Result<()>;
    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>>;
    fn public_key_bytes(&self) -> Vec<u8>;
}

pub struct KexExchange {
    pub client_version: Vec<u8>,
    pub server_version: Vec<u8>,
    pub client_kex_init: Vec<u8>,
    pub server_kex_init: Vec<u8>,
}

impl KexExchange {
    pub fn compute_session_id(
        client_version: &[u8],
        server_version: &[u8],
        client_kex_init: &[u8],
        server_kex_init: &[u8],
        server_host_key: &[u8],
        client_public_key: &[u8],
        server_public_key: &[u8],
        shared_secret: &[u8],
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();

        let mut buf = Vec::new();
        SshString(client_version.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        buf.clear();
        SshString(server_version.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        buf.clear();
        SshString(client_kex_init.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        buf.clear();
        SshString(server_kex_init.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        buf.clear();
        SshString(server_host_key.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        buf.clear();
        SshString(client_public_key.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        buf.clear();
        SshString(server_public_key.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        use crate::encoding::SshMpInt;
        buf.clear();
        SshMpInt(shared_secret.to_vec()).encode(&mut buf).unwrap();
        hasher.update(&buf);

        hasher.finalize().to_vec()
    }
}

pub fn compute_exchange_hash(
    exchange: &KexExchange,
    server_host_key: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
    shared_secret: &[u8],
) -> Vec<u8> {
    KexExchange::compute_session_id(
        &exchange.client_version,
        &exchange.server_version,
        &exchange.client_kex_init,
        &exchange.server_kex_init,
        server_host_key,
        client_public_key,
        server_public_key,
        shared_secret,
    )
}

pub struct Curve25519Kex {
    private_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,
}

impl Curve25519Kex {
    pub fn new() -> Self {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        Curve25519Kex { private_key, public_key }
    }

    pub fn kex_name() -> &'static str {
        "curve25519-sha256"
    }
}

impl KexAlgorithm for Curve25519Kex {
    fn name(&self) -> &str {
        Self::kex_name()
    }

    fn generate_keypair(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }

    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        if peer_public_key.len() != 32 {
            return Err(SshError::KexFailed("invalid curve25519 public key length".into()));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(peer_public_key);
        let peer = x25519_dalek::PublicKey::from(key_bytes);
        let shared = self.private_key.diffie_hellman(&peer);
        Ok(shared.as_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}

pub struct DhGroup14Kex {
    private_key: num_bigint::BigUint,
    public_key: num_bigint::BigUint,
    p: num_bigint::BigUint,
    g: num_bigint::BigUint,
}

impl DhGroup14Kex {
    pub fn new() -> Self {
        let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

        let p = num_bigint::BigUint::from_str_radix(p_hex, 16).unwrap();
        let g = num_bigint::BigUint::from(2u32);

        use rand::Rng;
        let mut rng = OsRng;
        let mut private_key_bytes = [0u8; 256];
        rng.fill(&mut private_key_bytes);
        let private_key = num_bigint::BigUint::from_bytes_be(&private_key_bytes) % &p;
        let public_key = g.modpow(&private_key, &p);

        DhGroup14Kex { private_key, public_key, p, g }
    }

    pub fn kex_name() -> &'static str {
        "diffie-hellman-group14-sha256"
    }
}

impl KexAlgorithm for DhGroup14Kex {
    fn name(&self) -> &str {
        Self::kex_name()
    }

    fn generate_keypair(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }

    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let peer = num_bigint::BigUint::from_bytes_be(peer_public_key);
        if peer >= self.p {
            return Err(SshError::KexFailed("peer public key >= p".into()));
        }
        let shared = peer.modpow(&self.private_key, &self.p);
        Ok(shared.to_bytes_be())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes_be()
    }
}

pub struct EcdhP256Kex {
    private_key: p256::ecdh::EphemeralSecret,
    public_key_bytes_cache: Vec<u8>,
}

impl EcdhP256Kex {
    pub fn new() -> Self {
        let private_key = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let public_key = p256::PublicKey::from(&private_key);
        let public_key_bytes_cache = public_key.to_sec1_bytes().to_vec();
        EcdhP256Kex {
            private_key,
            public_key_bytes_cache,
        }
    }

    pub fn kex_name() -> &'static str {
        "ecdh-sha2-nistp256"
    }
}

impl KexAlgorithm for EcdhP256Kex {
    fn name(&self) -> &str {
        Self::kex_name()
    }

    fn generate_keypair(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }

    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let peer_point = p256::EncodedPoint::from_bytes(peer_public_key)
            .map_err(|e| SshError::KexFailed(format!("invalid peer ECDH public key: {}", e)))?;
        let peer_pubkey = p256::PublicKey::from_sec1_bytes(peer_point.as_bytes())
            .map_err(|e| SshError::KexFailed(format!("invalid peer ECDH key: {}", e)))?;
        let shared = self.private_key.diffie_hellman(&peer_pubkey);
        Ok(shared.raw_secret_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_bytes_cache.clone()
    }
}

pub fn derive_key(
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    char_tag: u8,
    key_len: usize,
) -> Vec<u8> {
    let mut hasher = Sha256::new();

    use crate::encoding::SshMpInt;
    let mut buf = Vec::new();
    SshMpInt(shared_secret.to_vec()).encode(&mut buf).unwrap();
    hasher.update(&buf);

    hasher.update(exchange_hash);
    hasher.update(&[char_tag]);
    hasher.update(session_id);

    let hash = hasher.finalize().to_vec();
    hash[..key_len].to_vec()
}

pub fn derive_initial_iv(
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    iv_len: usize,
) -> Vec<u8> {
    derive_key(shared_secret, exchange_hash, session_id, b'C', iv_len)
}

pub fn derive_encryption_key(
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_len: usize,
) -> Vec<u8> {
    derive_key(shared_secret, exchange_hash, session_id, b'D', key_len)
}

pub fn derive_integrity_key(
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_len: usize,
) -> Vec<u8> {
    derive_key(shared_secret, exchange_hash, session_id, b'E', key_len)
}
