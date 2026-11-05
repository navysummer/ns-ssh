use crate::error::{Result, SshError};
use crate::encoding::*;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512, Digest};
use rand::rngs::OsRng;
use num_traits::Num;

pub trait KexAlgorithm: Send + Sync {
    fn name(&self) -> &str;
    fn hash_name(&self) -> &'static str { "sha256" }
    fn generate_keypair(&mut self) -> Result<()>;
    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>>;
    fn public_key_bytes(&self) -> Vec<u8>;
}

enum Khasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Khasher {
    fn new(name: &str) -> Self {
        match name {
            "sha1" => Khasher::Sha1(Sha1::new()),
            "sha256" => Khasher::Sha256(Sha256::new()),
            "sha384" => Khasher::Sha384(Sha384::new()),
            "sha512" => Khasher::Sha512(Sha512::new()),
            other => panic!("unsupported hash {}", other),
        }
    }
    fn update(&mut self, data: &[u8]) {
        match self {
            Khasher::Sha1(h) => h.update(data),
            Khasher::Sha256(h) => h.update(data),
            Khasher::Sha384(h) => h.update(data),
            Khasher::Sha512(h) => h.update(data),
        }
    }
    fn finalize(self) -> Vec<u8> {
        match self {
            Khasher::Sha1(h) => h.finalize().to_vec(),
            Khasher::Sha256(h) => h.finalize().to_vec(),
            Khasher::Sha384(h) => h.finalize().to_vec(),
            Khasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

pub struct KexExchange {
    pub client_version: Vec<u8>,
    pub server_version: Vec<u8>,
    pub client_kex_init: Vec<u8>,
    pub server_kex_init: Vec<u8>,
}

impl KexExchange {
    pub fn compute_session_id(
        hash_name: &str,
        client_version: &[u8],
        server_version: &[u8],
        client_kex_init: &[u8],
        server_kex_init: &[u8],
        server_host_key: &[u8],
        client_public_key: &[u8],
        server_public_key: &[u8],
        shared_secret: &[u8],
        public_keys_as_mpint: bool,
    ) -> Vec<u8> {
        let mut hasher = Khasher::new(hash_name);

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

        use crate::encoding::SshMpInt;
        // RFC 4253 §8: for finite-field DH, e and f are hashed as mpints.
        // RFC 5656 §4 / RFC 8731 §4: ECDH and curve25519 ephemeral keys are
        // hashed as byte strings, not mpints. Encoding the wrong one only
        // breaks half the time (when the high bit is set), so this must be
        // selected explicitly rather than inferred from the value.
        buf.clear();
        if public_keys_as_mpint {
            SshMpInt::from_bytes_be(client_public_key).encode(&mut buf).unwrap();
        } else {
            SshString(client_public_key.to_vec()).encode(&mut buf).unwrap();
        }
        hasher.update(&buf);

        buf.clear();
        if public_keys_as_mpint {
            SshMpInt::from_bytes_be(server_public_key).encode(&mut buf).unwrap();
        } else {
            SshString(server_public_key.to_vec()).encode(&mut buf).unwrap();
        }
        hasher.update(&buf);

        buf.clear();
        // `K` is an mpint (RFC 4253 §8). The raw ECDH secret for P-521 is 66
        // bytes wide with a leading zero about half the time (the field is only
        // 521 bits); mpint canonical form strips leading zero bytes, and
        // OpenSSH does the same. Keeping them made the exchange hash differ on
        // ~half of P-521 handshakes ("Host key verification failed").
        SshMpInt::from_bytes_be(shared_secret).encode(&mut buf).unwrap();
        hasher.update(&buf);

        hasher.finalize()
    }
}

pub fn compute_exchange_hash(
    hash_name: &str,
    exchange: &KexExchange,
    server_host_key: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
    shared_secret: &[u8],
    public_keys_as_mpint: bool,
) -> Vec<u8> {
    KexExchange::compute_session_id(
        hash_name,
        &exchange.client_version,
        &exchange.server_version,
        &exchange.client_kex_init,
        &exchange.server_kex_init,
        server_host_key,
        client_public_key,
        server_public_key,
        shared_secret,
        public_keys_as_mpint,
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

pub struct ModpKex {
    name: &'static str,
    hash: &'static str,
    private_key: num_bigint::BigUint,
    public_key: num_bigint::BigUint,
    p: num_bigint::BigUint,
    g: num_bigint::BigUint,
    exp_bytes: usize,
}

pub const GROUP14_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

const GROUP16_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

const GROUP18_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF";

impl ModpKex {
    fn new(name: &'static str, hash: &'static str, p_hex: &str, exp_bytes: usize) -> Self {
        let p = num_bigint::BigUint::from_str_radix(p_hex, 16).expect("valid hex");
        let g = num_bigint::BigUint::from(2u32);
        Self::with_params(name, hash, p, g, exp_bytes)
    }

    pub fn with_params(
        name: &'static str,
        hash: &'static str,
        p: num_bigint::BigUint,
        g: num_bigint::BigUint,
        exp_bytes: usize,
    ) -> Self {
        use rand::RngCore;
        let mut rng = OsRng;
        let mut private_key_bytes = vec![0u8; exp_bytes];
        rng.fill_bytes(&mut private_key_bytes);
        let private_key = num_bigint::BigUint::from_bytes_be(&private_key_bytes) % &p;
        let public_key = g.modpow(&private_key, &p);
        ModpKex {
            name,
            hash,
            private_key,
            public_key,
            p,
            g,
            exp_bytes,
        }
    }

    pub fn group14_sha256() -> Self { Self::new("diffie-hellman-group14-sha256", "sha256", GROUP14_P, 256) }
    pub fn group14_sha1() -> Self { Self::new("diffie-hellman-group14-sha1", "sha1", GROUP14_P, 256) }
    pub fn group16_sha512() -> Self { Self::new("diffie-hellman-group16-sha512", "sha512", GROUP16_P, 512) }
    pub fn group18_sha512() -> Self { Self::new("diffie-hellman-group18-sha512", "sha512", GROUP18_P, 1024) }
    // The group-exchange variants start from a placeholder group; the actual
    // group arrives from the peer (server reply / client request) and is set
    // with `with_params`. See `select_gex_group` for server-side selection.
    pub fn gex_sha256() -> Self { Self::new("diffie-hellman-group-exchange-sha256", "sha256", GROUP16_P, 512) }
    pub fn gex_sha1() -> Self { Self::new("diffie-hellman-group-exchange-sha1", "sha1", GROUP14_P, 256) }

    pub fn group14_p() -> Vec<u8> {
        num_bigint::BigUint::from_str_radix(GROUP14_P, 16).expect("valid hex").to_bytes_be()
    }
    pub fn group14_g() -> Vec<u8> {
        num_bigint::BigUint::from(2u32).to_bytes_be()
    }

    pub fn p(&self) -> &num_bigint::BigUint { &self.p }
    pub fn g(&self) -> &num_bigint::BigUint { &self.g }
}

/// A group selected for a `diffie-hellman-group-exchange-*` negotiation.
#[derive(Clone, Debug)]
pub struct GexGroup {
    pub p: num_bigint::BigUint,
    pub g: num_bigint::BigUint,
    pub exp_bytes: usize,
}

/// Pick the RFC 3526 MODP group that best matches a client's GEX request.
///
/// RFC 4419 §3: the server must answer with a group whose size is within
/// `[min, max]` and preferably close to `nbits`. Returns `None` when no
/// supported group fits the requested range.
pub fn select_gex_group(min: u32, nbits: u32, max: u32) -> Option<GexGroup> {
    // RFC 4419 has no groups below 1024 bits; our smallest supported group is
    // the 2048-bit group14, so smaller requests cannot be satisfied.
    let lo = min.max(1024);
    if max < lo {
        return None;
    }
    let target = u64::from(nbits).clamp(u64::from(lo), u64::from(max));
    let mut best: Option<(u32, &'static str, usize)> = None;
    for (bits, hex, exp_bytes) in [
        (2048u32, GROUP14_P, 256usize),
        (4096, GROUP16_P, 512),
        (8192, GROUP18_P, 1024),
    ] {
        if bits < lo || bits > max {
            continue;
        }
        let better = match best {
            None => true,
            // Prefer the size closest to `nbits`; on a tie keep the larger
            // (more conservative) group since iteration is ascending.
            Some((prev, _, _)) => {
                u64::from(bits).abs_diff(target) <= u64::from(prev).abs_diff(target)
            }
        };
        if better {
            best = Some((bits, hex, exp_bytes));
        }
    }
    let (_, hex, exp_bytes) = best?;
    let p = num_bigint::BigUint::from_str_radix(hex, 16).expect("valid hex");
    let g = num_bigint::BigUint::from(2u32);
    Some(GexGroup { p, g, exp_bytes })
}

/// Parse an OpenSSH `moduli` file, returning the usable DH-GEX groups.
///
/// Each data line has seven whitespace-separated fields:
/// `date type tests tries size generator modulus`, where `size` is the prime
/// length in bits and `modulus` is hex. Comment and malformed lines are
/// skipped (OpenSSH's `moduli` has a `# Time Type ...` header comment).
pub fn parse_moduli(content: &str) -> Vec<GexGroup> {
    let mut groups = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        let Ok(bits) = fields[4].parse::<u32>() else { continue };
        let Ok(g) = num_bigint::BigUint::from_str_radix(fields[5], 10) else { continue };
        let Ok(p) = num_bigint::BigUint::from_str_radix(fields[6], 16) else { continue };
        if bits == 0 || p.bits() != u64::from(bits) || g < 2u32.into() {
            continue;
        }
        groups.push(GexGroup { p, g, exp_bytes: (bits as usize + 7) / 8 });
    }
    groups
}

/// Like [`select_gex_group`], but prefer the groups supplied by `ModuliFile`.
/// When `candidates` is empty, the built-in RFC 3526 groups are used.
pub fn select_gex_group_with(
    min: u32,
    nbits: u32,
    max: u32,
    candidates: &[GexGroup],
) -> Option<GexGroup> {
    if candidates.is_empty() {
        return select_gex_group(min, nbits, max);
    }
    let lo = min.max(1024);
    if max < lo {
        return None;
    }
    let target = u64::from(nbits).clamp(u64::from(lo), u64::from(max));
    let mut best: Option<(u64, u64, &GexGroup)> = None;
    for group in candidates {
        let bits = group.p.bits();
        if bits < u64::from(lo) || bits > u64::from(max) {
            continue;
        }
        let distance = bits.abs_diff(target);
        let better = match best {
            None => true,
            // Closer to the preferred size wins; on a tie the larger group is
            // the more conservative choice (matching the built-in selection).
            Some((best_distance, best_bits, _)) => {
                distance < best_distance || (distance == best_distance && bits > best_bits)
            }
        };
        if better {
            best = Some((distance, bits, group));
        }
    }
    best.map(|(_, _, group)| group.clone())
}

pub fn compute_gex_exchange_hash(
    hash_name: &str,
    exchange: &KexExchange,
    min: u32,
    nbits: u32,
    max: u32,
    p: &[u8],
    g: &[u8],
    server_host_key: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
    shared_secret: &[u8],
) -> Vec<u8> {
    let mut hasher = Khasher::new(hash_name);
    use crate::encoding::SshMpInt;
    let mut buf = Vec::new();

    SshString(exchange.client_version.clone()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshString(exchange.server_version.clone()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshString(exchange.client_kex_init.clone()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshString(exchange.server_kex_init.clone()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshString(server_host_key.to_vec()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();

    min.encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    nbits.encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    max.encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshMpInt(p.to_vec()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshMpInt(g.to_vec()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();

    SshMpInt(client_public_key.to_vec()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshMpInt(server_public_key.to_vec()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();
    SshMpInt::from_bytes_be(shared_secret).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();

    hasher.finalize()
}

impl KexAlgorithm for ModpKex {
    fn name(&self) -> &str { self.name }
    fn hash_name(&self) -> &'static str { self.hash }
    fn generate_keypair(&mut self) -> Result<()> {
        // Regenerate only the private exponent; the modulus/generator stay as
        // configured. GEX fills them in from the peer, so replacing `self`
        // with a fixed-group constructor here would silently discard the
        // negotiated group and break interoperability.
        use rand::RngCore;
        let mut rng = OsRng;
        let mut private_key_bytes = vec![0u8; self.exp_bytes];
        rng.fill_bytes(&mut private_key_bytes);
        let one = num_bigint::BigUint::from(1u32);
        self.private_key = num_bigint::BigUint::from_bytes_be(&private_key_bytes)
            % (&self.p - &one)
            + &one;
        self.public_key = self.g.modpow(&self.private_key, &self.p);
        Ok(())
    }
    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let peer = num_bigint::BigUint::from_bytes_be(peer_public_key);
        // RFC 4253 §8 / RFC 4419: a peer's public value must be in [2, p-2].
        // Rejecting 0, 1 and p avoids the degenerate shared secrets 0/1/p-1.
        if peer <= num_bigint::BigUint::from(1u32) {
            return Err(SshError::KexFailed("peer public key must be >= 2".into()));
        }
        if peer >= &self.p - num_bigint::BigUint::from(1u32) {
            return Err(SshError::KexFailed("peer public key out of range".into()));
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
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    char_tag: u8,
    key_len: usize,
) -> Vec<u8> {
    let mut hasher = Khasher::new(hash_name);

    use crate::encoding::SshMpInt;
    // RFC 4253 §7.2 feeds K into the key derivation function in the same
    // canonical mpint form as the exchange hash. A raw P-521 x-coordinate can
    // be 66 bytes with a leading zero; encoding it untrimmed produced keys
    // that disagreed with OpenSSH whenever that byte was zero.
    let mut buf = Vec::new();
    SshMpInt::from_bytes_be(shared_secret).encode(&mut buf).unwrap();
    hasher.update(&buf);

    hasher.update(exchange_hash);
    hasher.update(&[char_tag]);
    hasher.update(session_id);

    let hash = hasher.finalize();
    let hash_len = hash.len();
    if key_len <= hash_len {
        return hash[..key_len].to_vec();
    }

    // K1 = HASH(K || H || X || session_id)
    // K[i+1] = HASH(K || H || K[1] || ... || K[i])
    let mut out = hash.clone();
    while out.len() < key_len {
        let mut h = Khasher::new(hash_name);
        let mut b = Vec::new();
        SshMpInt::from_bytes_be(shared_secret).encode(&mut b).unwrap();
        h.update(&b);
        h.update(exchange_hash);
        h.update(&out);
        let next = h.finalize();
        out.extend_from_slice(&next);
    }
    out.truncate(key_len);
    out
}

pub fn derive_initial_iv(
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    iv_len: usize,
) -> Vec<u8> {
    derive_key(hash_name, shared_secret, exchange_hash, session_id, b'A', iv_len)
}

pub fn derive_encryption_key(
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_len: usize,
) -> Vec<u8> {
    derive_key(hash_name, shared_secret, exchange_hash, session_id, b'C', key_len)
}

pub fn derive_integrity_key(
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_len: usize,
) -> Vec<u8> {
    derive_key(hash_name, shared_secret, exchange_hash, session_id, b'E', key_len)
}

// Server-to-client letters per RFC 4253 §7.2: 'B' (IV), 'D' (key), 'F' (MAC).
pub fn derive_s2c_initial_iv(
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    iv_len: usize,
) -> Vec<u8> {
    derive_key(hash_name, shared_secret, exchange_hash, session_id, b'B', iv_len)
}

pub fn derive_s2c_encryption_key(
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_len: usize,
) -> Vec<u8> {
    derive_key(hash_name, shared_secret, exchange_hash, session_id, b'D', key_len)
}

pub fn derive_s2c_integrity_key(
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_len: usize,
) -> Vec<u8> {
    derive_key(hash_name, shared_secret, exchange_hash, session_id, b'F', key_len)
}

pub struct EcdhP384Kex {
    private_key: p384::ecdh::EphemeralSecret,
    public_key_bytes_cache: Vec<u8>,
}

impl EcdhP384Kex {
    pub fn new() -> Self {
        let private_key = p384::ecdh::EphemeralSecret::random(&mut OsRng);
        let public_key = p384::PublicKey::from(&private_key);
        let public_key_bytes_cache = public_key.to_sec1_bytes().to_vec();
        EcdhP384Kex {
            private_key,
            public_key_bytes_cache,
        }
    }

    pub fn kex_name() -> &'static str {
        "ecdh-sha2-nistp384"
    }
}

impl KexAlgorithm for EcdhP384Kex {
    fn name(&self) -> &str {
        Self::kex_name()
    }

    fn hash_name(&self) -> &'static str { "sha384" }

    fn generate_keypair(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }

    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let peer_point = p384::EncodedPoint::from_bytes(peer_public_key)
            .map_err(|e| SshError::KexFailed(format!("invalid peer ECDH P-384 public key: {}", e)))?;
        let peer_pubkey = p384::PublicKey::from_sec1_bytes(peer_point.as_bytes())
            .map_err(|e| SshError::KexFailed(format!("invalid peer ECDH P-384 key: {}", e)))?;
        let shared = self.private_key.diffie_hellman(&peer_pubkey);
        Ok(shared.raw_secret_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_bytes_cache.clone()
    }
}

pub struct EcdhP521Kex {
    private_key: p521::ecdh::EphemeralSecret,
    public_key_bytes_cache: Vec<u8>,
}

impl EcdhP521Kex {
    pub fn new() -> Self {
        let private_key = p521::ecdh::EphemeralSecret::random(&mut OsRng);
        let public_key = p521::PublicKey::from(&private_key);
        let public_key_bytes_cache = public_key.to_sec1_bytes().to_vec();
        EcdhP521Kex {
            private_key,
            public_key_bytes_cache,
        }
    }

    pub fn kex_name() -> &'static str {
        "ecdh-sha2-nistp521"
    }
}

impl KexAlgorithm for EcdhP521Kex {
    fn name(&self) -> &str {
        Self::kex_name()
    }

    fn hash_name(&self) -> &'static str { "sha512" }

    fn generate_keypair(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }

    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let peer_point = p521::EncodedPoint::from_bytes(peer_public_key)
            .map_err(|e| SshError::KexFailed(format!("invalid peer ECDH P-521 public key: {}", e)))?;
        let peer_pubkey = p521::PublicKey::from_sec1_bytes(peer_point.as_bytes())
            .map_err(|e| SshError::KexFailed(format!("invalid peer ECDH P-521 key: {}", e)))?;
        let shared = self.private_key.diffie_hellman(&peer_pubkey);
        Ok(shared.raw_secret_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_bytes_cache.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gex_selects_group_inside_requested_bounds() {
        // OpenSSH's default request (min 2048, preferred 3072, max 8192):
        // 4096 is the closest supported size to the preferred 3072.
        let g = select_gex_group(2048, 3072, 8192).unwrap();
        assert_eq!(g.p.bits(), 4096);
        assert_eq!(g.g, num_bigint::BigUint::from(2u32));

        // A narrow window forces the only group that fits.
        assert_eq!(select_gex_group(2048, 2048, 2048).unwrap().p.bits(), 2048);
        assert_eq!(select_gex_group(4096, 4096, 8192).unwrap().p.bits(), 4096);
        assert_eq!(select_gex_group(8192, 8192, 8192).unwrap().p.bits(), 8192);

        // Below 2048 bits none of our safe primes fit; above 8192 too.
        assert!(select_gex_group(1024, 1024, 1024).is_none());
        assert!(select_gex_group(9000, 9000, u32::MAX).is_none());

        // A legacy request carries no maximum; we must cap at our largest
        // supported group instead of attempting an unbounded size.
        assert_eq!(
            select_gex_group(2048, 8192, u32::MAX).unwrap().p.bits(),
            8192
        );

        // nbits outside [min, max] is clamped before choosing.
        assert_eq!(select_gex_group(2048, 16, 2048).unwrap().p.bits(), 2048);
    }

    #[test]
    fn moduli_file_groups_are_parsed_and_selected() {
        let content = format!(
            "# Time Type Tests Tries Size Generator Modulus\n\
             20200101 2 6 100 2048 2 {}\n\
             wrong fields\n\
             nothex 2 6 100 2048 2 ZZZZ\n",
            GROUP14_P
        );
        let groups = parse_moduli(&content);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].p.bits(), 2048);
        assert_eq!(groups[0].exp_bytes, 256);
        assert_eq!(groups[0].g, num_bigint::BigUint::from(2u32));

        // A file group inside the requested window is selected.
        assert_eq!(
            select_gex_group_with(2048, 2048, 2048, &groups).unwrap().p.bits(),
            2048
        );
        // No candidate in range -> no group (no silent built-in fallback).
        assert!(select_gex_group_with(4096, 4096, 8192, &groups).is_none());
        // Empty list falls back to the built-in RFC 3526 groups.
        assert_eq!(
            select_gex_group_with(2048, 3072, 8192, &[]).unwrap().p.bits(),
            4096
        );
    }

    #[test]
    fn modp_rejects_degenerate_peer_public_values() {
        let mut kex = ModpKex::group14_sha256();
        kex.generate_keypair().unwrap();
        for bad in [vec![], vec![0u8], vec![1u8]] {
            assert!(kex.compute_shared_secret(&bad).is_err(), "{bad:?}");
        }
        let p_minus_one = (kex.p() - num_bigint::BigUint::from(1u32)).to_bytes_be();
        assert!(kex.compute_shared_secret(&p_minus_one).is_err());
    }
}

#[test]
fn exchange_hash_encodes_ephemeral_keys_by_family() {
    // A value whose top bit is set is the discriminator: as an mpint it gains
    // a 0x00 sign byte, as a plain string it does not. Encoding MODP keys the
    // string way silently breaks OpenSSH interop for ~half of all exchanges.
    let exchange = KexExchange {
        client_version: b"SSH-2.0-test".to_vec(),
        server_version: b"SSH-2.0-test".to_vec(),
        client_kex_init: vec![crate::msg::SSH_MSG_KEXINIT],
        server_kex_init: vec![crate::msg::SSH_MSG_KEXINIT],
    };
    let high_bit = vec![0x80u8, 0x01];
    let shared = vec![0x02u8];
    let as_mpint = compute_exchange_hash(
        "sha256", &exchange, b"hostkey", &high_bit, &high_bit, &shared, true,
    );
    let as_string = compute_exchange_hash(
        "sha256", &exchange, b"hostkey", &high_bit, &high_bit, &shared, false,
    );
    assert_ne!(as_mpint, as_string);

    // Values below 0x80 encode identically, which is why the bug only showed
    // up on roughly half of the handshakes.
    let low_bit = vec![0x01u8, 0x02];
    assert_eq!(
        compute_exchange_hash("sha256", &exchange, b"k", &low_bit, &low_bit, &shared, true),
        compute_exchange_hash("sha256", &exchange, b"k", &low_bit, &low_bit, &shared, false),
    );
}

#[test]
fn exchange_hash_uses_canonical_mpints_for_shared_secret() {
    // P-521 field elements are 521 bits, so their raw 66-byte encoding starts
    // with 0x00 about half the time. mpint canonical form strips leading zero
    // bytes and OpenSSH does the same, so the exchange hash must not depend on
    // the untrimmed width.
    let exchange = KexExchange {
        client_version: b"SSH-2.0-test".to_vec(),
        server_version: b"SSH-2.0-test".to_vec(),
        client_kex_init: vec![crate::msg::SSH_MSG_KEXINIT],
        server_kex_init: vec![crate::msg::SSH_MSG_KEXINIT],
    };
    let pub_key = vec![0x01u8, 0x02];
    let trimmed = compute_exchange_hash(
        "sha512", &exchange, b"hostkey", &pub_key, &pub_key, &[0x01], true,
    );
    let with_leading_zero = compute_exchange_hash(
        "sha512", &exchange, b"hostkey", &pub_key, &pub_key, &[0x00, 0x01], true,
    );
    assert_eq!(trimmed, with_leading_zero);

    // Key derivation also consumes K as a canonical mpint (RFC 4253 §7.2).
    let hash = [0xabu8; 32];
    let session = [0xcdu8; 20];
    assert_eq!(
        derive_encryption_key("sha512", &[0x01], &hash, &session, 32),
        derive_encryption_key("sha512", &[0x00, 0x01], &hash, &session, 32),
    );
}
