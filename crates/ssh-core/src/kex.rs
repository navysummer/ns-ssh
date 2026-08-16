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

const GROUP16_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6278C7EBF61F441E8945D43F598A46A0C10263553185B46DADFC697AA0B4C4507905B81D1C737D9558B92A63C546E1347FB753542DC5F9386B2AB9A07CE1C4C8CA2689757A1AA097F27C7AB2A28C67B47387944CC3B6FFA3CAB70E81DB2D08D74262B68B72137C211D6AB95D909C55A0CC8212728511640CF3B4FBB6D57DE4997D5F8038E67028C1F158F825E7F0C36F51C356B4935875F37181566DA1A4621E8DD9E2F141B32F8740518686C985B8E307710FC48151512795CEFEA09A1F820444D05E489F04970E1A2D948658B79A0482E339C97C926C75128A24A58065320BD225E22E7055996296326E1F33867B2080E30B0D94D6D2F02B7EEB022C49FAE1F16203945CE353E9385E5C3314971BC42FDFA6B9B886540A37EDDF29CC414B70340928E56C2F290877994E31488C3F154D074DC6BE80064710E07F24F8DB23EF22ECCEB2F9830A86358BCE8BCF444435D4F3F2F9CE9825950F6FDE4F6A1CDFD93C40D11CB94123D0C1FC64E59C25777A050F269510C90FC12949D65D66FB54CD7DBAD0A5B62C817EE322A25E00F645E31AF4EF09A3FD2A5BE4DF9E97D0143B5B3B4E0E3E60858659B9635894851944488E8F570A183C6BD1444909FAE479141BE83A49312B674B066E8D41AFDE819FA2DA037D28BF1184A0341F4D3AF9665CA531DDBE1A08A7E685943D164CAFFD9F52187592098DB49CFE22351C1881898852F59F16FC6FDEB0D2869A290F0C1A4752940754E099490700A7E6417BB4A8B900394D022C2213BF14857ACBF5A2D2BCB380159CCF8D1A94343C8BE785CD080BA42790B0B3449C2950E45E08F7165CC428FF345FC5C97F7A0FC6E4E4432228449F74281D8DF4BB516BD8D6707A23D09A0FA90D2136C330903486A5645B3ACF217C130C1299439CC096F30665BA12C91EA9392A14EB197398B8DE54EE1903D22379DE34127B95F3CE5C580832190B2DEE5C0DE18F9D05656C1D86EFE98B07309228BB5E14167BB4425456CFFC151601B9591D2617055B8DA5E11D6E099C221B13D77F2F9215D1632CE5BA8A345DF4190E8EA03D76D8FB62933A6B3FDD8C1414BE2F38A5B951B86E1D3E8673587089935DB551F8334191A2F4D41093A3D3BE9152D34F83E84135961B98D9A7387290B5D7517FBE720040E141EA0F4430D28CCE80EA37F07E66BF647B19D555FCCFE152639F99034CC2A201B42FC129D0DE5816DFD31F9CC8F6F1800325F9786B748039F684B1FE1F5CF242413F5D9440FDE586D5D4B40A97EB27673824D369F04C05804EE98A7A72C05E713B9B7724C2D178968CD549A6C9212BEB0DB07B112B65797B6469BDF70C2975F3308D4219D570A2F00A050E21D7133D229C2F0221CE138DF6B174220E02A592F74CE7F6CF182601D2862E14032DDB87E1066D3B32890D8412F31151E928A9AC19A03C3286B0099D2511AC0E7FF1C9B548B1984D691C69BB323E40EB1705030634D213CE0354F8D6CC4EBB747FBE38A9C341D2EBC7EA050F460330A5F8C61B4D4193744367FBAAFC92848429B64F5293183D40C0AB37DDE796C28A4E841062F15BA5026F76488E36B970449E48188D383F384D41DF9E26B89D0B52762F77134C832614A41F4070BDE37021C8787C8838681642AA212A6F455227C2F028A57ED04A2251D212630BAE067C8111BA84A92B5691986DA91918F08679732BAADFE60F59F9817C4AA9CF5911C644A66C99D502333946D6EBE28C74FC8A64C5845113B2139A7936AF608730B72FFAF2CF3C1FFFFFFFFFFFFFFFF";

const GROUP18_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6278C7EBF61F441E8945D43F598A46A0C10263553185B46DADFC697AA0B4C4507905B81D1C737D9558B92A63C546E1347FB753542DC5F9386B2AB9A07CE1C4C8CA2689757A1AA097F27C7AB2A28C67B47387944CC3B6FFA3CAB70E81DB2D08D74262B68B72137C211D6AB95D909C55A0CC8212728511640CF3B4FBB6D57DE4997D5F8038E67028C1F158F825E7F0C36F51C356B4935875F37181566DA1A4621E8DD9E2F141B32F8740518686C985B8E307710FC48151512795CEFEA09A1F820444D05E489F04970E1A2D948658B79A0482E339C97C926C75128A24A58065320BD225E22E7055996296326E1F33867B2080E30B0D94D6D2F02B7EEB022C49FAE1F16203945CE353E9385E5C3314971BC42FDFA6B9B886540A37EDDF29CC414B70340928E56C2F290877994E31488C3F154D074DC6BE80064710E07F24F8DB23EF22ECCEB2F9830A86358BCE8BCF444435D4F3F2F9CE9825950F6FDE4F6A1CDFD93C40D11CB94123D0C1FC64E59C25777A050F269510C90FC12949D65D66FB54CD7DBAD0A5B62C817EE322A25E00F645E31AF4EF09A3FD2A5BE4DF9E97D0143B5B3B4E0E3E60858659B9635894851944488E8F570A183C6BD1444909FAE479141BE83A49312B674B066E8D41AFDE819FA2DA037D28BF1184A0341F4D3AF9665CA531DDBE1A08A7E685943D164CAFFD9F52187592098DB49CFE22351C1881898852F59F16FC6FDEB0D2869A290F0C1A4752940754E099490700A7E6417BB4A8B900394D022C2213BF14857ACBF5A2D2BCB380159CCF8D1A94343C8BE785CD080BA42790B0B3449C2950E45E08F7165CC428FF345FC5C97F7A0FC6E4E4432228449F74281D8DF4BB516BD8D6707A23D09A0FA90D2136C330903486A5645B3ACF217C130C1299439CC096F30665BA12C91EA9392A14EB197398B8DE54EE1903D22379DE34127B95F3CE5C580832190B2DEE5C0DE18F9D05656C1D86EFE98B07309228BB5E14167BB4425456CFFC151601B9591D2617055B8DA5E11D6E099C221B13D77F2F9215D1632CE5BA8A345DF4190E8EA03D76D8FB62933A6B3FDD8C1414BE2F38A5B951B86E1D3E8673587089935DB551F8334191A2F4D41093A3D3BE9152D34F83E84135961B98D9A7387290B5D7517FBE720040E141EA0F4430D28CCE80EA37F07E66BF647B19D555FCCFE152639F99034CC2A201B42FC129D0DE5816DFD31F9CC8F6F1800325F9786B748039F684B1FE1F5CF242413F5D9440FDE586D5D4B40A97EB27673824D369F04C05804EE98A7A72C05E713B9B7724C2D178968CD549A6C9212BEB0DB07B112B65797B6469BDF70C2975F3308D4219D570A2F00A050E21D7133D229C2F0221CE138DF6B174220E02A592F74CE7F6CF182601D2862E14032DDB87E1066D3B32890D8412F31151E928A9AC19A03C3286B0099D2511AC0E7FF1C9B548B1984D691C69BB323E40EB1705030634D213CE0354F8D6CC4EBB747FBE38A9C341D2EBC7EA050F460330A5F8C61B4D4193744367FBAAFC92848429B64F5293183D40C0AB37DDE796C28A4E841062F15BA5026F76488E36B970449E48188D383F384D41DF9E26B89D0B52762F77134C832614A41F4070BDE37021C8787C8838681642AA212A6F455227C2F028A57ED04A2251D212630BAE067C8111BA84A92B5691986DA91918F08679732BAADFE60F59F9817C4AA9CF5911C644A66C99D502333946D6EBE28C74FC8A64C5845113B2139A7936AF608730B72FFAF2CF3C1FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A932108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6278C7EBF61F441E8945D43F598A46A0C10263553185B46DADFC697AA0B4C4507905B81D1C737D9558B92A63C546E1347FB753542DC5F9386B2AB9A07CE1C4C8CA2689757A1AA097F27C7AB2A28C67B47387944CC3B6FFA3CAB70E81DB2D08D74262B68B72137C211D6AB95D909C55A0CC8212728511640CF3B4FBB6D57DE4997D5F8038E67028C1F158F825E7F0C36F51C356B4935875F37181566DA1A4621E8DD9E2F141B32F8740518686C985B8E307710FC48151512795CEFEA09A1F820444D05E489F04970E1A2D948658B79A0482E339C97C926C75128A24A58065320BD225E22E7055996296326E1F33867B2080E30B0D94D6D2F02B7EEB022C49FAE1F16203945CE353E9385E5C3314971BC42FDFA6B9B886540A37EDDF29CC414B70340928E56C2F290877994E31488C3F154D074DC6BE80064710E07F24F8DB23EF22ECCEB2F9830A86358BCE8BCF444435D4F3F2F9CE9825950F6FDE4F6A1CDFD93C40D11CB94123D0C1FC64E59C25777A050F269510C90FC12949D65D66FB54CD7DBAD0A5B62C817EE322A25E00F645E31AF4EF09A3FD2A5BE4DF9E97D0143B5B3B4E0E3E60858659B9635894851944488E8F570A183C6BD1444909FAE479141BE83A49312B674B066E8D41AFDE819FA2DA037D28BF1184A0341F4D3AF9665CA531DDBE1A08A7E685943D164CAFFD9F52187592098DB49CFE22351C1881898852F59F16FC6FDEB0D2869A290F0C1A4752940754E099490700A7E6417BB4A8B900394D022C2213BF14857ACBF5A2D2BCB380159CCF8D1A94343C8BE785CD080BA42790B0B3449C2950E45E08F7165CC428FF345FC5C97F7A0FC6E4E4432228449F74281D8DF4BB516BD8D6707A23D09A0FA90D2136C330903486A5645B3ACF217C130C1299439CC096F30665BA12C91EA9392A14EB197398B8DE54EE1903D22379DE34127B95F3CE5C580832190B2DEE5C0DE18F9D05656C1D86EFE98B07309228BB5E14167BB4425456CFFC151601B9591D2617055B8DA5E11D6E099C221B13D77F2F9215D1632CE5BA8A345DF4190E8EA03D76D8FB62933A6B3FDD8C1414BE2F38A5B951B86E1D3E8673587089935DB551F8334191A2F4D41093A3D3BE9152D34F83E84135961B98D9A7387290B5D7517FBE720040E141EA0F4430D28CCE80EA37F07E66BF647B19D555FCCFE152639F99034CC2A201B42FC129D0DE5816DFD31F9CC8F6F1800325F9786B748039F684B1FE1F5CF242413F5D9440FDE586D5D4B40A97EB27673824D369F04C05804EE98A7A72C05E713B9B7724C2D178968CD549A6C9212BEB0DB07B112B65797B6469BDF70C2975F3308D4219D570A2F00A050E21D7133D229C2F0221CE138DF6B174220E02A592F74CE7F6CF182601D2862E14032DDB87E1066D3B32890D8412F31151E928A9AC19A03C3286B0099D2511AC0E7FF1C9B548B1984D691C69BB323E40EB1705030634D213CE0354F8D6CC4EBB747FBE38A9C341D2EBC7EA050F460330A5F8C61B4D4193744367FBAAFC92848429B64F5293183D40C0AB37DDE796C28A4E841062F15BA5026F76488E36B970449E48188D383F384D41DF9E26B89D0B52762F77134C832614A41F4070BDE37021C8787C8838681642AA212A6F455227C2F028A57ED04A2251D212630BAE067C8111BA84A92B5691986DA91918F08679732BAADFE60F59F9817C4AA9CF5911C644A66C99D502333946D6EBE28C74FC8A64C5845113B2139A7936AF608730B72FFAF2CF3C1FFFFFFFFFFFFFFFF";

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
    // group-exchange SHA256/SHA1 are mapped to fixed group16/14 for simplicity (no real min/max/prime negotiation)
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
    SshMpInt(shared_secret.to_vec()).encode(&mut buf).unwrap();
    hasher.update(&buf); buf.clear();

    hasher.finalize()
}

impl KexAlgorithm for ModpKex {
    fn name(&self) -> &str { self.name }
    fn hash_name(&self) -> &'static str { self.hash }
    fn generate_keypair(&mut self) -> Result<()> {
        *self = match (self.name, self.hash) {
            ("diffie-hellman-group14-sha256", _) => Self::group14_sha256(),
            ("diffie-hellman-group14-sha1", _) => Self::group14_sha1(),
            ("diffie-hellman-group16-sha512", _) => Self::group16_sha512(),
            ("diffie-hellman-group18-sha512", _) => Self::group18_sha512(),
            ("diffie-hellman-group-exchange-sha256", _) => Self::gex_sha256(),
            ("diffie-hellman-group-exchange-sha1", _) => Self::gex_sha1(),
            _ => Self::group14_sha256(),
        };
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
    hash_name: &str,
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    char_tag: u8,
    key_len: usize,
) -> Vec<u8> {
    let mut hasher = Khasher::new(hash_name);

    use crate::encoding::SshMpInt;
    let mut buf = Vec::new();
    SshMpInt(shared_secret.to_vec()).encode(&mut buf).unwrap();
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
        SshMpInt(shared_secret.to_vec()).encode(&mut b).unwrap();
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
