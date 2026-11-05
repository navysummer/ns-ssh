use crate::error::{Result, SshError};
use crate::encoding::*;
use crate::cipher::SshCipher;
use crate::mac::SshMac;
use crate::kex::*;
use crate::msg;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

pub const MAX_PACKET_SIZE: usize = 256 * 1024;

/// Pseudo KEX algorithms from the strict-kex proposal (Terrapin mitigation).
/// Each side advertises its own name; strict mode is active only when both the
/// client's `...-c-...` and the server's `...-s-...` names were exchanged.
pub const KEX_STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const KEX_STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";

// Default algorithm lists follow OpenSSH 9.9p2's local KEXINIT proposal
// as observed over the wire (ssh -vvv). Only algorithms we actually
// implement appear here; sntrup/mlkem (KEX), umac (MAC), certificate/
// sk-hostkey and ssh-rsa (host key), aes*-cbc/3des (cipher) remain
// available via explicit config but are no longer advertised by default.
const DEFAULT_KEX: &[&str] = &[
    "ecdh-sha2-nistp256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
];

const DEFAULT_HOST_KEYS: &[&str] = &[
    // Certificate variants are preferred, as OpenSSH does; they only
    // negotiate when the server actually presents a certified host key.
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

const DEFAULT_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
];

const DEFAULT_MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-256",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-512",
    "hmac-sha1",
];

/// Full cipher set that `create_cipher` can construct, for explicit `Ciphers`
/// config (the default proposal only advertises `DEFAULT_CIPHERS`).
const SUPPORTED_CIPHERS: &[&str] = &[
    "none",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
];

/// Full MAC set that `create_mac` can construct, for explicit `MACs` config.
const SUPPORTED_MACS: &[&str] = &[
    "none",
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
];
/// Return the default supported algorithms for a `-Q` query (key/cipher/mac/kex).
pub fn supported_algorithms(query: &str) -> Option<&'static [&'static str]> {
    match query.to_lowercase().as_str() {
        "key" | "hostkey" | "host-key" => Some(DEFAULT_HOST_KEYS),
        "key-sig" | "sig" => Some(DEFAULT_SIG_ALGS),
        "cipher" | "ciphers" => Some(DEFAULT_CIPHERS),
        "mac" | "macs" => Some(DEFAULT_MACS),
        "kex" | "key-exchange" | "key-exchange-algorithm" => Some(DEFAULT_KEX),
        "help" => Some(&["help", "key", "key-sig", "sig", "cipher", "mac", "kex"]),
        _ => None,
    }
}

/// Non-certificate signature (public key) algorithms, for `-Q sig`.
const DEFAULT_SIG_ALGS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

fn filter_algos<'a>(
    defaults: &'a [&'a str],
    supported: &'a [&'a str],
    config: Option<&'a [String]>,
) -> Vec<&'a str> {
    match config {
        Some(list) if !list.is_empty() => {
            // OpenSSH supports leading `+`/`-`/`^` on the whole comma list to
            // modify the built-in default set:
            //   `KexAlgorithms +curve25519-sha256`   (append to default)
            //   `KexAlgorithms -diffie-hellman-group14-sha1` (remove from default)
            //   `KexAlgorithms ^ecdh-sha2-nistp256`   (remove from default)
            let first = list.first().map(|s| s.trim()).unwrap_or("");
            let items: Vec<&str> = std::iter::once(
                first.trim_start_matches(|c| c == '+' || c == '-' || c == '^'),
            )
            .chain(list.iter().skip(1).map(|s| s.trim()))
            .collect();

            if let Some(_rest) = first.strip_prefix('+') {
                // Append the listed algorithms to the defaults (dedup, keep order).
                let mut out: Vec<&str> = defaults.to_vec();
                for item in items {
                    if !out.contains(&item) && supported.contains(&item) {
                        out.push(item);
                    }
                }
                out
            } else if first.starts_with('-') || first.starts_with('^') {
                // Remove the listed algorithms from the defaults.
                defaults
                    .iter()
                    .copied()
                    .filter(|d| !items.iter().any(|n| *n == *d))
                    .collect()
            } else {
                // Explicit list: keep only algorithms we support, preserving
                // order. `supported` includes legacy/default-disabled algorithms
                // (e.g. `none` cipher/MAC, MD5 MACs) so they are selectable when
                // explicitly configured but never advertised by default.
                list.iter()
                    .filter_map(|item| {
                        let item = item.trim();
                        supported.iter().find(|s| **s == item).copied()
                    })
                    .collect()
            }
        }
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
    /// Both strict-kex pseudo algorithms were present in the exchange.
    pub strict_kex: bool,
    /// RFC 8308: the client advertised `ext-info-c` (client-side negotiation).
    pub client_ext_info_c: bool,
    pub server_ext_info_s: bool,
    /// RFC 4253 §7: the client set `first_kex_packet_follows` but the guessed
    /// algorithm was not selected, so the client's next KEX packet must be
    /// discarded by the receiver.
    pub client_first_kex_follows_wrong_guess: bool,
    /// Same as above for the server side.
    pub server_first_kex_follows_wrong_guess: bool,
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
    /// Strict KEX was negotiated (both pseudo algorithms were advertised).
    /// When true, non-KEX packets are rejected during key exchange and the
    /// sequence numbers reset to zero after NEWKEYS.
    pub strict_kex: bool,
    /// The peer's KEXINIT for the current exchange has been received. Until
    /// that point generic packets already in flight are legal (strict KEX only
    /// binds senders after they know the exchange started).
    pub strict_kex_peer_kexinit: bool,
    pub compression_active_c2s: bool,
    pub compression_active_s2c: bool,
    pub compression_enabled: bool,
    pub client_version: Vec<u8>,
    pub server_version: Vec<u8>,
    pub client_kex_init: Vec<u8>,
    pub server_kex_init: Vec<u8>,
    pub outgoing_seq: u64,
    pub incoming_seq: u64,
    /// Actual bytes written to the wire (including the 4-byte packet_length
    /// field and any MAC/AEAD tag) since this transport was created.
    pub bytes_out: u64,
    /// Actual bytes read from the wire since this transport was created.
    pub bytes_in: u64,
    pub exchange: Option<KexExchange>,
    pub last_rekey_bytes: u64,
    pub last_rekey_instant: std::time::Instant,
    /// Rekey when this many bytes have been sent+received since the last rekey.
    pub rekey_bytes: u64,
    /// Rekey when this many seconds have elapsed since the last rekey.
    pub rekey_seconds: u64,
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
            strict_kex: false,
            strict_kex_peer_kexinit: false,
            compression_active_c2s: false,
            compression_active_s2c: false,
            compression_enabled: true,
            client_version: msg::SSH_VERSION.as_bytes().to_vec(),
            server_version: Vec::new(),
            client_kex_init: Vec::new(),
            server_kex_init: Vec::new(),
            outgoing_seq: 0,
            incoming_seq: 0,
            bytes_out: 0,
            bytes_in: 0,
            exchange: None,
            last_rekey_bytes: 0,
            last_rekey_instant: std::time::Instant::now(),
            rekey_bytes: Self::REKEY_BYTES,
            rekey_seconds: Self::REKEY_SECONDS,
        }
    }

    pub fn build_kex_init(
        &mut self,
        host_key_algorithms: Option<&[String]>,
        kex_algorithms: Option<&[String]>,
        ciphers: Option<&[String]>,
        macs: Option<&[String]>,
        is_server: bool,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(msg::SSH_MSG_KEXINIT);
        let mut cookie = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cookie);
        payload.extend_from_slice(&cookie);

        let mut kex_list: Vec<&str> = filter_algos(DEFAULT_KEX, DEFAULT_KEX, kex_algorithms);
        // Terrapin mitigation: always advertise our strict-kex pseudo algorithm.
        // The peer detects it in this name-list; it is never selected as a real
        // key exchange (see `choose_kex_algorithm`).
        kex_list.push(if is_server { KEX_STRICT_SERVER } else { KEX_STRICT_CLIENT });
        // RFC 8308 §3: the client advertises `ext-info-c` to ask the server to
        // send SSH_MSG_EXT_INFO; the server advertises `ext-info-s`. Both are
        // pseudo algorithms, never selected as a real KEX.
        kex_list.push(if is_server { "ext-info-s" } else { "ext-info-c" });
        payload.extend(encode_name_list(&kex_list));

        let host_key_list: Vec<&str> = match host_key_algorithms {
            Some(algs) if !algs.is_empty() => algs.iter().map(|s| s.as_str()).collect(),
            _ => DEFAULT_HOST_KEYS.to_vec(),
        };
        payload.extend(encode_name_list(&host_key_list));

        let cipher_list: Vec<&str> = filter_algos(DEFAULT_CIPHERS, SUPPORTED_CIPHERS, ciphers);
        payload.extend(encode_name_list(&cipher_list));
        payload.extend(encode_name_list(&cipher_list));

        let mac_list: Vec<&str> = filter_algos(DEFAULT_MACS, SUPPORTED_MACS, macs);
        payload.extend(encode_name_list(&mac_list));
        payload.extend(encode_name_list(&mac_list));

        // RFC 4253 §7.1: the first algorithm on the client's list that the
        // server also supports is chosen. Put zlib first when compression is
        // enabled so it is actually negotiated; otherwise "none" wins.
        let comp_list: Vec<&str> = if self.compression_enabled {
            vec!["zlib@openssh.com", "none"]
        } else {
            vec!["none", "zlib@openssh.com"]
        };
        payload.extend(encode_name_list(&comp_list));
        payload.extend(encode_name_list(&comp_list));

        payload.extend(encode_name_list(&[]));
        payload.extend(encode_name_list(&[]));

        payload.extend_from_slice(&[0u8; 5]);

        self.client_kex_init = payload.clone();
        payload
    }

    pub fn prepare_rekey(&mut self, is_server: bool) -> Vec<u8> {
        // A fresh exchange starts; in-flight generic packets are legal until
        // the peer's KEXINIT arrives.
        self.strict_kex_peer_kexinit = false;
        let mut cookie = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cookie);
        let mut payload = Vec::new();
        payload.push(msg::SSH_MSG_KEXINIT);
        payload.extend_from_slice(&cookie);
        let source = if is_server { self.server_kex_init.clone() } else { self.client_kex_init.clone() };
        payload.extend(source[17..].to_vec());
        if is_server {
            self.server_kex_init = payload.clone();
        } else {
            self.client_kex_init = payload.clone();
        }
        payload
    }

    pub const REKEY_BYTES: u64 = 1 << 30;
    pub const REKEY_SECONDS: u64 = 3600;

    pub fn needs_rekey(&self, total_bytes: u64, elapsed_secs: u64) -> bool {
        total_bytes.saturating_sub(self.last_rekey_bytes) >= self.rekey_bytes
            || elapsed_secs >= self.rekey_seconds
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_out.saturating_add(self.bytes_in)
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
        let _client_lang_cs = SshNameList::decode(&mut cr)?;
        let _client_lang_sc = SshNameList::decode(&mut cr)?;
        // RFC 4253 §7: after the two language lists comes a single byte
        // `first_kex_packet_follows` and a reserved uint32.
        let client_first_kex_follows = *cr.first().unwrap_or(&0) != 0;

        let mut sr = &server_kex[17..];

        let server_kex_algos = SshNameList::decode(&mut sr)?;
        let server_host_key = SshNameList::decode(&mut sr)?;
        let server_ciphers_cs = SshNameList::decode(&mut sr)?;
        let server_ciphers_sc = SshNameList::decode(&mut sr)?;
        let server_macs_cs = SshNameList::decode(&mut sr)?;
        let server_macs_sc = SshNameList::decode(&mut sr)?;
        let server_comps_cs = SshNameList::decode(&mut sr)?;
        let server_comps_sc = SshNameList::decode(&mut sr)?;
        let _server_lang_cs = SshNameList::decode(&mut sr)?;
        let _server_lang_sc = SshNameList::decode(&mut sr)?;
        let server_first_kex_follows = *sr.first().unwrap_or(&0) != 0;

        // Strict KEX (Terrapin mitigation) requires the client to advertise
        // `-c-` and the server to advertise `-s-`; either name alone is inert.
        let strict_kex = client_kex_algos.0.iter().any(|a| a == KEX_STRICT_CLIENT)
            && server_kex_algos.0.iter().any(|a| a == KEX_STRICT_SERVER);

        let kex = choose_kex_algorithm(&client_kex_algos.0, &server_kex_algos.0)
            .ok_or_else(|| SshError::KexFailed("no common key exchange algorithm".into()))?;
        let host_key = choose_algorithm(&client_host_key.0, &server_host_key.0)
            .ok_or_else(|| SshError::KexFailed("no common host key algorithm".into()))?;
        let cipher_cs = choose_algorithm(&client_ciphers_cs.0, &server_ciphers_cs.0)
            .ok_or_else(|| SshError::KexFailed("no common client-to-server cipher".into()))?;
        let cipher_sc = choose_algorithm(&client_ciphers_sc.0, &server_ciphers_sc.0)
            .ok_or_else(|| SshError::KexFailed("no common server-to-client cipher".into()))?;
        // AEAD ciphers (including chacha20-poly1305@openssh.com) carry their
        // own authentication tag (Poly1305 / GCM); there is no separate MAC
        // algorithm. OpenSSH reports "<implicit>" in this case.
        let mac_cs = if crate::cipher::create_cipher(&cipher_cs)
            .map(|c| c.is_aead()).unwrap_or(false) {
            "none".to_string()
        } else {
            choose_algorithm(&client_macs_cs.0, &server_macs_cs.0)
                .ok_or_else(|| SshError::KexFailed("no common client-to-server mac".into()))?
        };
        let mac_sc = if crate::cipher::create_cipher(&cipher_sc)
            .map(|c| c.is_aead()).unwrap_or(false) {
            "none".to_string()
        } else {
            choose_algorithm(&client_macs_sc.0, &server_macs_sc.0)
                .ok_or_else(|| SshError::KexFailed("no common server-to-client mac".into()))?
        };
        let comp_cs = choose_algorithm(&client_comps_cs.0, &server_comps_cs.0)
            .unwrap_or_else(|| "none".to_string());
        let comp_sc = choose_algorithm(&client_comps_sc.0, &server_comps_sc.0)
            .unwrap_or_else(|| "none".to_string());

        // RFC 4253 §7: if `first_kex_packet_follows` was set but the guessed
        // algorithm was not selected, the peer's next KEX packet must be
        // discarded by the receiver.
        let client_first_kex_follows_wrong_guess = client_first_kex_follows
            && client_kex_algos.0.first() != Some(&kex);
        let server_first_kex_follows_wrong_guess = server_first_kex_follows
            && server_kex_algos.0.first() != Some(&kex);

        Ok(AlgorithmNegotiation {
            kex_algorithm: kex,
            host_key_algorithm: host_key,
            client_to_server_cipher: cipher_cs,
            server_to_client_cipher: cipher_sc,
            client_to_server_mac: mac_cs,
            server_to_client_mac: mac_sc,
            client_to_server_compression: comp_cs,
            server_to_client_compression: comp_sc,
            strict_kex,
            // RFC 8308 §3.1: `ext-info-c`/`ext-info-s` are pseudo algorithms
            // carried in the KEX name-list; their presence signals the peer's
            // willingness to exchange EXT_INFO.
            client_ext_info_c: client_kex_algos.0.iter().any(|a| a == "ext-info-c"),
            server_ext_info_s: server_kex_algos.0.iter().any(|a| a == "ext-info-s"),
            client_first_kex_follows_wrong_guess: client_first_kex_follows_wrong_guess,
            server_first_kex_follows_wrong_guess: server_first_kex_follows_wrong_guess,
        })
    }

    /// Message types allowed on the wire while a strict KEX is in progress.
    /// The Terrapin draft forbids generic transport messages (IGNORE, DEBUG,
    /// UNIMPLEMENTED, EXT_INFO) between KEXINIT and NEWKEYS.
    pub fn is_allowed_during_strict_kex(msg_type: u8) -> bool {
        matches!(msg_type, msg::SSH_MSG_DISCONNECT | msg::SSH_MSG_KEXINIT | msg::SSH_MSG_NEWKEYS)
            || (msg::SSH_MSG_KEXDH_INIT..=msg::SSH_MSG_KEX_DH_GEX_REQUEST).contains(&msg_type)
    }

    /// Reject a non-KEX packet received while strict KEX is active. Called from
    /// every packet reader so the rule applies uniformly to core, client-local
    /// and server-local transport implementations.
    ///
    /// Like OpenSSH (`kex_protocol_error`), the ordering rule only applies to
    /// the initial key exchange: Terrapin targets the first KEX, and rekeys
    /// routinely deliver data packets that were already in flight when the
    /// peer's KEXINIT was sent. The session id is recorded only after the
    /// initial NEWKEYS, so its presence marks a rekey.
    pub fn check_strict_kex_packet(&self, payload: &[u8]) -> Result<()> {
        if !self.strict_kex
            || !self.strict_kex_peer_kexinit
            || self.session_id.is_some()
            || self.state == KexState::Established
        {
            return Ok(());
        }
        match payload.first() {
            Some(&t) if Self::is_allowed_during_strict_kex(t) => Ok(()),
            Some(&t) => Err(SshError::Protocol(format!(
                "strict KEX: message {} is not allowed during key exchange (state={:?}, incoming_seq={})",
                t, self.state, self.incoming_seq
            ))),
            None => Err(SshError::Protocol("strict KEX: empty packet".into())),
        }
    }

    /// After both NEWKEYS have crossed under strict KEX, both sequence
    /// numbers restart at zero. In non-strict mode they keep counting (as
    /// OpenSSH did before strict KEX existed).
    ///
    /// The reset is part of the initial exchange only: OpenSSH resets the
    /// counters when `SSH2_MSG_NEWKEYS` is seen while `kex_strict` is set, and
    /// `kex_strict` is only ever set for the initial KEX. Resetting on rekey
    /// would desynchronise the MAC sequence numbers with OpenSSH.
    pub fn reset_sequences_after_newkeys(&mut self) {
        if self.strict_kex && self.session_id.is_none() {
            self.outgoing_seq = 0;
            self.incoming_seq = 0;
        }
    }

    pub fn create_kex_algorithm(name: &str) -> Result<Box<dyn KexAlgorithm>> {
        match name {
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
                Ok(Box::new(Curve25519Kex::new()))
            }
            "sntrup761x25519-sha512" | "sntrup761x25519-sha512@openssh.com" => {
                Ok(Box::new(SntrupX25519Kex::new()))
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
            KEX_STRICT_CLIENT | KEX_STRICT_SERVER => Err(SshError::UnsupportedAlgorithm(
                "strict-kex is a pseudo-kex, not negotiable alone".into(),
            )),
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
        let s2c_key_len = crate::cipher::create_cipher(&negotiation.server_to_client_cipher)?.key_len();
        let s2c_iv_len = crate::cipher::create_cipher(&negotiation.server_to_client_cipher)?.iv_len();
        let s2c_mac_len = crate::mac::create_mac(&negotiation.server_to_client_mac)?.key_len();

        // RFC 9941 §3: the hybrid KEX encodes K as a `string` (not an mpint)
        // in both the exchange hash and key derivation. All other KEX methods
        // use the canonical mpint form.
        let hybrid = negotiation.kex_algorithm.starts_with("sntrup761x25519");
        let (c2s_iv, c2s_key, c2s_mac_key) = if hybrid {
            (
                crate::kex::derive_hybrid_key(shared_secret, exchange_hash, session_id, b'A', iv_len),
                crate::kex::derive_hybrid_key(shared_secret, exchange_hash, session_id, b'C', key_len),
                crate::kex::derive_hybrid_key(shared_secret, exchange_hash, session_id, b'E', mac_len),
            )
        } else {
            (
                derive_initial_iv(hash_name, shared_secret, exchange_hash, session_id, iv_len),
                derive_encryption_key(hash_name, shared_secret, exchange_hash, session_id, key_len),
                derive_integrity_key(hash_name, shared_secret, exchange_hash, session_id, mac_len),
            )
        };

        let s2c_iv = if hybrid {
            crate::kex::derive_hybrid_key(shared_secret, exchange_hash, session_id, b'B', s2c_iv_len)
        } else {
            crate::kex::derive_s2c_initial_iv(hash_name, shared_secret, exchange_hash, session_id, s2c_iv_len)
        };
        let s2c_key = if hybrid {
            crate::kex::derive_hybrid_key(shared_secret, exchange_hash, session_id, b'D', s2c_key_len)
        } else {
            crate::kex::derive_s2c_encryption_key(hash_name, shared_secret, exchange_hash, session_id, s2c_key_len)
        };
        let s2c_mac_key = if hybrid {
            crate::kex::derive_hybrid_key(shared_secret, exchange_hash, session_id, b'F', s2c_mac_len)
        } else {
            crate::kex::derive_s2c_integrity_key(hash_name, shared_secret, exchange_hash, session_id, s2c_mac_len)
        };

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

        if std::env::var("NS_DEBUG_PKT").is_ok() {
            let h = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
            eprintln!("KEYS c2s_key={} c2s_iv={} c2s_mac={} s2c_key={} s2c_iv={} s2c_mac={}",
                h(&c2s_key), h(&c2s_iv), h(&c2s_mac_key), h(&s2c_key), h(&s2c_iv), h(&s2c_mac_key));
        }

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

/// Like `choose_algorithm`, but never returns a pseudo algorithm: strict-kex
/// names appear in the KEX name-list yet have no key exchange implementation.
fn choose_kex_algorithm(client: &[String], server: &[String]) -> Option<String> {
    client
        .iter()
        .filter(|c| !is_pseudo_kex(c))
        .find(|c| server.contains(c))
        .cloned()
}

fn is_pseudo_kex(name: &str) -> bool {
    name == KEX_STRICT_CLIENT || name == KEX_STRICT_SERVER || name == "ext-info-c" || name == "ext-info-s"
}

pub async fn send_version_string(stream: &mut (impl AsyncWrite + Unpin), version: &[u8]) -> Result<()> {
    stream.write_all(version).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_version_string(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    // RFC 4253 §4.2: the server may send arbitrary "banner" lines before its
    // identification string. Any line that does not start with "SSH-" is
    // ancillary text and must be skipped; the protocol starts at the first
    // "SSH-" line.
    loop {
        let mut line = Vec::new();
        loop {
            stream.read_exact(&mut buf).await?;
            if buf[0] == b'\n' {
                break;
            }
            if buf[0] != b'\r' {
                line.push(buf[0]);
            }
            if line.len() > 255 {
                return Err(SshError::Protocol("version string too long".into()));
            }
        }
        if line.starts_with(b"SSH-") {
            return Ok(line);
        }
    }
}

/// Compute the random-padding length for an SSH packet (RFC 4253 §6).
///
/// `base` is the length of `padding_length byte + payload` (i.e. 1 + payload.len()).
///
/// When `packet_length_encrypted` is true (non-ETM MAC, or the pre-key "none"
/// cipher) the 4-byte packet_length field is part of the encrypted stream and
/// OpenSSH requires `(4 + packet_length)` to be a multiple of the block size
/// (`need = 4 + packlen - block_size` must be block-aligned). When false
/// (ETM MAC or an AEAD cipher) the packet_length field is authenticated but not
/// encrypted, so OpenSSH requires `packet_length` itself to be a multiple of
/// the block size. Minimum padding is 4 bytes.
pub fn compute_packet_padding(
    base: usize,
    block_size: usize,
    packet_length_encrypted: bool,
) -> usize {
    let target = if packet_length_encrypted { (block_size - 4) % block_size } else { 0 };
    let rem = base % block_size;
    let mut padding_len = (target + block_size - rem) % block_size;
    if padding_len < 4 { padding_len += block_size; }
    padding_len
}

/// Validate a decrypted/plain packet body (`padding_length || payload || padding`)
/// and return the payload.
///
/// `padding_length` is supplied by the peer, so it must never be trusted for
/// slice arithmetic: RFC 4253 §6 requires at least 4 bytes of padding and at
/// least one payload byte, and any body that violates that is rejected with
/// `InvalidPacket` instead of underflowing `body.len() - 1 - padding_length`
/// (which used to panic in debug builds and slice out of bounds otherwise).
pub fn unpack_packet_body(body: &[u8]) -> Result<Vec<u8>> {
    let padding_len = match body.first() {
        Some(v) => *v as usize,
        None => return Err(SshError::InvalidPacket("empty packet body".into())),
    };
    // RFC 4253 §6: "There MUST be at least four bytes of padding."
    if padding_len < 4 {
        return Err(SshError::InvalidPacket(format!(
            "invalid padding length: {}",
            padding_len
        )));
    }
    // Reject before subtracting: keeps at least one payload byte
    // (RFC 4253 §6: the payload "MUST be at least one byte").
    if padding_len + 1 >= body.len() {
        return Err(SshError::InvalidPacket(format!(
            "padding length {} exceeds packet body length {}",
            padding_len,
            body.len()
        )));
    }
    Ok(body[1..body.len() - padding_len].to_vec())
}

/// Set the IP type-of-service (IPv4 `IP_TOS`) or traffic class (IPv6
/// `IPV6_TCLASS`) on a connected socket, implementing OpenSSH's `IPQoS`.
/// A negative `tos` (OpenSSH `none`) leaves the socket untouched.
/// Failures are intentionally silent: QoS is best-effort.
#[cfg(unix)]
pub fn set_ip_qos<S: std::os::unix::io::AsRawFd>(stream: &S, tos: i32) {
    if tos < 0 {
        return;
    }
    let fd = stream.as_raw_fd();
    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) != 0 {
            return;
        }
        let val: libc::c_int = tos;
        let (level, opt) = match addr.ss_family as libc::c_int {
            libc::AF_INET => (libc::IPPROTO_IP, libc::IP_TOS),
            libc::AF_INET6 => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
            _ => return,
        };
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

pub async fn send_raw_packet(stream: &mut (impl AsyncWrite + Unpin), payload: &[u8]) -> Result<()> {
    let base = 1 + payload.len();
    let padding_len = compute_packet_padding(base, 8, true);
    let mut padding = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
    let body_len = base + padding_len;
    // RFC 4253 §6: packet_length excludes its own 4-byte field.
    let packet_len_field = body_len as u32;

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

    if total_len > MAX_PACKET_SIZE || total_len < 5 {
        return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
    }
    let body_len = total_len;

    let mut rest = vec![0u8; body_len];
    stream.read_exact(&mut rest).await?;

    unpack_packet_body(&rest)
}

pub async fn send_encrypted_packet(
    stream: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
    transport: &mut SshTransport,
    is_newkeys: bool,
    is_aead: bool,
) -> Result<()> {
    if transport.client_to_server_cipher.is_none() {
        // Unencrypted pre-KEX / NEWKEYS packets still count toward the rekey
        // budget; the padding rule is deterministic, so the wire length is
        // known before writing.
        let base = 1 + payload.len();
        transport.bytes_out += (4 + base + compute_packet_padding(base, 8, true)) as u64;
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
    let mac = transport.client_to_server_mac.as_ref();
    let block_size = cipher.block_size().max(8);
    let seq = transport.outgoing_seq;
    let wire_len: usize;

    if is_aead {
        let chachapoly = cipher.is_chachapoly();
        let base = 1 + payload.len();
        // AEAD always uses aadlen=4 (OpenSSH: aadlen = (mac && etm) || authlen
        // ? 4 : 0), so packet_length itself must be block-aligned — for
        // AES-GCM (block 16) and chacha20-poly1305 (block 8) alike. chacha
        // merely encrypts the length field on the wire with its header key;
        // that does not change the padding rule.
        let padding_len = compute_packet_padding(base, block_size, false);
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = body_len as u32;

        let mut packet = Vec::new();
        packet.extend(&packet_len_field.to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend(&payload);
        packet.extend(&padding[..padding_len]);

        if chachapoly {
            let ciphertext = cipher.encrypt(seq, &packet)?;
            wire_len = ciphertext.len();
            stream.write_all(&ciphertext).await?;
        } else {
            // AES-GCM authenticates the cleartext packet_length as AAD.
            let ciphertext = cipher.encrypt_with_aad(seq, &packet[..4], &packet[4..])?;
            packet.truncate(4);
            packet.extend(&ciphertext);
            wire_len = packet.len();
            stream.write_all(&packet).await?;
        }
    } else {
        let mac = mac.unwrap();
        let base = 1 + payload.len();
        // ETM leaves packet_length in the clear (target 0); non-ETM encrypts it.
        let padding_len = compute_packet_padding(base, block_size, !mac.as_ref().is_etm());
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = body_len as u32;
        let len_bytes = packet_len_field.to_be_bytes();

        let mut packet_data = Vec::new();
        packet_data.push(padding_len as u8);
        packet_data.extend(&payload);
        packet_data.extend(&padding[..padding_len]);

        let packet = if mac.as_ref().is_etm() {
            // RFC 6668: ETM leaves packet_length in the clear and authenticates
            // seq || packet_length || ciphertext, so encrypt only the body.
            let ciphertext = cipher.encrypt(seq, &packet_data)?;
            let mut etm_input = Vec::with_capacity(4 + ciphertext.len());
            etm_input.extend_from_slice(&len_bytes);
            etm_input.extend_from_slice(&ciphertext);
            let mac_tag = mac.as_ref().compute_tag(seq, &etm_input)?;

            let mut packet = Vec::new();
            packet.extend_from_slice(&len_bytes);
            packet.extend(&ciphertext);
            packet.extend(&mac_tag);
            packet
        } else {
            // RFC 4253 §6.4: a non-ETM MAC's packet_length is encrypted as
            // part of the first cipher block. Encrypt the whole packet (length
            // included) and authenticate the plaintext packet.
            let mut plain = Vec::with_capacity(4 + packet_data.len());
            plain.extend_from_slice(&len_bytes);
            plain.extend_from_slice(&packet_data);
            let mac_tag = mac.as_ref().compute_tag(seq, &plain)?;
            let mut packet = cipher.encrypt(seq, &plain)?;
            packet.extend(&mac_tag);
            packet
        };

        wire_len = packet.len();
        stream.write_all(&packet).await?;
    }

    // RFC 4253 §6.4: every packet, including NEWKEYS, consumes a sequence
    // number. `is_newkeys` only suppresses compression for the NEWKEYS packet
    // itself; the counters must keep advancing so both peers stay in sync
    // across rekeys (strict KEX resets them afterwards for the initial KEX).
    transport.bytes_out += wire_len as u64;
    transport.outgoing_seq += 1;
    stream.flush().await?;
    Ok(())
}

pub async fn receive_encrypted_packet(
    stream: &mut (impl AsyncRead + Unpin),
    transport: &mut SshTransport,
    is_newkeys: bool,
    is_aead: bool,
) -> Result<Vec<u8>> {
    if transport.server_to_client_cipher.is_none() {
        let payload = receive_raw_packet(stream).await?;
        let base = 1 + payload.len();
        transport.bytes_in += (4 + base + compute_packet_padding(base, 8, true)) as u64;
        transport.check_strict_kex_packet(&payload)?;
        return Ok(payload);
    }

    let cipher = transport.server_to_client_cipher.as_mut().unwrap();
    let mac = transport.server_to_client_mac.as_ref();
    let seq = transport.incoming_seq;

    let payload = if is_aead {
        let tag_len = cipher.tag_len();
        if cipher.is_chachapoly() {
            // chacha20-poly1305@openssh.com: the 4-byte packet_length is
            // encrypted with the header key, and the Poly1305 tag follows the
            // ciphertext. `cipher.decrypt` expects ciphertext || tag.
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let plen = cipher.decrypt_length(seq, &len_buf)? as usize;
            // AEAD uses aadlen=4, so packet_length is block-aligned.
            if plen > MAX_PACKET_SIZE || plen < 5 || plen % cipher.block_size() != 0 {
                return Err(SshError::InvalidPacket(format!("invalid packet size: {}", plen)));
            }
            let mut ct = Vec::with_capacity(4 + plen + tag_len);
            ct.extend_from_slice(&len_buf);
            let mut body_ct = vec![0u8; plen];
            stream.read_exact(&mut body_ct).await?;
            ct.extend_from_slice(&body_ct);
            if tag_len > 0 {
                let mut tag = vec![0u8; tag_len];
                stream.read_exact(&mut tag).await?;
                ct.extend_from_slice(&tag);
            }
            let plaintext = cipher.decrypt(seq, &ct)
                .map_err(|_| SshError::DecryptionFailed)?;
            if plaintext.len() < 4 {
                return Err(SshError::Protocol("chacha packet too short".into()));
            }
            let payload = unpack_packet_body(&plaintext[4..])?;
            transport.bytes_in += (4 + plen + tag_len) as u64;
            transport.incoming_seq += 1;
            payload
        } else {
            // GCM and other AEAD ciphers: packet_length is cleartext and
            // authenticated; the tag follows the ciphertext.
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let total_len = u32::from_be_bytes(len_buf) as usize;
            // AEAD uses aadlen=4, so packet_length is block-aligned.
            if total_len > MAX_PACKET_SIZE || total_len < 5 || total_len % cipher.block_size() != 0 {
                return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
            }
            let mut ciphertext = vec![0u8; total_len + tag_len];
            stream.read_exact(&mut ciphertext).await?;
            // AES-GCM authenticates the cleartext packet_length as AAD.
            let plaintext = cipher.decrypt_with_aad(seq, &len_buf, &ciphertext)
                .map_err(|_| SshError::DecryptionFailed)?;
            let payload = unpack_packet_body(&plaintext)?;
            transport.bytes_in += (4 + total_len + tag_len) as u64;
            transport.incoming_seq += 1;
            payload
        }
    } else {
        let mac = mac.unwrap();
        let (payload, wire_len) = if mac.as_ref().is_etm() {
            receive_etm_packet(stream, cipher, mac, seq).await?
        } else {
            receive_non_etm_packet(stream, cipher, mac, seq).await?
        };
        transport.bytes_in += wire_len as u64;
        transport.incoming_seq += 1;
        payload
    };

    let payload = if !is_newkeys
        && (transport.server_to_client_compression == "zlib"
            || (transport.server_to_client_compression == "zlib@openssh.com"
                && transport.compression_active_s2c))
    {
        zlib_decompress(&payload)?
    } else {
        payload
    };
    transport.check_strict_kex_packet(&payload)?;
    Ok(payload)
}

pub async fn send_encrypted_packet_server(
    stream: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
    transport: &mut SshTransport,
    is_newkeys: bool,
    is_aead: bool,
) -> Result<()> {
    if transport.server_to_client_cipher.is_none() || transport.server_to_client_mac.is_none() {
        let base = 1 + payload.len();
        transport.bytes_out += (4 + base + compute_packet_padding(base, 8, true)) as u64;
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
    let wire_len: usize;

    if is_aead {
        let chachapoly = cipher.is_chachapoly();
        let base = 1 + payload.len();
        // AEAD always uses aadlen=4, so packet_length is block-aligned for
        // both AES-GCM (16) and chacha20-poly1305 (8).
        let padding_len = compute_packet_padding(base, block_size, false);
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = body_len as u32;

        let mut packet = Vec::new();
        packet.extend(&packet_len_field.to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend(&payload);
        packet.extend(&padding[..padding_len]);

        if chachapoly {
            // encrypt() returns ciphertext || tag over the whole packet.
            let ciphertext = cipher.encrypt(seq, &packet)?;
            wire_len = ciphertext.len();
            stream.write_all(&ciphertext).await?;
        } else {
            // AES-GCM authenticates the cleartext packet_length as AAD.
            let ciphertext = cipher.encrypt_with_aad(seq, &packet[..4], &packet[4..])?;
            packet.truncate(4);
            packet.extend(&ciphertext);
            wire_len = packet.len();
            stream.write_all(&packet).await?;
        }
    } else {
        let base = 1 + payload.len();
        // ETM leaves packet_length in the clear (target 0); non-ETM encrypts it.
        let padding_len = compute_packet_padding(base, block_size, !mac.as_ref().is_etm());
        let mut padding = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..padding_len.min(64)]);
        let body_len = base + padding_len;
        let packet_len_field = body_len as u32;
        let len_bytes = packet_len_field.to_be_bytes();

        let mut packet_data = Vec::new();
        packet_data.push(padding_len as u8);
        packet_data.extend(&payload);
        packet_data.extend(&padding[..padding_len]);

        let packet = if mac.as_ref().is_etm() {
            // RFC 6668: ETM leaves packet_length in the clear and authenticates
            // seq || packet_length || ciphertext, so encrypt only the body.
            let ciphertext = cipher.encrypt(seq, &packet_data)?;
            let mut etm_input = Vec::with_capacity(4 + ciphertext.len());
            etm_input.extend_from_slice(&len_bytes);
            etm_input.extend_from_slice(&ciphertext);
            let mac_tag = mac.as_ref().compute_tag(seq, &etm_input)?;

            let mut packet = Vec::new();
            packet.extend_from_slice(&len_bytes);
            packet.extend(&ciphertext);
            packet.extend(&mac_tag);
            packet
        } else {
            // RFC 4253 §6.4: a non-ETM MAC's packet_length is encrypted as
            // part of the first cipher block. Encrypt the whole packet (length
            // included) and authenticate the plaintext packet.
            let mut plain = Vec::with_capacity(4 + packet_data.len());
            plain.extend_from_slice(&len_bytes);
            plain.extend_from_slice(&packet_data);
            let mac_tag = mac.as_ref().compute_tag(seq, &plain)?;
            let mut packet = cipher.encrypt(seq, &plain)?;
            packet.extend(&mac_tag);
            packet
        };

        wire_len = packet.len();
        stream.write_all(&packet).await?;
    }

    // Every packet consumes a sequence number; `is_newkeys` only suppresses
    // compression for the NEWKEYS packet itself.
    transport.bytes_out += wire_len as u64;
    transport.outgoing_seq += 1;
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
        let payload = receive_raw_packet(stream).await?;
        let base = 1 + payload.len();
        transport.bytes_in += (4 + base + compute_packet_padding(base, 8, true)) as u64;
        transport.check_strict_kex_packet(&payload)?;
        return Ok(payload);
    }

    let cipher = transport.client_to_server_cipher.as_mut().unwrap();
    let mac = transport.client_to_server_mac.as_ref().unwrap();
    let seq = transport.incoming_seq;

    let payload = if is_aead {
        let tag_len = cipher.tag_len();
        if cipher.is_chachapoly() {
            // chacha20-poly1305@openssh.com: encrypted packet_length (header
            // key) followed by the body and the Poly1305 tag.
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let plen = cipher.decrypt_length(seq, &len_buf)? as usize;
            // AEAD uses aadlen=4, so packet_length is block-aligned.
            if plen > MAX_PACKET_SIZE || plen < 5 || plen % cipher.block_size() != 0 {
                return Err(SshError::InvalidPacket(format!("invalid packet size: {}", plen)));
            }
            let mut ct = Vec::with_capacity(4 + plen + tag_len);
            ct.extend_from_slice(&len_buf);
            let mut body_ct = vec![0u8; plen];
            stream.read_exact(&mut body_ct).await?;
            ct.extend_from_slice(&body_ct);
            if tag_len > 0 {
                let mut tag = vec![0u8; tag_len];
                stream.read_exact(&mut tag).await?;
                ct.extend_from_slice(&tag);
            }
            let plaintext = cipher.decrypt(seq, &ct)
                .map_err(|_| SshError::DecryptionFailed)?;
            if plaintext.len() < 4 {
                return Err(SshError::Protocol("chacha packet too short".into()));
            }
            let payload = unpack_packet_body(&plaintext[4..])?;
            transport.bytes_in += (4 + plen + tag_len) as u64;
            transport.incoming_seq += 1;
            payload
        } else {
            // GCM and other AEAD ciphers: packet_length is cleartext.
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let total_len = u32::from_be_bytes(len_buf) as usize;
            // AEAD uses aadlen=4, so packet_length is block-aligned.
            if total_len > MAX_PACKET_SIZE || total_len < 5 || total_len % cipher.block_size() != 0 {
                return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
            }
            let mut ciphertext = vec![0u8; total_len + tag_len];
            stream.read_exact(&mut ciphertext).await?;
            // AES-GCM authenticates the cleartext packet_length as AAD.
            let plaintext = cipher.decrypt_with_aad(seq, &len_buf, &ciphertext)
                .map_err(|_| SshError::DecryptionFailed)?;
            let payload = unpack_packet_body(&plaintext)?;
            transport.bytes_in += (4 + total_len + tag_len) as u64;
            transport.incoming_seq += 1;
            payload
        }
    } else {
        let (payload, wire_len) = if mac.is_etm() {
            receive_etm_packet(stream, cipher, mac, seq).await?
        } else {
            receive_non_etm_packet(stream, cipher, mac, seq).await?
        };
        transport.bytes_in += wire_len as u64;
        transport.incoming_seq += 1;
        payload
    };

    let payload = if !is_newkeys
        && (transport.client_to_server_compression == "zlib"
            || (transport.client_to_server_compression == "zlib@openssh.com"
                && transport.compression_active_c2s))
    {
        zlib_decompress(&payload)?
    } else {
        payload
    };
    transport.check_strict_kex_packet(&payload)?;
    Ok(payload)
}

/// Read an ETM packet: packet_length is cleartext, the MAC covers
/// `seq || packet_length || ciphertext` and is verified before decryption.
/// Returns the payload and the number of wire bytes consumed.
async fn receive_etm_packet(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    cipher: &mut Box<dyn SshCipher>,
    mac: &Box<dyn SshMac>,
    seq: u64,
) -> Result<(Vec<u8>, usize)> {
    let block_size = cipher.block_size().max(8);
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;

    if total_len > MAX_PACKET_SIZE || total_len < 5 || total_len % block_size != 0 {
        return Err(SshError::InvalidPacket(format!("invalid packet size: {}", total_len)));
    }

    let mut ciphertext = vec![0u8; total_len];
    stream.read_exact(&mut ciphertext).await?;
    let mut mac_buf = vec![0u8; mac.tag_len()];
    stream.read_exact(&mut mac_buf).await?;

    let mut etm_input = Vec::with_capacity(4 + ciphertext.len());
    etm_input.extend_from_slice(&len_buf);
    etm_input.extend_from_slice(&ciphertext);
    if !mac.verify_tag(seq, &etm_input, &mac_buf)? {
        return Err(SshError::DecryptionFailed);
    }

    let plaintext = cipher.decrypt(seq, &ciphertext)
        .map_err(|_| SshError::DecryptionFailed)?;
    Ok((unpack_packet_body(&plaintext)?, 4 + total_len + mac.tag_len()))
}

/// Read a non-ETM packet (RFC 4253 §6.4): the 4-byte packet_length is part of
/// the encrypted stream, so the first cipher block must be decrypted to learn
/// the body length. The MAC covers the plaintext packet
/// `seq || packet_length || padding_length || payload || padding`.
/// Returns the payload and the number of wire bytes consumed.
async fn receive_non_etm_packet(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    cipher: &mut Box<dyn SshCipher>,
    mac: &Box<dyn SshMac>,
    seq: u64,
) -> Result<(Vec<u8>, usize)> {
    let block_size = cipher.block_size().max(8);
    let mut first_block = vec![0u8; block_size];
    stream.read_exact(&mut first_block).await?;
    let plain_first = cipher.decrypt(seq, &first_block)
        .map_err(|_| SshError::DecryptionFailed)?;
    if plain_first.len() < 4 {
        return Err(SshError::Protocol("non-ETM packet too short".into()));
    }
    let plen = u32::from_be_bytes([plain_first[0], plain_first[1], plain_first[2], plain_first[3]])
        as usize;
    if plen > MAX_PACKET_SIZE || plen < 5 {
        return Err(SshError::InvalidPacket(format!("invalid packet size: {}", plen)));
    }
    // `packet_length` plus its own 4-byte field is what the cipher stream
    // covers, so `4 + plen` must be block-aligned and at least one block.
    if 4 + plen < block_size || (4 + plen) % block_size != 0 {
        return Err(SshError::InvalidPacket(format!(
            "invalid non-ETM packet size: {} (block size {})",
            plen, block_size
        )));
    }

    let rest_len = 4 + plen - block_size;
    let mut rest = vec![0u8; rest_len];
    stream.read_exact(&mut rest).await?;
    let rest_plain = cipher.decrypt(seq, &rest)
        .map_err(|_| SshError::DecryptionFailed)?;

    let mut full = plain_first;
    full.extend_from_slice(&rest_plain);

    let mut mac_buf = vec![0u8; mac.tag_len()];
    stream.read_exact(&mut mac_buf).await?;
    if mac.tag_len() > 0 && !mac.verify_tag(seq, &full, &mac_buf)? {
        return Err(SshError::DecryptionFailed);
    }

    unpack_packet_body(&full[4..]).map(|p| (p, block_size + rest_len + mac.tag_len()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_algorithms_lists() {
        let key = supported_algorithms("key").unwrap();
        assert!(key.contains(&"ssh-ed25519"));
        assert!(key.contains(&"rsa-sha2-512"));
        let cipher = supported_algorithms("cipher").unwrap();
        assert!(cipher.contains(&"aes256-ctr"));
        assert!(cipher.contains(&"chacha20-poly1305@openssh.com"));
        let mac = supported_algorithms("mac").unwrap();
        assert!(mac.contains(&"hmac-sha2-256-etm@openssh.com"));
        // OpenSSH never advertises `none` as a MAC; doing so would let a peer
        // negotiate an unauthenticated channel (Terrapin-class downgrade).
        assert!(!mac.contains(&"none"));
        let kex = supported_algorithms("kex").unwrap();
        assert!(kex.contains(&"curve25519-sha256"));
        assert!(supported_algorithms("nonsense").is_none());
    }

    #[test]
    fn filter_algos_handles_caret_prefix() {
        // Explicit list keeps only supported algorithms, preserving order.
        let list = vec!["curve25519-sha256".to_string(), "not-real".to_string()];
        let out = filter_algos(DEFAULT_KEX, DEFAULT_KEX, Some(&list));
        assert_eq!(out, vec!["curve25519-sha256"]);

        // `^` prefix excludes algorithms from the default set.
        let list = vec!["^ecdh-sha2-nistp256".to_string()];
        let out = filter_algos(DEFAULT_KEX, DEFAULT_KEX, Some(&list));
        assert!(out.contains(&"curve25519-sha256"));
        assert!(!out.contains(&"ecdh-sha2-nistp256"));

        // `^` on a whole comma list excludes multiple algorithms.
        let list = vec![
            "^aes128-gcm@openssh.com".to_string(),
            "aes256-gcm@openssh.com".to_string(),
        ];
        let out = filter_algos(DEFAULT_CIPHERS, SUPPORTED_CIPHERS, Some(&list));
        assert!(!out.contains(&"aes128-gcm@openssh.com"));
        assert!(!out.contains(&"aes256-gcm@openssh.com"));
        assert!(out.contains(&"aes256-ctr"));

        // `+` appends to the default set.
        let list = vec!["+3des-cbc".to_string()];
        let out = filter_algos(DEFAULT_CIPHERS, SUPPORTED_CIPHERS, Some(&list));
        assert!(out.contains(&"3des-cbc"));
        assert_eq!(out.len(), DEFAULT_CIPHERS.len() + 1);
        assert!(out.ends_with(&["3des-cbc"]));

        // `-` removes from the default set.
        let list = vec!["-aes256-ctr".to_string()];
        let out = filter_algos(DEFAULT_CIPHERS, SUPPORTED_CIPHERS, Some(&list));
        assert!(!out.contains(&"aes256-ctr"));
        assert!(out.contains(&"aes128-ctr"));
    }

    #[test]
    fn compression_negotiation_prefers_zlib_when_enabled() {
        // Both sides enable compression -> zlib is chosen (RFC 4253 order).
        let mut c = SshTransport::new();
        c.compression_enabled = true;
        let c_init = c.build_kex_init(None, None, None, None, false);
        let mut s = SshTransport::new();
        s.compression_enabled = true;
        let s_init = s.build_kex_init(None, None, None, None, true);
        let neg = SshTransport::negotiate_algorithms(&c_init, &s_init).unwrap();
        assert_eq!(neg.client_to_server_compression, "zlib@openssh.com");
        assert_eq!(neg.server_to_client_compression, "zlib@openssh.com");

        // Both disabled (the default) -> none is chosen.
        let mut c2 = SshTransport::new();
        c2.compression_enabled = false;
        let c2_init = c2.build_kex_init(None, None, None, None, false);
        let mut s2 = SshTransport::new();
        s2.compression_enabled = false;
        let s2_init = s2.build_kex_init(None, None, None, None, true);
        let neg2 = SshTransport::negotiate_algorithms(&c2_init, &s2_init).unwrap();
        assert_eq!(neg2.client_to_server_compression, "none");
        assert_eq!(neg2.server_to_client_compression, "none");
    }

    #[test]
    fn strict_kex_is_enabled_only_when_both_sides_advertise_it() {
        let mut c = SshTransport::new();
        let c_init = c.build_kex_init(None, None, None, None, false);
        let mut s = SshTransport::new();
        let s_init = s.build_kex_init(None, None, None, None, true);

        let neg = SshTransport::negotiate_algorithms(&c_init, &s_init).unwrap();
        assert!(neg.strict_kex);
        // The pseudo algorithm must never be selected as the real KEX.
        assert!(!is_pseudo_kex(&neg.kex_algorithm));

        // A peer that advertises only the client pseudo (an older server that
        // does not implement strict KEX) leaves strict mode off, preserving
        // compatibility.
        let mut legacy_server = SshTransport::new();
        let legacy_init = legacy_server.build_kex_init(None, None, None, None, false);
        let neg_legacy = SshTransport::negotiate_algorithms(&c_init, &legacy_init).unwrap();
        assert!(!neg_legacy.strict_kex);
    }

    #[test]
    fn strict_kex_rejects_non_kex_packets_until_newkeys() {
        let mut t = SshTransport::new();
        t.strict_kex = true;
        t.state = KexState::KexDhInitSent;

        // Before the peer's KEXINIT arrives, packets already in flight are
        // legal (strict KEX only binds senders once the exchange is known).
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_CHANNEL_WINDOW_ADJUST]).is_ok());

        t.strict_kex_peer_kexinit = true;
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_IGNORE]).is_err());
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_DEBUG]).is_err());
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_KEXINIT]).is_ok());
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_KEXDH_INIT]).is_ok());
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_NEWKEYS]).is_ok());

        // After NEWKEYS generic messages are legal again.
        t.state = KexState::Established;
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_IGNORE]).is_ok());

        // A rekey (session id already recorded) is not subject to the
        // ordering rule: data packets in flight when the peer sent its
        // KEXINIT are legal, matching OpenSSH's KEX_INITIAL-only check.
        t.session_id = Some(vec![1, 2, 3]);
        t.state = KexState::NewKeysSent;
        t.strict_kex_peer_kexinit = true;
        assert!(t.check_strict_kex_packet(&[msg::SSH_MSG_CHANNEL_REQUEST]).is_ok());
    }

    #[test]
    fn strict_kex_resets_sequence_numbers_after_newkeys() {
        let mut t = SshTransport::new();
        t.strict_kex = true;
        t.outgoing_seq = 3;
        t.incoming_seq = 2;
        t.reset_sequences_after_newkeys();
        assert_eq!(t.outgoing_seq, 0);
        assert_eq!(t.incoming_seq, 0);

        // Without strict KEX the counters must keep counting.
        let mut plain = SshTransport::new();
        plain.outgoing_seq = 3;
        plain.incoming_seq = 2;
        plain.reset_sequences_after_newkeys();
        assert_eq!(plain.outgoing_seq, 3);
        assert_eq!(plain.incoming_seq, 2);

        // Strict KEX only resets after the *initial* NEWKEYS; a rekey (session
        // id present) keeps counting so the MAC sequence stays in sync.
        let mut rekey = SshTransport::new();
        rekey.strict_kex = true;
        rekey.session_id = Some(vec![1, 2, 3]);
        rekey.outgoing_seq = 3;
        rekey.incoming_seq = 2;
        rekey.reset_sequences_after_newkeys();
        assert_eq!(rekey.outgoing_seq, 3);
        assert_eq!(rekey.incoming_seq, 2);
    }

    /// Build a raw packet body: padding_length, payload, padding.
    fn packet_body(padding_len: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(padding_len);
        body.extend_from_slice(payload);
        body.extend(std::iter::repeat(0xAAu8).take(padding_len as usize));
        body
    }

    #[test]
    fn unpack_packet_body_accepts_valid_packet() {
        let payload = b"\x14\x01\x02\x03";
        let body = packet_body(4, payload);
        assert_eq!(unpack_packet_body(&body).unwrap(), payload);
    }

    #[test]
    fn unpack_packet_body_rejects_empty_body() {
        assert!(matches!(
            unpack_packet_body(&[]),
            Err(SshError::InvalidPacket(_))
        ));
    }

    #[test]
    fn unpack_packet_body_rejects_padding_below_rfc_minimum() {
        // RFC 4253 §6 requires at least four padding bytes. A peer sending
        // padding_length = 0..=3 must be rejected, not silently accepted.
        for padding_len in 0..4u8 {
            let body = packet_body(padding_len, b"\x14");
            assert!(matches!(
                unpack_packet_body(&body),
                Err(SshError::InvalidPacket(_))
            ));
        }
    }

    #[test]
    fn unpack_packet_body_rejects_padding_larger_than_body() {
        // This is the regression guard for the old
        // `body_len - 1 - padding_len` arithmetic: padding_len = 255 on a
        // short body used to underflow and panic/slice out of bounds.
        let mut body = vec![255u8];
        body.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            unpack_packet_body(&body),
            Err(SshError::InvalidPacket(_))
        ));

        // padding_length == body.len() also underflows the payload length.
        let body = vec![9u8; 9];
        assert!(matches!(
            unpack_packet_body(&body),
            Err(SshError::InvalidPacket(_))
        ));
    }

    #[test]
    fn unpack_packet_body_rejects_zero_length_payload() {
        // padding_length + 1 == body.len(): one padding byte too many leaves
        // no payload at all, which RFC 4253 forbids.
        let body = vec![8u8; 9];
        assert!(matches!(
            unpack_packet_body(&body),
            Err(SshError::InvalidPacket(_))
        ));
    }

    #[tokio::test]
    async fn read_version_string_skips_banner_lines() {
        // A proxy may prepend arbitrary text lines; only the SSH- line counts.
        let input = b"proxy says hello\r\nnot a version line\nSSH-2.0-NS_SSH\r\n";
        let mut reader: &[u8] = input;
        assert_eq!(
            read_version_string(&mut reader).await.unwrap(),
            b"SSH-2.0-NS_SSH"
        );
    }

    #[tokio::test]
    async fn read_version_string_rejects_overlong_line() {
        // RFC 4253 §4.2 caps each line at 255 bytes; reject instead of
        // buffering unbounded ancillary text.
        let mut input = vec![b'x'; 300];
        input.extend_from_slice(b"\r\nSSH-2.0-x\r\n");
        let mut reader: &[u8] = &input;
        assert!(matches!(
            read_version_string(&mut reader).await,
            Err(SshError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn receive_raw_packet_returns_payload_and_rejects_bad_padding() {
        // Valid raw packet: total_len = 6, padding_length = 4, payload = [0x14].
        let mut wire = Vec::new();
        wire.extend_from_slice(&6u32.to_be_bytes());
        wire.extend_from_slice(&packet_body(4, b"\x14"));
        let mut reader: &[u8] = &wire;
        assert_eq!(receive_raw_packet(&mut reader).await.unwrap(), vec![0x14]);

        // Peer-controlled padding_length larger than the body is an error,
        // never a panic.
        let mut wire = Vec::new();
        wire.extend_from_slice(&9u32.to_be_bytes());
        let mut body = vec![255u8];
        body.extend_from_slice(&[0u8; 8]);
        wire.extend_from_slice(&body);
        let mut reader: &[u8] = &wire;
        assert!(matches!(
            receive_raw_packet(&mut reader).await,
            Err(SshError::InvalidPacket(_))
        ));
    }

    const TEST_KEY: [u8; 32] = [0x42; 32];
    const TEST_IV: [u8; 16] = [0x24; 16];
    const TEST_MAC_KEY: [u8; 32] = [0x11; 32];

    fn make_cipher(name: &str) -> Box<dyn SshCipher> {
        let mut c = crate::cipher::create_cipher(name).unwrap();
        c.set_key(&TEST_KEY[..c.key_len()]).unwrap();
        c.set_iv(&TEST_IV[..c.iv_len()]).unwrap();
        c
    }

    fn make_mac(name: &str) -> Box<dyn SshMac> {
        let mut m = crate::mac::create_mac(name).unwrap();
        m.set_key(&TEST_MAC_KEY[..m.key_len()]).unwrap();
        m
    }

    /// Install a matching cipher/MAC pair on the client-to-server direction
    /// with a non-ETM MAC (the RFC 4253 §6.4 packet layout).
    fn install_client_direction(t: &mut SshTransport, cipher_name: &str, seq: u64) {
        t.client_to_server_cipher = Some(make_cipher(cipher_name));
        t.client_to_server_mac = Some(make_mac("hmac-sha2-256"));
        t.outgoing_seq = seq;
        t.incoming_seq = seq;
    }

    /// Install a matching cipher/MAC pair on the server-to-client direction.
    fn install_server_direction(t: &mut SshTransport, cipher_name: &str, seq: u64) {
        t.server_to_client_cipher = Some(make_cipher(cipher_name));
        t.server_to_client_mac = Some(make_mac("hmac-sha2-256"));
        t.outgoing_seq = seq;
        t.incoming_seq = seq;
    }

    fn plaintext_packet_len(payload_len: usize, block_size: usize) -> usize {
        let base = 1 + payload_len;
        1 + payload_len + compute_packet_padding(base, block_size, true)
    }

    #[tokio::test]
    async fn non_etm_roundtrip_client_to_server() {
        // AES-CTR (stream) and AES-CBC (stateful chaining) must both work: the
        // receiver decrypts the first block to learn packet_length and then
        // continues the same cipher stream for the remainder.
        for cipher_name in ["aes128-ctr", "aes128-cbc"] {
            let mut sender = SshTransport::new();
            let mut receiver = SshTransport::new();
            install_client_direction(&mut sender, cipher_name, 9);
            install_client_direction(&mut receiver, cipher_name, 9);

            let payload = vec![msg::SSH_MSG_SERVICE_REQUEST, 0, 0, 0, 4, b'n', b'o', b'p', b'e'];
            let mut wire: Vec<u8> = Vec::new();
            send_encrypted_packet(&mut wire, &payload, &mut sender, false, false)
                .await
                .unwrap();

            let block_size = make_cipher(cipher_name).block_size();
            let plen = plaintext_packet_len(payload.len(), block_size);
            // The 4-byte packet_length is part of the ciphertext, so the bytes
            // on the wire must not equal the plaintext length.
            let wire_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
            assert_ne!(wire_len, plen, "{cipher_name}: packet_length leaked in clear");
            assert_eq!(wire.len(), 4 + plen + 32, "{cipher_name}: wrong wire layout");

            let mut reader: &[u8] = &wire;
            let got = receive_encrypted_packet_server(&mut reader, &mut receiver, false, false)
                .await
                .unwrap();
            assert_eq!(got, payload);
            assert_eq!(receiver.incoming_seq, 10);
            assert_eq!(sender.outgoing_seq, 10);
        }
    }

    #[tokio::test]
    async fn non_etm_roundtrip_server_to_client() {
        for cipher_name in ["aes128-ctr", "aes128-cbc"] {
            let mut sender = SshTransport::new();
            let mut receiver = SshTransport::new();
            install_server_direction(&mut sender, cipher_name, 3);
            install_server_direction(&mut receiver, cipher_name, 3);

            let payload = vec![msg::SSH_MSG_CHANNEL_DATA, 1, 2, 3, 4];
            let mut wire: Vec<u8> = Vec::new();
            send_encrypted_packet_server(&mut wire, &payload, &mut sender, false, false)
                .await
                .unwrap();

            let block_size = make_cipher(cipher_name).block_size();
            let plen = plaintext_packet_len(payload.len(), block_size);
            let wire_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
            assert_ne!(wire_len, plen, "{cipher_name}: packet_length leaked in clear");
            assert_eq!(wire.len(), 4 + plen + 32, "{cipher_name}: wrong wire layout");

            let mut reader: &[u8] = &wire;
            let got = receive_encrypted_packet(&mut reader, &mut receiver, false, false)
                .await
                .unwrap();
            assert_eq!(got, payload);
            assert_eq!(receiver.incoming_seq, 4);
        }
    }

    #[tokio::test]
    async fn byte_counters_reflect_actual_wire_lengths() {
        // non-ETM (ciphertext covers the length field) and AEAD (tag appended
        // after the ciphertext) must both report exactly what crossed the wire.
        for (cipher_name, aead) in [("aes128-ctr", false), ("aes128-gcm@openssh.com", true)] {
            let mut sender = SshTransport::new();
            let mut receiver = SshTransport::new();
            install_client_direction(&mut sender, cipher_name, 0);
            install_client_direction(&mut receiver, cipher_name, 0);

            let payload = vec![msg::SSH_MSG_IGNORE, 1, 2, 3];
            let mut wire: Vec<u8> = Vec::new();
            send_encrypted_packet(&mut wire, &payload, &mut sender, false, aead)
                .await
                .unwrap();
            let mut reader: &[u8] = &wire;
            let got = receive_encrypted_packet_server(&mut reader, &mut receiver, false, aead)
                .await
                .unwrap();
            assert_eq!(got, payload);
            assert_eq!(sender.bytes_out as usize, wire.len(), "{cipher_name}: bytes_out");
            assert_eq!(receiver.bytes_in as usize, wire.len(), "{cipher_name}: bytes_in");
            assert_eq!(sender.total_bytes() as usize, wire.len());
            assert_eq!(receiver.total_bytes() as usize, wire.len());
        }
    }

    #[test]
    fn rekey_budget_uses_bytes_since_last_rekey() {
        let mut t = SshTransport::new();
        // Default budget is 1 GiB; a few packets must not trigger a rekey.
        t.bytes_out = 10_000;
        t.bytes_in = 10_000;
        assert!(!t.needs_rekey(t.total_bytes(), 0));

        // Once the baseline is recorded, only bytes sent/received *after* it
        // count: 1000 bytes below the budget must stay false, reaching it true.
        t.last_rekey_bytes = t.total_bytes();
        t.rekey_bytes = 1000;
        t.bytes_out += 999;
        assert!(!t.needs_rekey(t.total_bytes(), 0));
        t.bytes_out += 1;
        assert!(t.needs_rekey(t.total_bytes(), 0));

        // The time-based limit is independent of the byte budget.
        assert!(t.needs_rekey(t.total_bytes(), SshTransport::REKEY_SECONDS));
    }

    #[tokio::test]
    async fn non_etm_rejects_tampered_mac() {
        let mut sender = SshTransport::new();
        install_client_direction(&mut sender, "aes128-ctr", 0);
        let payload = vec![msg::SSH_MSG_IGNORE, 1];
        let mut wire: Vec<u8> = Vec::new();
        send_encrypted_packet(&mut wire, &payload, &mut sender, false, false)
            .await
            .unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;

        let mut receiver = SshTransport::new();
        install_client_direction(&mut receiver, "aes128-ctr", 0);
        let mut reader: &[u8] = &wire;
        assert!(matches!(
            receive_encrypted_packet_server(&mut reader, &mut receiver, false, false).await,
            Err(SshError::DecryptionFailed)
        ));
    }

    #[tokio::test]
    async fn non_etm_rejects_impossible_packet_length() {
        // The length is only known after decrypting the first block, so a
        // malicious peer can encode any value here. Reject lengths that are
        // out of range or that cannot tile the cipher stream in whole blocks.
        for (cipher_name, bad_len) in [("aes128-ctr", 4u32), ("aes128-ctr", 22), ("aes128-cbc", 22)] {
            let block_size = make_cipher(cipher_name).block_size();
            let mut plain = vec![0u8; block_size];
            plain[..4].copy_from_slice(&bad_len.to_be_bytes());
            let mut enc = make_cipher(cipher_name);
            let wire = enc.encrypt(0, &plain).unwrap();

            let mut receiver = SshTransport::new();
            install_client_direction(&mut receiver, cipher_name, 0);
            let mut reader: &[u8] = &wire;
            assert!(
                matches!(
                    receive_encrypted_packet_server(&mut reader, &mut receiver, false, false).await,
                    Err(SshError::InvalidPacket(_))
                ),
                "{cipher_name}: accepted packet_length {bad_len} (block {block_size})"
            );
        }
    }

    fn install_client_aead(t: &mut SshTransport, cipher_name: &str, seq: u64) {
        t.client_to_server_cipher = Some(make_cipher(cipher_name));
        // AEAD carries its own tag; the negotiation still installs a "none" MAC.
        t.client_to_server_mac = Some(make_mac("none"));
        t.outgoing_seq = seq;
        t.incoming_seq = seq;
    }

    fn install_server_aead(t: &mut SshTransport, cipher_name: &str, seq: u64) {
        t.server_to_client_cipher = Some(make_cipher(cipher_name));
        t.server_to_client_mac = Some(make_mac("none"));
        t.outgoing_seq = seq;
        t.incoming_seq = seq;
    }

    /// AEAD (aadlen=4) pads `packet_length` itself to a whole block.
    fn aead_plaintext_packet_len(payload_len: usize, block_size: usize) -> usize {
        let base = 1 + payload_len;
        base + compute_packet_padding(base, block_size, false)
    }

    #[tokio::test]
    async fn aead_gcm_client_to_server_layout_and_roundtrip() {
        for cipher_name in ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com"] {
            let mut sender = SshTransport::new();
            let mut receiver = SshTransport::new();
            install_client_aead(&mut sender, cipher_name, 4);
            install_client_aead(&mut receiver, cipher_name, 4);

            let payload = vec![msg::SSH_MSG_SERVICE_REQUEST, 0, 0, 0, 4, b'n', b'o', b'p', b'e'];
            let mut wire: Vec<u8> = Vec::new();
            send_encrypted_packet(&mut wire, &payload, &mut sender, false, true)
                .await
                .unwrap();

            // AES-GCM has a 16-byte block, but its *padding* rule is
            // packet_length % 16 == 0 (aadlen=4), not (4 + packet_length) % 16.
            let block_size = make_cipher(cipher_name).block_size();
            assert_eq!(block_size, 16, "{cipher_name}: unexpected block size");
            let plen = aead_plaintext_packet_len(payload.len(), block_size);
            let tag_len = make_cipher(cipher_name).tag_len();

            let wire_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
            assert_eq!(wire_len, plen, "{cipher_name}: packet_length must be cleartext");
            assert_eq!(plen % block_size, 0, "{cipher_name}: packet_length not block-aligned");
            assert_eq!(wire.len(), 4 + plen + tag_len, "{cipher_name}: wrong wire layout");

            let mut reader: &[u8] = &wire;
            let got = receive_encrypted_packet_server(&mut reader, &mut receiver, false, true)
                .await
                .unwrap();
            assert_eq!(got, payload);
            assert_eq!(receiver.incoming_seq, 5);
        }
    }

    #[tokio::test]
    async fn aead_gcm_server_to_client_layout_and_roundtrip() {
        for cipher_name in ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com"] {
            let mut sender = SshTransport::new();
            let mut receiver = SshTransport::new();
            install_server_aead(&mut sender, cipher_name, 2);
            install_server_aead(&mut receiver, cipher_name, 2);

            let payload = vec![msg::SSH_MSG_CHANNEL_DATA, 1, 2, 3, 4];
            let mut wire: Vec<u8> = Vec::new();
            send_encrypted_packet_server(&mut wire, &payload, &mut sender, false, true)
                .await
                .unwrap();

            let block_size = make_cipher(cipher_name).block_size();
            let plen = aead_plaintext_packet_len(payload.len(), block_size);
            let tag_len = make_cipher(cipher_name).tag_len();
            assert_eq!(
                u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize,
                plen
            );
            assert_eq!(wire.len(), 4 + plen + tag_len);

            let mut reader: &[u8] = &wire;
            let got = receive_encrypted_packet(&mut reader, &mut receiver, false, true)
                .await
                .unwrap();
            assert_eq!(got, payload);
            assert_eq!(receiver.incoming_seq, 3);
        }
    }

    #[tokio::test]
    async fn aead_gcm_rejects_tampered_ciphertext() {
        let mut sender = SshTransport::new();
        install_client_aead(&mut sender, "aes128-gcm@openssh.com", 0);
        let payload = vec![msg::SSH_MSG_IGNORE, 1];
        let mut wire: Vec<u8> = Vec::new();
        send_encrypted_packet(&mut wire, &payload, &mut sender, false, true)
            .await
            .unwrap();
        // Flip a byte inside the ciphertext (not the cleartext length, which
        // would only change how many bytes are read).
        wire[5] ^= 0x01;

        let mut receiver = SshTransport::new();
        install_client_aead(&mut receiver, "aes128-gcm@openssh.com", 0);
        let mut reader: &[u8] = &wire;
        assert!(matches!(
            receive_encrypted_packet_server(&mut reader, &mut receiver, false, true).await,
            Err(SshError::DecryptionFailed)
        ));
    }

    #[test]
    fn ext_info_negotiation_flags() {
        // Both sides advertise their ext-info pseudo algorithm by default.
        let mut c = SshTransport::new();
        let c_init = c.build_kex_init(None, None, None, None, false);
        let mut s = SshTransport::new();
        let s_init = s.build_kex_init(None, None, None, None, true);
        let neg = SshTransport::negotiate_algorithms(&c_init, &s_init).unwrap();
        assert!(neg.client_ext_info_c);
        assert!(neg.server_ext_info_s);

        // The pseudo algorithm must never be selected as the real KEX.
        assert!(!is_pseudo_kex(&neg.kex_algorithm));
    }

    #[test]
    fn first_kex_follows_wrong_guess_is_detected() {
        // Build a KEXINIT, then patch the trailing `first_kex_packet_follows`
        // byte to 1 so the receiver knows the sender guessed its own first
        // KEX choice. If that guess disagrees with the negotiated algorithm,
        // the receiver must discard the sender's next packet.
        let mut c = SshTransport::new();
        let mut c_init = c.build_kex_init(None, None, None, None, false);
        // The flag byte sits after the two language lists and before the
        // 4-byte reserved field at the end of the KEXINIT payload.
        let flag_pos = c_init.len() - 5;
        c_init[flag_pos] = 1;
        let mut s = SshTransport::new();
        let s_init = s.build_kex_init(None, None, None, None, true);

        let neg = SshTransport::negotiate_algorithms(&c_init, &s_init).unwrap();
        // The client's guess is its own first KEX entry; wrong-guess must be
        // true exactly when that entry is not the negotiated algorithm.
        let guessed = {
            let mut r = &c_init[17..];
            let list = SshNameList::decode(&mut r).unwrap();
            list.0.first().cloned().unwrap_or_default()
        };
        assert_eq!(neg.client_first_kex_follows_wrong_guess, guessed != neg.kex_algorithm);

        // A well-formed KEXINIT with the flag cleared never forces a discard.
        let mut c2 = SshTransport::new();
        let c2_init = c2.build_kex_init(None, None, None, None, false);
        let neg2 = SshTransport::negotiate_algorithms(&c2_init, &s_init).unwrap();
        assert!(!neg2.client_first_kex_follows_wrong_guess);
        assert!(!neg2.server_first_kex_follows_wrong_guess);
    }

    #[test]
    fn none_cipher_is_negotiable_only_when_explicitly_configured() {
        // With the default proposal, `none` must never be advertised.
        let mut c = SshTransport::new();
        let c_init = c.build_kex_init(None, None, None, None, false);
        let mut s = SshTransport::new();
        let s_init = s.build_kex_init(None, None, None, None, true);
        let neg = SshTransport::negotiate_algorithms(&c_init, &s_init).unwrap();
        assert_ne!(neg.client_to_server_cipher, "none");
        assert_ne!(neg.server_to_client_cipher, "none");

        // When both sides explicitly configure `none` (with `none` MAC), it is
        // negotiated.
        let mut c2 = SshTransport::new();
        let c2_init = c2.build_kex_init(None, None, Some(&["none".to_string()]), Some(&["none".to_string()]), false);
        let mut s2 = SshTransport::new();
        let s2_init = s2.build_kex_init(None, None, Some(&["none".to_string()]), Some(&["none".to_string()]), true);
        let neg2 = SshTransport::negotiate_algorithms(&c2_init, &s2_init).unwrap();
        assert_eq!(neg2.client_to_server_cipher, "none");
        assert_eq!(neg2.server_to_client_cipher, "none");
    }
}


