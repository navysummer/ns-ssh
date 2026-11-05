//! `ns-ssh-agent` daemon: holds private keys and serves the SSH agent
//! protocol over a UNIX domain socket.
//!
//! Message types follow OpenSSH's `PROTOCOL.agent`:
//!   SSH_AGENTC_REQUEST_IDENTITIES  11 -> SSH_AGENT_IDENTITIES_ANSWER   12
//!   SSH_AGENTC_SIGN_REQUEST        13 -> SSH_AGENT_SIGN_RESPONSE       14
//!   SSH_AGENTC_ADD_IDENTITY        17 -> SSH_AGENT_SUCCESS              6
//!   SSH_AGENTC_REMOVE_ALL_IDENTITIES 19 -> SSH_AGENT_SUCCESS            6
//!   (any failure -> SSH_AGENT_FAILURE 5)

use ssh_core::error::{Result, SshError};
use ssh_core::hostkey::{EcdsaP256HostKey, Ed25519HostKey, HostKeySigner};
use ssh_core::encoding::{SshBytes, SshDecode, SshEncode, SshString};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;

/// One stored identity: the public key blob (as returned to
/// `SSH_AGENTC_REQUEST_IDENTITIES`) plus the signer used to answer
/// `SSH_AGENTC_SIGN_REQUEST`.
struct Identity {
    blob: Vec<u8>,
    comment: String,
    signer: Box<dyn HostKeySigner>,
}

/// The agent's in-memory key store, shared across all client connections.
struct AgentState {
    identities: Vec<Identity>,
}

impl AgentState {
    fn new() -> Self {
        AgentState { identities: Vec::new() }
    }

    fn request_identities(&self) -> Vec<(Vec<u8>, String)> {
        self.identities
            .iter()
            .map(|id| (id.blob.clone(), id.comment.clone()))
            .collect()
    }

    fn add_identity(&mut self, blob: Vec<u8>, comment: String, signer: Box<dyn HostKeySigner>) {
        // OpenSSH keeps the last-added duplicate; drop any prior copy of the
        // same public key so `ssh-add` twice does not duplicate entries.
        self.identities.retain(|id| id.blob != blob);
        self.identities.push(Identity { blob, comment, signer });
    }

    fn remove_all(&mut self) {
        self.identities.clear();
    }

    /// Find a signer whose public blob matches `key_blob` and sign `data`.
    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let id = self
            .identities
            .iter()
            .find(|id| id.blob == key_blob)
            .ok_or_else(|| SshError::AuthFailed("agent: identity not found".into()))?;
        // Flags bit 1 (SSH_AGENT_RSA_SHA2_256) / bit 2 (SHA2_512) only select
        // the signature algorithm for RSA keys; ed25519/ecdsa always use their
        // native scheme, so the flag is not consulted here.
        let _ = flags;
        id.signer.sign(data)
    }
}

/// Parse a `SSH2_AGENTC_ADD_IDENTITY` key blob into a public blob, comment and
/// a signer. The wire format (from OpenSSH `ssh-add`) is:
///   - ed25519: string "ssh-ed25519", string pk(32), string seed||pk(64), string comment
///   - ecdsa:   string "ecdsa-sha2-<curve>", string curve, string point, string scalar_mpint, string comment
fn parse_add_identity(payload: &[u8]) -> Result<(Vec<u8>, String, Box<dyn HostKeySigner>)> {
    let mut r = payload;
    let key_type = SshString::decode(&mut r)?.as_str()?.to_string();
    match key_type.as_str() {
        "ssh-ed25519" => {
            let pk = SshBytes::decode(&mut r)?.0;
            let sk64 = SshBytes::decode(&mut r)?.0;
            let comment = SshString::decode(&mut r)?.as_str()?.to_string();
            if pk.len() != 32 {
                return Err(SshError::InvalidKey("ed25519 pk must be 32 bytes".into()));
            }
            if sk64.len() != 64 {
                return Err(SshError::InvalidKey("ed25519 private blob must be 64 bytes".into()));
            }
            let seed: [u8; 32] = sk64[..32].try_into().unwrap();
            let signer = Ed25519HostKey::from_bytes(&seed)?;
            // Public blob for REQUEST_IDENTITIES: string type || string pk.
            let mut blob = Vec::new();
            SshString::new("ssh-ed25519").encode(&mut blob)?;
            SshBytes(pk).encode(&mut blob)?;
            Ok((blob, comment, Box::new(signer)))
        }
        "ecdsa-sha2-nistp256" => {
            let curve = SshString::decode(&mut r)?.as_str()?.to_string();
            let point = SshBytes::decode(&mut r)?.0;
            let scalar_mpint = SshBytes::decode(&mut r)?.0;
            let comment = SshString::decode(&mut r)?.as_str()?.to_string();
            if curve != "nistp256" {
                return Err(SshError::InvalidKey(format!("unsupported ecdsa curve {}", curve)));
            }
            // scalar mpint may carry a leading 0x00 padding byte.
            let scalar: &[u8] = if scalar_mpint.len() == 33 && scalar_mpint[0] == 0 {
                &scalar_mpint[1..]
            } else {
                &scalar_mpint
            };
            let signer = EcdsaP256HostKey::from_secret_bytes(scalar)?;
            // Public blob: string type || string curve || string point.
            let mut blob = Vec::new();
            SshString::new("ecdsa-sha2-nistp256").encode(&mut blob)?;
            SshString::new("nistp256").encode(&mut blob)?;
            SshBytes(point).encode(&mut blob)?;
            Ok((blob, comment, Box::new(signer)))
        }
        other => Err(SshError::InvalidKey(format!(
            "agent: unsupported key type {}",
            other
        ))),
    }
}

/// Serve one agent client connection. Reads a 4-byte big-endian length, then
/// that many payload bytes, dispatches the request and writes the reply back.
fn handle_client(stream: &mut impl ReadWrite, state: &Arc<Mutex<AgentState>>) -> Result<()> {
    loop {
        // Length prefix; EOF cleanly ends the connection.
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(SshError::Io(e)),
        }
        let payload_len = u32::from_be_bytes(len_buf) as usize;
        if payload_len == 0 || payload_len > 16 * 1024 * 1024 {
            return Err(SshError::Protocol("agent: invalid payload length".into()));
        }
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload)?;

        let reply = match payload.first().copied() {
            Some(SSH_AGENTC_REQUEST_IDENTITIES) => {
                let ids = state.lock().unwrap().request_identities();
                let mut resp = vec![SSH_AGENT_IDENTITIES_ANSWER];
                (ids.len() as u32).encode(&mut resp)?;
                for (blob, comment) in &ids {
                    SshBytes(blob.clone()).encode(&mut resp)?;
                    SshString::new(comment).encode(&mut resp)?;
                }
                resp
            }
            Some(SSH_AGENTC_SIGN_REQUEST) => {
                let mut r = &payload[1..];
                let key_blob = SshBytes::decode(&mut r)?.0;
                let data = SshBytes::decode(&mut r)?.0;
                let flags = u32::decode(&mut r)?;
                match state.lock().unwrap().sign(&key_blob, &data, flags) {
                    Ok(sig) => {
                        let mut resp = vec![SSH_AGENT_SIGN_RESPONSE];
                        SshBytes(sig).encode(&mut resp)?;
                        resp
                    }
                    Err(_) => vec![SSH_AGENT_FAILURE],
                }
            }
            Some(SSH_AGENTC_ADD_IDENTITY) => {
                let result = parse_add_identity(&payload[1..]).and_then(|(blob, comment, signer)| {
                    state.lock().unwrap().add_identity(blob, comment, signer);
                    Ok(())
                });
                match result {
                    Ok(()) => vec![SSH_AGENT_SUCCESS],
                    Err(_) => vec![SSH_AGENT_FAILURE],
                }
            }
            Some(SSH_AGENTC_REMOVE_ALL_IDENTITIES) => {
                state.lock().unwrap().remove_all();
                vec![SSH_AGENT_SUCCESS]
            }
            _ => vec![SSH_AGENT_FAILURE],
        };

        let mut framed = Vec::with_capacity(4 + reply.len());
        framed.extend_from_slice(&(reply.len() as u32).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed)?;
        stream.flush()?;
    }
}

/// Small abstraction so `handle_client` works on both a `tokio::net::UnixStream`
/// (blocking via `std::os::unix::net::UnixStream`) and a raw file descriptor.
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Run the agent daemon in the foreground, serving `socket_path`.
pub fn run_agent_foreground(socket_path: &Path) -> Result<()> {
    let state = Arc::new(Mutex::new(AgentState::new()));

    // Bind the listener with a restrictive mode (OpenSSH uses 0600).
    let listener = std::os::unix::net::UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let _ = handle_client(&mut stream, &state);
                });
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

/// Compute the default agent socket path:
/// `$TMPDIR/ssh-XXXXXXXXXX/agent.<ppid>` (OpenSSH convention).
pub fn default_socket_path() -> PathBuf {
    let tmp = std::env::var("TMPDIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    let suffix = std::process::id();
    tmp.join(format!("ssh-agent-{}-{}", suffix, std::process::id()))
        .join(format!("agent.{}", std::process::id()))
}

/// Set restrictive umask + create the socket parent directory.
pub fn prepare_socket_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
