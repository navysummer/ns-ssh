use crate::error::Result;
use crate::encoding::*;
use crate::msg;
use crate::hostkey::HostKeySigner;

pub enum AuthMethod {
    Password(String),
    PublicKey(Box<dyn HostKeySigner>),
    KeyboardInteractive(Vec<(String, String)>),
    None,
}

pub fn build_userauth_request(
    username: &str,
    service: &str,
    method: &AuthMethod,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut payload).unwrap();
    SshString::new(service).encode(&mut payload).unwrap();

    match method {
        AuthMethod::Password(password) => {
            SshString::new("password").encode(&mut payload).unwrap();
            payload.push(0);
            SshString::new(password).encode(&mut payload).unwrap();
        }
        AuthMethod::PublicKey(signer) => {
            SshString::new("publickey").encode(&mut payload).unwrap();
            payload.push(1);
            SshString::new(signer.algorithm_name()).encode(&mut payload).unwrap();
            let pub_key = signer.public_key_bytes();
            SshBytes(pub_key).encode(&mut payload).unwrap();

            let sign_data = build_sign_data(username, service, signer.as_ref());
            let signature = signer.sign(&sign_data).unwrap_or_default();
            SshBytes(signature).encode(&mut payload).unwrap();
        }
        AuthMethod::KeyboardInteractive(_) => {
            SshString::new("keyboard-interactive").encode(&mut payload).unwrap();
            SshString::new("").encode(&mut payload).unwrap();
            SshString::new("").encode(&mut payload).unwrap();
        }
        AuthMethod::None => {
            SshString::new("none").encode(&mut payload).unwrap();
        }
    }

    payload
}

fn build_sign_data(username: &str, service: &str, signer: &(dyn HostKeySigner + '_)) -> Vec<u8> {
    let mut data = Vec::new();

    SshBytes(Vec::new()).encode(&mut data).unwrap();

    data.push(msg::SSH_MSG_USERAUTH_REQUEST);

    SshString::new(username).encode(&mut data).unwrap();
    SshString::new(service).encode(&mut data).unwrap();
    SshString::new("publickey").encode(&mut data).unwrap();
    data.push(1);
    SshString::new(signer.algorithm_name()).encode(&mut data).unwrap();
    SshBytes(signer.public_key_bytes()).encode(&mut data).unwrap();

    data
}

/// Build the signature payload for hostbased authentication (RFC 4252 §8).
pub fn build_hostbased_sign_data(
    username: &str,
    service: &str,
    key_alg: &str,
    public_key: &[u8],
    client_hostname: &str,
    client_username: &str,
    session_id: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    SshBytes(session_id.to_vec()).encode(&mut data).unwrap();
    data.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut data).unwrap();
    SshString::new(service).encode(&mut data).unwrap();
    SshString::new("hostbased").encode(&mut data).unwrap();
    SshString::new(key_alg).encode(&mut data).unwrap();
    SshBytes(public_key.to_vec()).encode(&mut data).unwrap();
    SshString::new(client_hostname).encode(&mut data).unwrap();
    SshString::new(client_username).encode(&mut data).unwrap();
    data
}

/// Build a signed hostbased SSH_MSG_USERAUTH_REQUEST (RFC 4252 §8).
pub fn build_userauth_hostbased(
    username: &str,
    service: &str,
    signer: &dyn HostKeySigner,
    client_hostname: &str,
    client_username: &str,
    session_id: &[u8],
) -> Vec<u8> {
    let sign_data = build_hostbased_sign_data(
        username,
        service,
        signer.algorithm_name(),
        &signer.public_key_bytes(),
        client_hostname,
        client_username,
        session_id,
    );
    let signature = signer.sign(&sign_data).unwrap_or_default();
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut payload).unwrap();
    SshString::new(service).encode(&mut payload).unwrap();
    SshString::new("hostbased").encode(&mut payload).unwrap();
    SshString::new(signer.algorithm_name()).encode(&mut payload).unwrap();
    SshBytes(signer.public_key_bytes()).encode(&mut payload).unwrap();
    SshString::new(client_hostname).encode(&mut payload).unwrap();
    SshString::new(client_username).encode(&mut payload).unwrap();
    SshBytes(signature).encode(&mut payload).unwrap();
    payload
}

pub fn build_userauth_request_with_session(
    username: &str,
    service: &str,
    method: &AuthMethod,
    session_id: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut payload).unwrap();
    SshString::new(service).encode(&mut payload).unwrap();

    match method {
        AuthMethod::Password(password) => {
            SshString::new("password").encode(&mut payload).unwrap();
            payload.push(0);
            SshString::new(password).encode(&mut payload).unwrap();
        }
        AuthMethod::PublicKey(signer) => {
            SshString::new("publickey").encode(&mut payload).unwrap();
            payload.push(1);
            SshString::new(signer.algorithm_name()).encode(&mut payload).unwrap();
            let pub_key = signer.public_key_bytes();
            SshBytes(pub_key).encode(&mut payload).unwrap();

            let sign_data = build_sign_data_with_session(username, service, signer.as_ref(), session_id);
            let signature = signer.sign(&sign_data).unwrap_or_default();
            SshBytes(signature).encode(&mut payload).unwrap();
        }
        AuthMethod::KeyboardInteractive(_) => {
            SshString::new("keyboard-interactive").encode(&mut payload).unwrap();
            SshString::new("").encode(&mut payload).unwrap();
            SshString::new("").encode(&mut payload).unwrap();
        }
        AuthMethod::None => {
            SshString::new("none").encode(&mut payload).unwrap();
        }
    }

    payload
}

fn build_sign_data_with_session(
    username: &str,
    service: &str,
    signer: &(dyn HostKeySigner + '_),
    session_id: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();

    SshBytes(session_id.to_vec()).encode(&mut data).unwrap();

    data.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut data).unwrap();
    SshString::new(service).encode(&mut data).unwrap();
    SshString::new("publickey").encode(&mut data).unwrap();
    data.push(1);
    SshString::new(signer.algorithm_name()).encode(&mut data).unwrap();
    SshBytes(signer.public_key_bytes()).encode(&mut data).unwrap();

    data
}

/// Build the string to be signed when authenticating with a key that is
/// managed by an SSH agent (only the public blob is available).
pub fn build_sign_data_for_agent(
    username: &str,
    service: &str,
    algorithm: &str,
    public_key: &[u8],
    session_id: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();

    SshBytes(session_id.to_vec()).encode(&mut data).unwrap();

    data.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut data).unwrap();
    SshString::new(service).encode(&mut data).unwrap();
    SshString::new("publickey").encode(&mut data).unwrap();
    data.push(1);
    SshString::new(algorithm).encode(&mut data).unwrap();
    SshBytes(public_key.to_vec()).encode(&mut data).unwrap();

    data
}

pub fn parse_userauth_failure(payload: &[u8]) -> Result<Vec<String>> {
    let mut r = &payload[1..];
    let name_list = SshNameList::decode(&mut r)?;
    Ok(name_list.0)
}

pub fn parse_userauth_info_request(payload: &[u8]) -> Result<Vec<(String, String, bool, bool)>> {
    let mut r = &payload[1..];
    let _name = SshString::decode(&mut r)?.as_str()?.to_string();
    let _instruction = SshString::decode(&mut r)?.as_str()?.to_string();
    let _lang = SshString::decode(&mut r)?;
    let num_prompts = u32::decode(&mut r)? as usize;

    let mut prompts = Vec::new();
    for _ in 0..num_prompts {
        let prompt = SshString::decode(&mut r)?.as_str()?.to_string();
        let echo = bool::decode(&mut r)?;
        prompts.push((prompt, String::new(), echo, false));
    }

    Ok(prompts)
}

pub fn build_userauth_pubkey_query(
    username: &str,
    service: &str,
    algorithm: &str,
    public_key: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut payload).unwrap();
    SshString::new(service).encode(&mut payload).unwrap();
    SshString::new("publickey").encode(&mut payload).unwrap();
    payload.push(0);
    SshString::new(algorithm).encode(&mut payload).unwrap();
    SshBytes(public_key.to_vec()).encode(&mut payload).unwrap();
    payload
}

pub fn build_userauth_pubkey_signed(
    username: &str,
    service: &str,
    algorithm: &str,
    public_key: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut payload).unwrap();
    SshString::new(service).encode(&mut payload).unwrap();
    SshString::new("publickey").encode(&mut payload).unwrap();
    payload.push(1);
    SshString::new(algorithm).encode(&mut payload).unwrap();
    SshBytes(public_key.to_vec()).encode(&mut payload).unwrap();
    SshBytes(signature.to_vec()).encode(&mut payload).unwrap();
    payload
}

pub fn build_userauth_info_response(answers: &[String]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_INFO_RESPONSE);
    (answers.len() as u32).encode(&mut payload).unwrap();
    for a in answers {
        SshString::new(a.as_str()).encode(&mut payload).unwrap();
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::Ed25519HostKey;

    /// Hostbased request: wire fields match RFC 4252 §8 and the embedded
    /// signature verifies against the reconstructed sign data (the exact
    /// reconstruction the server performs).
    #[test]
    fn hostbased_request_roundtrip() {
        let signer = Ed25519HostKey::generate().unwrap();
        let session_id = b"session-id-0123456789";
        let payload = build_userauth_hostbased(
            "alice",
            "ssh-connection",
            &signer,
            "client.example.com",
            "alice-local",
            session_id,
        );

        let mut r = &payload[..];
        assert_eq!(u8::decode(&mut r).unwrap(), msg::SSH_MSG_USERAUTH_REQUEST);
        assert_eq!(SshString::decode(&mut r).unwrap().as_str().unwrap(), "alice");
        assert_eq!(SshString::decode(&mut r).unwrap().as_str().unwrap(), "ssh-connection");
        assert_eq!(SshString::decode(&mut r).unwrap().as_str().unwrap(), "hostbased");
        let key_type = SshString::decode(&mut r).unwrap().as_str().unwrap().to_string();
        assert_eq!(key_type, "ssh-ed25519");
        let public_key = SshBytes::decode(&mut r).unwrap().0;
        assert_eq!(public_key, signer.public_key_bytes());
        assert_eq!(SshString::decode(&mut r).unwrap().as_str().unwrap(), "client.example.com");
        assert_eq!(SshString::decode(&mut r).unwrap().as_str().unwrap(), "alice-local");
        let signature = SshBytes::decode(&mut r).unwrap().0;
        assert!(r.is_empty());

        let data = build_hostbased_sign_data(
            "alice",
            "ssh-connection",
            &key_type,
            &public_key,
            "client.example.com",
            "alice-local",
            session_id,
        );
        assert!(signer.verify(&data, &signature).unwrap());
        // Any field change must invalidate the signature.
        let bad = build_hostbased_sign_data(
            "alice",
            "ssh-connection",
            &key_type,
            &public_key,
            "other.example.com",
            "alice-local",
            session_id,
        );
        assert!(!signer.verify(&bad, &signature).unwrap_or(false));
    }
}

