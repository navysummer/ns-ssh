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
    payload.extend(SshString::new(username).0);
    payload.extend(SshString::new(service).0);

    match method {
        AuthMethod::Password(password) => {
            payload.extend(SshString::new(service).0);
            payload.extend(SshString::new("password").0);
            payload.push(0);
            payload.extend(SshString::new(password).0);
        }
        AuthMethod::PublicKey(signer) => {
            payload.extend(SshString::new("publickey").0);
            payload.push(1);
            payload.extend(SshString::new(signer.algorithm_name()).0);
            let pub_key = signer.public_key_bytes();
            payload.extend(SshBytes(pub_key).0);

            let sign_data = build_sign_data(username, service, signer.as_ref());
            let signature = signer.sign(&sign_data).unwrap_or_default();
            payload.extend(SshBytes(signature).0);
        }
        AuthMethod::KeyboardInteractive(_) => {
            payload.extend(SshString::new("ssh-connection").0);
            payload.extend(SshString::new("keyboard-interactive").0);
            payload.extend(SshString::new("en").0);
            payload.extend(SshString::new("").0);
        }
        AuthMethod::None => {
            payload.extend(SshString::new("none").0);
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

pub fn build_userauth_request_with_session(
    username: &str,
    service: &str,
    method: &AuthMethod,
    session_id: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_REQUEST);
    payload.extend(SshString::new(username).0);
    payload.extend(SshString::new(service).0);

    match method {
        AuthMethod::Password(password) => {
            payload.extend(SshString::new(service).0);
            payload.extend(SshString::new("password").0);
            payload.push(0);
            payload.extend(SshString::new(password).0);
        }
        AuthMethod::PublicKey(signer) => {
            payload.extend(SshString::new("publickey").0);
            payload.push(1);
            payload.extend(SshString::new(signer.algorithm_name()).0);
            let pub_key = signer.public_key_bytes();
            payload.extend(SshBytes(pub_key).0);

            let sign_data = build_sign_data_with_session(username, service, signer.as_ref(), session_id);
            let signature = signer.sign(&sign_data).unwrap_or_default();
            payload.extend(SshBytes(signature).0);
        }
        AuthMethod::KeyboardInteractive(_) => {
            payload.extend(SshString::new("ssh-connection").0);
            payload.extend(SshString::new("keyboard-interactive").0);
            payload.extend(SshString::new("en").0);
            payload.extend(SshString::new("").0);
        }
        AuthMethod::None => {
            payload.extend(SshString::new("none").0);
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
