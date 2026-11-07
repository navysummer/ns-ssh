//! RFC 4462 GSS-API user authentication (`gssapi-with-mic`).
//!
//! This module holds the protocol-level pieces that are independent of any
//! concrete GSS-API implementation: the mechanism OID list (DER-encoded ASN.1
//! object identifiers), the message payload builders, and the MIC input
//! construction. The actual GSS-API calls live in the client/server crates
//! (which dlopen the system GSSAPI library), but the wire format is shared.

use crate::encoding::*;
use crate::error::Result;
use crate::msg;

/// The Kerberos 5 mechanism OID (RFC 4120 / RFC 4462 §3.1): the DER bytes of
/// `1.2.840.113554.1.2.2`, the standard Kerberos GSS-API mechanism.
pub const OID_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// The SPNEGO mechanism OID (`1.3.6.1.5.5.2`), the IETF generic negotiation
/// mechanism.
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Mechanisms this implementation supports, in client preference order.
/// Kerberos 5 first, then SPNEGO (which may negotiate Kerberos underneath).
pub const SUPPORTED_MECHANISMS: &[&[u8]] = &[OID_KRB5, OID_SPNEGO];

/// The GSS-API host-based service name type OID (`1.3.6.1.5.6.2`), used to
/// build the `host@hostname` target name for `gss_init_sec_context`.
pub const OID_HOSTBASED_SERVICE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x06, 0x02];

/// The GSS-API user name type OID (`1.2.840.113554.1.2.1.1`).
pub const OID_USER_NAME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01];

/// The GSS-API export name type OID (`1.3.6.1.5.6.4`).
pub const OID_EXPORT_NAME: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x06, 0x04];

/// Build the `SSH_MSG_USERAUTH_REQUEST` payload for `gssapi-with-mic` with the
/// given mechanism OIDs (RFC 4462 §3.2).
pub fn build_userauth_request(
    username: &str,
    service: &str,
    mechanism_oids: &[&[u8]],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut payload).unwrap();
    SshString::new(service).encode(&mut payload).unwrap();
    SshString::new(msg::SSH_AUTH_METHOD_GSSAPI_WITH_MIC)
        .encode(&mut payload)
        .unwrap();
    (mechanism_oids.len() as u32)
        .encode(&mut payload)
        .unwrap();
    for oid in mechanism_oids {
        SshBytes(oid.to_vec()).encode(&mut payload).unwrap();
    }
    payload
}

/// Encode a `SSH_MSG_USERAUTH_GSSAPI_RESPONSE` payload (RFC 4462 §3.3).
pub fn build_response(selected_oid: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_GSSAPI_RESPONSE);
    SshBytes(selected_oid.to_vec()).encode(&mut payload).unwrap();
    payload
}

/// Encode a `SSH_MSG_USERAUTH_GSSAPI_TOKEN` payload (RFC 4462 §3.4).
pub fn build_token(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_GSSAPI_TOKEN);
    SshBytes(data.to_vec()).encode(&mut payload).unwrap();
    payload
}

/// Encode a `SSH_MSG_USERAUTH_GSSAPI_MIC` payload (RFC 4462 §3.5).
pub fn build_mic(mic: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_GSSAPI_MIC);
    SshBytes(mic.to_vec()).encode(&mut payload).unwrap();
    payload
}

/// Encode a `SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE` payload (RFC 4462 §3.6).
pub fn build_exchange_complete() -> Vec<u8> {
    vec![msg::SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE]
}

/// Encode a `SSH_MSG_USERAUTH_GSSAPI_ERROR` payload (RFC 4462 §3.8).
pub fn build_error(major_status: u32, minor_status: u32, message: &str, language: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_GSSAPI_ERROR);
    major_status.encode(&mut payload).unwrap();
    minor_status.encode(&mut payload).unwrap();
    SshString::new(message).encode(&mut payload).unwrap();
    SshString::new(language).encode(&mut payload).unwrap();
    payload
}

/// Encode a `SSH_MSG_USERAUTH_GSSAPI_ERRTOK` payload (RFC 4462 §3.9).
pub fn build_err_tok(error_token: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_USERAUTH_GSSAPI_ERRTOK);
    SshBytes(error_token.to_vec()).encode(&mut payload).unwrap();
    payload
}

/// Decode the mechanism OID list from a `gssapi-with-mic` USERAUTH_REQUEST
/// payload (after the method name). Returns `(n, oids)`.
pub fn decode_mechanism_oids(payload: &[u8]) -> Result<(u32, Vec<Vec<u8>>)> {
    let mut r = payload;
    let n = u32::decode(&mut r)?;
    let mut oids = Vec::with_capacity(n as usize);
    for _ in 0..n {
        oids.push(SshBytes::decode(&mut r)?.0);
    }
    Ok((n, oids))
}

/// Decode the selected mechanism OID from a GSSAPI_RESPONSE payload.
pub fn decode_response(payload: &[u8]) -> Result<Vec<u8>> {
    let mut r = payload;
    Ok(SshBytes::decode(&mut r)?.0)
}

/// Decode the token data from a GSSAPI_TOKEN payload.
pub fn decode_token(payload: &[u8]) -> Result<Vec<u8>> {
    let mut r = payload;
    Ok(SshBytes::decode(&mut r)?.0)
}

/// Decode the MIC from a GSSAPI_MIC payload.
pub fn decode_mic(payload: &[u8]) -> Result<Vec<u8>> {
    let mut r = payload;
    Ok(SshBytes::decode(&mut r)?.0)
}

/// Decode the error token from a GSSAPI_ERRTOK payload.
pub fn decode_err_tok(payload: &[u8]) -> Result<Vec<u8>> {
    let mut r = payload;
    Ok(SshBytes::decode(&mut r)?.0)
}

/// Build the data that the client's `GSS_GetMIC()` is computed over
/// (RFC 4462 §3.5): `string session_id || byte USERAUTH_REQUEST ||
/// string user || string service || string "gssapi-with-mic"`.
pub fn build_mic_data(session_id: &[u8], username: &str, service: &str) -> Vec<u8> {
    let mut data = Vec::new();
    SshBytes(session_id.to_vec()).encode(&mut data).unwrap();
    data.push(msg::SSH_MSG_USERAUTH_REQUEST);
    SshString::new(username).encode(&mut data).unwrap();
    SshString::new(service).encode(&mut data).unwrap();
    SshString::new(msg::SSH_AUTH_METHOD_GSSAPI_WITH_MIC)
        .encode(&mut data)
        .unwrap();
    data
}

/// Return true when `oid` is one this implementation supports.
pub fn is_supported_mechanism(oid: &[u8]) -> bool {
    SUPPORTED_MECHANISMS.iter().any(|m| *m == oid)
}

/// Pick the first client mechanism we support (client preference order wins).
pub fn choose_mechanism(client_oids: &[Vec<u8>]) -> Option<Vec<u8>> {
    // The client lists in preference order and the server must choose the
    // first it supports; equivalently pick the highest-priority supported one.
    for oid in client_oids {
        if is_supported_mechanism(oid) {
            return Some(oid.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_oids_are_der_encoded() {
        // Kerberos 5: 1.2.840.113554.1.2.2
        assert_eq!(
            OID_KRB5,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]
        );
        // SPNEGO: 1.3.6.1.5.5.2
        assert_eq!(OID_SPNEGO, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
    }

    #[test]
    fn userauth_request_round_trips_mechanisms() {
        let payload = build_userauth_request("alice", "ssh-connection", &[OID_KRB5, OID_SPNEGO]);
        // First byte is the message type.
        assert_eq!(payload[0], msg::SSH_MSG_USERAUTH_REQUEST);
        let mut r = &payload[1..];
        assert_eq!(SshString::decode(&mut r).unwrap().as_str().unwrap(), "alice");
        assert_eq!(
            SshString::decode(&mut r).unwrap().as_str().unwrap(),
            "ssh-connection"
        );
        assert_eq!(
            SshString::decode(&mut r).unwrap().as_str().unwrap(),
            "gssapi-with-mic"
        );
        let (n, oids) = decode_mechanism_oids(r).unwrap();
        assert_eq!(n, 2);
        assert_eq!(oids, vec![OID_KRB5.to_vec(), OID_SPNEGO.to_vec()]);
    }

    #[test]
    fn response_token_mic_round_trip() {
        // Response carries the selected OID.
        let resp = build_response(OID_KRB5);
        assert_eq!(resp[0], msg::SSH_MSG_USERAUTH_GSSAPI_RESPONSE);
        assert_eq!(decode_response(&resp[1..]).unwrap(), OID_KRB5);

        // Token carries raw GSSAPI bytes.
        let tok = build_token(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(tok[0], msg::SSH_MSG_USERAUTH_GSSAPI_TOKEN);
        assert_eq!(decode_token(&tok[1..]).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);

        // MIC carries the message integrity code.
        let mic = build_mic(&[1, 2, 3, 4]);
        assert_eq!(mic[0], msg::SSH_MSG_USERAUTH_GSSAPI_MIC);
        assert_eq!(decode_mic(&mic[1..]).unwrap(), vec![1, 2, 3, 4]);

        // Exchange-complete has no body.
        let ec = build_exchange_complete();
        assert_eq!(ec, vec![msg::SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE]);
    }

    #[test]
    fn error_and_err_tok_round_trip() {
        let err = build_error(0x8000_0001, 42, "bad credentials", "en-US");
        assert_eq!(err[0], msg::SSH_MSG_USERAUTH_GSSAPI_ERROR);

        let et = build_err_tok(&[9, 9, 9]);
        assert_eq!(et[0], msg::SSH_MSG_USERAUTH_GSSAPI_ERRTOK);
        assert_eq!(decode_err_tok(&et[1..]).unwrap(), vec![9, 9, 9]);
    }

    #[test]
    fn mic_data_matches_rfc_layout() {
        let data = build_mic_data(&[0x01; 32], "bob", "ssh-connection");
        let mut r = &data[..];
        assert_eq!(SshBytes::decode(&mut r).unwrap().0, vec![0x01; 32]);
        assert_eq!(r[0], msg::SSH_MSG_USERAUTH_REQUEST);
        let mut body = &r[1..];
        assert_eq!(SshString::decode(&mut body).unwrap().as_str().unwrap(), "bob");
        assert_eq!(
            SshString::decode(&mut body).unwrap().as_str().unwrap(),
            "ssh-connection"
        );
        assert_eq!(
            SshString::decode(&mut body).unwrap().as_str().unwrap(),
            "gssapi-with-mic"
        );
    }

    #[test]
    fn mechanism_choice_prefers_client_order() {
        let oids = vec![OID_SPNEGO.to_vec(), OID_KRB5.to_vec()];
        // Both supported; client listed SPNEGO first so the server picks it.
        assert_eq!(choose_mechanism(&oids).unwrap(), OID_SPNEGO.to_vec());
        // Only one supported.
        let oids2 = vec![vec![0x01, 0x02], OID_KRB5.to_vec()];
        assert_eq!(choose_mechanism(&oids2).unwrap(), OID_KRB5.to_vec());
        // None supported.
        assert!(choose_mechanism(&[vec![0x01, 0x02]]).is_none());
    }
}
