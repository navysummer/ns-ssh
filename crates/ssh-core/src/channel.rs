use crate::error::{Result, SshError};
use crate::encoding::*;
use crate::msg;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

pub type ChannelId = u32;

pub struct Channel {
    pub local_id: ChannelId,
    pub remote_id: Option<ChannelId>,
    pub channel_type: String,
    pub window_size: u32,
    pub max_packet_size: u32,
    pub data_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub ext_data_tx: Option<mpsc::Sender<(u32, Vec<u8>)>>,
    pub ext_data_rx: Option<mpsc::Receiver<(u32, Vec<u8>)>>,
    pub closed: bool,
}

pub struct ChannelManager {
    channels: HashMap<ChannelId, Channel>,
    next_channel_id: ChannelId,
    pub pty_width: u32,
    pub pty_height: u32,
    pub env_vars: Vec<(String, String)>,
}

impl ChannelManager {
    pub fn new() -> Self {
        ChannelManager {
            channels: HashMap::new(),
            next_channel_id: 0,
            pty_width: 80,
            pty_height: 24,
            env_vars: Vec::new(),
        }
    }

    pub fn alloc_channel(
        &mut self,
        channel_type: &str,
        window_size: u32,
        max_packet_size: u32,
    ) -> ChannelId {
        let id = self.next_channel_id;
        self.next_channel_id += 1;

        let (data_tx, data_rx) = mpsc::channel(256);
        let (ext_tx, ext_rx) = if channel_type == "session" {
            let (tx, rx) = mpsc::channel(64);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let channel = Channel {
            local_id: id,
            remote_id: None,
            channel_type: channel_type.to_string(),
            window_size,
            max_packet_size,
            data_tx: Some(data_tx),
            data_rx: Some(data_rx),
            ext_data_tx: ext_tx,
            ext_data_rx: ext_rx,
            closed: false,
        };

        self.channels.insert(id, channel);
        id
    }

    pub fn take_data_rx(&mut self, local_id: ChannelId) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.channels.get_mut(&local_id).and_then(|c| c.data_rx.take())
    }

    pub fn take_ext_data_rx(&mut self, local_id: ChannelId) -> Option<mpsc::Receiver<(u32, Vec<u8>)>> {
        self.channels.get_mut(&local_id).and_then(|c| c.ext_data_rx.take())
    }

    pub fn set_remote_id(&mut self, local_id: ChannelId, remote_id: ChannelId) {
        if let Some(ch) = self.channels.get_mut(&local_id) {
            ch.remote_id = Some(remote_id);
        }
    }

    pub fn get_channel(&self, local_id: ChannelId) -> Option<&Channel> {
        self.channels.get(&local_id)
    }

    pub fn get_channel_mut(&mut self, local_id: ChannelId) -> Option<&mut Channel> {
        self.channels.get_mut(&local_id)
    }

    pub fn find_by_remote_id(&self, remote_id: ChannelId) -> Option<&Channel> {
        self.channels.values().find(|c| c.remote_id == Some(remote_id))
    }

    pub fn close_channel(&mut self, local_id: ChannelId) {
        if let Some(ch) = self.channels.get_mut(&local_id) {
            ch.closed = true;
        }
        self.channels.remove(&local_id);
    }

    pub fn channels(&self) -> &HashMap<ChannelId, Channel> {
        &self.channels
    }

    pub fn next_channel_id(&self) -> ChannelId {
        self.next_channel_id
    }
}

pub fn build_channel_open(channel_type: &str, sender_channel: ChannelId, window_size: u32, max_packet_size: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN);
    SshString::new(channel_type).encode(&mut payload).unwrap();
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload
}

pub fn build_channel_open_confirmation(
    recipient_channel: ChannelId,
    sender_channel: ChannelId,
    window_size: u32,
    max_packet_size: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    payload.extend(recipient_channel.to_be_bytes());
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload
}

pub fn build_channel_open_failure(
    recipient_channel: ChannelId,
    reason: u32,
    message: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN_FAILURE);
    payload.extend(recipient_channel.to_be_bytes());
    payload.extend(reason.to_be_bytes());
    SshString::new(message).encode(&mut payload).unwrap();
    SshString::new("").encode(&mut payload).unwrap();
    payload
}

pub fn build_channel_data(channel_id: ChannelId, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_DATA);
    payload.extend(channel_id.to_be_bytes());
    SshBytes(data.to_vec()).encode(&mut payload).unwrap();
    payload
}

pub fn build_channel_extended_data(channel_id: ChannelId, data_type: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_EXTENDED_DATA);
    payload.extend(channel_id.to_be_bytes());
    payload.extend(data_type.to_be_bytes());
    SshBytes(data.to_vec()).encode(&mut payload).unwrap();
    payload
}

pub fn build_channel_window_adjust(channel_id: ChannelId, amount: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_WINDOW_ADJUST);
    payload.extend(channel_id.to_be_bytes());
    payload.extend(amount.to_be_bytes());
    payload
}

pub fn build_channel_eof(channel_id: ChannelId) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_EOF);
    payload.extend(channel_id.to_be_bytes());
    payload
}

pub fn build_channel_close(channel_id: ChannelId) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_CLOSE);
    payload.extend(channel_id.to_be_bytes());
    payload
}

pub fn build_channel_request(
    channel_id: ChannelId,
    request_type: &str,
    want_reply: bool,
    extra: Option<&[u8]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_REQUEST);
    payload.extend(channel_id.to_be_bytes());
    SshString::new(request_type).encode(&mut payload).unwrap();
    payload.push(want_reply as u8);
    if let Some(data) = extra {
        payload.extend_from_slice(data);
    }
    payload
}

pub fn build_pty_request(
    term: &str,
    width: u32,
    height: u32,
    pixel_width: u32,
    pixel_height: u32,
    modes: &[(u8, u32)],
) -> Vec<u8> {
    let mut data = Vec::new();
    SshString::new(term).encode(&mut data).unwrap();
    data.extend(width.to_be_bytes());
    data.extend(height.to_be_bytes());
    data.extend(pixel_width.to_be_bytes());
    data.extend(pixel_height.to_be_bytes());

    let mut mode_str = Vec::new();
    for &(opcode, value) in modes {
        mode_str.push(opcode);
        mode_str.extend(value.to_be_bytes());
    }
    mode_str.push(0); // TTY_OP_END
    SshBytes(mode_str).encode(&mut data).unwrap();

    data
}

pub fn build_exec_request(command: &str) -> Vec<u8> {
    let mut data = Vec::new();
    SshString::new(command).encode(&mut data).unwrap();
    data
}

pub fn build_shell_request() -> Vec<u8> {
    Vec::new()
}

pub fn build_subsystem_request(subsystem: &str) -> Vec<u8> {
    let mut data = Vec::new();
    SshString::new(subsystem).encode(&mut data).unwrap();
    data
}

pub fn build_env_request(name: &str, value: &str) -> Vec<u8> {
    let mut data = Vec::new();
    SshString::new(name).encode(&mut data).unwrap();
    SshString::new(value).encode(&mut data).unwrap();
    data
}

pub fn build_window_change(width: u32, height: u32, pixel_width: u32, pixel_height: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(width.to_be_bytes());
    data.extend(height.to_be_bytes());
    data.extend(pixel_width.to_be_bytes());
    data.extend(pixel_height.to_be_bytes());
    data
}

pub fn build_signal_request(signal_name: &str) -> Vec<u8> {
    let mut data = Vec::new();
    SshString::new(signal_name).encode(&mut data).unwrap();
    data
}

pub fn parse_channel_open(payload: &[u8]) -> Result<(String, ChannelId, u32, u32)> {
    let mut r = &payload[1..];
    let channel_type = SshString::decode(&mut r)?.as_str()?.to_string();
    let sender_channel = u32::decode(&mut r)?;
    let window_size = u32::decode(&mut r)?;
    let max_packet_size = u32::decode(&mut r)?;
    Ok((channel_type, sender_channel, window_size, max_packet_size))
}

pub fn parse_channel_data(payload: &[u8]) -> Result<(ChannelId, Vec<u8>)> {
    let mut r = &payload[1..];
    let channel_id = u32::decode(&mut r)?;
    let data = SshBytes::decode(&mut r)?;
    Ok((channel_id, data.0))
}

pub fn parse_channel_request(payload: &[u8]) -> Result<(ChannelId, String, bool)> {
    let mut r = &payload[1..];
    let channel_id = u32::decode(&mut r)?;
    let request_type = SshString::decode(&mut r)?.as_str()?.to_string();
    let want_reply = bool::decode(&mut r)?;
    Ok((channel_id, request_type, want_reply))
}

pub fn parse_channel_open_confirmation(payload: &[u8]) -> Result<(ChannelId, ChannelId, u32, u32)> {
    let mut r = &payload[1..];
    let recipient_channel = u32::decode(&mut r)?;
    let sender_channel = u32::decode(&mut r)?;
    let window_size = u32::decode(&mut r)?;
    let max_packet = u32::decode(&mut r)?;
    Ok((recipient_channel, sender_channel, window_size, max_packet))
}

pub fn parse_channel_open_failure(payload: &[u8]) -> Result<(ChannelId, u32, String)> {
    let mut r = &payload[1..];
    let recipient_channel = u32::decode(&mut r)?;
    let reason = u32::decode(&mut r)?;
    let message = SshString::decode(&mut r)?.as_str()?.to_string();
    Ok((recipient_channel, reason, message))
}

pub fn build_direct_tcpip_open(
    sender_channel: ChannelId,
    window_size: u32,
    max_packet_size: u32,
    host_to_connect: &str,
    port_to_connect: u32,
    originator_ip: &str,
    originator_port: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN);
    payload.extend(encode_string(msg::SSH_CHANNEL_TYPE_DIRECT_TCPIP));
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload.extend(encode_string(host_to_connect));
    payload.extend(port_to_connect.to_be_bytes());
    payload.extend(encode_string(originator_ip));
    payload.extend(originator_port.to_be_bytes());
    payload
}

pub fn parse_direct_tcpip_open(payload: &[u8]) -> Result<(ChannelId, u32, u32, String, u32, String, u32)> {
    let mut r = &payload[1..];
    let _type = SshString::decode(&mut r)?;
    let sender_channel = u32::decode(&mut r)?;
    let window_size = u32::decode(&mut r)?;
    let max_packet = u32::decode(&mut r)?;
    let host = SshString::decode(&mut r)?.as_str()?.to_string();
    let port = u32::decode(&mut r)?;
    let orig_ip = SshString::decode(&mut r)?.as_str()?.to_string();
    let orig_port = u32::decode(&mut r)?;
    Ok((sender_channel, window_size, max_packet, host, port, orig_ip, orig_port))
}

pub fn build_forwarded_tcpip_open(
    sender_channel: ChannelId,
    window_size: u32,
    max_packet_size: u32,
    address_connected: &str,
    port_connected: u32,
    originator_ip: &str,
    originator_port: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN);
    payload.extend(encode_string(msg::SSH_CHANNEL_TYPE_FORWARDED_TCPIP));
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload.extend(encode_string(address_connected));
    payload.extend(port_connected.to_be_bytes());
    payload.extend(encode_string(originator_ip));
    payload.extend(originator_port.to_be_bytes());
    payload
}

pub fn parse_forwarded_tcpip_open(payload: &[u8]) -> Result<(ChannelId, u32, u32, String, u32, String, u32)> {
    let mut r = &payload[1..];
    let _type = SshString::decode(&mut r)?;
    let sender_channel = u32::decode(&mut r)?;
    let window_size = u32::decode(&mut r)?;
    let max_packet = u32::decode(&mut r)?;
    let addr = SshString::decode(&mut r)?.as_str()?.to_string();
    let port = u32::decode(&mut r)?;
    let orig_ip = SshString::decode(&mut r)?.as_str()?.to_string();
    let orig_port = u32::decode(&mut r)?;
    Ok((sender_channel, window_size, max_packet, addr, port, orig_ip, orig_port))
}

pub fn build_x11_open(
    sender_channel: ChannelId,
    window_size: u32,
    max_packet_size: u32,
    originator_address: &str,
    originator_port: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN);
    payload.extend(encode_string(msg::SSH_CHANNEL_TYPE_X11));
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload.extend(encode_string(originator_address));
    payload.extend(originator_port.to_be_bytes());
    payload
}

pub fn build_direct_streamlocal_open(
    sender_channel: ChannelId,
    window_size: u32,
    max_packet_size: u32,
    socket_path: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN);
    payload.extend(encode_string(msg::SSH_CHANNEL_TYPE_DIRECT_STREAMLOCAL));
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload.extend(encode_string(socket_path));
    payload
}

pub fn build_forwarded_streamlocal_open(
    sender_channel: ChannelId,
    window_size: u32,
    max_packet_size: u32,
    socket_path: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN);
    payload.extend(encode_string(msg::SSH_CHANNEL_TYPE_FORWARDED_STREAMLOCAL));
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload.extend(encode_string(socket_path));
    payload
}

pub fn build_auth_agent_open(
    sender_channel: ChannelId,
    window_size: u32,
    max_packet_size: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_OPEN);
    payload.extend(encode_string(msg::SSH_CHANNEL_TYPE_AUTH_AGENT));
    payload.extend(sender_channel.to_be_bytes());
    payload.extend(window_size.to_be_bytes());
    payload.extend(max_packet_size.to_be_bytes());
    payload
}

pub fn build_global_request_tcpip_forward(
    want_reply: bool,
    address_to_bind: &str,
    port_to_bind: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_GLOBAL_REQUEST);
    payload.extend(encode_string(msg::SSH_GLOBAL_REQUEST_TCPIP_FORWARD));
    payload.push(want_reply as u8);
    payload.extend(encode_string(address_to_bind));
    payload.extend(port_to_bind.to_be_bytes());
    payload
}

pub fn build_global_request_cancel_tcpip_forward(
    want_reply: bool,
    address_to_bind: &str,
    port_to_bind: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_GLOBAL_REQUEST);
    payload.extend(encode_string(msg::SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD));
    payload.push(want_reply as u8);
    payload.extend(encode_string(address_to_bind));
    payload.extend(port_to_bind.to_be_bytes());
    payload
}

pub fn build_global_request_streamlocal_forward(
    want_reply: bool,
    socket_path: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_GLOBAL_REQUEST);
    payload.extend(encode_string(msg::SSH_GLOBAL_REQUEST_STREAMLOCAL_FORWARD));
    payload.push(want_reply as u8);
    payload.extend(encode_string(socket_path));
    payload
}

pub fn build_global_request_keepalive(want_reply: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_GLOBAL_REQUEST);
    payload.extend(encode_string(msg::SSH_GLOBAL_REQUEST_KEEPALIVE));
    payload.push(want_reply as u8);
    payload
}

pub fn build_global_request_no_more_sessions(want_reply: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_GLOBAL_REQUEST);
    payload.extend(encode_string(msg::SSH_GLOBAL_REQUEST_NO_MORE_SESSIONS));
    payload.push(want_reply as u8);
    payload
}

pub fn parse_global_request(payload: &[u8]) -> Result<(String, bool, Vec<u8>)> {
    let mut r = &payload[1..];
    let request_name = SshString::decode(&mut r)?.as_str()?.to_string();
    let want_reply = bool::decode(&mut r)?;
    let rest = r.to_vec();
    Ok((request_name, want_reply, rest))
}

pub fn parse_tcpip_forward_request(extra: &[u8]) -> Result<(String, u32)> {
    let mut r = extra;
    let addr = SshString::decode(&mut r)?.as_str()?.to_string();
    let port = u32::decode(&mut r)?;
    Ok((addr, port))
}

pub fn build_request_success(extra: Option<&[u8]>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_REQUEST_SUCCESS);
    if let Some(data) = extra {
        payload.extend(data);
    }
    payload
}

pub fn build_request_failure() -> Vec<u8> {
    vec![msg::SSH_MSG_REQUEST_FAILURE]
}

pub fn build_unimplemented(sequence: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5);
    payload.push(msg::SSH_MSG_UNIMPLEMENTED);
    sequence.encode(&mut payload);
    payload
}

pub fn build_x11_request(
    single_connection: bool,
    x11_auth_protocol: &str,
    x11_auth_cookie: &str,
    x11_screen_number: u32,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(single_connection as u8);
    data.extend(encode_string(x11_auth_protocol));
    data.extend(encode_string(x11_auth_cookie));
    data.extend(x11_screen_number.to_be_bytes());
    data
}

pub fn build_channel_success(recipient: ChannelId) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_SUCCESS);
    payload.extend(recipient.to_be_bytes());
    payload
}

pub fn build_channel_failure(recipient: ChannelId) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_CHANNEL_FAILURE);
    payload.extend(recipient.to_be_bytes());
    payload
}

pub fn build_disconnect(reason_code: u32, description: &str, language: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_DISCONNECT);
    payload.extend(reason_code.to_be_bytes());
    SshString::new(description).encode(&mut payload).unwrap();
    SshString::new(language).encode(&mut payload).unwrap();
    payload
}

pub fn build_ext_info(entries: &[(String, String)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(msg::SSH_MSG_EXT_INFO);
    payload.extend((entries.len() as u32).to_be_bytes());
    for (k, v) in entries {
        SshString::new(k).encode(&mut payload).unwrap();
        SshString::new(v).encode(&mut payload).unwrap();
    }
    payload
}

pub fn parse_ext_info(payload: &[u8]) -> Result<Vec<(String, String)>> {
    let mut r = &payload[1..];
    let count = u32::decode(&mut r)? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let k = SshString::decode(&mut r)?.as_str()?.to_string();
        let v = SshString::decode(&mut r)?.as_str()?.to_string();
        entries.push((k, v));
    }
    Ok(entries)
}
