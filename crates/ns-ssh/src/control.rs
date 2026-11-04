//! ControlMaster connection multiplexing (client side).
//!
//! A master process keeps an SSH connection alive and listens on a Unix
//! socket. Slave processes connect to that socket, request a session, and
//! have their stdio multiplexed over the master's existing transport.
//!
//! The wire protocol is a small length-prefixed frame format (u32 length,
//! then payload), shared over the Unix socket.

use ssh_core::encoding::*;
use ssh_core::error::{Result, SshError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

// Request types (slave -> master).
pub const CTRL_OPEN_SESSION: u8 = 0x01;
pub const CTRL_DATA: u8 = 0x02;
pub const CTRL_EOF: u8 = 0x03;
pub const CTRL_CLOSE: u8 = 0x04;
pub const CTRL_WINDOW_CHANGE: u8 = 0x05;
// ControlMaster commands (`ssh -O ...`).
pub const CTRL_CHECK: u8 = 0x06;
pub const CTRL_EXIT: u8 = 0x07;

// Response types (master -> slave).
pub const CTRL_OPEN_CONFIRM: u8 = 0x81;
pub const CTRL_OPEN_FAILURE: u8 = 0x82;
pub const CTRL_DATA_RESP: u8 = 0x83;
pub const CTRL_EXTENDED_DATA: u8 = 0x84;
pub const CTRL_EOF_RESP: u8 = 0x85;
pub const CTRL_CLOSE_RESP: u8 = 0x86;
pub const CTRL_EXIT_STATUS: u8 = 0x87;
pub const CTRL_OK: u8 = 0x88;
pub const CTRL_ERR: u8 = 0x89;

/// A request from a slave to open a session channel on the master.
#[derive(Debug, Clone)]
pub struct OpenSessionRequest {
    pub request_id: u32,
    pub command: Option<String>,
    pub pty: bool,
    pub term: String,
    pub width: u32,
    pub height: u32,
    pub envs: Vec<(String, String)>,
    /// Request `auth-agent-req@openssh.com` forwarding on the session.
    pub want_agent: bool,
    /// Request `x11-req` forwarding on the session.
    pub want_x11: bool,
    /// Slave's agent socket path (`SSH_AUTH_SOCK`) for agent forwarding.
    pub agent_socket: Option<String>,
    /// Slave's X11 display (`DISPLAY`) for X11 forwarding.
    pub x11_display: Option<String>,
}

/// A frame sent by a slave to the master.
#[derive(Debug, Clone)]
pub enum ControlRequest {
    OpenSession(OpenSessionRequest),
    Data { request_id: u32, data: Vec<u8> },
    Eof { request_id: u32 },
    Close { request_id: u32 },
    WindowChange { request_id: u32, width: u32, height: u32 },
    /// `ssh -O check`: report whether the master is running.
    Check,
    /// `ssh -O exit` / `ssh -O stop`: terminate the master.
    Exit,
}

/// A frame sent by the master back to a slave.
#[derive(Debug, Clone)]
pub enum ControlResponse {
    OpenConfirm { request_id: u32, remote_id: u32 },
    OpenFailure { request_id: u32, reason: String },
    Data { request_id: u32, data: Vec<u8> },
    ExtendedData { request_id: u32, dtype: u32, data: Vec<u8> },
    Eof { request_id: u32 },
    Close { request_id: u32 },
    ExitStatus { request_id: u32, code: u32 },
    /// Command acknowledged (used by `-O check` / `-O exit`); carries the
    /// master process id.
    Ok(u32),
    /// Command failed with a message.
    Error(String),
}

/// Encode a request payload (the caller frames it with a length prefix).
pub fn encode_request(req: &ControlRequest) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    match req {
        ControlRequest::OpenSession(s) => {
            payload.push(CTRL_OPEN_SESSION);
            s.request_id.encode(&mut payload)?;
            match &s.command {
                Some(c) => {
                    true.encode(&mut payload)?;
                    SshString::new(c).encode(&mut payload)?;
                }
                None => {
                    false.encode(&mut payload)?;
                }
            }
            s.pty.encode(&mut payload)?;
            SshString::new(&s.term).encode(&mut payload)?;
            s.width.encode(&mut payload)?;
            s.height.encode(&mut payload)?;
            (s.envs.len() as u32).encode(&mut payload)?;
            for (k, v) in &s.envs {
                SshString::new(k).encode(&mut payload)?;
                SshString::new(v).encode(&mut payload)?;
            }
            s.want_agent.encode(&mut payload)?;
            s.want_x11.encode(&mut payload)?;
            match &s.agent_socket {
                Some(p) => {
                    true.encode(&mut payload)?;
                    SshString::new(p).encode(&mut payload)?;
                }
                None => false.encode(&mut payload)?,
            }
            match &s.x11_display {
                Some(d) => {
                    true.encode(&mut payload)?;
                    SshString::new(d).encode(&mut payload)?;
                }
                None => false.encode(&mut payload)?,
            }
        }
        ControlRequest::Data { request_id, data } => {
            payload.push(CTRL_DATA);
            request_id.encode(&mut payload)?;
            SshBytes(data.clone()).encode(&mut payload)?;
        }
        ControlRequest::Eof { request_id } => {
            payload.push(CTRL_EOF);
            request_id.encode(&mut payload)?;
        }
        ControlRequest::Close { request_id } => {
            payload.push(CTRL_CLOSE);
            request_id.encode(&mut payload)?;
        }
        ControlRequest::WindowChange { request_id, width, height } => {
            payload.push(CTRL_WINDOW_CHANGE);
            request_id.encode(&mut payload)?;
            width.encode(&mut payload)?;
            height.encode(&mut payload)?;
        }
        ControlRequest::Check => payload.push(CTRL_CHECK),
        ControlRequest::Exit => payload.push(CTRL_EXIT),
    }
    Ok(payload)
}

/// Decode a request payload (without the length prefix).
pub fn decode_request(data: &[u8]) -> Result<ControlRequest> {
    if data.is_empty() {
        return Err(SshError::Protocol("empty control frame".into()));
    }
    let mut r = data;
    let ty = data[0];
    r = &r[1..];
    match ty {
        CTRL_OPEN_SESSION => {
            let request_id = u32::decode(&mut r)?;
            let has_cmd = bool::decode(&mut r)?;
            let command = if has_cmd {
                Some(SshString::decode(&mut r)?.as_str()?.to_string())
            } else {
                None
            };
            let pty = bool::decode(&mut r)?;
            let term = SshString::decode(&mut r)?.as_str()?.to_string();
            let width = u32::decode(&mut r)?;
            let height = u32::decode(&mut r)?;
            let n = u32::decode(&mut r)? as usize;
            let mut envs = Vec::with_capacity(n.min(128));
            for _ in 0..n.min(128) {
                let k = SshString::decode(&mut r)?.as_str()?.to_string();
                let v = SshString::decode(&mut r)?.as_str()?.to_string();
                envs.push((k, v));
            }
            let want_agent = bool::decode(&mut r)?;
            let want_x11 = bool::decode(&mut r)?;
            let agent_socket = if bool::decode(&mut r)? {
                Some(SshString::decode(&mut r)?.as_str()?.to_string())
            } else {
                None
            };
            let x11_display = if bool::decode(&mut r)? {
                Some(SshString::decode(&mut r)?.as_str()?.to_string())
            } else {
                None
            };
            Ok(ControlRequest::OpenSession(OpenSessionRequest {
                request_id, command, pty, term, width, height, envs,
                want_agent, want_x11, agent_socket, x11_display,
            }))
        }
        CTRL_DATA => {
            let request_id = u32::decode(&mut r)?;
            let data = SshBytes::decode(&mut r)?.0;
            Ok(ControlRequest::Data { request_id, data })
        }
        CTRL_EOF => {
            let request_id = u32::decode(&mut r)?;
            Ok(ControlRequest::Eof { request_id })
        }
        CTRL_CLOSE => {
            let request_id = u32::decode(&mut r)?;
            Ok(ControlRequest::Close { request_id })
        }
        CTRL_WINDOW_CHANGE => {
            let request_id = u32::decode(&mut r)?;
            let width = u32::decode(&mut r)?;
            let height = u32::decode(&mut r)?;
            Ok(ControlRequest::WindowChange { request_id, width, height })
        }
        CTRL_CHECK => Ok(ControlRequest::Check),
        CTRL_EXIT => Ok(ControlRequest::Exit),
        _ => Err(SshError::Protocol(format!("unknown control request type {}", ty))),
    }
}

/// Encode a response frame.
pub fn encode_response(resp: &ControlResponse) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    match resp {
        ControlResponse::OpenConfirm { request_id, remote_id } => {
            payload.push(CTRL_OPEN_CONFIRM);
            request_id.encode(&mut payload)?;
            remote_id.encode(&mut payload)?;
        }
        ControlResponse::OpenFailure { request_id, reason } => {
            payload.push(CTRL_OPEN_FAILURE);
            request_id.encode(&mut payload)?;
            SshString::new(reason).encode(&mut payload)?;
        }
        ControlResponse::Data { request_id, data } => {
            payload.push(CTRL_DATA_RESP);
            request_id.encode(&mut payload)?;
            SshBytes(data.clone()).encode(&mut payload)?;
        }
        ControlResponse::ExtendedData { request_id, dtype, data } => {
            payload.push(CTRL_EXTENDED_DATA);
            request_id.encode(&mut payload)?;
            dtype.encode(&mut payload)?;
            SshBytes(data.clone()).encode(&mut payload)?;
        }
        ControlResponse::Eof { request_id } => {
            payload.push(CTRL_EOF_RESP);
            request_id.encode(&mut payload)?;
        }
        ControlResponse::Close { request_id } => {
            payload.push(CTRL_CLOSE_RESP);
            request_id.encode(&mut payload)?;
        }
        ControlResponse::ExitStatus { request_id, code } => {
            payload.push(CTRL_EXIT_STATUS);
            request_id.encode(&mut payload)?;
            code.encode(&mut payload)?;
        }
        ControlResponse::Ok(pid) => {
            payload.push(CTRL_OK);
            pid.encode(&mut payload)?;
        }
        ControlResponse::Error(msg) => {
            payload.push(CTRL_ERR);
            SshString::new(msg).encode(&mut payload)?;
        }
    }
    Ok(payload)
}

/// Decode a response payload (without the length prefix).
pub fn decode_response(data: &[u8]) -> Result<ControlResponse> {
    if data.is_empty() {
        return Err(SshError::Protocol("empty control frame".into()));
    }
    let mut r = data;
    let ty = data[0];
    r = &r[1..];
    match ty {
        CTRL_OPEN_CONFIRM => {
            let request_id = u32::decode(&mut r)?;
            let remote_id = u32::decode(&mut r)?;
            Ok(ControlResponse::OpenConfirm { request_id, remote_id })
        }
        CTRL_OPEN_FAILURE => {
            let request_id = u32::decode(&mut r)?;
            let reason = SshString::decode(&mut r)?.as_str()?.to_string();
            Ok(ControlResponse::OpenFailure { request_id, reason })
        }
        CTRL_DATA_RESP => {
            let request_id = u32::decode(&mut r)?;
            let data = SshBytes::decode(&mut r)?.0;
            Ok(ControlResponse::Data { request_id, data })
        }
        CTRL_EXTENDED_DATA => {
            let request_id = u32::decode(&mut r)?;
            let dtype = u32::decode(&mut r)?;
            let data = SshBytes::decode(&mut r)?.0;
            Ok(ControlResponse::ExtendedData { request_id, dtype, data })
        }
        CTRL_EOF_RESP => {
            let request_id = u32::decode(&mut r)?;
            Ok(ControlResponse::Eof { request_id })
        }
        CTRL_CLOSE_RESP => {
            let request_id = u32::decode(&mut r)?;
            Ok(ControlResponse::Close { request_id })
        }
        CTRL_EXIT_STATUS => {
            let request_id = u32::decode(&mut r)?;
            let code = u32::decode(&mut r)?;
            Ok(ControlResponse::ExitStatus { request_id, code })
        }
        CTRL_OK => {
            let pid = u32::decode(&mut r)?;
            Ok(ControlResponse::Ok(pid))
        }
        CTRL_ERR => {
            let msg = SshString::decode(&mut r)?.as_str()?.to_string();
            Ok(ControlResponse::Error(msg))
        }
        _ => Err(SshError::Protocol(format!("unknown control response type {}", ty))),
    }
}

/// Read one length-prefixed frame from a stream.
pub async fn read_frame(stream: &mut (impl AsyncReadExt + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(SshError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(SshError::Protocol("control frame too large".into()));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Write one length-prefixed frame to a stream.
pub async fn write_frame(stream: &mut (impl AsyncWriteExt + Unpin), payload: &[u8]) -> Result<()> {
    stream.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Send a ControlMaster command (`ssh -O check` / `-O exit`) over the socket
/// and wait for the master's acknowledgement. Returns the exit code (0 on
/// success, 255 if the master is not running).
pub async fn run_control_command(socket: UnixStream, command: &str) -> i32 {
    let mut sock = socket;
    let req = match command.to_lowercase().as_str() {
        "check" => ControlRequest::Check,
        "exit" | "stop" => ControlRequest::Exit,
        other => {
            eprintln!("ns-ssh: unsupported control command: {}", other);
            return 1;
        }
    };
    let frame = match encode_request(&req) {
        Ok(f) => f,
        Err(e) => { eprintln!("ns-ssh: failed to encode control command: {}", e); return 1; }
    };
    if write_frame(&mut sock, &frame).await.is_err() {
        eprintln!("ns-ssh: failed to send control command to master");
        return 255;
    }
    let Some(frame) = (match read_frame(&mut sock).await {
        Ok(f) => f,
        Err(e) => { eprintln!("ns-ssh: control socket error: {}", e); return 255; }
    }) else {
        eprintln!("ns-ssh: control socket closed by master");
        return 255;
    };
    match decode_response(&frame) {
        Ok(ControlResponse::Ok(pid)) => {
            match req {
                ControlRequest::Check => eprintln!("Master running (pid={})", pid),
                _ => {}
            }
            0
        }
        Ok(ControlResponse::Error(msg)) => { eprintln!("ns-ssh: {}", msg); 1 }
        _ => { eprintln!("ns-ssh: unexpected response from master"); 1 }
    }
}

/// Connect to the master's control socket and run a session as a slave.
pub async fn run_control_slave(
    socket: UnixStream,
    request: OpenSessionRequest,
    batch_mode: bool,
) -> Result<i32> {
    let mut sock = socket;
    let req_id = request.request_id;
    let frame = encode_request(&ControlRequest::OpenSession(request))?;
    write_frame(&mut sock, &frame).await?;

    // Wait for the open confirmation.
    let _remote_id = loop {
        let Some(frame) = read_frame(&mut sock).await? else {
            return Err(SshError::Protocol("control socket closed".into()));
        };
        match decode_response(&frame)? {
            ControlResponse::OpenConfirm { request_id, remote_id: rid } => {
                if request_id == req_id {
                    break rid;
                }
            }
            ControlResponse::OpenFailure { reason, .. } => {
                eprintln!("ns-ssh: session open failed: {}", reason);
                return Ok(1);
            }
            _ => {}
        }
    };

    // Forward stdin/stdout over the control socket.
    let (mut rd, mut wr) = sock.into_split();

    let (data_tx, mut data_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    // When the session is done (close/exit-status received), signal the writer
    // to drop its write half so the master sees the connection close.
    let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
    let reader_task = tokio::spawn(async move {
        loop {
            let Some(frame) = read_frame(&mut rd).await? else {
                let _ = close_tx.send(());
                break;
            };
            match decode_response(&frame)? {
                ControlResponse::Data { request_id, data } if request_id == req_id => {
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(&data);
                    let _ = std::io::stdout().flush();
                }
                ControlResponse::ExtendedData { request_id, data, .. } if request_id == req_id => {
                    use std::io::Write;
                    let _ = std::io::stderr().write_all(&data);
                    let _ = std::io::stderr().flush();
                }
                ControlResponse::ExitStatus { request_id, code } if request_id == req_id => {
                    let _ = data_tx.send(code.to_be_bytes().to_vec());
                    let _ = close_tx.send(());
                    break;
                }
                ControlResponse::Close { request_id, .. } | ControlResponse::Eof { request_id, .. } if request_id == req_id => {
                    let _ = close_tx.send(());
                    break;
                }
                _ => {}
            }
        }
        Ok::<(), SshError>(())
    });

    // stdin -> control socket
    let writer_task = tokio::spawn(async move {
        loop {
            let n = tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let mut buf = [0u8; 4096];
                match std::io::stdin().read(&mut buf) {
                    Ok(n) => (n, buf),
                    Err(_) => (0, [0u8; 4096]),
                }
            }).await.unwrap_or((0, [0u8; 4096]));
            if n.0 == 0 { break; }
            let frame = encode_request(&ControlRequest::Data { request_id: req_id, data: n.1[..n.0].to_vec() })?;
            if write_frame(&mut wr, &frame).await.is_err() { break; }
        }
        let eof = encode_request(&ControlRequest::Eof { request_id: req_id })?;
        let _ = write_frame(&mut wr, &eof).await;
        // Keep the write half alive until the reader signals the session is done,
        // otherwise closing the write half early makes the master think the whole
        // slave connection is gone.
        let _ = close_rx.await;
        Ok::<(), SshError>(())
    });

    let mut exit_code: i32 = 0;
    if let Ok(Some(code)) = tokio::time::timeout(
        std::time::Duration::from_secs(3600),
        async {
            let _ = reader_task.await;
            data_rx.recv().await
        }
    ).await {
        if code.len() == 4 {
            exit_code = u32::from_be_bytes([code[0], code[1], code[2], code[3]]) as i32;
        }
    }
    let _ = writer_task.await;
    let _ = batch_mode;
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_session_roundtrip_with_agent_x11() {
        let req = OpenSessionRequest {
            request_id: 7,
            command: Some("ls -la".to_string()),
            pty: true,
            term: "xterm-256color".to_string(),
            width: 120,
            height: 40,
            envs: vec![("LANG".to_string(), "en_US.UTF-8".to_string())],
            want_agent: true,
            want_x11: true,
            agent_socket: Some("/tmp/ssh-agent.sock".to_string()),
            x11_display: Some(":0".to_string()),
        };
        let encoded = encode_request(&ControlRequest::OpenSession(req.clone())).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        match decoded {
            ControlRequest::OpenSession(d) => {
                assert_eq!(d.request_id, 7);
                assert_eq!(d.command.as_deref(), Some("ls -la"));
                assert!(d.pty);
                assert_eq!(d.term, "xterm-256color");
                assert_eq!(d.width, 120);
                assert_eq!(d.height, 40);
                assert_eq!(d.envs, vec![("LANG".to_string(), "en_US.UTF-8".to_string())]);
                assert!(d.want_agent);
                assert!(d.want_x11);
                assert_eq!(d.agent_socket.as_deref(), Some("/tmp/ssh-agent.sock"));
                assert_eq!(d.x11_display.as_deref(), Some(":0"));
            }
            _ => panic!("expected OpenSession"),
        }
    }

    #[test]
    fn open_session_roundtrip_no_forwarding() {
        let req = OpenSessionRequest {
            request_id: 1,
            command: None,
            pty: false,
            term: "xterm".to_string(),
            width: 80,
            height: 24,
            envs: Vec::new(),
            want_agent: false,
            want_x11: false,
            agent_socket: None,
            x11_display: None,
        };
        let encoded = encode_request(&ControlRequest::OpenSession(req)).unwrap();
        match decode_request(&encoded).unwrap() {
            ControlRequest::OpenSession(d) => {
                assert!(!d.want_agent);
                assert!(!d.want_x11);
                assert!(d.agent_socket.is_none());
                assert!(d.x11_display.is_none());
            }
            _ => panic!("expected OpenSession"),
        }
    }
}
