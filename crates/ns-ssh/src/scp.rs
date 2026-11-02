use crate::client::SshClient;
use crate::config::ResolvedConfig;
use ssh_core::error::{Result, SshError};
use ssh_core::channel::ChannelId;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn new_scp_client(config: &ResolvedConfig) -> Result<SshClient> {
    let mut client = SshClient::new(config.clone());
    client.connect().await?;
    client.handshake().await?;
    client.authenticate().await?;
    client.request_connection_service().await?;
    Ok(client)
}

async fn recv_byte(client: &mut SshClient, local_id: ChannelId) -> Result<u8> {
    loop {
        match client.recv_channel_data(local_id).await? {
            Some(data) => {
                if data.is_empty() {
                    continue;
                }
                if data.len() > 1 {
                    return Err(SshError::Protocol("unexpected data during SCP control".into()));
                }
                return Ok(data[0]);
            }
            None => return Err(SshError::Protocol("SCP channel closed during transfer".into())),
        }
    }
}

async fn recv_control_line(client: &mut SshClient, local_id: ChannelId) -> Result<String> {
    let mut line = Vec::new();
    loop {
        match client.recv_channel_data(local_id).await? {
            Some(data) => {
                for b in data {
                    if b == b'\n' {
                        return Ok(String::from_utf8_lossy(&line).into_owned());
                    }
                    line.push(b);
                }
            }
            None => return Err(SshError::Protocol("SCP channel closed while reading control".into())),
        }
    }
}

async fn send_byte(client: &mut SshClient, local_id: ChannelId, b: u8) -> Result<()> {
    client.send_channel_data(local_id, &[b]).await
}

pub async fn scp_upload(config: &ResolvedConfig, local_path: &Path, remote_path: &str) -> Result<()> {
    let mut client = new_scp_client(config).await?;
    let remote_cmd = format!("scp -t -p {}", remote_path);
    let local_id = client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    let metadata = std::fs::metadata(local_path).map_err(|e| SshError::Io(e))?;

    // Three-way handshake: the remote scp -t sends an initial ack byte (0) when ready.
    let init = recv_byte(&mut client, local_id).await?;
    if init != 0 {
        return Err(SshError::Protocol("SCP remote did not start cleanly".into()));
    }

    if metadata.is_dir() {
        return scp_upload_recursive(&mut client, local_id, local_path, remote_path).await;
    }

    let mode = format!("{:04o}", metadata.permissions().mode() & 0o7777);
    let size = metadata.len();
    let fname = local_path.file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());

    // Send timestamp-preservation header (requires -p on the remote).
    if let Ok(mtime) = metadata.modified() {
        if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
            let secs = dur.as_secs();
            let usecs = dur.subsec_micros();
            let tmsg = format!("T{} 0 {} 0\n", secs, usecs);
            client.send_channel_data(local_id, tmsg.as_bytes()).await?;
            let t_ack = recv_byte(&mut client, local_id).await?;
            if t_ack != 0 {
                return Err(SshError::Protocol("SCP rejected timestamp".into()));
            }
        }
    }

    let control_msg = format!("C{} {} {}\n", mode, size, fname);

    client.send_channel_data(local_id, control_msg.as_bytes()).await?;
    let ack = recv_byte(&mut client, local_id).await?;
    if ack != 0 {
        return Err(SshError::Protocol("SCP rejected control message".into()));
    }

    let mut file = tokio::fs::File::open(local_path).await.map_err(|e| SshError::Io(e))?;
    let mut buf = vec![0u8; 16384];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        client.send_channel_data(local_id, &buf[..n]).await?;
    }

    client.send_channel_data(local_id, &[0]).await?;
    let _ack = recv_byte(&mut client, local_id).await?;

    Ok(())
}

pub async fn scp_download(config: &ResolvedConfig, remote_path: &str, local_path: &Path) -> Result<()> {
    let mut client = new_scp_client(config).await?;
    let remote_cmd = format!("scp -f -p {}", remote_path);
    let local_id = client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    send_byte(&mut client, local_id, 0).await?;

    // Read the first control header (skipping an optional T timestamp header).
    let (control, mtime) = read_first_control(&mut client, local_id).await?;
    let (kind, mode, size, fname) = parse_control(&control)?;

    match kind {
        'C' => {
            send_byte(&mut client, local_id, 0).await?;
            let dest = if local_path.is_dir() {
                local_path.join(&fname)
            } else {
                local_path.to_path_buf()
            };
            recv_scp_file(&mut client, local_id, &dest, mode, size, mtime).await?;
        }
        'D' => {
            send_byte(&mut client, local_id, 0).await?;
            let dir = if local_path.is_dir() {
                local_path.join(&fname)
            } else {
                local_path.to_path_buf()
            };
            std::fs::create_dir_all(&dir).map_err(|e| SshError::Io(e))?;
            apply_file_meta(&dir, mode, mtime)?;
            scp_recv_entries(&mut client, local_id, &dir).await?;
        }
        _ => {
            return Err(SshError::Protocol("unexpected SCP control message".into()));
        }
    }

    Ok(())
}

/// Read one control header, transparently skipping an optional T timestamp header.
async fn read_first_control(client: &mut SshClient, local_id: ChannelId) -> Result<(String, Option<(i64, i64)>)> {
    let mut control = recv_control_line(client, local_id).await?;
    let mut mtime = None;
    if control.starts_with('T') {
        mtime = parse_timestamp(&control);
        send_byte(client, local_id, 0).await?;
        control = recv_control_line(client, local_id).await?;
    }
    Ok((control, mtime))
}

/// Parse a T<mtime> 0 <usec> 0 timestamp header into (sec, usec).
fn parse_timestamp(line: &str) -> Option<(i64, i64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 && parts[0].starts_with('T') {
        let sec: i64 = parts[0][1..].parse().ok()?;
        let usec: i64 = parts[2].parse().ok()?;
        Some((sec, usec))
    } else {
        None
    }
}

/// Apply a file mode and mtime to `dest` after transfer.
fn apply_file_meta(dest: &Path, mode: Option<u32>, mtime: Option<(i64, i64)>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(m) = mode {
            let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(m & 0o7777));
        }
        if let Some((sec, usec)) = mtime {
            let nsec = usec * 1000;
            let times = [
                libc::timespec { tv_sec: sec, tv_nsec: nsec },
                libc::timespec { tv_sec: sec, tv_nsec: nsec },
            ];
            if let Ok(cpath) = std::ffi::CString::new(dest.as_os_str().as_encoded_bytes()) {
                unsafe {
                    libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0);
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dest, mode, mtime);
    }
    Ok(())
}

/// Parse a control message into (kind, mode, size, filename). For directories, size is 0.
fn parse_control(control: &str) -> Result<(char, Option<u32>, u64, String)> {
    let parts: Vec<&str> = control.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(SshError::Protocol("invalid SCP control message".into()));
    }
    let kind = parts[0].chars().next().unwrap_or(' ');
    let mode = if parts[0].len() > 1 {
        u32::from_str_radix(&parts[0][1..], 8).ok()
    } else {
        None
    };
    let size: u64 = parts[1].parse()
        .map_err(|_| SshError::Protocol("invalid file size".into()))?;
    let fname = parts[2..].join(" ");
    Ok((kind, mode, size, fname))
}

/// Receive file data of `size` bytes and write it to `dest`, then ack.
async fn recv_scp_file(
    client: &mut SshClient,
    local_id: ChannelId,
    dest: &Path,
    mode: Option<u32>,
    size: u64,
    mtime: Option<(i64, i64)>,
) -> Result<()> {
    let mut file = tokio::fs::File::create(dest).await.map_err(|e| SshError::Io(e))?;
    let mut remaining = size;
    while remaining > 0 {
        match client.recv_channel_data(local_id).await? {
            Some(data) => {
                if data.is_empty() {
                    continue;
                }
                let take = data.len().min(remaining as usize);
                file.write_all(&data[..take]).await?;
                remaining -= take as u64;
            }
            None => return Err(SshError::Protocol("connection closed during transfer".into())),
        }
    }
    send_byte(client, local_id, 0).await?;
    apply_file_meta(dest, mode, mtime)?;
    Ok(())
}

/// Recursively receive directory entries into `dest_dir` until an 'E' header or channel close.
async fn scp_recv_entries(client: &mut SshClient, local_id: ChannelId, dest_dir: &Path) -> Result<()> {
    loop {
        let mut control = match recv_control_line_opt(client, local_id).await? {
            Some(c) => c,
            None => return Ok(()), // channel closed = normal end
        };
        if control.starts_with('E') {
            send_byte(client, local_id, 0).await?;
            return Ok(());
        }
        // Skip optional T timestamp header preceding a C/D entry.
        let mut mtime = None;
        if control.starts_with('T') {
            mtime = parse_timestamp(&control);
            send_byte(client, local_id, 0).await?;
            control = match recv_control_line_opt(client, local_id).await? {
                Some(c) => c,
                None => return Ok(()),
            };
        }
        let (kind, mode, size, fname) = parse_control(&control)?;
        match kind {
            'C' => {
                send_byte(client, local_id, 0).await?;
                let dest = dest_dir.join(&fname);
                recv_scp_file(client, local_id, &dest, mode, size, mtime).await?;
            }
            'D' => {
                send_byte(client, local_id, 0).await?;
                let dir = dest_dir.join(&fname);
                std::fs::create_dir_all(&dir).map_err(|e| SshError::Io(e))?;
                apply_file_meta(&dir, mode, mtime)?;
                Box::pin(scp_recv_entries(client, local_id, &dir)).await?;
            }
            _ => return Err(SshError::Protocol("unexpected SCP control message".into())),
        }
    }
}

/// Like recv_control_line, but returns Ok(None) when the channel closes with no pending data.
async fn recv_control_line_opt(client: &mut SshClient, local_id: ChannelId) -> Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        match client.recv_channel_data(local_id).await? {
            Some(data) => {
                for b in data {
                    if b == b'\n' {
                        return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
                    }
                    line.push(b);
                }
            }
            None => {
                if line.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
        }
    }
}

async fn send_timestamp(client: &mut SshClient, local_id: ChannelId, meta: &std::fs::Metadata) -> Result<()> {
    if let Ok(mtime) = meta.modified() {
        if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
            let tmsg = format!("T{} 0 {} 0\n", dur.as_secs(), dur.subsec_micros());
            client.send_channel_data(local_id, tmsg.as_bytes()).await?;
            let ack = recv_byte(client, local_id).await?;
            if ack != 0 {
                return Err(SshError::Protocol("SCP rejected timestamp".into()));
            }
        }
    }
    Ok(())
}

pub async fn scp_upload_recursive(
    client: &mut SshClient,
    local_id: ChannelId,
    local_dir: &Path,
    remote_path: &str,
) -> Result<()> {
    let entries = std::fs::read_dir(local_dir).map_err(|e| SshError::Io(e))?;
    let mut names: Vec<_> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| SshError::Io(e))?;
        names.push(entry.file_name());
    }
    names.sort();

    let dmeta = std::fs::metadata(local_dir).map_err(|e| SshError::Io(e))?;
    send_timestamp(client, local_id, &dmeta).await?;

    client.send_channel_data(local_id, format!("D0755 0 {}\n", remote_path).as_bytes()).await?;
    let ack = recv_byte(client, local_id).await?;
    if ack != 0 {
        return Err(SshError::Protocol("SCP rejected directory".into()));
    }

    for name in names {
        let full = local_dir.join(&name);
        let fname = name.to_string_lossy().into_owned();
        let meta = std::fs::metadata(&full).map_err(|e| SshError::Io(e))?;
        if meta.is_dir() {
            Box::pin(scp_upload_recursive(client, local_id, &full, &fname)).await?;
        } else {
            send_timestamp(client, local_id, &meta).await?;
            let mode = format!("{:04o}", meta.permissions().mode() & 0o7777);
            let size = meta.len();
            client.send_channel_data(local_id, format!("C{} {} {}\n", mode, size, fname).as_bytes()).await?;
            let ack = recv_byte(client, local_id).await?;
            if ack != 0 {
                return Err(SshError::Protocol("SCP rejected file".into()));
            }
            let mut file = tokio::fs::File::open(&full).await.map_err(|e| SshError::Io(e))?;
            let mut buf = vec![0u8; 16384];
            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client.send_channel_data(local_id, &buf[..n]).await?;
            }
            client.send_channel_data(local_id, &[0]).await?;
            let _ack = recv_byte(client, local_id).await?;
        }
    }

    client.send_channel_data(local_id, b"E\n").await?;
    let _ack = recv_byte(client, local_id).await?;

    Ok(())
}