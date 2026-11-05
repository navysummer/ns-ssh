use crate::client::SshClient;
use crate::config::ResolvedConfig;
use ssh_core::error::{Result, SshError};
use ssh_core::channel::ChannelId;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Timestamps carried by an SCP `T` header: (mtime_sec, mtime_usec,
/// atime_sec, atime_usec). OpenSSH emits all four fields so `scp -p` can
/// restore both modification and access times.
type ScpTimes = (i64, i64, i64, i64);

async fn new_scp_client(config: &ResolvedConfig) -> Result<SshClient> {
    let mut client = SshClient::new(config.clone());
    client.connect().await?;
    client.handshake().await?;
    client.authenticate().await?;
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
                    // The remote scp sends an error message (e.g. "scp: ...")
                    // instead of a single ack byte; surface it for diagnosis.
                    let msg = String::from_utf8_lossy(&data);
                    return Err(SshError::Protocol(format!(
                        "remote scp error: {}",
                        msg.trim()
                    )));
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

pub async fn scp_upload(config: &ResolvedConfig, local_path: &Path, remote_path: &str, recursive: bool) -> Result<()> {
    let mut client = new_scp_client(config).await?;
    // OpenSSH passes -r to the remote `scp -t` only when the local side
    // recurses; without it the remote rejects a directory header.
    let remote_cmd = if recursive {
        format!("scp -t -r -p {}", remote_path)
    } else {
        format!("scp -t -p {}", remote_path)
    };
    let local_id = client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    let metadata = std::fs::metadata(local_path).map_err(|e| SshError::Io(e))?;

    // Three-way handshake: the remote scp -t sends an initial ack byte (0) when ready.
    let init = recv_byte(&mut client, local_id).await?;
    if init != 0 {
        return Err(SshError::Protocol("SCP remote did not start cleanly".into()));
    }

    if metadata.is_dir() {
        // OpenSSH scp requires -r to recurse into a directory source; without
        // it a directory is an error rather than a silent recursive copy.
        if !recursive {
            return Err(SshError::Protocol(format!(
                "{} is a directory (use -r to copy recursively)",
                local_path.display()
            )));
        }
        let dir_name = local_path.file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "scp".to_string());
        return scp_upload_recursive(&mut client, local_id, local_path, &dir_name).await;
    }

    let mode = format!("{:04o}", metadata.permissions().mode() & 0o7777);
    let size = metadata.len();
    let fname = local_path.file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());

    // Send timestamp-preservation header (mtime + atime, requires -p remote).
    send_timestamp(&mut client, local_id, &metadata).await?;

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

/// Upload multiple local sources to a single remote target in one SCP session
/// (`scp f1 f2 host:/dst/`). Each source is sent as a separate C (file) or
/// D (directory, requires -r) record; the session ends with a close byte.
pub async fn scp_upload_multi(
    config: &ResolvedConfig,
    sources: &[std::path::PathBuf],
    remote_path: &str,
    recursive: bool,
) -> Result<()> {
    if sources.is_empty() {
        return Err(SshError::Protocol("no source files".into()));
    }
    let mut client = new_scp_client(config).await?;
    let remote_cmd = if recursive {
        format!("scp -t -r -p {}", remote_path)
    } else {
        format!("scp -t -p {}", remote_path)
    };
    let local_id = client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    let init = recv_byte(&mut client, local_id).await?;
    if init != 0 {
        return Err(SshError::Protocol("SCP remote did not start cleanly".into()));
    }

    for src in sources {
        let meta = std::fs::metadata(src).map_err(|e| SshError::Io(e))?;
        if meta.is_dir() {
            if !recursive {
                return Err(SshError::Protocol(format!(
                    "{} is a directory (use -r to copy recursively)",
                    src.display()
                )));
            }
            let dir_name = src.file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| "scp".to_string());
            send_timestamp(&mut client, local_id, &meta).await?;
            scp_upload_recursive(&mut client, local_id, src, &dir_name).await?;
        } else {
            send_timestamp(&mut client, local_id, &meta).await?;
            let mode = format!("{:04o}", meta.permissions().mode() & 0o7777);
            let size = meta.len();
            let fname = src.file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".to_string());
            client.send_channel_data(local_id, format!("C{} {} {}\n", mode, size, fname).as_bytes()).await?;
            let ack = recv_byte(&mut client, local_id).await?;
            if ack != 0 {
                return Err(SshError::Protocol("SCP rejected control message".into()));
            }
            let mut file = tokio::fs::File::open(src).await.map_err(|e| SshError::Io(e))?;
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
        }
    }
    Ok(())
}
pub async fn scp_download(config: &ResolvedConfig, remote_path: &str, local_path: &Path, recursive: bool) -> Result<()> {
    let mut client = new_scp_client(config).await?;
    let remote_cmd = if recursive {
        format!("scp -f -r -p {}", remote_path)
    } else {
        format!("scp -f -p {}", remote_path)
    };
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
            let _ = recv_scp_file(&mut client, local_id, &dest, mode, size, mtime).await?;
        }
        'D' => {
            // OpenSSH scp requires -r to descend into a directory source.
            if !recursive {
                return Err(SshError::Protocol(format!(
                    "{} is a directory (use -r to copy recursively)",
                    remote_path
                )));
            }
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

/// Download multiple remote sources to a single local target in one SCP
/// session (`scp host:/f1 host:/f2 local_dir`). The remote `scp -f` sends one
/// control record per source; we loop until the channel closes.
pub async fn scp_download_multi(
    config: &ResolvedConfig,
    sources: &[String],
    local_path: &Path,
    recursive: bool,
) -> Result<()> {
    if sources.is_empty() {
        return Err(SshError::Protocol("no source files".into()));
    }
    let mut client = new_scp_client(config).await?;
    // The remote `scp -f` must receive bare paths, not `user@host:path` specs.
    let path_args: Vec<String> = sources
        .iter()
        .map(|s| {
            s.rsplit_once(':')
                .map(|(_, p)| p.to_string())
                .unwrap_or_else(|| s.clone())
        })
        .collect();
    let remote_cmd = if recursive {
        format!("scp -f -r -p {}", path_args.join(" "))
    } else {
        format!("scp -f -p {}", path_args.join(" "))
    };
    let local_id = client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;
    send_byte(&mut client, local_id, 0).await?;

    let dest_dir = if local_path.is_dir() {
        local_path.to_path_buf()
    } else {
        local_path.to_path_buf()
    };
    std::fs::create_dir_all(&dest_dir).map_err(|e| SshError::Io(e))?;

    // A buffered line reader: `recv_channel_data` may coalesce several control
    // lines (T + C) into one packet, and the old per-call reader discarded the
    // bytes after the first '\n'. Keep a carry buffer so no line is lost.
    struct LineReader {
        client: SshClient,
        local_id: ChannelId,
        carry: Vec<u8>,
    }
    impl LineReader {
        fn new(client: SshClient, local_id: ChannelId) -> Self {
            Self { client, local_id, carry: Vec::new() }
        }
        async fn next(&mut self) -> Result<Option<String>> {
            loop {
                if let Some(pos) = self.carry.iter().position(|&b| b == b'\n') {
                    let mut line: Vec<u8> = self.carry.drain(..=pos).collect();
                    line.pop();
                    return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
                }
                match self.client.recv_channel_data(self.local_id).await? {
                    Some(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        self.carry.extend_from_slice(&data);
                    }
                    None => {
                        if self.carry.is_empty() {
                            return Ok(None);
                        }
                        let line = std::mem::take(&mut self.carry);
                        return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
                    }
                }
            }
        }
    }

    // Loop receiving entries until the channel closes (normal end).
    let mut reader = LineReader::new(client, local_id);
    loop {
        let control = match reader.next().await? {
            Some(c) => c,
            None => break,
        };
        if control.starts_with('E') {
            send_byte(&mut reader.client, reader.local_id, 0).await?;
            continue;
        }
        let mut mtime = None;
        let control = if control.starts_with('T') {
            mtime = parse_timestamp(&control);
            send_byte(&mut reader.client, reader.local_id, 0).await?;
            match reader.next().await? {
                Some(c) => c,
                None => break,
            }
        } else {
            control
        };
        let (kind, mode, size, fname) = parse_control(&control)?;
        match kind {
            'C' => {
                send_byte(&mut reader.client, reader.local_id, 0).await?;
                let dest = dest_dir.join(&fname);
                let leftover = recv_scp_file(
                    &mut reader.client,
                    reader.local_id,
                    &dest,
                    mode,
                    size,
                    mtime,
                )
                .await?;
                if !leftover.is_empty() {
                    // Bytes after the '\0' marker belong to the next control
                    // line; keep them so the reader does not lose them.
                    reader.carry.extend_from_slice(&leftover);
                }
            }
            'D' => {
                if !recursive {
                    return Err(SshError::Protocol(format!(
                        "{} is a directory (use -r to copy recursively)",
                        fname
                    )));
                }
                send_byte(&mut reader.client, reader.local_id, 0).await?;
                let dir = dest_dir.join(&fname);
                std::fs::create_dir_all(&dir).map_err(|e| SshError::Io(e))?;
                apply_file_meta(&dir, mode, mtime)?;
                scp_recv_entries(&mut reader.client, reader.local_id, &dir).await?;
            }
            _ => return Err(SshError::Protocol("unexpected SCP control message".into())),
        }
    }
    Ok(())
}
/// Read one control header, transparently skipping an optional T timestamp header.
async fn read_first_control(client: &mut SshClient, local_id: ChannelId) -> Result<(String, Option<ScpTimes>)> {
    let mut control = recv_control_line(client, local_id).await?;
    let mut mtime = None;
    if control.starts_with('T') {
        mtime = parse_timestamp(&control);
        send_byte(client, local_id, 0).await?;
        control = recv_control_line(client, local_id).await?;
    }
    Ok((control, mtime))
}

/// Parse a `T<mtime_sec> <mtime_usec> <atime_sec> <atime_usec>` timestamp
/// header into (mtime_sec, mtime_usec, atime_sec, atime_usec). OpenSSH emits
/// all four fields so `scp -p` can restore both mtime and atime.
fn parse_timestamp(line: &str) -> Option<ScpTimes> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 && parts[0].starts_with('T') {
        let msec: i64 = parts[0][1..].parse().ok()?;
        let musec: i64 = parts[1].parse().ok()?;
        let asec: i64 = parts[2].parse().ok()?;
        let ausec: i64 = parts[3].parse().ok()?;
        Some((msec, musec, asec, ausec))
    } else {
        None
    }
}

/// Apply a file mode, mtime and atime to `dest` after transfer.
fn apply_file_meta(dest: &Path, mode: Option<u32>, times: Option<ScpTimes>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(m) = mode {
            let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(m & 0o7777));
        }
        if let Some((msec, musec, asec, ausec)) = times {
            let mt = libc::timespec { tv_sec: msec, tv_nsec: musec * 1000 };
            let at = libc::timespec { tv_sec: asec, tv_nsec: ausec * 1000 };
            // utimensat expects [atime, mtime] in that order.
            let ts = [at, mt];
            if let Ok(cpath) = std::ffi::CString::new(dest.as_os_str().as_encoded_bytes()) {
                unsafe {
                    libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), ts.as_ptr(), 0);
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dest, mode, times);
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
    times: Option<ScpTimes>,
) -> Result<Vec<u8>> {
    let mut file = tokio::fs::File::create(dest).await.map_err(|e| SshError::Io(e))?;
    let mut remaining = size;
    let mut leftover: Vec<u8> = Vec::new();
    while remaining > 0 {
        match client.recv_channel_data(local_id).await? {
            Some(data) => {
                if data.is_empty() {
                    continue;
                }
                let take = data.len().min(remaining as usize);
                file.write_all(&data[..take]).await?;
                remaining -= take as u64;
                if take < data.len() {
                    // File data ended mid-chunk; the rest holds the '\0'
                    // file-end marker and possibly the next control line.
                    leftover.extend_from_slice(&data[take..]);
                    break;
                }
            }
            None => return Err(SshError::Protocol("connection closed during transfer".into())),
        }
    }
    if leftover.first() == Some(&0) {
        // Drop the '\0' marker; anything after it is the next header.
        leftover.remove(0);
    } else if remaining == 0 {
        // Data ended exactly at a chunk boundary: the '\0' marker is the next
        // chunk. Consume it and keep any bytes that follow.
        loop {
            match client.recv_channel_data(local_id).await? {
                Some(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    if data.len() > 1 {
                        leftover.extend_from_slice(&data[1..]);
                    }
                    break;
                }
                None => return Err(SshError::Protocol("connection closed during transfer".into())),
            }
        }
    }
    send_byte(client, local_id, 0).await?;
    apply_file_meta(dest, mode, times)?;
    Ok(leftover)
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
                let _ = recv_scp_file(client, local_id, &dest, mode, size, mtime).await?;
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
    // OpenSSH T header: T<mtime_sec> <mtime_usec> <atime_sec> <atime_usec>.
    let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    let atime = meta.accessed().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    if let (Some(m), Some(a)) = (mtime, atime) {
        let tmsg = format!(
            "T{} {} {} {}\n",
            m.as_secs(), m.subsec_micros(), a.as_secs(), a.subsec_micros()
        );
        client.send_channel_data(local_id, tmsg.as_bytes()).await?;
        let ack = recv_byte(client, local_id).await?;
        if ack != 0 {
            return Err(SshError::Protocol("SCP rejected timestamp".into()));
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