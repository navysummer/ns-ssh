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
    let remote_cmd = format!("scp -t {}", remote_path);
    let local_id = client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    let metadata = std::fs::metadata(local_path).map_err(|e| SshError::Io(e))?;
    if metadata.is_dir() {
        return scp_upload_recursive(&mut client, local_id, local_path, remote_path).await;
    }

    let mode = format!("{:o}", metadata.permissions().mode());
    let size = metadata.len();
    let fname = local_path.file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
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
    let remote_cmd = format!("scp -f {}", remote_path);
    let local_id = client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    send_byte(&mut client, local_id, 0).await?;

    let control = recv_control_line(&mut client, local_id).await?;
    let parts: Vec<&str> = control.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(SshError::Protocol("invalid SCP control message".into()));
    }
    let _mode = parts[0];
    let size: u64 = parts[1].parse()
        .map_err(|_| SshError::Protocol("invalid file size".into()))?;

    send_byte(&mut client, local_id, 0).await?;

    let mut file = tokio::fs::File::create(local_path).await.map_err(|e| SshError::Io(e))?;
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

    send_byte(&mut client, local_id, 0).await?;
    let _ack = recv_byte(&mut client, local_id).await?;

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
            let mode = format!("{:o}", meta.permissions().mode());
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