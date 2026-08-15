use crate::client::SshClient;
use crate::config::ResolvedConfig;
use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::msg;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn scp_upload(config: &ResolvedConfig, local_path: &Path, remote_path: &str) -> Result<()> {
    let mut client = SshClient::new(config.clone());
    client.connect().await?;
    client.handshake().await?;
    client.authenticate().await?;

    let remote_cmd = format!(
        "scp -t {}",
        remote_path
    );
    client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    let stream = client.stream.as_mut().ok_or_else(|| SshError::Protocol("no stream".into()))?;

    let metadata = std::fs::metadata(local_path)
        .map_err(|e| SshError::Io(e))?;

    let mode = format!("{:o}", metadata.permissions().mode());
    let size = metadata.len();

    let control_msg = format!("C{} {} {}\n", mode, size, local_path.file_name().unwrap().to_string_lossy());
    stream.write_all(control_msg.as_bytes()).await?;

    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await?;
    if ack[0] != 0 {
        return Err(SshError::Protocol("SCP protocol error".into()));
    }

    let mut file = tokio::fs::File::open(local_path).await
        .map_err(|e| SshError::Io(e))?;
    let mut buf = vec![0u8; 16384];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 { break; }
        stream.write_all(&buf[..n]).await?;
    }

    stream.write_all(&[0]).await?;

    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await?;

    Ok(())
}

pub async fn scp_download(config: &ResolvedConfig, remote_path: &str, local_path: &Path) -> Result<()> {
    let mut client = SshClient::new(config.clone());
    client.connect().await?;
    client.handshake().await?;
    client.authenticate().await?;

    let remote_cmd = format!(
        "scp -f {}",
        remote_path
    );
    client.request_session(Some(&remote_cmd), false, "dumb", 80, 24).await?;

    let stream = client.stream.as_mut().ok_or_else(|| SshError::Protocol("no stream".into()))?;

    stream.write_all(&[0u8]).await?;

    let mut control = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        control.push(byte[0]);
    }

    let control_str = String::from_utf8_lossy(&control);
    let parts: Vec<&str> = control_str.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(SshError::Protocol("invalid SCP control message".into()));
    }

    let _mode = parts[0];
    let size: u64 = parts[1].parse()
        .map_err(|_| SshError::Protocol("invalid file size".into()))?;

    stream.write_all(&[0u8]).await?;

    let mut file = tokio::fs::File::create(local_path).await
        .map_err(|e| SshError::Io(e))?;

    let mut remaining = size;
    let mut buf = vec![0u8; 16384];
    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = stream.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(SshError::Protocol("connection closed during transfer".into()));
        }
        file.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }

    stream.write_all(&[0u8]).await?;

    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await?;

    Ok(())
}

pub async fn scp_upload_recursive(config: &ResolvedConfig, local_dir: &Path, remote_path: &str) -> Result<()> {
    let entries = std::fs::read_dir(local_dir)
        .map_err(|e| SshError::Io(e))?;

    for entry in entries {
        let entry = entry.map_err(|e| SshError::Io(e))?;
        let path = entry.path();
        let file_name = path.file_name().unwrap().to_string_lossy();

        if path.is_dir() {
            let remote_subdir = format!("{}/{}", remote_path, file_name);
            let mut client = SshClient::new(config.clone());
            client.connect().await?;
            client.handshake().await?;
            client.authenticate().await?;
            let mkdir_cmd = format!("mkdir -p {}", remote_subdir);
            client.request_session(Some(&mkdir_cmd), false, "dumb", 80, 24).await?;
            drop(client);

            Box::pin(scp_upload_recursive(config, &path, &remote_subdir)).await?;
        } else {
            scp_upload(config, &path, remote_path).await?;
        }
    }

    Ok(())
}
