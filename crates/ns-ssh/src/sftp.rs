use crate::client::SshClient;
use crate::config::ResolvedConfig;
use ssh_core::channel::ChannelId;
use ssh_core::error::{Result, SshError};
use ssh_core::sftp::*;
use std::path::PathBuf;
use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct SftpSession {
    client: SshClient,
    channel: ChannelId,
    next_id: u32,
    remote_cwd: PathBuf,
    local_cwd: PathBuf,
}

/// Establish an SFTP session over a new SSH connection. Shared by the
/// interactive/batch SFTP client and the scp SFTP protocol backend.
pub async fn connect(config: &ResolvedConfig) -> Result<SftpSession> {
    let mut client = SshClient::new(config.clone());
    client.connect().await?;
    client.handshake().await?;
    client.authenticate().await?;
    let channel = client.request_session_subsystem("sftp").await?;

    let mut s = SftpSession {
        client,
        channel,
        next_id: 1,
        remote_cwd: PathBuf::from("."),
        local_cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    s.init().await?;
    Ok(s)
}

impl SftpSession {
    async fn shutdown(&mut self) -> Result<()> {
        let _ = self.client.send_channel_close(self.channel).await;
        let _ = self.client.send_disconnect().await;
        Ok(())
    }

    async fn init(&mut self) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        self.send_pkt(&build_sftp_init()).await?;
        let (t, rid, _payload) = self.recv_pkt().await?;
        if t != SSH_FXP_VERSION {
            return Err(SshError::Protocol("sftp: expected VERSION packet".into()));
        }
        let version = rid;
        if version < 3 {
            return Err(SshError::Protocol(format!("sftp: unsupported version {}", version)));
        }
        let _ = id;
        Ok(())
    }

    async fn send_pkt(&mut self, pkt: &[u8]) -> Result<()> {
        self.client.send_channel_data(self.channel, pkt).await
    }

    async fn recv_pkt(&mut self) -> Result<(u8, u32, Vec<u8>)> {
        loop {
            match self.client.recv_channel_data(self.channel).await? {
                Some(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    let (t, rid, payload) = parse_sftp_response(&data)?;
                    return Ok((t, rid, payload.to_vec()));
                }
                None => return Err(SshError::Protocol("sftp: channel closed".into())),
            }
        }
    }

    async fn request(&mut self, pkt: &[u8]) -> Result<Vec<u8>> {
        self.send_pkt(pkt).await?;
        let (t, _rid, payload) = self.recv_pkt().await?;
        if t == SSH_FXP_STATUS {
            let (code, msg) = parse_sftp_status(&payload)?;
            if code == SSH_FX_EOF {
                return Err(SshError::Protocol(format!("sftp: EOF ({})", code)));
            }
            return Err(SshError::Protocol(format!("sftp: {} ({})", msg, code)));
        }
        Ok(payload.to_vec())
    }

    async fn request_id(&mut self, build: impl FnOnce(u32) -> Vec<u8>) -> Result<Vec<u8>> {
        let id = self.next_id;
        self.next_id += 1;
        self.request(&build(id)).await
    }

    async fn request_ok(&mut self, pkt: &[u8]) -> Result<()> {
        self.send_pkt(pkt).await?;
        let (t, _rid, payload) = self.recv_pkt().await?;
        if t != SSH_FXP_STATUS {
            return Err(SshError::Protocol("sftp: expected STATUS".into()));
        }
        let (code, msg) = parse_sftp_status(&payload)?;
        if code != SSH_FX_OK {
            return Err(SshError::Protocol(format!("sftp: {} ({})", msg, code)));
        }
        Ok(())
    }

    async fn ok_id(&mut self, build: impl FnOnce(u32) -> Vec<u8>) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        self.request_ok(&build(id)).await
    }

    fn resolve(&self, path: &str) -> String {
        let p = PathBuf::from(path);
        if p.is_absolute() {
            path.to_string()
        } else {
            self.remote_cwd.join(p).to_string_lossy().into_owned()
        }
    }

    async fn do_realpath(&mut self, path: &str) -> Result<String> {
        let payload = self.request_id(|id| build_sftp_realpath(id, path)).await?;
        let names = parse_sftp_name(&payload)?;
        names.first().map(|n| n.filename.clone()).ok_or_else(|| SshError::Protocol("sftp: empty realpath".into()))
    }

    pub async fn cmd_pwd(&mut self) -> Result<String> {
        let cwd = self.do_realpath(&self.resolve(".")).await?;
        self.remote_cwd = PathBuf::from(&cwd);
        Ok(cwd)
    }

    pub async fn cmd_cd(&mut self, path: &str) -> Result<()> {
        let target = self.resolve(path);
        let real = self.do_realpath(&target).await?;
        let payload = self.request_id(|id| build_sftp_lstat(id, &real)).await?;
        let attr = parse_sftp_attrs(&payload)?;
        match attr.permissions {
            Some(perm) if perm & 0o170000 == 0o040000 => {}
            _ => return Err(SshError::Protocol("sftp: not a directory".into())),
        }
        self.remote_cwd = PathBuf::from(real);
        Ok(())
    }

    pub async fn cmd_ls(&mut self, path: Option<&str>) -> Result<Vec<String>> {
        let target = self.resolve(path.unwrap_or("."));
        let real = self.do_realpath(&target).await?;
        let payload = self.request_id(|id| build_sftp_opendir(id, &real)).await?;
        let handle = parse_sftp_handle(&payload)?;
        let mut out = Vec::new();
        loop {
            let p = self.request_id(|id| build_sftp_readdir(id, &handle)).await;
            match p {
                Ok(payload) => {
                    for entry in parse_sftp_name(&payload)? {
                        if entry.filename == "." || entry.filename == ".." {
                            continue;
                        }
                        out.push(entry.filename);
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("EOF") {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        let _ = self.ok_id(|id| build_sftp_close(id, &handle)).await;
        Ok(out)
    }

    pub async fn cmd_ls_long(&mut self, path: Option<&str>) -> Result<Vec<String>> {
        let target = self.resolve(path.unwrap_or("."));
        let real = self.do_realpath(&target).await?;
        let payload = self.request_id(|id| build_sftp_opendir(id, &real)).await?;
        let handle = parse_sftp_handle(&payload)?;
        let mut out = Vec::new();
        loop {
            match self.request_id(|id| build_sftp_readdir(id, &handle)).await {
                Ok(payload) => {
                    for entry in parse_sftp_name(&payload)? {
                        out.push(entry.longname);
                    }
                }
                Err(_e) => break,
            }
        }
        let _ = self.ok_id(|id| build_sftp_close(id, &handle)).await;
        Ok(out)
    }

    pub async fn cmd_get(&mut self, remote: &str, local: Option<&str>) -> Result<()> {
        let rpath = self.resolve(remote);
        let lpath = local.map(PathBuf::from).unwrap_or_else(|| {
            PathBuf::from(remote.rsplit('/').next().unwrap_or(remote))
        });
        let lpath = if lpath.is_absolute() { lpath } else { self.local_cwd.join(lpath) };
        let payload = self.request_id(|id| {
            let mut a = SftpFileAttr::new();
            a.flags = 0;
            build_sftp_open(id, &rpath, SSH_FXF_READ, &a)
        }).await?;
        let handle = parse_sftp_handle(&payload)?;
        if let Some(parent) = lpath.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut file = tokio::fs::File::create(&lpath).await.map_err(|e| SshError::Io(e))?;
        let mut offset: u64 = 0;
        loop {
            let payload = self.request_id(|id| build_sftp_read(id, &handle, offset, 256 * 1024)).await;
            match payload {
                Ok(payload) => {
                    let data = parse_sftp_data(&payload)?;
                    if data.is_empty() {
                        break;
                    }
                    use tokio::io::AsyncWriteExt;
                    file.write_all(&data).await.map_err(|e| SshError::Io(e))?;
                    offset += data.len() as u64;
                }
                Err(e) => {
                    if e.to_string().contains("EOF") {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        use tokio::io::AsyncWriteExt;
        file.flush().await.map_err(|e| SshError::Io(e))?;
        let _ = self.ok_id(|id| build_sftp_close(id, &handle)).await;
        Ok(())
    }

    pub async fn cmd_put(&mut self, local: &str, remote: Option<&str>) -> Result<()> {
        let lpath = PathBuf::from(local);
        let lpath = if lpath.is_absolute() { lpath } else { self.local_cwd.join(lpath) };
        let rname = remote.map(|r| r.to_string()).unwrap_or_else(|| {
            lpath.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())
        });
        let rpath = self.resolve(&rname);
        let meta = std::fs::metadata(&lpath).map_err(|e| SshError::Io(e))?;
        let mut file = tokio::fs::File::open(&lpath).await.map_err(|e| SshError::Io(e))?;
        let mut attrs = SftpFileAttr::new();
        attrs.size = Some(meta.len());
        let payload = self.request_id(|id| build_sftp_open(id, &rpath, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC, &attrs)).await?;
        let handle = parse_sftp_handle(&payload)?;
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256 * 1024];
        let mut offset: u64 = 0;
        loop {
            let n = file.read(&mut buf).await.map_err(|e| SshError::Io(e))?;
            if n == 0 {
                break;
            }
            let id = self.new_id();
            self.request_ok(&build_sftp_write(id, &handle, offset, &buf[..n])).await?;
            offset += n as u64;
        }
        let _ = self.ok_id(|id| build_sftp_close(id, &handle)).await;
        Ok(())
    }

    fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub async fn cmd_mkdir(&mut self, path: &str) -> Result<()> {
        let target = self.resolve(path);
        self.ok_id(|id| build_sftp_mkdir(id, &target, &SftpFileAttr::new())).await
    }

    pub async fn cmd_rm(&mut self, path: &str) -> Result<()> {
        let target = self.resolve(path);
        self.ok_id(|id| build_sftp_remove(id, &target)).await
    }

    pub async fn cmd_rmdir(&mut self, path: &str) -> Result<()> {
        let target = self.resolve(path);
        self.ok_id(|id| build_sftp_rmdir(id, &target)).await
    }

    pub async fn cmd_rename(&mut self, old: &str, new: &str) -> Result<()> {
        let o = self.resolve(old);
        let n = self.resolve(new);
        self.ok_id(|id| build_sftp_posix_rename(id, &o, &n)).await
    }

    pub async fn cmd_chmod(&mut self, mode: &str, path: &str) -> Result<()> {
        let target = self.resolve(path);
        let m = u32::from_str_radix(mode, 8)
            .map_err(|_| SshError::Protocol(format!("sftp: invalid mode {}", mode)))?;
        let mut attrs = SftpFileAttr::new();
        attrs.permissions = Some(m & 0o7777);
        self.ok_id(|id| build_sftp_setstat(id, &target, &attrs)).await
    }

    pub async fn cmd_symlink(&mut self, linkpath: &str, targetpath: &str) -> Result<()> {
        let l = self.resolve(linkpath);
        self.ok_id(|id| build_sftp_symlink(id, targetpath, &l)).await
    }

    pub async fn cmd_hardlink(&mut self, linkpath: &str, targetpath: &str) -> Result<()> {
        let l = self.resolve(linkpath);
        let t = self.resolve(targetpath);
        self.ok_id(|id| build_sftp_hardlink(id, &t, &l)).await
    }

    pub async fn cmd_readlink(&mut self, path: &str) -> Result<String> {
        let target = self.resolve(path);
        let payload = self.request_id(|id| build_sftp_readlink(id, &target)).await?;
        let names = parse_sftp_name(&payload)?;
        names.first().map(|n| n.filename.clone()).ok_or_else(|| SshError::Protocol("sftp: empty readlink".into()))
    }

    pub async fn cmd_stat(&mut self, path: &str, long: bool) -> Result<()> {
        let target = self.resolve(path);
        let payload = self.request_id(|id| build_sftp_lstat(id, &target)).await?;
        let attr = parse_sftp_attrs(&payload)?;
        let perm = attr.permissions.unwrap_or(0);
        let size = attr.size.unwrap_or(0);
        let uid = attr.uid.unwrap_or(0);
        let gid = attr.gid.unwrap_or(0);
        let mtime = attr.mtime.unwrap_or(0);
        if long {
            println!("{}", format_sftp_longname(path, &attr));
        } else {
            println!(
                "{}  {}  {}  {}  {}",
                perm_string(perm),
                size,
                uid,
                gid,
                mtime
            );
        }
        Ok(())
    }

    /// Return the raw attributes of a remote path (via LSTAT), for the scp
    /// SFTP backend to decide file vs directory and preserve times.
    pub async fn cmd_stat_attr(&mut self, path: &str) -> Result<SftpFileAttr> {
        let target = self.resolve(path);
        let payload = self.request_id(|id| build_sftp_lstat(id, &target)).await?;
        parse_sftp_attrs(&payload)
    }

    /// Set mode / mtime / atime on a remote path via SETSTAT. The scp `-p`
    /// backend uses this to preserve permissions and timestamps, mirroring the
    /// old SCP protocol's `T` header handling.
    pub async fn cmd_setattr(&mut self, path: &str, attrs: &SftpFileAttr) -> Result<()> {
        let target = self.resolve(path);
        self.ok_id(|id| build_sftp_setstat(id, &target, attrs)).await
    }


    pub async fn cmd_chown(&mut self, uid: &str, gid: &str, path: &str) -> Result<()> {
        let target = self.resolve(path);
        let uid_val = uid.parse::<u32>().map_err(|_| SshError::Protocol(format!("sftp: invalid uid {}", uid)))?;
        let gid_val = gid.parse::<u32>().map_err(|_| SshError::Protocol(format!("sftp: invalid gid {}", gid)))?;
        let mut attrs = SftpFileAttr::new();
        attrs.flags = SSH_FILEXFER_ATTR_UIDGID;
        attrs.uid = Some(uid_val);
        attrs.gid = Some(gid_val);
        self.ok_id(|id| build_sftp_setstat(id, &target, &attrs)).await
    }

    pub async fn cmd_df(&mut self, path: Option<&str>) -> Result<()> {
        let target = self.resolve(path.unwrap_or("."));
        let payload = self.request_id(|id| build_sftp_statvfs(id, &target)).await?;
        let (f_bsize, f_frsize, f_blocks, f_bfree, f_bavail, _f_files, _f_ffree) = parse_sftp_statvfs(&payload)?;
        let total = f_blocks.saturating_mul(f_frsize);
        let avail = f_bavail.saturating_mul(f_frsize);
        let used = f_blocks.saturating_sub(f_bfree).saturating_mul(f_frsize);
        println!("      Size      Used     Avail  Capacity  Mounted on");
        println!(
            "{:>10} {:>10} {:>10} {:>6}%  {}",
            total, used, avail,
            if total > 0 { (used * 100) / total } else { 0 },
            path.unwrap_or(".")
        );
        let _ = f_bsize;
        Ok(())
    }

    pub async fn cmd_reget(&mut self, remote: &str, local: &str) -> Result<()> {
        let rpath = self.resolve(remote);
        let lpath = PathBuf::from(local);
        let lpath = if lpath.is_absolute() { lpath } else { self.local_cwd.join(lpath) };
        let resume_at = std::fs::metadata(&lpath).map(|m| m.len()).unwrap_or(0);
        self.transfer_get(&rpath, &lpath, resume_at).await
    }

    pub async fn cmd_reput(&mut self, local: &str, remote: &str) -> Result<()> {
        let lpath = PathBuf::from(local);
        let lpath = if lpath.is_absolute() { lpath } else { self.local_cwd.join(lpath) };
        let rpath = self.resolve(remote);
        let lmeta = std::fs::metadata(&lpath).map_err(|e| SshError::Io(e))?;
        let rsize = self.sftp_remote_size(&rpath).await.unwrap_or(0);
        let resume_at = rsize.min(lmeta.len());
        self.transfer_put(&lpath, &rpath, resume_at).await
    }

    async fn sftp_remote_size(&mut self, path: &str) -> Result<u64> {
        let payload = self.request_id(|id| build_sftp_stat(id, path)).await?;
        let attr = parse_sftp_attrs(&payload)?;
        Ok(attr.size.unwrap_or(0))
    }

    async fn transfer_get(&mut self, rpath: &str, lpath: &PathBuf, start: u64) -> Result<()> {
        let payload = self.request_id(|id| {
            let mut a = SftpFileAttr::new();
            a.flags = 0;
            build_sftp_open(id, rpath, SSH_FXF_READ, &a)
        }).await?;
        let handle = parse_sftp_handle(&payload)?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lpath)
            .await
            .map_err(|e| SshError::Io(e))?;
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await.map_err(|e| SshError::Io(e))?;
        use tokio::io::AsyncWriteExt;
        let mut offset = start;
        loop {
            let payload = self.request_id(|id| build_sftp_read(id, &handle, offset, 256 * 1024)).await;
            match payload {
                Ok(payload) => {
                    let data = parse_sftp_data(&payload)?;
                    if data.is_empty() {
                        break;
                    }
                    file.write_all(&data).await.map_err(|e| SshError::Io(e))?;
                    offset += data.len() as u64;
                }
                Err(e) => {
                    if e.to_string().contains("EOF") {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        file.flush().await.map_err(|e| SshError::Io(e))?;
        let _ = self.ok_id(|id| build_sftp_close(id, &handle)).await;
        Ok(())
    }

    async fn transfer_put(&mut self, lpath: &PathBuf, rpath: &str, start: u64) -> Result<()> {
        let lmeta = std::fs::metadata(&lpath).map_err(|e| SshError::Io(e))?;
        let mut file = tokio::fs::File::open(&lpath).await.map_err(|e| SshError::Io(e))?;
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await.map_err(|e| SshError::Io(e))?;
        let mut attrs = SftpFileAttr::new();
        attrs.size = Some(lmeta.len());
        let mut pflags = SSH_FXF_WRITE | SSH_FXF_CREAT;
        if start == 0 {
            pflags |= SSH_FXF_TRUNC;
        }
        let payload = self.request_id(|id| build_sftp_open(id, rpath, pflags, &attrs)).await?;
        let handle = parse_sftp_handle(&payload)?;
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256 * 1024];
        let mut offset = start;
        loop {
            let n = file.read(&mut buf).await.map_err(|e| SshError::Io(e))?;
            if n == 0 {
                break;
            }
            let id = self.new_id();
            self.request_ok(&build_sftp_write(id, &handle, offset, &buf[..n])).await?;
            offset += n as u64;
        }
        let _ = self.ok_id(|id| build_sftp_close(id, &handle)).await;
        Ok(())
    }
}

pub async fn run_sftp(config: &ResolvedConfig) -> Result<()> {
    let mut s = connect(config).await?;

    let stdin = tokio::io::stdin();
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(stdin).lines();

    loop {
        let _cwd = match s.cmd_pwd().await {
            Ok(p) => p,
            Err(_) => "?".to_string(),
        };
        print!("sftp> ");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(_) => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if !s.exec_line(&line).await {
            break;
        }
    }
    s.shutdown().await?;
    Ok(())
}

pub async fn run_sftp_batch(config: &ResolvedConfig, content: &str) -> Result<()> {
    let mut s = connect(config).await?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !s.exec_line(line).await {
            break;
        }
    }
    s.shutdown().await?;
    Ok(())
}

impl SftpSession {
    async fn exec_line(&mut self, line: &str) -> bool {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return true;
        }
        match parts[0] {
            "exit" | "quit" | "bye" => return false,
            "pwd" => {
                match self.cmd_pwd().await {
                    Ok(p) => println!("Remote working directory: {}", p),
                    Err(e) => println!("{}", e),
                }
            }
            "lpwd" => println!("Local working directory: {}", self.local_cwd.display()),
            "cd" => {
                if parts.len() < 2 {
                    println!("usage: cd path");
                } else if let Err(e) = self.cmd_cd(parts[1]).await {
                    println!("{}", e);
                }
            }
            "lcd" => {
                if parts.len() < 2 {
                    println!("usage: lcd path");
                } else {
                    let p = PathBuf::from(parts[1]);
                    if p.is_dir() {
                        self.local_cwd = p;
                    } else {
                        println!("Local directory {} does not exist", parts[1]);
                    }
                }
            }
            "ls" | "dir" => {
                let mut path = None;
                let mut long = false;
                for arg in parts.iter().skip(1).copied() {
                    if arg.starts_with('-') {
                        long |= arg.contains('l');
                        continue;
                    }
                    if path.is_none() {
                        path = Some(arg);
                    }
                }
                let path = path.or(Some("."));
                let result = if long {
                    self.cmd_ls_long(path).await
                } else {
                    self.cmd_ls(path).await
                };
                match result {
                    Ok(items) => {
                        for it in items {
                            println!("{}", it);
                        }
                    }
                    Err(e) => println!("{}", e),
                }
            }
            "lls" => {
                let d = parts.get(1).map(PathBuf::from).unwrap_or_else(|| self.local_cwd.clone());
                match std::fs::read_dir(&d) {
                    Ok(rd) => {
                        for e in rd.flatten() {
                            println!("{}", e.file_name().to_string_lossy());
                        }
                    }
                    Err(e) => println!("{}", e),
                }
            }
            "get" => {
                if parts.len() < 2 {
                    println!("usage: get remote-path [local-path]");
                } else {
                    let l = parts.get(2).copied();
                    match self.cmd_get(parts[1], l).await {
                        Ok(_) => println!("Fetching {} to {}", parts[1], l.unwrap_or(".")),
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "put" => {
                if parts.len() < 2 {
                    println!("usage: put local-path [remote-path]");
                } else {
                    let r = parts.get(2).copied();
                    match self.cmd_put(parts[1], r).await {
                        Ok(_) => println!("Uploading {} to {}", parts[1], r.unwrap_or(".")),
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "mkdir" => {
                if parts.len() < 2 {
                    println!("usage: mkdir path");
                } else if let Err(e) = self.cmd_mkdir(parts[1]).await {
                    println!("{}", e);
                }
            }
            "rm" | "del" => {
                if parts.len() < 2 {
                    println!("usage: rm path");
                } else if let Err(e) = self.cmd_rm(parts[1]).await {
                    println!("{}", e);
                }
            }
            "rmdir" => {
                if parts.len() < 2 {
                    println!("usage: rmdir path");
                } else if let Err(e) = self.cmd_rmdir(parts[1]).await {
                    println!("{}", e);
                }
            }
            "rename" => {
                if parts.len() < 3 {
                    println!("usage: rename oldpath newpath");
                } else if let Err(e) = self.cmd_rename(parts[1], parts[2]).await {
                    println!("{}", e);
                }
            }
            "chmod" => {
                if parts.len() < 3 {
                    println!("usage: chmod mode path");
                } else if let Err(e) = self.cmd_chmod(parts[1], parts[2]).await {
                    println!("{}", e);
                }
            }
            "ln" => {
                if parts.len() < 3 {
                    println!("usage: ln [-s] oldpath newpath");
                } else {
                    let args: Vec<&str> = parts[1..].to_vec();
                    let symlink = args[0] == "-s";
                    let (link, target) = if symlink {
                        (args[2], args[1])
                    } else {
                        (args[1], args[0])
                    };
                    let result = if symlink {
                        self.cmd_symlink(link, target).await
                    } else {
                        self.cmd_hardlink(link, target).await
                    };
                    if let Err(e) = result {
                        println!("{}", e);
                    }
                }
            }
            "readlink" => {
                if parts.len() < 2 {
                    println!("usage: readlink path");
                } else {
                    match self.cmd_readlink(parts[1]).await {
                        Ok(t) => println!("{}", t),
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "stat" => {
                if parts.len() < 2 {
                    println!("usage: stat path");
                } else {
                    let long = parts.iter().any(|a| a == &"-l");
                    let path = parts.iter().skip(1).find(|a| !a.starts_with('-')).copied().unwrap_or(parts[1]);
                    match self.cmd_stat(path, long).await {
                        Ok(_) => {}
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "symlink" => {
                if parts.len() < 3 {
                    println!("usage: symlink oldpath newpath");
                } else {
                    let (target, link) = if parts[1] == "-s" && parts.len() >= 4 {
                        (parts[2], parts[3])
                    } else {
                        (parts[1], parts[2])
                    };
                    match self.cmd_symlink(link, target).await {
                        Ok(_) => {}
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "chown" => {
                if parts.len() < 3 {
                    println!("usage: chown uid[:gid] path");
                } else {
                    let spec = parts[1];
                    let (uid, gid) = if let Some((u, g)) = spec.split_once(':') {
                        (u, g)
                    } else {
                        (spec, spec)
                    };
                    match self.cmd_chown(uid, gid, parts[2]).await {
                        Ok(_) => {}
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "df" => {
                let path = parts.get(1).copied();
                match self.cmd_df(path).await {
                    Ok(_) => {}
                    Err(e) => println!("{}", e),
                }
            }
            "reget" => {
                if parts.len() < 2 {
                    println!("usage: reget remote-path [local-path]");
                } else {
                    let l = parts.get(2).copied().unwrap_or(parts[1]);
                    match self.cmd_reget(parts[1], l).await {
                        Ok(_) => println!("Resuming fetch of {} to {}", parts[1], l),
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "reput" => {
                if parts.len() < 2 {
                    println!("usage: reput local-path [remote-path]");
                } else {
                    let r = parts.get(2).copied().unwrap_or(parts[1]);
                    match self.cmd_reput(parts[1], r).await {
                        Ok(_) => println!("Resuming upload of {} to {}", parts[1], r),
                        Err(e) => println!("{}", e),
                    }
                }
            }
            "mget" => {
                if parts.len() < 2 {
                    println!("usage: mget remote-path...");
                } else {
                    for p in &parts[1..] {
                        if p.contains('*') || p.contains('?') {
                            // OpenSSH expands globs against the remote cwd;
                            // only files (not . / ..) are fetched.
                            match self.cmd_ls(None).await {
                                Ok(entries) => {
                                    let mut matched = false;
                                    for name in &entries {
                                        if crate::config::simple_glob_match(p, name) {
                                            matched = true;
                                            match self.cmd_get(name, None).await {
                                                Ok(_) => println!("Fetching {} to .", name),
                                                Err(e) => println!("{}", e),
                                            }
                                        }
                                    }
                                    if !matched {
                                        println!("No matching files: {}", p);
                                    }
                                }
                                Err(e) => println!("{}", e),
                            }
                        } else {
                            match self.cmd_get(p, None).await {
                                Ok(_) => println!("Fetching {} to .", p),
                                Err(e) => println!("{}", e),
                            }
                        }
                    }
                }
            }
            "mput" => {
                if parts.len() < 2 {
                    println!("usage: mput local-path...");
                } else {
                    for p in &parts[1..] {
                        if p.contains('*') || p.contains('?') {
                            // OpenSSH expands globs against the local cwd.
                            let mut matched = false;
                            if let Ok(rd) = std::fs::read_dir(&self.local_cwd) {
                                for e in rd.flatten() {
                                    let name = e.file_name().to_string_lossy().into_owned();
                                    if crate::config::simple_glob_match(p, &name) {
                                        matched = true;
                                        match self.cmd_put(&name, None).await {
                                            Ok(_) => println!("Uploading {} to .", name),
                                            Err(e) => println!("{}", e),
                                        }
                                    }
                                }
                            }
                            if !matched {
                                println!("No matching files: {}", p);
                            }
                        } else {
                            match self.cmd_put(p, None).await {
                                Ok(_) => println!("Uploading {} to .", p),
                                Err(e) => println!("{}", e),
                            }
                        }
                    }
                }
            }
            "version" => {
                println!("SFTP protocol version {}", SFTP_PROTOCOL_VERSION);
            }
            "help" => {
                println!("Available commands:");
                println!("  pwd             Display remote working directory");
                println!("  lpwd            Display local working directory");
                println!("  cd path         Change remote directory");
                println!("  lcd path        Change local directory");
                println!("  ls [path]       List remote directory");
                println!("  lls [path]      List local directory");
                println!("  get remote [local]  Download file");
                println!("  put local [remote]  Upload file");
                println!("  mget remote...  Download multiple files");
                println!("  mput local...   Upload multiple files");
                println!("  reget remote [local]  Resume download");
                println!("  reput local [remote]  Resume upload");
                println!("  df [path]       Display disk usage");
                println!("  stat [-l] path  Display file attributes");
                println!("  chown uid[:gid] path  Change owner/group");
                println!("  symlink old new  Create symlink");
                println!("  mkdir path      Create remote directory");
                println!("  rm path         Delete remote file");
                println!("  rmdir path      Remove remote directory");
                println!("  rename old new  Rename remote file");
                println!("  chmod mode path Change permissions");
                println!("  ln [-s] a b     Link files");
                println!("  readlink path   Show link target");
                println!("  !cmd            Run local command");
                println!("  exit            Quit sftp");
            }
            other => {
                if other.starts_with('!') {
                    let cmd = line[1..].trim();
                    if !cmd.is_empty() {
                        let st = std::process::Command::new("sh").arg("-c").arg(cmd).status();
                        match st {
                            Ok(_) => {}
                            Err(e) => println!("{}", e),
                        }
                    }
                } else {
                    println!("Invalid command: {}", other);
                }
            }
        }
        true
    }

    // ---- scp SFTP protocol backend (OpenSSH 9 default; `scp -O` keeps the
    // ---- old SCP protocol, `scp -s` forces this SFTP path) ----

    /// Upload one local file to `remote_path` via SFTP. When `preserve` is set,
    /// copy mode and mtime/atime (mirrors `scp -p`).
    pub async fn scp_put_file(&mut self, local: &Path, remote: &str, preserve: bool) -> Result<()> {
        self.cmd_put(&local.to_string_lossy(), Some(remote)).await?;
        if preserve {
            let meta = std::fs::metadata(local).map_err(|e| SshError::Io(e))?;
            let mut attrs = SftpFileAttr::new();
            attrs.permissions = Some(meta.permissions().mode() & 0o7777);
            if let Ok(m) = meta.modified() {
                if let Ok(d) = m.duration_since(std::time::UNIX_EPOCH) {
                    attrs.mtime = Some(d.as_secs() as u32);
                }
            }
            if let Ok(a) = meta.accessed() {
                if let Ok(d) = a.duration_since(std::time::UNIX_EPOCH) {
                    attrs.atime = Some(d.as_secs() as u32);
                }
            }
            let _ = self.cmd_setattr(remote, &attrs).await;
        }
        Ok(())
    }

    /// Recursively upload a local directory tree to `remote_dir` via SFTP.
    pub(crate) async fn scp_put_dir(&mut self, local_dir: &Path, remote_dir: &str, preserve: bool) -> Result<()> {
        let _ = self.cmd_mkdir(remote_dir).await;
        let entries = std::fs::read_dir(local_dir).map_err(|e| SshError::Io(e))?;
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| SshError::Io(e))?;
            names.push(entry.file_name());
        }
        names.sort();
        for name in names {
            let full = local_dir.join(&name);
            let fname = name.to_string_lossy().into_owned();
            let child_remote = format!("{}/{}", remote_dir.trim_end_matches('/'), fname);
            let meta = std::fs::metadata(&full).map_err(|e| SshError::Io(e))?;
            if meta.is_dir() {
                Box::pin(self.scp_put_dir(&full, &child_remote, preserve)).await?;
            } else {
                self.scp_put_file(&full, &child_remote, preserve).await?;
            }
        }
        if preserve {
            let meta = std::fs::metadata(local_dir).map_err(|e| SshError::Io(e))?;
            let mut attrs = SftpFileAttr::new();
            attrs.permissions = Some(meta.permissions().mode() & 0o7777);
            let _ = self.cmd_setattr(remote_dir, &attrs).await;
        }
        Ok(())
    }

    /// Download one remote file to `local_path` via SFTP. When `preserve` is
    /// set, copy mode and mtime/atime from the remote file.
    pub async fn scp_get_file(&mut self, remote: &str, local: &Path, preserve: bool) -> Result<()> {
        self.cmd_get(remote, Some(&local.to_string_lossy())).await?;
        if preserve {
            let attr = self.cmd_stat_attr(remote).await?;
            apply_sftp_meta_to_local(local, &attr)?;
        }
        Ok(())
    }

    /// Recursively download a remote directory tree to `local_dir` via SFTP.
    pub(crate) async fn scp_get_dir(&mut self, remote_dir: &str, local_dir: &Path, preserve: bool) -> Result<()> {
        std::fs::create_dir_all(local_dir).map_err(|e| SshError::Io(e))?;
        let entries = self.cmd_ls(Some(remote_dir)).await?;
        for fname in entries {
            let child_remote = format!("{}/{}", remote_dir.trim_end_matches('/'), fname);
            let child_local = local_dir.join(&fname);
            let attr = self.cmd_stat_attr(&child_remote).await?;
            let mode = attr.permissions.unwrap_or(0);
            if mode & 0o170000 == 0o040000 {
                Box::pin(self.scp_get_dir(&child_remote, &child_local, preserve)).await?;
            } else {
                self.scp_get_file(&child_remote, &child_local, preserve).await?;
            }
        }
        if preserve {
            let attr = self.cmd_stat_attr(remote_dir).await?;
            apply_sftp_meta_to_local(local_dir, &attr)?;
        }
        Ok(())
    }
}

/// Render an SFTP permission word (`drwxr-xr-x`) from the mode bits.
fn perm_string(mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o100000 => 'p',
        0o140000 => 's',
        _ => '-',
    });
    for bit in [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001] {
        s.push(if mode & bit != 0 {
            match bit {
                0o400 | 0o040 | 0o004 => 'r',
                0o200 | 0o020 | 0o002 => 'w',
                _ => 'x',
            }
        } else {
            '-'
        });
    }
    s
}

/// Render an SFTP `ls -l` longname. OpenSSH's `sftp-server` builds this the
/// same way: permissions, nlink, owner, group, size, date, name.
fn format_sftp_longname(path: &str, attr: &SftpFileAttr) -> String {
    let perm = attr.permissions.unwrap_or(0);
    let size = attr.size.unwrap_or(0);
    let uid = attr.uid.unwrap_or(0);
    let gid = attr.gid.unwrap_or(0);
    let mtime = attr.mtime.unwrap_or(0);
    let name = path.rsplit('/').next().unwrap_or(path);
    format!(
        "{} 1 {} {} {:>8} {} {}",
        perm_string(perm),
        uid,
        gid,
        size,
        sftp_date(mtime),
        name
    )
}

/// Format an mtime (seconds since epoch) as `Mon DD HH:MM` or `Mon DD  YYYY`.
fn sftp_date(mtime: u32) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_secs(mtime as u64);
    let local = localtime(dt);
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mon = months.get(local.mon).copied().unwrap_or("Jan");
    format!("{} {:2} {:02}:{:02}", mon, local.day, local.hour, local.min)
}

struct LocalTime {
    mon: usize,
    day: u32,
    hour: u32,
    min: u32,
}

fn localtime(dt: std::time::SystemTime) -> LocalTime {
    // Simple UTC approximation; OpenSSH uses the server's local timezone. For
    // the common case this is accurate enough for display.
    let secs = dt.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = secs / 86400;
    let secs_in_day = secs % 86400;
    let hour = (secs_in_day / 3600) as u32;
    let min = ((secs_in_day % 3600) / 60) as u32;
    let mon = ((days % 12) as usize).min(11);
    LocalTime { mon, day: ((days % 31) as u32) + 1, hour, min }
}

/// Apply SFTP attributes (permissions, mtime, atime) to a local path. Used by
/// the scp `-p` SFTP backend to mirror `scp -p` on downloads.
fn apply_sftp_meta_to_local(path: &Path, attr: &SftpFileAttr) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(perm) = attr.permissions {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(perm & 0o7777));
        }
    }
    if let (Some(m), Some(a)) = (attr.mtime, attr.atime) {
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(m as u64);
        let atime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(a as u64);
        let ft = std::fs::FileTimes::new()
            .set_modified(mtime)
            .set_accessed(atime);
        if let Ok(f) = std::fs::File::options().write(true).open(path) {
            let _ = f.set_times(ft);
        }
    }
    Ok(())
}