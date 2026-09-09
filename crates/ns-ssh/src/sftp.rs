use crate::client::SshClient;
use crate::config::ResolvedConfig;
use ssh_core::channel::ChannelId;
use ssh_core::error::{Result, SshError};
use ssh_core::sftp::*;
use ssh_core::{SshBytes, SshDecode, SshEncode, SshString};
use std::path::{Path, PathBuf};

pub struct SftpSession {
    client: SshClient,
    channel: ChannelId,
    next_id: u32,
    remote_cwd: PathBuf,
    local_cwd: PathBuf,
}

async fn new_sftp_client(config: &ResolvedConfig) -> Result<SftpSession> {
    let mut client = SshClient::new(config.clone());
    client.connect().await?;
    client.handshake().await?;
    client.authenticate().await?;
    client.request_connection_service().await?;
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
        self.ok_id(|id| build_sftp_symlink(id, &l, targetpath)).await
    }

    pub async fn cmd_readlink(&mut self, path: &str) -> Result<String> {
        let target = self.resolve(path);
        let payload = self.request_id(|id| build_sftp_readlink(id, &target)).await?;
        let names = parse_sftp_name(&payload)?;
        names.first().map(|n| n.filename.clone()).ok_or_else(|| SshError::Protocol("sftp: empty readlink".into()))
    }
}

pub async fn run_sftp(config: &ResolvedConfig) -> Result<()> {
    let mut s = new_sftp_client(config).await?;

    let stdin = tokio::io::stdin();
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(stdin).lines();

    loop {
        let cwd = match s.cmd_pwd().await {
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
    let mut s = new_sftp_client(config).await?;
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
                for arg in parts.iter().skip(1).copied() {
                    if arg.starts_with('-') {
                        continue;
                    }
                    if path.is_none() {
                        path = Some(arg);
                    }
                }
                let path = path.or(Some("."));
                match self.cmd_ls(path).await {
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
                    let (link, target) = if args[0] == "-s" {
                        (args[2], args[1])
                    } else {
                        (args[1], args[0])
                    };
                    if let Err(e) = self.cmd_symlink(link, target).await {
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
}