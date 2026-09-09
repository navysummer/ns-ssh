use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::msg;
use ssh_core::channel::*;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Command as TokioCommand, Child, ChildStdout, ChildStderr};
use tokio::process::ChildStdin;

pub struct Session {
    pub id: u32,
    pub username: String,
    pub pty: bool,
    pub term: String,
    pub width: u32,
    pub height: u32,
    pub env_vars: HashMap<String, String>,
    pub command: Option<String>,
    pub child: Option<Child>,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    pub pty_read: Option<Box<dyn AsyncRead + Send + Unpin>>,
    pub pty_write: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    pub pty_resize_fd: Option<i32>,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

pub struct SessionManager {
    sessions: HashMap<u32, Session>,
    next_id: u32,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create_session(
        &mut self,
        username: String,
        pty: bool,
        term: String,
        width: u32,
        height: u32,
    ) -> u32 {
        let id = self.next_id;
        self.next_id += 1;

        let session = Session {
            id,
            username,
            pty,
            term,
            width,
            height,
            env_vars: HashMap::new(),
            command: None,
            child: None,
            stdin: None,
            stdout: None,
            stderr: None,
            pty_read: None,
            pty_write: None,
            pty_resize_fd: None,
            status: SessionStatus::Pending,
        };

        self.sessions.insert(id, session);
        id
    }

    pub fn get_session(&self, id: u32) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn get_session_mut(&mut self, id: u32) -> Option<&mut Session> {
        self.sessions.get_mut(&id)
    }

    pub fn first_session_id(&self) -> Option<u32> {
        self.sessions.keys().next().cloned()
    }

    pub fn remove_session(&mut self, id: u32) {
        self.sessions.remove(&id);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn set_command(&mut self, id: u32, command: String) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.command = Some(command);
        }
    }

    pub fn set_env_var(&mut self, id: u32, name: String, value: String) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.env_vars.insert(name, value);
        }
    }

    pub fn set_window_size(&mut self, id: u32, width: u32, height: u32) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.width = width;
            session.height = height;
        }
    }

    pub fn start_session(&mut self, id: u32, work_dir: &str) -> Result<()> {
        let session = self.sessions.get_mut(&id)
            .ok_or_else(|| SshError::Protocol("session not found".into()))?;

        let username = session.username.clone();
        let command = session.command.clone();
        let env_vars = session.env_vars.clone();
        let pty = session.pty;
        let user_info = get_user_info(&username)?;
        let uid = user_info.uid;
        let gid = user_info.gid;

        let (pty_read, pty_write, pty_resize_fd, pty_stdio) = if pty {
            open_pty(session.width, session.height)?
        } else {
            (None, None, None, None)
        };

        let mut pty_stdio = pty_stdio;
        let mut build_base = |c: &mut TokioCommand| {
            c.current_dir(work_dir)
                .env("HOME", &user_info.home_dir)
                .env("USER", &username)
                .env("LOGNAME", &username)
                .env("SHELL", &user_info.shell)
                .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
                .env("TERM", &session.term)
                .env_clear();
            for (name, value) in &env_vars {
                c.env(name, value);
            }
            configure_pre_exec(c, uid, gid, pty);
            if let Some((si, so, se)) = pty_stdio.take() {
                c.stdin(std::process::Stdio::from(si))
                    .stdout(std::process::Stdio::from(so))
                    .stderr(std::process::Stdio::from(se));
            } else {
                c.stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());
            }
        };

        let mut cmd = if let Some(ref cmd_str) = command {
            let mut c = TokioCommand::new("/bin/sh");
            c.arg("-c").arg(cmd_str);
            build_base(&mut c);
            c.spawn()
                .map_err(|e| SshError::Subprocess(format!("failed to exec: {}", e)))?
        } else {
            let mut c = TokioCommand::new(&user_info.shell);
            build_base(&mut c);
            c.spawn()
                .map_err(|e| SshError::Subprocess(format!("failed to exec: {}", e)))?
        };

        let stdin = cmd.stdin.take();
        let stdout = cmd.stdout.take();
        let stderr = cmd.stderr.take();

        session.stdin = stdin;
        session.stdout = stdout;
        session.stderr = stderr;
        session.pty_read = pty_read;
        session.pty_write = pty_write;
        session.pty_resize_fd = pty_resize_fd;
        session.child = Some(cmd);
        session.status = SessionStatus::Running;

        Ok(())
    }

    pub fn resize_pty(&mut self, id: u32, width: u32, height: u32) -> Result<()> {
        if let Some(session) = self.sessions.get(&id) {
            if let Some(fd) = session.pty_resize_fd {
                if fd >= 0 {
                    let ws = libc::winsize {
                        ws_row: height as libc::c_ushort,
                        ws_col: width as libc::c_ushort,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    unsafe {
                        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn check_exit_status(&mut self, id: u32) -> Option<i32> {
        if let Some(session) = self.sessions.get_mut(&id) {
            if let Some(ref mut child) = session.child {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        session.status = SessionStatus::Completed;
                        if let Some(code) = status.code() {
                            Some(code)
                        } else {
                            #[cfg(unix)]
                            {
                                use std::os::unix::process::ExitStatusExt;
                                Some(128 + status.signal().unwrap_or(1))
                            }
                            #[cfg(not(unix))]
                            { Some(1) }
                        }
                    }
                    Ok(None) => None,
                    Err(_) => {
                        session.status = SessionStatus::Failed;
                        Some(1)
                    }
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn is_running(&self, id: u32) -> bool {
        self.sessions.get(&id)
            .map(|s| s.status == SessionStatus::Running)
            .unwrap_or(false)
    }
}

fn configure_pre_exec(cmd: &mut TokioCommand, uid: u32, gid: u32, _pty: bool) {
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgid(gid) != 0 {
                eprintln!("setgid failed");
            }
            if libc::setuid(uid) != 0 {
                eprintln!("setuid failed");
            }
            Ok(())
        });
    }
}

#[cfg(unix)]
fn open_pty(
    width: u32,
    height: u32,
) -> Result<(
    Option<Box<dyn AsyncRead + Send + Unpin>>,
    Option<Box<dyn AsyncWrite + Send + Unpin>>,
    Option<i32>,
    Option<(std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd)>,
)> {
    use std::os::unix::io::FromRawFd;
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Err(SshError::Io(std::io::Error::last_os_error()));
    }

    let ws = libc::winsize {
        ws_row: height as libc::c_ushort,
        ws_col: width as libc::c_ushort,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(slave, libc::TIOCSWINSZ, &ws);
    }

    let resize_fd = unsafe { libc::dup(slave) };

    let stdin_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(slave) };
    let stdout_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(libc::dup(slave)) };
    let stderr_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(libc::dup(slave)) };

    unsafe {
        let flags = libc::fcntl(master, libc::F_GETFL);
        let _ = libc::fcntl(master, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }

    let master_rd = unsafe { libc::dup(master) };
    let master_wr = unsafe { libc::dup(master) };
    unsafe {
        let flags = libc::fcntl(master_rd, libc::F_GETFL);
        let _ = libc::fcntl(master_rd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        let flags = libc::fcntl(master_wr, libc::F_GETFL);
        let _ = libc::fcntl(master_wr, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
    let rd_file = unsafe { std::fs::File::from_raw_fd(master_rd) };
    let wr_file = unsafe { std::fs::File::from_raw_fd(master_wr) };
    let rd_file = tokio::fs::File::from_std(rd_file);
    let wr_file = tokio::fs::File::from_std(wr_file);
    let rd: Box<dyn AsyncRead + Send + Unpin> = Box::new(rd_file);
    let wr: Box<dyn AsyncWrite + Send + Unpin> = Box::new(wr_file);
    unsafe { libc::close(master); }

    Ok((
        Some(rd),
        Some(wr),
        Some(resize_fd),
        Some((stdin_fd, stdout_fd, stderr_fd)),
    ))
}

#[cfg(not(unix))]
fn open_pty(
    _width: u32,
    _height: u32,
) -> Result<(
    Option<Box<dyn AsyncRead + Send + Unpin>>,
    Option<Box<dyn AsyncWrite + Send + Unpin>>,
    Option<i32>,
    Option<(std::process::Stdio, std::process::Stdio, std::process::Stdio)>,
)> {
    Err(SshError::Protocol("pty not supported on this platform".into()))
}

pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub home_dir: String,
    pub shell: String,
}

pub fn get_user_info(username: &str) -> Result<UserInfo> {
    use std::process::Command;

    let output = match Command::new("getent")
        .args(["passwd", username])
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            let output = Command::new("id")
                .args(["-P", username])
                .output()
                .map_err(|e| SshError::Io(e))?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = stdout.trim().split(':').collect();
                if parts.len() >= 9 {
                    let home_dir = parts[8].to_string();
                    let shell = parts[9].to_string();
                    return Ok(UserInfo {
                        uid: parts[2].parse().unwrap_or(1000),
                        gid: parts[3].parse().unwrap_or(1000),
                        home_dir,
                        shell,
                    });
                }
            }

            let output = Command::new("id")
                .args(["-u", username])
                .output()
                .map_err(|e| SshError::Io(e))?;

            let uid = if output.status.success() {
                String::from_utf8_lossy(&output.stdout).trim().parse().unwrap_or(1000)
            } else {
                1000
            };

            return Ok(UserInfo {
                uid,
                gid: uid,
                home_dir: std::env::var("HOME").unwrap_or_else(|_| format!("/home/{}", username)),
                shell: "/bin/bash".to_string(),
            });
        }
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stdout.trim().split(':').collect();
        if parts.len() >= 7 {
            return Ok(UserInfo {
                uid: parts[2].parse().unwrap_or(1000),
                gid: parts[3].parse().unwrap_or(1000),
                home_dir: parts[5].to_string(),
                shell: parts[6].to_string(),
            });
        }
    }

    let output = Command::new("id")
        .args(["-u", username])
        .output()
        .map_err(|e| SshError::Io(e))?;

    let uid = if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().parse().unwrap_or(1000)
    } else {
        1000
    };

    Ok(UserInfo {
        uid,
        gid: uid,
        home_dir: std::env::var("HOME").unwrap_or_else(|_| format!("/home/{}", username)),
        shell: "/bin/bash".to_string(),
    })
}

pub fn write_pid_file(pid_file: &str) -> Result<()> {
    let pid = std::process::id();
    std::fs::write(pid_file, pid.to_string())
        .map_err(|e| SshError::Io(e))
}

pub fn daemonize() -> Result<()> {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(SshError::Protocol("fork failed".into()));
        }
        if pid > 0 {
            std::process::exit(0);
        }
        libc::setsid();
    }
    Ok(())
}
