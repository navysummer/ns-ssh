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
    /// Chroot directory to use (from ChrootDirectory or authorized_keys).
    pub chroot_dir: Option<String>,
    /// Forced command from authorized_keys command= option.
    pub auth_key_command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// How a session's child process terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildExit {
    /// Normal exit with a status code.
    Status(i32),
    /// Killed by a signal (signal number, signal name without "SIG" prefix).
    Signal(i32, String),
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
            chroot_dir: None,
            auth_key_command: None,
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

    pub fn session_ids(&self) -> Vec<u32> {
        self.sessions.keys().cloned().collect()
    }

    pub fn set_pty(&mut self, id: u32, term: String, width: u32, height: u32) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.pty = true;
            session.term = term;
            session.width = width;
            session.height = height;
        }
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

    pub fn set_auth_key_command(&mut self, id: u32, command: String) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.auth_key_command = Some(command);
        }
    }

    pub fn set_chroot_dir(&mut self, id: u32, dir: String) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.chroot_dir = Some(dir);
        }
    }

    pub fn set_pty_disabled(&mut self, id: u32) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.pty = false;
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
        let env_vars = session.env_vars.clone();
        let pty = session.pty;
        let user_info = get_user_info(&username)?;
        let uid = user_info.uid;
        let gid = user_info.gid;

        // Determine effective working directory and chroot
        let effective_workdir = if let Some(ref chroot) = session.chroot_dir {
            // Inside chroot, home is relative to chroot root
            format!("{}/{}", chroot, user_info.home_dir)
        } else {
            work_dir.to_string()
        };

        let (pty_read, pty_write, pty_resize_fd, pty_stdio) = if pty {
            open_pty(session.width, session.height)?
        } else {
            (None, None, None, None)
        };

        let mut pty_stdio = pty_stdio;
        let mut build_base = |c: &mut TokioCommand| {
            c.current_dir(&effective_workdir)
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
            let post_chroot_cwd = if session.chroot_dir.is_some() {
                Some(user_info.home_dir.as_str())
            } else {
                None
            };
            configure_pre_exec(c, uid, gid, pty, session.chroot_dir.as_deref(), post_chroot_cwd);
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

        // Build effective command: auth key command= > session command > shell
        let effective_cmd = session.auth_key_command
            .clone()
            .or_else(|| session.command.clone());

        let mut cmd = if let Some(ref cmd_str) = effective_cmd {
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
        match self.poll_child_exit(id) {
            Some(ChildExit::Status(code)) => Some(code),
            Some(ChildExit::Signal(sig, _)) => Some(128 + sig),
            None => None,
        }
    }

    /// Poll a session child and report how it terminated (status or signal).
    pub fn poll_child_exit(&mut self, id: u32) -> Option<ChildExit> {
        if let Some(session) = self.sessions.get_mut(&id) {
            if let Some(ref mut child) = session.child {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        session.status = SessionStatus::Completed;
                        if let Some(code) = status.code() {
                            Some(ChildExit::Status(code))
                        } else {
                            #[cfg(unix)]
                            {
                                use std::os::unix::process::ExitStatusExt;
                                if let Some(sig) = status.signal() {
                                    Some(ChildExit::Signal(sig, signal_name(sig).to_string()))
                                } else {
                                    Some(ChildExit::Status(1))
                                }
                            }
                            #[cfg(not(unix))]
                            { Some(ChildExit::Status(1)) }
                        }
                    }
                    Ok(None) => None,
                    Err(_) => {
                        session.status = SessionStatus::Failed;
                        Some(ChildExit::Status(1))
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

fn configure_pre_exec(cmd: &mut TokioCommand, uid: u32, gid: u32, pty: bool, chroot: Option<&str>, chroot_cwd: Option<&str>) {
    let mut chroot_owned = chroot.map(|s| std::ffi::CString::new(s));
    let mut cwd_owned = chroot_cwd.map(|s| std::ffi::CString::new(s));
    unsafe {
        cmd.pre_exec(move || {
            // Apply chroot if specified (must use CString for NUL-termination)
            if let Some(Ok(dir)) = chroot_owned.take() {
                if libc::chroot(dir.as_ptr()) != 0 {
                    eprintln!("chroot failed: {}", std::io::Error::last_os_error());
                    return std::io::Result::Err(std::io::Error::last_os_error());
                }
                // After chroot, current dir should be "/"
                if libc::chdir(b"/\0".as_ptr() as *const libc::c_char) != 0 {
                    eprintln!("chdir / after chroot failed: {}", std::io::Error::last_os_error());
                    return std::io::Result::Err(std::io::Error::last_os_error());
                }
                if let Some(Ok(cwd)) = cwd_owned.take() {
                    if libc::chdir(cwd.as_ptr()) != 0 {
                        eprintln!("chdir {} after chroot failed: {}", cwd.to_string_lossy(), std::io::Error::last_os_error());
                        return std::io::Result::Err(std::io::Error::last_os_error());
                    }
                }
            }
            // Place the session in its own session + process group so signal
            // forwarding can target the whole group (`kill(-pid, sig)`),
            // matching OpenSSH. For PTY sessions, make the pty slave (fd 0)
            // the controlling terminal.
            if libc::setsid() != 0 {
                // Not fatal: continue without a fresh session.
            }
            if pty {
                libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0);
            }
            // Reset signal dispositions so the session child is killable by
            // signal forwarding even if the server inherited SIG_IGN (e.g. it
            // was started as a background job). OpenSSH does this too.
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
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

    // Use a dup of the MASTER (not the slave) for TIOCSWINSZ. Holding a slave
    // fd in the parent keeps the slave side open for the whole session, so the
    // pty master read never returns EOF when the child exits and the server
    // hangs in exit_poll waiting for the reader task to finish (readers_done
    // never reaches 0). TIOCSWINSZ is valid on the master fd.
    let resize_fd = unsafe { libc::dup(master) };

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

/// Map a signal number to its OpenSSH name (without "SIG" prefix).
pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        1 => "HUP",
        2 => "INT",
        3 => "QUIT",
        4 => "ILL",
        5 => "TRAP",
        6 => "ABRT",
        7 => "BUS",
        8 => "FPE",
        9 => "KILL",
        10 => "USR1",
        11 => "SEGV",
        12 => "USR2",
        13 => "PIPE",
        14 => "ALRM",
        15 => "TERM",
        16 => "STKFLT",
        17 => "CHLD",
        18 => "CONT",
        19 => "STOP",
        20 => "TSTP",
        21 => "TTIN",
        22 => "TTOU",
        23 => "URG",
        24 => "XCPU",
        25 => "XFSZ",
        26 => "VTALRM",
        27 => "PROF",
        28 => "WINCH",
        29 => "IO",
        30 => "PWR",
        31 => "SYS",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_name_mapping() {
        assert_eq!(signal_name(2), "INT");
        assert_eq!(signal_name(15), "TERM");
        assert_eq!(signal_name(9), "KILL");
        assert_eq!(signal_name(99), "UNKNOWN");
    }
}
