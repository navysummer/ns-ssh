use ssh_core::error::{Result, SshError};
use ssh_core::encoding::*;
use ssh_core::msg;
use ssh_core::channel::*;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

        let mut cmd = if let Some(ref cmd_str) = command {
            let mut c = TokioCommand::new("/bin/sh");
            c.arg("-c")
                .arg(cmd_str)
                .current_dir(work_dir)
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
            configure_pre_exec(&mut c, uid, gid, pty);
            c.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            c.spawn()
                .map_err(|e| SshError::Subprocess(format!("failed to exec: {}", e)))?
        } else {
            let mut c = TokioCommand::new(&user_info.shell);
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
            configure_pre_exec(&mut c, uid, gid, pty);
            c.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            c.spawn()
                .map_err(|e| SshError::Subprocess(format!("failed to exec: {}", e)))?
        };

        let stdin = cmd.stdin.take();
        let stdout = cmd.stdout.take();
        let stderr = cmd.stderr.take();

        session.stdin = stdin;
        session.stdout = stdout;
        session.stderr = stderr;
        session.child = Some(cmd);
        session.status = SessionStatus::Running;

        Ok(())
    }

    pub fn check_exit_status(&mut self, id: u32) -> Option<i32> {
        if let Some(session) = self.sessions.get_mut(&id) {
            if let Some(ref mut child) = session.child {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        session.status = SessionStatus::Completed;
                        status.code()
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

pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub home_dir: String,
    pub shell: String,
}

pub fn get_user_info(username: &str) -> Result<UserInfo> {
    use std::process::Command;

    let output = Command::new("getent")
        .args(["passwd", username])
        .output()
        .map_err(|e| SshError::Io(e))?;

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
        home_dir: format!("/home/{}", username),
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
