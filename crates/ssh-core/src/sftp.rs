use crate::error::{Result, SshError};
use crate::encoding::*;

pub const SSH_FXP_INIT: u8 = 1;
pub const SSH_FXP_VERSION: u8 = 2;
pub const SSH_FXP_OPEN: u8 = 3;
pub const SSH_FXP_CLOSE: u8 = 4;
pub const SSH_FXP_READ: u8 = 5;
pub const SSH_FXP_WRITE: u8 = 6;
pub const SSH_FXP_LSTAT: u8 = 7;
pub const SSH_FXP_FSTAT: u8 = 8;
pub const SSH_FXP_SETSTAT: u8 = 9;
pub const SSH_FXP_FSETSTAT: u8 = 10;
pub const SSH_FXP_OPENDIR: u8 = 11;
pub const SSH_FXP_READDIR: u8 = 12;
pub const SSH_FXP_REMOVE: u8 = 13;
pub const SSH_FXP_MKDIR: u8 = 14;
pub const SSH_FXP_RMDIR: u8 = 15;
pub const SSH_FXP_REALPATH: u8 = 16;
pub const SSH_FXP_STAT: u8 = 17;
pub const SSH_FXP_RENAME: u8 = 18;
pub const SSH_FXP_READLINK: u8 = 19;
pub const SSH_FXP_SYMLINK: u8 = 20;
pub const SSH_FXP_STATUS: u8 = 101;
pub const SSH_FXP_HANDLE: u8 = 102;
pub const SSH_FXP_DATA: u8 = 103;
pub const SSH_FXP_NAME: u8 = 104;
pub const SSH_FXP_ATTRS: u8 = 105;

pub const SSH_FXP_EXTENDED: u8 = 200;
pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_BAD_MESSAGE: u32 = 5;
pub const SSH_FX_NO_CONNECTION: u32 = 6;
pub const SSH_FX_CONNECTION_LOST: u32 = 7;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;
pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

pub const SSH_FXF_READ: u32 = 0x00000001;
pub const SSH_FXF_WRITE: u32 = 0x00000002;
pub const SSH_FXF_APPEND: u32 = 0x00000004;
pub const SSH_FXF_CREAT: u32 = 0x00000008;
pub const SSH_FXF_TRUNC: u32 = 0x00000010;
pub const SSH_FXF_EXCL: u32 = 0x00000020;

pub const SFTP_PROTOCOL_VERSION: u32 = 3;

#[derive(Clone)]
pub struct SftpFileAttr {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub flags: u32,
}

impl SftpFileAttr {
    pub fn new() -> Self {
        SftpFileAttr {
            size: None,
            uid: None,
            gid: None,
            permissions: None,
            atime: None,
            mtime: None,
            flags: 0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut flags = self.flags;
        if self.size.is_some() { flags |= SSH_FILEXFER_ATTR_SIZE; }
        if self.uid.is_some() || self.gid.is_some() { flags |= SSH_FILEXFER_ATTR_UIDGID; }
        if self.permissions.is_some() { flags |= SSH_FILEXFER_ATTR_PERMISSIONS; }
        if self.atime.is_some() || self.mtime.is_some() { flags |= SSH_FILEXFER_ATTR_ACMODTIME; }
        buf.extend(flags.to_be_bytes());

        if let Some(size) = self.size {
            buf.extend(size.to_be_bytes());
        }
        if self.flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            buf.extend(self.uid.unwrap_or(0).to_be_bytes());
            buf.extend(self.gid.unwrap_or(0).to_be_bytes());
        }
        if self.flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            buf.extend(self.permissions.unwrap_or(0).to_be_bytes());
        }
        if self.flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            buf.extend(self.atime.unwrap_or(0).to_be_bytes());
            buf.extend(self.mtime.unwrap_or(0).to_be_bytes());
        }
        buf
    }

    pub fn decode(r: &mut &[u8]) -> Result<Self> {
        let flags = u32::decode(r)?;
        let mut attr = SftpFileAttr::new();
        attr.flags = flags;

        if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            attr.size = Some(u64::decode(r)?);
        }
        if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            attr.uid = Some(u32::decode(r)?);
            attr.gid = Some(u32::decode(r)?);
        }
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            attr.permissions = Some(u32::decode(r)?);
        }
        if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            attr.atime = Some(u32::decode(r)?);
            attr.mtime = Some(u32::decode(r)?);
        }

        Ok(attr)
    }
}

#[derive(Clone)]
pub struct SftpNameEntry {
    pub filename: String,
    pub longname: String,
    pub attrs: SftpFileAttr,
}

impl SftpNameEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::new(&self.filename).encode(&mut buf).unwrap();
        SshString::new(&self.longname).encode(&mut buf).unwrap();
        buf.extend(self.attrs.encode());
        buf
    }
}

pub fn build_sftp_init() -> Vec<u8> {
    let mut buf = Vec::new();
    let length = 1 + 4; // type + version
    buf.extend((length as u32).to_be_bytes());
    buf.push(SSH_FXP_INIT);
    buf.extend(SFTP_PROTOCOL_VERSION.to_be_bytes());
    buf
}

pub fn build_sftp_open(id: u32, path: &str, pflags: u32, attrs: &SftpFileAttr) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_OPEN);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    payload.extend(pflags.to_be_bytes());
    payload.extend(attrs.encode());
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_close(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_CLOSE);
    payload.extend(id.to_be_bytes());
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_read(id: u32, handle: &[u8], offset: u64, len: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_READ);
    payload.extend(id.to_be_bytes());
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    payload.extend(offset.to_be_bytes());
    payload.extend(len.to_be_bytes());
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_write(id: u32, handle: &[u8], offset: u64, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_WRITE);
    payload.extend(id.to_be_bytes());
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    payload.extend(offset.to_be_bytes());
    SshBytes(data.to_vec()).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_opendir(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_OPENDIR);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_readdir(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_READDIR);
    payload.extend(id.to_be_bytes());
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_remove(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_REMOVE);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_mkdir(id: u32, path: &str, attrs: &SftpFileAttr) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_MKDIR);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    payload.extend(attrs.encode());
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_rmdir(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_RMDIR);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_realpath(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_REALPATH);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_stat(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_STAT);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_lstat(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_LSTAT);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_fstat(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_FSTAT);
    payload.extend(id.to_be_bytes());
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_setstat(id: u32, path: &str, attrs: &SftpFileAttr) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_SETSTAT);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    payload.extend(attrs.encode());
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_fsetstat(id: u32, handle: &[u8], attrs: &SftpFileAttr) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_FSETSTAT);
    payload.extend(id.to_be_bytes());
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    payload.extend(attrs.encode());
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_extended(id: u32, ext_name: &str, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_EXTENDED);
    payload.extend(id.to_be_bytes());
    SshString::new(ext_name).encode(&mut payload).unwrap();
    payload.extend_from_slice(data);
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_posix_rename(id: u32, oldpath: &str, newpath: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_EXTENDED);
    payload.extend(id.to_be_bytes());
    SshString::new("posix-rename@openssh.com").encode(&mut payload).unwrap();
    SshString::new(oldpath).encode(&mut payload).unwrap();
    SshString::new(newpath).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_statvfs(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_EXTENDED);
    payload.extend(id.to_be_bytes());
    SshString::new("statvfs@openssh.com").encode(&mut payload).unwrap();
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_fstatvfs(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_EXTENDED);
    payload.extend(id.to_be_bytes());
    SshString::new("fstatvfs@openssh.com").encode(&mut payload).unwrap();
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_fsync(id: u32, handle: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_EXTENDED);
    payload.extend(id.to_be_bytes());
    SshString::new("fsync@openssh.com").encode(&mut payload).unwrap();
    SshBytes(handle.to_vec()).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_hardlink(id: u32, oldpath: &str, newpath: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_EXTENDED);
    payload.extend(id.to_be_bytes());
    SshString::new("hardlink@openssh.com").encode(&mut payload).unwrap();
    SshString::new(oldpath).encode(&mut payload).unwrap();
    SshString::new(newpath).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_limits(id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_EXTENDED);
    payload.extend(id.to_be_bytes());
    SshString::new("limits@openssh.com").encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_rename(id: u32, oldpath: &str, newpath: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_RENAME);
    payload.extend(id.to_be_bytes());
    SshString::new(oldpath).encode(&mut payload).unwrap();
    SshString::new(newpath).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

pub fn build_sftp_readlink(id: u32, path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_READLINK);
    payload.extend(id.to_be_bytes());
    SshString::new(path).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

/// SFTP v3 `SSH_FXP_SYMLINK` carries the target before the link path. This
/// ordering matches OpenSSH's sftp-server (`oldpath` then `newpath`); sending
/// the link first made every v3 server reject the request.
pub fn build_sftp_symlink(id: u32, targetpath: &str, linkpath: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_FXP_SYMLINK);
    payload.extend(id.to_be_bytes());
    SshString::new(targetpath).encode(&mut payload).unwrap();
    SshString::new(linkpath).encode(&mut payload).unwrap();
    wrap_sftp_payload(&payload)
}

fn wrap_sftp_payload(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend((payload.len() as u32).to_be_bytes());
    buf.extend(payload);
    buf
}

pub fn parse_sftp_response(data: &[u8]) -> Result<(u8, u32, &[u8])> {
    if data.len() < 5 {
        return Err(SshError::Protocol("SFTP response too short".into()));
    }
    let msg_type = data[4];
    let id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    Ok((msg_type, id, &data[9..]))
}

pub fn parse_sftp_status(data: &[u8]) -> Result<(u32, String)> {
    let mut r = data;
    let status_code = u32::decode(&mut r)?;
    let message = SshString::decode(&mut r)?.as_str()?.to_string();
    Ok((status_code, message))
}

pub fn parse_sftp_handle(data: &[u8]) -> Result<Vec<u8>> {
    let mut r = data;
    let handle = SshBytes::decode(&mut r)?;
    Ok(handle.0)
}

pub fn parse_sftp_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut r = data;
    let d = SshBytes::decode(&mut r)?;
    Ok(d.0)
}

pub fn parse_sftp_name(data: &[u8]) -> Result<Vec<SftpNameEntry>> {
    let mut r = data;
    let count = u32::decode(&mut r)? as usize;
    let mut names = Vec::new();
    for _ in 0..count {
        let filename = SshString::decode(&mut r)?.as_str()?.to_string();
        let longname = SshString::decode(&mut r)?.as_str()?.to_string();
        let attrs = SftpFileAttr::decode(&mut r)?;
        names.push(SftpNameEntry { filename, longname, attrs });
    }
    Ok(names)
}

pub fn parse_sftp_attrs(data: &[u8]) -> Result<SftpFileAttr> {
    let mut r = data;
    SftpFileAttr::decode(&mut r)
}

/// Parse an `SSH_FXP_EXTENDED_REPLY` for `statvfs@openssh.com` / `fstatvfs@openssh.com`.
/// Returns `(f_bsize, f_frsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree)`.
pub fn parse_sftp_statvfs(data: &[u8]) -> Result<(u64, u64, u64, u64, u64, u64, u64)> {
    let mut r = data;
    let bsize = u64::decode(&mut r)?;
    let frsize = u64::decode(&mut r)?;
    let blocks = u64::decode(&mut r)?;
    let bfree = u64::decode(&mut r)?;
    let bavail = u64::decode(&mut r)?;
    let files = u64::decode(&mut r)?;
    let ffree = u64::decode(&mut r)?;
    Ok((bsize, frsize, blocks, bfree, bavail, files, ffree))
}
