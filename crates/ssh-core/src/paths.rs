//! Centralised configuration and data paths for ns-ssh.
//!
//! ns-ssh deliberately does **not** share the OpenSSH directories
//! (`~/.ssh`, `/etc/ssh`) so its own configuration and keys never mix with a
//! system OpenSSH installation. All default paths below are ns-ssh's own.
//!
//! Layout:
//! - User-level: `~/.config/ns-ssh/` (XDG config home, overridable via
//!   `NS_SSH_CONFIG_DIR`).
//! - System-level: `/etc/ns-ssh/` (overridable via `NS_SSH_ETC_DIR`).
//!
//! These are only the *defaults*: every path can be overridden by the usual
//! configuration directives (`UserKnownHostsFile`, `IdentityFile`, `HostKey`,
//! `AuthorizedKeysFile`, …) and by command-line flags.

use std::path::PathBuf;

/// Environment variable overriding the user-level config directory.
const USER_DIR_ENV: &str = "NS_SSH_CONFIG_DIR";
/// Environment variable overriding the system-level config directory.
const ETC_DIR_ENV: &str = "NS_SSH_ETC_DIR";

/// `~/.config/ns-ssh` (or `$NS_SSH_CONFIG_DIR`).
pub fn user_dir() -> PathBuf {
    if let Some(p) = std::env::var_os(USER_DIR_ENV) {
        return PathBuf::from(p);
    }
    let base = dirs::config_dir().unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")));
    base.join("ns-ssh")
}

/// `/etc/ns-ssh` (or `$NS_SSH_ETC_DIR`).
pub fn etc_dir() -> PathBuf {
    if let Some(p) = std::env::var_os(ETC_DIR_ENV) {
        return PathBuf::from(p);
    }
    PathBuf::from("/etc/ns-ssh")
}

/// Client configuration file: `~/.config/ns-ssh/config`.
pub fn client_config() -> PathBuf {
    user_dir().join("config")
}

/// Client known_hosts: `~/.config/ns-ssh/known_hosts`.
pub fn user_known_hosts() -> PathBuf {
    user_dir().join("known_hosts")
}

/// Client global known_hosts: `/etc/ns-ssh/known_hosts`.
pub fn global_known_hosts() -> PathBuf {
    etc_dir().join("known_hosts")
}

/// A default identity key path (no `.pub`): `~/.config/ns-ssh/id_<type>`.
pub fn identity(name: &str) -> PathBuf {
    user_dir().join(format!("id_{name}"))
}

/// Default identity candidates tried in order.
pub const DEFAULT_IDENTITY_NAMES: &[&str] = &["ed25519", "ecdsa", "rsa"];

/// Server configuration file: `/etc/ns-ssh/sshd_config`.
pub fn server_config() -> PathBuf {
    etc_dir().join("sshd_config")
}

/// Server default host key path: `/etc/ns-ssh/ssh_host_<type>_key`.
pub fn server_host_key(kind: &str) -> PathBuf {
    etc_dir().join(format!("ssh_host_{kind}_key"))
}

/// Server default host key candidates, in preference order.
pub const SERVER_HOST_KEY_NAMES: &[&str] = &["ed25519", "rsa", "ecdsa"];

/// Server host-based-auth known_hosts: `~/.config/ns-ssh/known_hosts`.
pub fn server_known_hosts() -> PathBuf {
    user_dir().join("known_hosts")
}

/// Server user's authorized_keys: `~/.config/ns-ssh/authorized_keys`.
pub fn server_authorized_keys() -> PathBuf {
    user_dir().join("authorized_keys")
}

/// Server user's rc script (PermitUserRC): `~/.config/ns-ssh/rc`.
pub fn server_user_rc() -> PathBuf {
    user_dir().join("rc")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_ns_ssh_owned() {
        assert!(user_dir().to_string_lossy().contains("ns-ssh"));
        assert!(etc_dir().to_string_lossy().contains("ns-ssh"));
        assert_eq!(client_config().file_name().unwrap(), "config");
        assert_eq!(user_known_hosts().file_name().unwrap(), "known_hosts");
        assert_eq!(global_known_hosts().file_name().unwrap(), "known_hosts");
        assert_eq!(identity("ed25519").file_name().unwrap(), "id_ed25519");
        assert_eq!(server_config().file_name().unwrap(), "sshd_config");
        assert_eq!(server_host_key("ed25519").file_name().unwrap(), "ssh_host_ed25519_key");
        assert_eq!(server_authorized_keys().file_name().unwrap(), "authorized_keys");
        assert_eq!(server_user_rc().file_name().unwrap(), "rc");
    }

    #[test]
    fn env_overrides_are_respected() {
        std::env::set_var(USER_DIR_ENV, "/tmp/ns-cfg");
        std::env::set_var(ETC_DIR_ENV, "/tmp/ns-etc");
        assert_eq!(user_dir(), PathBuf::from("/tmp/ns-cfg"));
        assert_eq!(etc_dir(), PathBuf::from("/tmp/ns-etc"));
        std::env::remove_var(USER_DIR_ENV);
        std::env::remove_var(ETC_DIR_ENV);
    }
}
