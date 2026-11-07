# ns-ssh

A pure Rust implementation of OpenSSH client (`ssh`) and server (`sshd`), with no C dependencies.

## Features

### ns-ssh (Client)
- SSH-2.0 protocol support
- Key exchange: Curve25519-SHA256, ECDH P-256/384/521, DH group14/16/18, DH group-exchange (SHA-256/SHA-1), and the post-quantum hybrids `sntrup761x25519-sha512` (RFC 9941) and `mlkem768x25519-sha256` (RFC 9765, OpenSSH 9.9 default)
- Ciphers: ChaCha20-Poly1305, AES-128/192/256-CTR, AES-128/256-GCM, AES-CBC, 3DES-CBC
- MAC: HMAC-SHA2-256/512, HMAC-SHA1, UMAC-64/128 (including the ETM variants)
- Host key algorithms: Ed25519, ECDSA P-256/384/521, RSA (rsa-sha2-256/512)
- Authentication: Public key, Password, SSH Agent (client + `ns-ssh-agent` daemon)
- Session management with PTY support
- Remote command execution
- Interactive shell
- Local and remote port forwarding
- Known hosts management
- SSH client config file parsing (~/.config/ns-ssh/config)
- Automatic rekeying (RekeyLimit; client- and server-initiated)

### ns-ssh-server (Server)
- SSH-2.0 protocol support
- Same cryptographic algorithms as client
- Password and public key authentication
- Authorized keys management
- Session and channel management
- PTY allocation support
- Environment variable handling
- Server config file (/etc/ns-ssh/sshd_config)
- Automatic host key generation
- Daemon mode support
- Automatic rekeying (RekeyLimit)
- SFTP subsystem (`internal-sftp`), including the OpenSSH extensions `posix-rename`, `statvfs`, `hardlink`, `fsync`, `limits`, `copy-data`, `expand-path`, `check-file`, `lsetstat`, `home-directory` and `users-groups-by-id`

### ns-scp / ns-sftp (客户端工具)

- `ns-scp`(与 `scp` 同义):**默认走 SFTP 协议**(OpenSSH 9 行为);`-s` 显式强制 SFTP,`-O` 回退旧 SCP 协议(远端 `scp -t/-f`)。支持单/多源、递归目录(`-r`)、属性保留(`-p`,mode+mtime+atime)。
- `ns-sftp`(与 `sftp` 同义):交互式/批处理(`-b`)SFTP 客户端,命令集与 OpenSSH `sftp` 对齐。
- 模式由调用名决定:`ns-ssh` 二进制被链接/复制为 `scp`/`ns-scp`/`sftp`/`ns-sftp` 时进入对应子命令。

### ns-ssl (TLS client/server)

- Pure-Rust TLS built on `rustls` (no OpenSSL/OpenSSH dependency)
- TLS 1.2 and TLS 1.3, client and server
- Certificate verification against `webpki-roots` or a custom `-CAfile`
- ALPN negotiation, mutual TLS (client certs)
- `openssl s_client` / `openssl s_server`-style CLI (`s_client`/`s_server`)
- Interoperates with real `openssl` (verified in both directions)

## Building

```bash
# Build in release mode
cargo build --release

# Binaries will be in:
# target/release/ns-ssh
# target/release/ns-ssh-server
# target/release/ns-ssl
```

## Cross-compilation for Linux

```bash
# Install musl target for fully static binaries
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl

# Build for x86_64 Linux (static, no dependencies)
cargo build --release --target x86_64-unknown-linux-musl

# Build for aarch64 Linux (static, no dependencies)
cargo build --release --target aarch64-unknown-linux-musl
```

## Usage

### Client (ns-ssh)

```bash
# Connect to a remote host
ns-ssh user@hostname

# Connect on custom port
ns-ssh -p 2222 user@hostname

# Execute a remote command
ns-ssh user@hostname ls -la

# Use specific identity file
ns-ssh -i ~/.config/ns-ssh/my_key user@hostname

# Local port forwarding
ns-ssh -L 8080:localhost:80 user@hostname

# Remote port forwarding
ns-ssh -R 9090:localhost:3000 user@hostname

# With proxy jump
ns-ssh -J jumphost user@target
```

### Server (ns-ssh-server)

```bash
# Run server (default port 22)
ns-ssh-server

# Run on custom port
ns-ssh-server -p 2222

# Run with debug output
ns-ssh-server -d

# Run in foreground (no daemon)
ns-ssh-server -D

# Use custom config file
ns-ssh-server -f /path/to/sshd_config
```


### Companion tools

The `ns-ssh` binary dispatches by `argv[0]`, so symlink it under the tool name
to use each one (the `ns-*` prefix is the project-native name; the plain names
are also accepted):

```bash
for t in ns-ssh ns-ssh-add ns-ssh-agent ns-ssh-copy-id ns-ssh-keyscan ns-ssh-keygen; do
  ln -sf "$(command -v ns-ssh)" "$t"
done

# key generation
ns-ssh-keygen -t ed25519 -f ~/.config/ns-ssh/id_ed25519

# agent daemon (holds private keys, exports SSH_AUTH_SOCK/SSH_AGENT_PID)
eval "$(ns-ssh-agent -s)"
ns-ssh-add ~/.config/ns-ssh/id_ed25519
ns-ssh-add -l          # list identities
ns-ssh-add -L          # list public keys
ns-ssh-add -D          # remove all

# copy a public key to a remote account's authorized_keys
ns-ssh-copy-id -i ~/.config/ns-ssh/id_ed25519.pub user@host

# scan a host's public keys into known_hosts
ns-ssh-keyscan host > ~/.config/ns-ssh/known_hosts
```

All five interoperate with the real OpenSSH tools: `ssh-add`/`ssh` work against
`ns-ssh-agent`, and `ns-ssh-add`/`ns-ssh` work against a real `ssh-agent`.

## Configuration

ns-ssh uses its **own** configuration and key paths, deliberately separate from
OpenSSH, so the two never read or overwrite each other's files:

| 用途 | 路径 |
|---|---|
| 客户端配置 | `~/.config/ns-ssh/config`（可用 `-F` 覆盖） |
| 客户端 known_hosts | `~/.config/ns-ssh/known_hosts`（可用 `UserKnownHostsFile` 覆盖） |
| 全局 known_hosts | `/etc/ns-ssh/known_hosts`（可用 `GlobalKnownHostsFile` 覆盖） |
| 默认身份密钥 | `~/.config/ns-ssh/id_ed25519` / `id_ecdsa` / `id_rsa` |
| 服务端配置 | `/etc/ns-ssh/sshd_config`（可用 `-f` 覆盖） |
| 服务端主机密钥 | `/etc/ns-ssh/ssh_host_ed25519_key` / `ssh_host_rsa_key` / `ssh_host_ecdsa_key` |
| 服务端 authorized_keys | `~/.config/ns-ssh/authorized_keys`（可用 `AuthorizedKeysFile` 覆盖） |
| 服务端用户 rc（PermitUserRC） | `~/.config/ns-ssh/rc` |

> 环境变量 `NS_SSH_CONFIG_DIR`（用户级，默认 `~/.config/ns-ssh`）与
> `NS_SSH_ETC_DIR`（系统级，默认 `/etc/ns-ssh`）可整体重定向这些默认位置。
> 除上述默认值外，所有配置指令（`HostKey`、`AuthorizedKeysFile`、
> `UserKnownHostsFile`、`IdentityFile` 等）仍可指向任意路径。

### Client (~/.config/ns-ssh/config)

```
Host myserver
    HostName 192.168.1.100
    User admin
    Port 22
    IdentityFile ~/.config/ns-ssh/id_ed25519

Host *
    StrictHostKeyChecking ask
    ForwardAgent no
```

### Server (/etc/ns-ssh/sshd_config)

```
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ns-ssh/ssh_host_ed25519_key
HostKey /etc/ns-ssh/ssh_host_rsa_key
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
AuthorizedKeysFile ~/.config/ns-ssh/authorized_keys
MaxAuthTries 6
MaxSessions 10
```

## Security Notes

- All cryptographic operations are implemented in pure Rust
- No dependencies on OpenSSL, libcrypto, or other C libraries
- Static linking support for fully self-contained binaries
- Follows SSH protocol best practices (RFC 4250-4254)

## License

Apache License 2.0
