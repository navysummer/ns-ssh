# ns-ssh

A pure Rust implementation of OpenSSH client (`ssh`) and server (`sshd`), with no C dependencies.

## Features

### ns-ssh (Client)
- SSH-2.0 protocol support
- Key exchange: Curve25519-SHA256, ECDH P-256, Diffie-Hellman Group 14
- Ciphers: ChaCha20-Poly1305, AES-128/192/256-CTR, AES-128/256-GCM
- MAC: HMAC-SHA2-256, HMAC-SHA2-512
- Host key algorithms: Ed25519, ECDSA P-256, RSA
- Authentication: Public key, Password, SSH Agent
- Session management with PTY support
- Remote command execution
- Interactive shell
- Local and remote port forwarding
- Known hosts management
- SSH client config file parsing (~/.ssh/config)

### ns-ssh-server (Server)
- SSH-2.0 protocol support
- Same cryptographic algorithms as client
- Password and public key authentication
- Authorized keys management
- Session and channel management
- PTY allocation support
- Environment variable handling
- Server config file (/etc/ssh/sshd_config compatible)
- Automatic host key generation
- Daemon mode support

## Building

```bash
# Build in release mode
cargo build --release

# Binaries will be in:
# target/release/ns-ssh
# target/release/ns-ssh-server
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
ns-ssh -i ~/.ssh/my_key user@hostname

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

## Configuration

### Client (~/.ssh/config)

```
Host myserver
    HostName 192.168.1.100
    User admin
    Port 22
    IdentityFile ~/.ssh/id_ed25519

Host *
    StrictHostKeyChecking ask
    ForwardAgent no
```

### Server (/etc/ssh/sshd_config compatible)

```
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
AuthorizedKeysFile ~/.ssh/authorized_keys
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
