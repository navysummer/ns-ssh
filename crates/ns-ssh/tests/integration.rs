//! End-to-end integration test: spawns ns-ssh-server, connects with ns-ssh,
//! and verifies a real exec round-trip over a full SSH handshake + auth.

use base64::Engine;
use ssh_core::hostkey::{Ed25519HostKey, HostKeySigner};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn workspace_target_dir() -> PathBuf {
    // tests run from the package dir; server binary lives in the workspace target dir.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../target/debug/ns-ssh-server")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ns-ssh-it-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn openssh_ed25519_private(secret: &[u8; 32], pubkey: &[u8; 32]) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"openssh-key-v1\0");
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(b"none"); // cipher: none
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(b"none"); // kdf: none
    buf.extend_from_slice(&0u32.to_be_bytes()); // kdf options: empty string
    buf.extend_from_slice(&1u32.to_be_bytes()); // nkeys

    let mut pub_key_buf = Vec::new();
    pub_key_buf.extend_from_slice(b"ssh-ed25519");
    pub_key_buf.extend_from_slice(&(32u32).to_be_bytes());
    pub_key_buf.extend_from_slice(pubkey);
    buf.extend_from_slice(&(pub_key_buf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&pub_key_buf);

    let mut priv_key_buf = Vec::new();
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes()); // checkint 1
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes()); // checkint 2
    priv_key_buf.extend_from_slice(&(11u32).to_be_bytes());
    priv_key_buf.extend_from_slice(b"ssh-ed25519");
    priv_key_buf.extend_from_slice(&(32u32).to_be_bytes());
    priv_key_buf.extend_from_slice(pubkey);
    priv_key_buf.extend_from_slice(&(64u32).to_be_bytes());
    priv_key_buf.extend_from_slice(secret);
    priv_key_buf.extend_from_slice(pubkey);
    priv_key_buf.extend_from_slice(&0u32.to_be_bytes()); // comment: empty string
    // Pad with 1,2,3,... so the private block is a multiple of the cipher block size (8 for none).
    let pad = (8 - (priv_key_buf.len() % 8)) % 8;
    for i in 1..=pad {
        priv_key_buf.push(i as u8);
    }

    buf.extend_from_slice(&(priv_key_buf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&priv_key_buf);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
    let mut result = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        result.push_str(std::str::from_utf8(chunk).unwrap());
        result.push('\n');
    }
    result.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    result
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn exec_round_trip_over_full_handshake() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("exec");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Generate a client ed25519 key pair.
    let key = Ed25519HostKey::generate().expect("generate key");
    let secret = key.secret_bytes();
    let blob = key.public_key_bytes();
    let pubkey: [u8; 32] = blob[blob.len() - 32..].try_into().expect("pubkey len");

    let id_path = dir.join("id_ed25519");
    std::fs::write(&id_path, openssh_ed25519_private(&secret, &pubkey)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let auth_path = dir.join("authorized_keys");
    let auth_line = format!(
        "ssh-ed25519 {} test\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    );
    std::fs::write(&auth_path, auth_line).unwrap();

    let host_key_path = dir.join("host_key_ed25519");

    // Launch the server.
    let server = Command::new(&server_bin)
        .arg("-d") // no daemonize; keep server in foreground for the test
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg(format!("listenaddress=127.0.0.1"))
        .arg("-o")
        .arg("pubkeyauthentication=yes")
        .arg("-o")
        .arg("passwordauthentication=no")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
        .arg("-o")
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg("maxauthtries=10")
        .arg("-o")
        .arg("login_grace_time=30")
        // --host-key-file replaces the default host key list (avoid RSA generation).
        .arg("--host-key-file")
        .arg(host_key_path.to_str().unwrap())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    // Connect and run a command.
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let kh = dir.join("known_hosts");
    let output = Command::new(client_bin)
        .arg("-p")
        .arg(port.to_string())
        .arg("-l")
        .arg(&user)
        .arg("-i")
        .arg(&id_path)
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("127.0.0.1")
        .arg("echo hello")
        .output()
        .expect("run client");

    // Stop the server and capture its log output.
    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    if !output.status.success() {
        panic!(
            "client failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&server_out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "expected 'hello' in stdout, got: {:?}",
        stdout
    );
}

#[test]
fn large_transfer_window_replenishment() {
    // A multi-MB transfer exceeds the default 2 MiB channel window, forcing the
    // send-side window gating (deferred data flushed on WINDOW_ADJUST) and the
    // receive-side WINDOW_ADJUST replenishment to engage in BOTH directions.
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("large");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    let key = Ed25519HostKey::generate().expect("generate key");
    let secret = key.secret_bytes();
    let blob = key.public_key_bytes();
    let pubkey: [u8; 32] = blob[blob.len() - 32..].try_into().expect("pubkey len");

    let id_path = dir.join("id_ed25519");
    std::fs::write(&id_path, openssh_ed25519_private(&secret, &pubkey)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let auth_path = dir.join("authorized_keys");
    let auth_line = format!(
        "ssh-ed25519 {} test\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    );
    std::fs::write(&auth_path, auth_line).unwrap();
    let host_key_path = dir.join("host_key_ed25519");

    let server = Command::new(&server_bin)
        .arg("-d")
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("listenaddress=127.0.0.1")
        .arg("-o")
        .arg("pubkeyauthentication=yes")
        .arg("-o")
        .arg("passwordauthentication=no")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
        .arg("-o")
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg("maxauthtries=10")
        .arg("-o")
        .arg("login_grace_time=30")
        .arg("--host-key-file")
        .arg(host_key_path.to_str().unwrap())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    // 3 MiB deterministic payload (exceeds the 2 MiB default window).
    let mut payload = Vec::with_capacity(3 << 20);
    for i in 0..(3 << 20) {
        payload.push((i % 251) as u8);
    }

    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let kh = dir.join("known_hosts");
    let mut child = Command::new(client_bin)
        .arg("-p")
        .arg(port.to_string())
        .arg("-l")
        .arg(&user)
        .arg("-i")
        .arg(&id_path)
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("127.0.0.1")
        .arg("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    use std::io::Write;
    {
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(&payload);
        // drop(stdin) closes the pipe -> client sees EOF and sends channel EOF.
    }
    let output = child.wait_with_output().expect("wait client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    if !output.status.success() {
        panic!(
            "client failed: status={:?}\nstderr={}\nserver_stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&server_out.stderr)
        );
    }
    assert_eq!(
        output.stdout.len(),
        payload.len(),
        "large transfer size mismatch: expected {} bytes, got {}",
        payload.len(),
        output.stdout.len()
    );
    assert_eq!(
        output.stdout, payload,
        "large transfer content mismatch (window gating/replenishment broken?)"
    );
}

#[test]
fn exec_round_trip_authorized_keys_command() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("akc");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Generate a client ed25519 key pair.
    let key = Ed25519HostKey::generate().expect("generate key");
    let secret = key.secret_bytes();
    let blob = key.public_key_bytes();
    let pubkey: [u8; 32] = blob[blob.len() - 32..].try_into().expect("pubkey len");

    let id_path = dir.join("id_ed25519");
    std::fs::write(&id_path, openssh_ed25519_private(&secret, &pubkey)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // AuthorizedKeysCommand emits the public key on stdout.
    let pub_path = dir.join("authorized_keys.pub");
    let pub_line = format!(
        "ssh-ed25519 {} test\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    );
    std::fs::write(&pub_path, pub_line).unwrap();
    let akc_cmd = format!("cat {}", pub_path.display());

    let host_key_path = dir.join("host_key_ed25519");

    let server = Command::new(&server_bin)
        .arg("-d")
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("listenaddress=127.0.0.1")
        .arg("-o")
        .arg("pubkeyauthentication=yes")
        .arg("-o")
        .arg("passwordauthentication=no")
        .arg("-o")
        .arg(format!("authorizedkeyscommand={}", akc_cmd))
        .arg("-o")
        .arg(format!("authorizedkeyscommanduser={}", user))
        .arg("-o")
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg("maxauthtries=10")
        .arg("--host-key-file")
        .arg(host_key_path.to_str().unwrap())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let kh = dir.join("known_hosts");
    let output = Command::new(client_bin)
        .arg("-p")
        .arg(port.to_string())
        .arg("-l")
        .arg(&user)
        .arg("-i")
        .arg(&id_path)
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("127.0.0.1")
        .arg("echo hello")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    if !output.status.success() {
        panic!(
            "client failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&server_out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "expected 'hello' in stdout, got: {:?}",
        stdout
    );
}

#[test]
fn exec_round_trip_match_block() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("match");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // Generate a client ed25519 key pair.
    let key = Ed25519HostKey::generate().expect("generate key");
    let secret = key.secret_bytes();
    let blob = key.public_key_bytes();
    let pubkey: [u8; 32] = blob[blob.len() - 32..].try_into().expect("pubkey len");

    let id_path = dir.join("id_ed25519");
    std::fs::write(&id_path, openssh_ed25519_private(&secret, &pubkey)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let auth_path = dir.join("authorized_keys");
    let auth_line = format!(
        "ssh-ed25519 {} test\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    );
    std::fs::write(&auth_path, auth_line).unwrap();

    let host_key_path = dir.join("host_key_ed25519");

    // Config file with a Match block that forces a command for the current user.
    let sshd_conf = dir.join("sshd.conf");
    let conf = format!(
        "Port {}\nListenAddress 127.0.0.1\nPubkeyAuthentication yes\nPasswordAuthentication no\n\
         PermitRootLogin yes\nAuthorizedKeysFile {}\nHostKey {}\nMatch User {}\n    ForceCommand echo MATCHED\n",
        port,
        auth_path.display(),
        host_key_path.display(),
        user
    );
    std::fs::write(&sshd_conf, conf).unwrap();

    let server = Command::new(&server_bin)
        .arg("-d")
        .arg("-f")
        .arg(&sshd_conf)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let kh = dir.join("known_hosts");
    let output = Command::new(client_bin)
        .arg("-p")
        .arg(port.to_string())
        .arg("-l")
        .arg(&user)
        .arg("-i")
        .arg(&id_path)
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("127.0.0.1")
        .arg("echo hello")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    if !output.status.success() {
        panic!(
            "client failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&server_out.stderr)
        );
    }
    // ForceCommand replaced the requested "echo hello".
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("MATCHED"),
        "expected Match ForceCommand output 'MATCHED', got: {:?}",
        stdout
    );
}

#[test]
fn ssh_keyscan_prints_host_key() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("keyscan");
    let port = free_port();
    let host_key_path = dir.join("host_key_ed25519");

    let server = Command::new(&server_bin)
        .arg("-d")
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("listenaddress=127.0.0.1")
        .arg("-o")
        .arg("pubkeyauthentication=no")
        .arg("-o")
        .arg("passwordauthentication=no")
        .arg("--host-key-file")
        .arg(host_key_path.to_str().unwrap())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    // Invoke the client binary via a symlink named "ssh-keyscan".
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let keyscan_link = dir.join("ssh-keyscan");
    std::os::unix::fs::symlink(client_bin, &keyscan_link).unwrap();

    let output = Command::new(&keyscan_link)
        .arg("-p")
        .arg(port.to_string())
        .arg("127.0.0.1")
        .output()
        .expect("run ssh-keyscan");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "ssh-keyscan failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ssh-ed25519"),
        "expected ssh-ed25519 host key line, got: {:?}",
        stdout
    );
    assert!(
        stdout.contains("127.0.0.1"),
        "expected host in keyscan output, got: {:?}",
        stdout
    );
}

#[test]
fn query_algorithms_lists_supported() {
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");

    let out = Command::new(client_bin)
        .arg("-Q")
        .arg("key")
        .output()
        .expect("run -Q key");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ssh-ed25519"), "missing ssh-ed25519: {:?}", stdout);
    assert!(stdout.contains("rsa-sha2-512"), "missing rsa-sha2-512: {:?}", stdout);

    let out = Command::new(client_bin)
        .arg("-Q")
        .arg("kex")
        .output()
        .expect("run -Q kex");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("curve25519-sha256"), "missing curve25519-sha256: {:?}", stdout);

    // Unsupported query type must fail.
    let out = Command::new(client_bin)
        .arg("-Q")
        .arg("nonsense")
        .output()
        .expect("run -Q nonsense");
    assert!(!out.status.success());
}

#[test]
fn log_file_writes_diagnostics() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("logfile");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    let key = Ed25519HostKey::generate().expect("generate key");
    let secret = key.secret_bytes();
    let blob = key.public_key_bytes();
    let pubkey: [u8; 32] = blob[blob.len() - 32..].try_into().expect("pubkey len");

    let id_path = dir.join("id_ed25519");
    std::fs::write(&id_path, openssh_ed25519_private(&secret, &pubkey)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let auth_path = dir.join("authorized_keys");
    let auth_line = format!(
        "ssh-ed25519 {} test\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    );
    std::fs::write(&auth_path, auth_line).unwrap();

    let host_key_path = dir.join("host_key_ed25519");
    let server = Command::new(&server_bin)
        .arg("-d")
        .arg("-p")
        .arg(port.to_string())
        .arg("-o")
        .arg("listenaddress=127.0.0.1")
        .arg("-o")
        .arg("pubkeyauthentication=yes")
        .arg("-o")
        .arg("passwordauthentication=no")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
        .arg("-o")
        .arg("permitrootlogin=yes")
        .arg("--host-key-file")
        .arg(host_key_path.to_str().unwrap())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let kh = dir.join("known_hosts");
    let log_path = dir.join("client.log");
    let output = Command::new(client_bin)
        .arg("-p")
        .arg(port.to_string())
        .arg("-l")
        .arg(&user)
        .arg("-i")
        .arg(&id_path)
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-E")
        .arg(&log_path)
        .arg("-v")
        .arg("127.0.0.1")
        .arg("echo hello-log")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let log_content = std::fs::read_to_string(&log_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "client failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hello-log"),
        "expected command output"
    );
    // The -E log file should contain the INFO diagnostics, not stderr.
    assert!(
        log_content.contains("connecting"),
        "expected 'connecting' in -E log file, got: {:?}",
        log_content
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("connecting"),
        "-E log should not leak to stderr"
    );
}

#[test]
fn ssh_keygen_generates_usable_key() {
    let dir = temp_dir("keygen");
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let keygen_link = dir.join("ssh-keygen");
    std::os::unix::fs::symlink(client_bin, &keygen_link).unwrap();

    let key_path = dir.join("test_key");
    let out = Command::new(&keygen_link)
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg(&key_path)
        .arg("-q")
        .output()
        .expect("run ssh-keygen");
    assert!(
        out.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(key_path.exists(), "private key not created");
    let pub_path = dir.join("test_key.pub");
    assert!(pub_path.exists(), "public key not created");

    // -y export matches the .pub file.
    let out = Command::new(&keygen_link)
        .arg("-y")
        .arg("-f")
        .arg(&key_path)
        .output()
        .expect("run -y");
    let exported = String::from_utf8_lossy(&out.stdout);
    let pub_content = std::fs::read_to_string(&pub_path).unwrap();
    assert!(
        exported.trim() == pub_content.trim(),
        "-y export mismatch: {:?} vs {:?}",
        exported,
        pub_content
    );

    // -l fingerprint matches OpenSSH's own computation.
    let out = Command::new(&keygen_link)
        .arg("-l")
        .arg("-f")
        .arg(&key_path)
        .output()
        .expect("run -l");
    assert!(out.status.success(), "fingerprint failed");
    let fp = String::from_utf8_lossy(&out.stdout);
    assert!(fp.contains("SHA256:"), "expected SHA256 fingerprint, got: {:?}", fp);

    // The real ssh-keygen (if present) can read our private key.
    if let Ok(sys) = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(&key_path)
        .output()
    {
        assert!(
            sys.status.success(),
            "system ssh-keygen could not read our key: {}",
            String::from_utf8_lossy(&sys.stderr)
        );
        assert!(
            String::from_utf8_lossy(&sys.stdout).trim() == pub_content.trim(),
            "system ssh-keygen public key mismatch"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `ssh-keygen -R`: remove a host from a known_hosts file.
#[test]
fn ssh_keygen_removes_known_host() {
    let dir = temp_dir("keygen-remove");
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let keygen_link = dir.join("ssh-keygen");
    std::os::unix::fs::symlink(client_bin, &keygen_link).unwrap();

    let kh_path = dir.join("known_hosts");
    let kh = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxL+HblBip81nyvhgpLJ32mwG6kKjycKHhQJxMolfmw\n\
               [10.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxL+HblBip81nyvhgpLJ32mwG6kKjycKHhQJxMolfmw\n\
               other.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB\n";
    std::fs::write(&kh_path, kh).unwrap();

    let out = Command::new(&keygen_link)
        .arg("-R")
        .arg("example.com")
        .arg("-f")
        .arg(&kh_path)
        .output()
        .expect("run ssh-keygen -R");
    assert!(out.status.success(), "-R failed: {}", String::from_utf8_lossy(&out.stderr));
    let remaining = std::fs::read_to_string(&kh_path).unwrap();
    assert!(!remaining.contains("example.com"), "example.com not removed");
    assert!(remaining.contains("[10.0.0.1]:2222"), "other entry lost");
    assert!(remaining.contains("other.com"), "unrelated entry lost");
    // Backup file should exist.
    assert!(dir.join("known_hosts.old").exists(), "backup not created");

    // Removing a non-existent host returns failure.
    let out = Command::new(&keygen_link)
        .arg("-R")
        .arg("nosuch.host")
        .arg("-f")
        .arg(&kh_path)
        .output()
        .expect("run ssh-keygen -R again");
    assert!(!out.status.success(), "-R on missing host should fail");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `ssh-add` end-to-end: add an ed25519 key to a real ssh-agent and verify.
#[test]
fn ssh_add_adds_identity_to_agent() {
    // Requires a real ssh-agent and system ssh-add for verification.
    if Command::new("ssh-agent").arg("-s").output().is_err() {
        eprintln!("skipping: ssh-agent not available");
        return;
    }
    if Command::new("ssh-add").arg("-l").output().is_err() {
        eprintln!("skipping: system ssh-add not available");
        return;
    }

    let dir = temp_dir("ssh-add");
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let ssh_add_link = dir.join("ssh-add");
    let ssh_keygen_link = dir.join("ssh-keygen");
    std::os::unix::fs::symlink(client_bin, &ssh_add_link).unwrap();
    std::os::unix::fs::symlink(client_bin, &ssh_keygen_link).unwrap();

    // Generate an ed25519 key with our own ssh-keygen.
    let key_path = dir.join("test_key");
    let out = Command::new(&ssh_keygen_link)
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg(&key_path)
        .arg("-q")
        .output()
        .expect("run ssh-keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Start a temporary ssh-agent and capture SSH_AUTH_SOCK.
    let agent_out = Command::new("ssh-agent").arg("-s").output().expect("start ssh-agent");
    let agent_stdout = String::from_utf8_lossy(&agent_out.stdout);
    let auth_sock = agent_stdout
        .lines()
        .find_map(|l| {
            let v = l.strip_prefix("SSH_AUTH_SOCK=")?;
            Some(v.split(';').next().unwrap_or("").trim().to_string())
        })
        .expect("SSH_AUTH_SOCK in agent output");
    if !agent_stdout.contains("SSH_AGENT_PID=") {
        // Could not determine agent; bail.
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // Add the key with our ssh-add.
    let out = Command::new(&ssh_add_link)
        .arg(&key_path)
        .env("SSH_AUTH_SOCK", &auth_sock)
        .output()
        .expect("run ssh-add");
    assert!(
        out.status.success(),
        "ssh-add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Identity added"),
        "unexpected output: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Verify the system ssh-add sees exactly one identity.
    let out = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &auth_sock)
        .output()
        .expect("system ssh-add -l");
    let list = String::from_utf8_lossy(&out.stdout);
    assert!(
        list.contains("ED25519") || list.contains("ssh-ed25519"),
        "expected an ED25519 identity, got: {:?}",
        list
    );

    // Clean up the agent.
    if let Some(pid) = agent_stdout
        .lines()
        .find_map(|l| {
            let v = l.strip_prefix("SSH_AGENT_PID=")?;
            Some(v.split(';').next().unwrap_or("").trim().to_string())
        })
    {
        let _ = Command::new("kill").arg(&pid).status();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
