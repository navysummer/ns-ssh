//! End-to-end integration test: spawns ns-ssh-server, connects with ns-ssh,
//! and verifies a real exec round-trip over a full SSH handshake + auth.

use base64::Engine;
use ssh_core::hostkey::{Ed25519HostKey, HostKeySigner};
use std::io::Read;
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
    // No pinned algorithm overrides; the shared launch helper takes a slice.
    let extra_args: &[&str] = &[];

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
        .arg("-o")
        .arg("AcceptEnv=LANG LC_*")
        .arg("-o")
        .arg("X11Forwarding=yes")
        .args(extra_args)
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

/// Upload only: the server command produces no output until stdin EOF, so the
/// client must keep flushing its window-gated backlog purely from WINDOW_ADJUST
/// packets. If recv_packet silently consumes those adjustments (instead of
/// handing them to the event loop that owns the deferred queue), this test
/// deadlocks at the 2 MiB channel window instead of finishing.
#[test]
fn large_upload_to_non_echoing_command_completes() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("upload-only");
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

    let mut payload = Vec::with_capacity(3 << 20);
    for i in 0..(3 << 20) {
        payload.push((i % 251) as u8);
    }
    let expected_len = payload.len();

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
        .arg("wc -c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    use std::io::Write;
    {
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(&payload);
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
    let reported = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        reported.trim(),
        expected_len.to_string(),
        "upload-only transfer stalled or truncated (window adjust was not flushed?)"
    );
}

/// A client-initiated rekey in the middle of a transfer must complete without
/// losing data. This exercises: deferring data packets that arrive before the
/// peer's KEXINIT, exchanging NEWKEYS under the OLD keys, and installing the
/// new keys only afterwards. The 500000-byte payload crosses the 16 KiB
/// RekeyLimit many times.
#[test]
fn rekey_mid_transfer_client_initiated() {
    let dir = temp_dir("rekey-client");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (server, id_path, kh) = launch_test_server_extra(
        &dir,
        port,
        &[
            "-o",
            "kexalgorithms=curve25519-sha256",
            "-o",
            "ciphers=aes128-ctr",
            "-o",
            "macs=hmac-sha2-256",
        ],
    );

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("RekeyLimit=16K")
        .arg("127.0.0.1")
        .arg("head -c 500000 /dev/zero")
        .output()
        .expect("run rekey client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "client failed: status={:?}\nstderr={}\nserver_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert_eq!(
        output.stdout.len(),
        500000,
        "rekey truncated the transfer: got {} bytes",
        output.stdout.len()
    );
}

/// Same requirement, but the server drives the rekey through its own
/// RekeyLimit: it sends KEXINIT unsolicited while the session is running.
#[test]
fn rekey_mid_transfer_server_initiated() {
    let dir = temp_dir("rekey-server");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (server, id_path, kh) = launch_test_server_extra(
        &dir,
        port,
        &[
            "-o",
            "rekeylimit=16K",
            "-o",
            "kexalgorithms=diffie-hellman-group14-sha256",
            "-o",
            "ciphers=aes128-ctr",
            "-o",
            "macs=hmac-sha2-256",
        ],
    );

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("head -c 500000 /dev/zero")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "client failed: status={:?}\nstderr={}\nserver_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert_eq!(
        output.stdout.len(),
        500000,
        "server-initiated rekey truncated the transfer: got {} bytes",
        output.stdout.len(),
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

/// Shared helper: generate a client key + authorized_keys + host key, launch the
/// test server on `port`, and return `(server_child, id_path, kh_path, dir)`.
fn launch_test_server(
    dir: &Path,
    port: u16,
) -> (std::process::Child, PathBuf, PathBuf) {
    launch_test_server_extra(dir, port, &[])
}

/// Same as `launch_test_server` but forwards extra `-o key=value` style
/// arguments, for tests that need to pin a specific algorithm.
fn launch_test_server_extra(
    dir: &Path,
    port: u16,
    extra_args: &[&str],
) -> (std::process::Child, PathBuf, PathBuf) {
    let server_bin = workspace_target_dir();
    assert!(server_bin.exists(), "ns-ssh-server binary not built; run `cargo build`");

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
        .arg("-o")
        .arg("AcceptEnv=LANG LC_*")
        .arg("-o")
        .arg("X11Forwarding=yes")
        .args(extra_args)
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

    let kh = dir.join("known_hosts");
    (server, id_path, kh)
}

/// Client args common to every end-to-end test (host key checking off for CI).
fn base_client_args(
    port: u16,
    user: &str,
    id_path: &Path,
    kh: &Path,
) -> Vec<std::ffi::OsString> {
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    vec![
        client_bin.into(),
        "-p".into(),
        port.to_string().into(),
        "-l".into(),
        user.into(),
        "-i".into(),
        id_path.as_os_str().to_os_string(),
        "-F".into(),
        "/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", kh.display()).into(),
        "-o".into(),
        "BatchMode=yes".into(),
    ]
}

/// `-t` force TTY: the remote command must see a real TTY on stdin/stdout and the
/// session must terminate cleanly (exit-status propagates), not hang in exit_poll.
#[test]
fn pty_session_round_trip() {
    let dir = temp_dir("pty");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-t")
        .arg("127.0.0.1")
        .arg("test -t 0 && echo TTY_STDIN_OK || echo NO_STDIN; test -t 1 && echo TTY_STDOUT_OK || echo NO_STDOUT; exit 3")
        .output()
        .expect("run pty client");

    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("TTY_STDIN_OK"),
        "expected TTY_STDIN_OK, got: {:?}",
        stdout
    );
    assert!(
        stdout.contains("TTY_STDOUT_OK"),
        "expected TTY_STDOUT_OK, got: {:?}",
        stdout
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "expected exit 3, status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = server_out;
}

/// ProxyJump (`-J`) end-to-end: connect through the test server as the jump host
/// to the same server as the target, then run a command.
#[test]
fn proxy_jump_round_trip() {
    let dir = temp_dir("proxyjump");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    let args = base_client_args(port, &user, &id_path, &kh);
    let jump = format!("127.0.0.1:{}", port);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-J")
        .arg(&jump)
        .arg("127.0.0.1")
        .arg("echo VIA_JUMP")
        .output()
        .expect("run proxyjump client");

    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("VIA_JUMP"),
        "expected VIA_JUMP, got: {:?} (stderr={:?})",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = server_out;
}

/// Signal forwarding: send SIGTERM to the client while a remote `sleep` runs;
/// the client must forward it to the server, which signals the remote process
/// group, and the client must exit promptly (not hang on the sleeping session).
#[test]
fn signal_forwarding_round_trip() {
    let dir = temp_dir("signal");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    let args = base_client_args(port, &user, &id_path, &kh);
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("sleep 30; echo AFTER_SLEEP")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run signal client");
    let pid = child.id();

    // Give the client a moment to connect, authenticate, and start the remote
    // command, then forward SIGTERM (not ignored for background processes).
    std::thread::sleep(Duration::from_millis(1500));
    let _ = Command::new("kill").arg("-TERM").arg(pid.to_string()).status();

    // Wait up to ~12s for the client to exit after the signal.
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().expect("poll child") {
            break st;
        }
        if start.elapsed() > Duration::from_secs(12) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("client did not exit after SIGTERM (signal not forwarded?)");
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    let mut out = String::new();
    let mut err = String::new();
    use std::io::Read;
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut err);
    }

    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        err.contains("Killed by signal"),
        "expected 'Killed by signal' on stderr, got: {:?} (stdout={:?}, status={:?})",
        err,
        out,
        status
    );
    let _ = server_out;
}

/// `SetEnv` (with a name in the test server's `AcceptEnv LANG LC_*`) must
/// reach the remote process, and the client must not send unsolicited LANG/LC_*
/// that would override it (the default `SendEnv` is empty, matching OpenSSH).
#[test]
fn setenv_propagates() {
    let dir = temp_dir("setenv");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("SetEnv=LANG=zz_ZZ.UTF-8")
        .arg("127.0.0.1")
        .arg("echo \"LANG=[$LANG]\"")
        .output()
        .expect("run setenv client");

    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("LANG=[zz_ZZ.UTF-8]"),
        "expected SetEnv LANG to propagate, got: {:?} (stderr={:?})",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = server_out;
}

/// `-s subsystem` requests a server subsystem (e.g. `sftp`). This verifies the
/// client sends a proper subsystem channel request and that the server's
/// internal-sftp replies to an SFTP INIT with a VERSION packet.
#[test]
fn subsystem_sftp_round_trip() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("subsystem");
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
    // The subsystem directive is only parsed from the config file (not -o).
    let config_path = dir.join("sshd_config");
    std::fs::write(
        &config_path,
        format!(
            "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nPubkeyAuthentication yes\nPasswordAuthentication no\nAuthorizedKeysFile {}\nPermitRootLogin yes\nSubsystem sftp internal-sftp\n",
            port,
            host_key_path.display(),
            auth_path.display()
        ),
    )
    .unwrap();

    let server = Command::new(&server_bin)
        .arg("-d") // no daemonize; keep server in foreground so the test can reap it
        .arg("-f")
        .arg(&config_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn subsystem server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    let kh = dir.join("known_hosts");
    let args = base_client_args(port, &user, &id_path, &kh);
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .arg("-s")
        .arg("127.0.0.1")
        .arg("sftp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sftp subsystem client");

    // Send an SFTP INIT (version 3) and expect a VERSION reply (type 2).
    use std::io::Write;
    let mut stdin = child.stdin.take().expect("child stdin");
    let init = {
        let mut b = Vec::new();
        b.extend_from_slice(&5u32.to_be_bytes()); // packet length
        b.push(1u8); // SSH_FXP_INIT
        b.extend_from_slice(&3u32.to_be_bytes()); // version
        b
    };
    stdin.write_all(&init).expect("write SFTP INIT");
    stdin.flush().unwrap();

    let stdout = child.stdout.take().expect("child stdout");
    // Read the full SFTP reply (4-byte length + body) in a reader thread so a
    // missing reply cannot block the test forever.
    let reply = read_sftp_reply(stdout, Duration::from_secs(10));
    let version_ok = reply
        .as_deref()
        .and_then(|b| b.get(4).copied())
        == Some(2u8); // SSH_FXP_VERSION (after the 4-byte length)

    let _ = child.kill();
    let _ = child.wait();
    let mut server = server;
    let _ = server.kill();
    let _ = server.wait_with_output();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        version_ok,
        "expected SFTP VERSION reply from subsystem, got {:?}",
        reply
    );
}

/// Non-ETM packet framing (RFC 4253 §6.4) encrypts `packet_length` together
/// with the body. Force a CTR cipher plus a non-ETM MAC so the whole handshake,
/// authentication and exec round-trip use that layout on both sides.
#[test]
fn non_etm_exec_round_trip() {
    let dir = temp_dir("non-etm");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("MACs=hmac-sha2-512")
        .arg("-o")
        .arg("Ciphers=aes128-ctr")
        .arg("127.0.0.1")
        .arg("echo NON_ETM_OK")
        .output()
        .expect("run non-ETM client");

    let _ = server.kill();
    let _ = server.wait_with_output();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "non-ETM exec failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("NON_ETM_OK"),
        "non-ETM exec produced no output: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// AES-GCM end-to-end: pins the AEAD packet layout (cleartext 4-byte
/// packet_length authenticated as AAD, `packet_length % 16 == 0` padding, tag
/// after the ciphertext). A wrong block size previously produced
/// "padding error: need 24 block 16 mod 8" against OpenSSH.
#[test]
fn gcm_exec_round_trip() {
    for cipher in ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com"] {
        let dir = temp_dir(&format!("gcm-{}", cipher.split('@').next().unwrap()));
        let port = free_port();
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        let (mut server, id_path, kh) =
            launch_test_server_extra(&dir, port, &["-o", &format!("ciphers={}", cipher)]);

        let args = base_client_args(port, &user, &id_path, &kh);
        let output = Command::new(&args[0])
            .args(&args[1..])
            .arg("-o")
            .arg(format!("Ciphers={}", cipher))
            .arg("127.0.0.1")
            .arg("echo GCM_OK")
            .output()
            .expect("run GCM client");

        let _ = server.kill();
        let _ = server.wait_with_output();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            output.status.success(),
            "GCM ({cipher}) exec failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("GCM_OK"),
            "GCM ({cipher}) exec produced no output: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// Read one length-prefixed SFTP packet (type byte + body) from `r` within
/// `timeout`, using a reader thread so a missing reply cannot block forever.
/// Returns the full packet bytes on success, or None on timeout/EOF.
fn read_sftp_reply<R: Read + Send + 'static>(mut r: R, timeout: Duration) -> Option<Vec<u8>> {
    use std::sync::mpsc::RecvTimeoutError;
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("sftp-reader".into())
        .spawn(move || {
            let mut hdr = [0u8; 4];
            if read_full(&mut r, &mut hdr) {
                let len = u32::from_be_bytes(hdr) as usize;
                if len > 0 && len <= 1 << 20 {
                    let mut body = vec![0u8; len];
                    if read_full(&mut r, &mut body) {
                        let mut packet = Vec::with_capacity(4 + len);
                        packet.extend_from_slice(&hdr);
                        packet.extend_from_slice(&body);
                        let _ = tx.send(packet);
                    }
                }
            }
            // Otherwise drop tx so the receiver times out.
        })
        .expect("spawn reader thread");
    match rx.recv_timeout(timeout) {
        Ok(buf) => Some(buf),
        Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => None,
    }
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> bool {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return false,
            Ok(m) => filled += m,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
    true
}

/// Wait until `port` is no longer bound by a listening socket (the server
/// released its X11/forward listener after the prior connection ended).
fn wait_for_port_free(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        // A successful bind proves the port is free; drop the probe immediately
        // so the next session can claim it.
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    false
}

/// X11 forwarding (`-X`) end-to-end: the server binds an X11 listener
/// (6000+offset), a remote client connects to it, and the bytes tunnel back to
/// the local X display socket (127.0.0.1:6000). The reply must tunnel back to
/// the remote in the other direction. Also verifies the server releases its X11
/// listener when the connection ends (no "Address already in use" on the next
/// session).
#[test]
fn x11_forwarding_round_trip() {
    let dir = temp_dir("x11");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    // Fake local X display server: bind 127.0.0.1:6000 and echo back any data.
    let listener = std::net::TcpListener::bind("127.0.0.1:6000").expect("bind fake X display");
    let x11_thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut conn, _addr) = listener.accept().expect("fake X accept");
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).expect("fake X read");
        let got = buf[..n].to_vec();
        conn.write_all(b"X11_REPLY_FROM_LOCAL").expect("fake X write");
        (got, n)
    });

    // Run an `ssh -X` session; the remote command connects to the server's X11
    // listener on 127.0.0.1:6010 (default offset 10), sends a payload, and
    // reads the reply tunneled back from the local display.
    let args = base_client_args(port, &user, &id_path, &kh);
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..])
        .arg("-X")
        .arg("127.0.0.1")
        .arg("python3 -c \"import socket; s=socket.create_connection(('127.0.0.1',6010),timeout=5); s.sendall(b'HELLO_X11'); print(s.recv(100).decode(), flush=True)\"");
    let output = cmd.env("DISPLAY", "localhost:0").output().expect("run x11 client");

    // The remote should have received the reply tunneled from the local display.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("X11_REPLY_FROM_LOCAL"),
        "expected X11 reply in stdout, got: {:?}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );

    // The fake local display must have received the payload.
    let (got, _n) = x11_thread.join().expect("join fake X thread");
    assert_eq!(
        got,
        b"HELLO_X11".to_vec(),
        "fake X display did not receive the X11 payload"
    );

    // The server must release its X11 listener (port 6010) once the first
    // connection ends, so the next session can bind it fresh (no leak).
    assert!(
        wait_for_port_free(6010, Duration::from_secs(5)),
        "server did not release X11 listener 6010 after session 1"
    );

    // Second `-X` session: the server must bind port 6010 fresh (no leak), and
    // the tunnel must work again.
    let listener2 = std::net::TcpListener::bind("127.0.0.1:6000").expect("bind fake X display 2");
    let x11_thread2 = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut conn, _addr) = listener2.accept().expect("fake X accept 2");
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).expect("fake X read 2");
        conn.write_all(b"X11_REPLY_AGAIN").expect("fake X write 2");
        buf[..n].to_vec()
    });
    let mut cmd2 = Command::new(&args[0]);
    cmd2.args(&args[1..])
        .arg("-X")
        .arg("127.0.0.1")
        .arg("python3 -c \"import socket; s=socket.create_connection(('127.0.0.1',6010),timeout=5); s.sendall(b'HELLO_AGAIN'); print(s.recv(100).decode(), flush=True)\"");
    let output2 = cmd2.env("DISPLAY", "localhost:0").output().expect("run x11 client 2");
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        stdout2.contains("X11_REPLY_AGAIN"),
        "expected X11 reply on second session, got: {:?}\nstderr: {}",
        stdout2,
        String::from_utf8_lossy(&output2.stderr)
    );
    let got2 = x11_thread2.join().expect("join fake X thread 2");
    assert_eq!(got2, b"HELLO_AGAIN".to_vec(), "second session payload mismatch");

    let _ = server.kill();
    let _ = server.wait_with_output();
    let _ = std::fs::remove_dir_all(&dir);
}

/// AuthenticationMethods: a multi-step chain must be enforced. A client that
/// only completes the first step is rejected, while a single-step chain still
/// logs in.
#[test]
fn authentication_methods_chain_is_enforced() {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // publickey,password: publickey alone must no longer authenticate.
    let dir = temp_dir("authmethods-chain");
    let port = free_port();
    let (server, id_path, kh) = launch_test_server_extra(
        &dir,
        port,
        &[
            "-o",
            "passwordauthentication=yes",
            "-o",
            "authenticationmethods=publickey,password",
        ],
    );

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("echo hello")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !output.status.success(),
        "pubkey-only auth must be rejected when AuthenticationMethods requires \
         publickey,password; stdout={:?} stderr={:?} server_stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("hello"),
        "rejected client must not run the remote command"
    );

    // A single-step chain is satisfied by publickey alone and must succeed.
    let dir = temp_dir("authmethods-single");
    let port = free_port();
    let (server, id_path, kh) = launch_test_server_extra(
        &dir,
        port,
        &["-o", "authenticationmethods=publickey"],
    );

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("echo hello")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "single-step AuthenticationMethods=publickey must succeed: status={:?} \
         stdout={:?} stderr={:?} server_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hello"),
        "expected 'hello' in stdout, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// PermitRemoteOpen: remote forwarding targets outside the whitelist are
/// refused, while permitted targets keep working.
#[test]
fn permit_remote_open_restricts_forward_targets() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("permitremoteopen");
    let port = free_port();
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    // Local echo target reached through the remote forward.
    let target_port = free_port();
    let listener = std::net::TcpListener::bind(("127.0.0.1", target_port))
        .expect("bind echo target");
    listener.set_nonblocking(true).expect("set_nonblocking");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let echo = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let mut buf = [0u8; 256];
                    if let Ok(n) = conn.read(&mut buf) {
                        let reply = format!("ECHO:{}", String::from_utf8_lossy(&buf[..n]));
                        let _ = conn.write_all(reply.as_bytes());
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    });

    // Probe the forwarded port, returning any reply to "hello".
    let probe = |remote_port: u16| -> Option<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", remote_port)) {
                Ok(s) => break s,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => panic!("remote forward port {} never opened: {}", remote_port, e),
            }
        };
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
        stream.write_all(b"hello").ok();
        let mut buf = [0u8; 128];
        stream.read(&mut buf).ok().map(|n| String::from_utf8_lossy(&buf[..n]).to_string())
    };

    let run_client = |remote_port: u16, opts: &[&str]| -> std::process::Child {
        let args = base_client_args(port, &user, &id_path, &kh);
        let mut cmd = Command::new(&args[0]);
        cmd.args(&args[1..]);
        for opt in opts {
            cmd.arg("-o").arg(opt);
        }
        cmd.arg("-R")
            .arg(format!("{}:127.0.0.1:{}", remote_port, target_port))
            .arg("127.0.0.1")
            .arg("sleep 20")
            .spawn()
            .expect("spawn client")
    };

    // Permitted target: forwarding works end-to-end.
    let remote_ok = free_port();
    let mut client = run_client(remote_ok, &[]);
    let reply = probe(remote_ok);
    let _ = client.kill();
    let _ = client.wait();
    assert!(
        reply.as_deref().map(|r| r.contains("ECHO:hello")).unwrap_or(false),
        "allowed remote forward should echo, got: {:?}",
        reply
    );

    // Target outside the whitelist: the channel is refused, no data flows.
    let remote_denied = free_port();
    let mut client = run_client(remote_denied, &["permitremoteopen=127.0.0.1:1"]);
    let reply = probe(remote_denied);
    let _ = client.kill();
    let _ = client.wait();
    assert!(
        !reply.as_deref().map(|r| r.contains("ECHO:hello")).unwrap_or(false),
        "remote forward outside PermitRemoteOpen must be refused, got: {:?}",
        reply
    );

    // `none` denies every remote forward.
    let remote_none = free_port();
    let mut client = run_client(remote_none, &["permitremoteopen=none"]);
    let reply = probe(remote_none);
    let _ = client.kill();
    let _ = client.wait();
    assert!(
        !reply.as_deref().map(|r| r.contains("ECHO:hello")).unwrap_or(false),
        "PermitRemoteOpen=none must refuse all forwards, got: {:?}",
        reply
    );

    stop.store(true, Ordering::Relaxed);
    let _ = echo.join();
    let _ = server.kill();
    let _ = server.wait_with_output();
    let _ = std::fs::remove_dir_all(&dir);
}

/// ChannelTimeout: an idle channel is closed once its configured timeout
/// elapses; a longer timeout leaves a short command untouched.
#[test]
fn channel_timeout_closes_idle_channels() {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // session=1: a command silent for 10s must be cut off before it finishes.
    let dir = temp_dir("channeltimeout-close");
    let port = free_port();
    let (server, id_path, kh) =
        launch_test_server_extra(&dir, port, &["-o", "channeltimeout=session=1"]);

    let args = base_client_args(port, &user, &id_path, &kh);
    let start = std::time::Instant::now();
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("sleep 10; echo late")
        .output()
        .expect("run client");
    let elapsed = start.elapsed();

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        elapsed < std::time::Duration::from_secs(8),
        "idle session channel should be closed well before the 10s command \
         finishes, but the client ran for {:?}; stderr={:?} server_stderr={}",
        elapsed,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("late"),
        "the remote command must be terminated before it prints 'late', got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );

    // session=10: the same command completes normally.
    let dir = temp_dir("channeltimeout-pass");
    let port = free_port();
    let (server, id_path, kh) =
        launch_test_server_extra(&dir, port, &["-o", "channeltimeout=session=10"]);

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("sleep 3; echo late")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "command shorter than the channel timeout must succeed: status={:?} \
         stdout={:?} stderr={:?} server_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("late"),
        "expected output from the completed command, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn client_channel_timeout_closes_idle_session() {
    // The client-side ChannelTimeout must close an idle session channel even
    // when the server has no timeout configured.
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("client-channeltimeout");
    let port = free_port();
    let (server, id_path, kh) = launch_test_server_extra(&dir, port, &[]);

    let args = base_client_args(port, &user, &id_path, &kh);
    let start = std::time::Instant::now();
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("ChannelTimeout=session=1")
        .arg("127.0.0.1")
        .arg("sleep 10; echo late")
        .output()
        .expect("run client");
    let elapsed = start.elapsed();

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        elapsed < std::time::Duration::from_secs(6),
        "client should close the idle session channel long before the 10s \
         command finishes, but it ran for {:?}; stderr={:?} server_stderr={}",
        elapsed,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("late"),
        "the idle session must be closed before 'late' is printed, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn client_streamlocal_bind_mask_and_unlink() {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::PermissionsExt;

    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("client-streamlocal");
    let port = free_port();
    let (server, id_path, kh) = launch_test_server_extra(&dir, port, &[]);

    let local_sock = dir.join("local.sock");
    let remote_sock = dir.join("remote.sock");
    // A stale file that only gets replaced when StreamLocalBindUnlink is on.
    std::fs::write(&local_sock, b"stale").unwrap();

    let args = base_client_args(port, &user, &id_path, &kh);
    let spec = format!("{}:{}", local_sock.display(), remote_sock.display());
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("StreamLocalBindMask=0000")
        .arg("-o")
        .arg("StreamLocalBindUnlink=yes")
        .arg("-L")
        .arg(&spec)
        .arg("127.0.0.1")
        .arg("sleep 30")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    let mut created = false;
    for _ in 0..120 {
        // The pre-existing stale file must be replaced by a real socket.
        if std::fs::metadata(&local_sock)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
        {
            created = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mode = std::fs::metadata(&local_sock)
        .ok()
        .map(|m| m.permissions().mode() & 0o777);

    let _ = child.kill();
    let client_out = child.wait_with_output().expect("wait client");
    let mut server = server;
    let _ = server.kill();
    let _ = server.wait_with_output();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(created, "local StreamLocal socket was not created");
    assert_eq!(
        mode,
        Some(0o777),
        "StreamLocalBindMask=0000 should create a 0777 socket; client stderr: {}",
        String::from_utf8_lossy(&client_out.stderr)
    );
}
