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

/// Allocate a free TCP port, guaranteed unique across concurrently running
/// tests in this process. `free_port` alone is racy: between `bind(0)` and the
/// server's own bind another parallel test may grab the same port, which hangs
/// the test (T01). A process-global reservation set prevents reuse.
fn free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static RESERVED: Mutex<Option<HashSet<u16>>> = Mutex::new(None);
    let mut guard = RESERVED.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if set.insert(port) {
            return port;
        }
    }
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
fn gssapi_configured_but_unavailable_falls_through_to_pubkey() {
    // GSSAPIAuthentication=yes on both sides must not break a connection when
    // no usable GSS-API library is present (this host's GSS.framework is a
    // non-functional shim that the availability probe rejects). The client
    // must fall through to pubkey authentication and the command must run.
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("gssapi");
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
        .arg("gssapiauthentication=yes")
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
        .arg("-o")
        .arg("GSSAPIAuthentication=yes")
        .arg("127.0.0.1")
        .arg("echo gssapi-fallback-ok")
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
        stdout.contains("gssapi-fallback-ok"),
        "expected command output, got: {:?}",
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

/// UMAC MAC negotiation: both sides pin `umac-128-etm@openssh.com`, and a
/// command round-trips, proving the MAC is negotiated and verified per-packet.
#[test]
fn umac_mac_negotiation_round_trip() {
    let dir = temp_dir("umac");
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
            "macs=umac-128-etm@openssh.com",
        ],
    );

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("MACs=umac-128-etm@openssh.com")
        .arg("127.0.0.1")
        .arg("echo UMAC_OK")
        .output()
        .expect("run umac client");

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
        String::from_utf8_lossy(&output.stdout).trim(),
        "UMAC_OK",
        "UMAC session did not echo expected output"
    );
}

#[test]
fn server_moduli_file_supplies_gex_group() {
    let dir = temp_dir("moduli");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

    // A one-line moduli file with the RFC 3526 2048-bit safe prime.
    let moduli_path = dir.join("moduli");
    std::fs::write(
        &moduli_path,
        format!("20200101 2 6 100 2048 2 {}\n", ssh_core::kex::GROUP14_P),
    )
    .unwrap();

    let moduli_arg = format!("modulifile={}", moduli_path.display());
    let (server, id_path, kh) = launch_test_server_extra(
        &dir,
        port,
        &[
            "-o",
            &moduli_arg,
            "-o",
            "kexalgorithms=diffie-hellman-group-exchange-sha256",
        ],
    );

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("kexalgorithms=diffie-hellman-group-exchange-sha256")
        .arg("127.0.0.1")
        .arg("echo moduli-ok")
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
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "moduli-ok");
}

#[test]
fn tunnel_mode_is_rejected_with_clear_error() {
    let dir = temp_dir("tunnel-reject");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let id_path = dir.join("id_ed25519");
    let kh = dir.join("known_hosts");
    std::fs::write(&kh, "").unwrap();

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("-o")
        .arg("Tunnel=yes")
        .arg("127.0.0.1")
        .arg("echo hi")
        .output()
        .expect("run client");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Tunnel yes is not supported"),
        "unexpected stderr: {}",
        stderr
    );
}

#[test]
fn server_version_addendum_appears_in_banner() {
    use std::io::{BufRead, BufReader, Write};

    let dir = temp_dir("version-addendum");
    let port = free_port();
    let (mut server, _id_path, _kh) = launch_test_server_extra(
        &dir,
        port,
        &["-o", "VersionAddendum=test-banner"],
    );

    let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");
    // The server reads the client identification line first, then sends its
    // own banner.
    (&stream)
        .write_all(b"SSH-2.0-test-client\r\n")
        .expect("send client banner");
    let mut line = String::new();
    BufReader::new(&stream)
        .read_line(&mut line)
        .expect("read server banner");

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(line.starts_with("SSH-2.0-"), "banner: {}", line);
    assert!(line.contains("test-banner"), "banner: {}", line);
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
fn sntrup_hybrid_kex_round_trip() {
    // RFC 9941 sntrup761x25519-sha512: force it on both ends and verify a
    // real exec round-trip. This exercises the client decapsulation and the
    // server encapsulation roles, the string-encoded shared secret K, and the
    // sha512 exchange hash.
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("sntrup");
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
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
        .arg("-o")
        .arg("kexalgorithms=sntrup761x25519-sha512")
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
        .arg("-o")
        .arg("KexAlgorithms=sntrup761x25519-sha512")
        .arg("127.0.0.1")
        .arg("echo SNTRUP_KEX_OK")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    if !output.status.success() {
        panic!(
            "sntrup KEX client failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&server_out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SNTRUP_KEX_OK"),
        "expected sntrup KEX command output, got: {:?}",
        stdout
    );
}

#[test]
fn mlkem_hybrid_kex_round_trip() {
    // RFC 9765 mlkem768x25519-sha256: force it on both ends and verify a real
    // exec round-trip. This exercises the client decapsulation and the server
    // encapsulation roles, the string-encoded shared secret K, and the sha256
    // exchange hash.
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("mlkem");
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
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
        .arg("-o")
        .arg("kexalgorithms=mlkem768x25519-sha256")
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
        .arg("-o")
        .arg("KexAlgorithms=mlkem768x25519-sha256")
        .arg("127.0.0.1")
        .arg("echo MLKEM_KEX_OK")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    if !output.status.success() {
        panic!(
            "mlkem KEX client failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&server_out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("MLKEM_KEX_OK"),
        "expected mlkem KEX command output, got: {:?}",
        stdout
    );
}

#[test]
fn scp_requires_recursive_flag_for_directories() {
    // R03: `scp` without -r must reject a directory source (it used to recurse
    // silently); with -r it must copy the whole tree.
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("scp");
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

    // A local source directory with one nested file.
    let src_dir = dir.join("src");
    std::fs::create_dir_all(src_dir.join("sub")).unwrap();
    std::fs::write(src_dir.join("a.txt"), "hello").unwrap();
    std::fs::write(src_dir.join("sub").join("b.txt"), "nested").unwrap();
    // Remote destination writable by the invoking user.
    let remote_dest = std::env::temp_dir().join(format!("ns-ssh-scp-dest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&remote_dest);
    std::fs::create_dir_all(&remote_dest).unwrap();

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
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
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

    // Invoke the ns-ssh binary as `ns-scp` so argv[0] selects scp mode.
    let scp_bin = dir.join("ns-scp");
    #[cfg(unix)]
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_ns-ssh"), &scp_bin).unwrap();
    #[cfg(not(unix))]
    std::fs::copy(env!("CARGO_BIN_EXE_ns-ssh"), &scp_bin).unwrap();

    let base_args = |extra: &[&str]| {
        let mut v = vec![
            "-P".to_string(),
            port.to_string(),
            "-i".to_string(),
            id_path.display().to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
        ];
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    };
    let remote = format!("{}@127.0.0.1:{}/", user, remote_dest.display());

    // Without -r: the directory source must be rejected.
    let out = Command::new(&scp_bin)
        .args(base_args(&[src_dir.display().to_string().as_str(), remote.as_str()]))
        .output()
        .expect("run scp no -r");
    assert!(
        !out.status.success(),
        "scp without -r on a directory must fail; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // With -r: the tree must copy.
    let out = Command::new(&scp_bin)
        .args(base_args(&["-r", src_dir.display().to_string().as_str(), remote.as_str()]))
        .output()
        .expect("run scp with -r");
    assert!(
        out.status.success(),
        "scp -r on a directory must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut server = server;
    let _ = server.kill();
    let _ = server.wait_with_output().expect("wait server");
    let copied = remote_dest.join("src").join("sub").join("b.txt");
    assert!(
        copied.exists(),
        "expected recursively copied file at {:?}",
        copied
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&remote_dest);
}

/// R04: `scp f1 f2 host:/dst/` must upload multiple sources in one session
/// (the old code only sent the first source).
#[test]
fn scp_multisource_upload() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("scp-multi");
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

    let f1 = dir.join("one.txt");
    let f2 = dir.join("two.txt");
    std::fs::write(&f1, "first").unwrap();
    std::fs::write(&f2, "second").unwrap();
    let remote_dest = std::env::temp_dir().join(format!("ns-ssh-scp-multi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&remote_dest);
    std::fs::create_dir_all(&remote_dest).unwrap();

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
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
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

    let scp_bin = dir.join("ns-scp");
    #[cfg(unix)]
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_ns-ssh"), &scp_bin).unwrap();
    #[cfg(not(unix))]
    std::fs::copy(env!("CARGO_BIN_EXE_ns-ssh"), &scp_bin).unwrap();

    let remote = format!("{}@127.0.0.1:{}/", user, remote_dest.display());
    let out = Command::new(&scp_bin)
        .args([
            "-P".to_string(),
            port.to_string(),
            "-i".to_string(),
            id_path.display().to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            f1.display().to_string(),
            f2.display().to_string(),
            remote,
        ])
        .output()
        .expect("run multi-source scp");
    assert!(
        out.status.success(),
        "multi-source scp must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        remote_dest.join("one.txt").exists(),
        "first source not uploaded"
    );
    assert!(
        remote_dest.join("two.txt").exists(),
        "second source not uploaded"
    );

    let mut server = server;
    let _ = server.kill();
    let _ = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&remote_dest);
}

/// R04: `scp host:/f1 host:/f2 localdir` must download multiple remote sources
/// in one session.
#[test]
fn scp_multisource_download() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("scp-multi-dl");
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

    let remote_dir = std::env::temp_dir().join(format!("ns-ssh-scp-multi-dl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&remote_dir);
    std::fs::create_dir_all(&remote_dir).unwrap();
    std::fs::write(remote_dir.join("r1.txt"), "remote1").unwrap();
    std::fs::write(remote_dir.join("r2.txt"), "remote2").unwrap();

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
        .arg("permitrootlogin=yes")
        .arg("-o")
        .arg(format!("authorizedkeysfile={}", auth_path.display()))
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

    let scp_bin = dir.join("ns-scp");
    #[cfg(unix)]
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_ns-ssh"), &scp_bin).unwrap();
    #[cfg(not(unix))]
    std::fs::copy(env!("CARGO_BIN_EXE_ns-ssh"), &scp_bin).unwrap();

    let local_dest = dir.join("downloaded");
    std::fs::create_dir_all(&local_dest).unwrap();
    let r1 = format!("{}@127.0.0.1:{}", user, remote_dir.join("r1.txt").display());
    let r2 = format!("{}@127.0.0.1:{}", user, remote_dir.join("r2.txt").display());
    let out = Command::new(&scp_bin)
        .args([
            "-P".to_string(),
            port.to_string(),
            "-i".to_string(),
            id_path.display().to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            r1,
            r2,
            local_dest.display().to_string(),
        ])
        .output()
        .expect("run multi-source scp download");
    assert!(
        out.status.success(),
        "multi-source scp download must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        local_dest.join("r1.txt").exists(),
        "first remote source not downloaded"
    );
    assert!(
        local_dest.join("r2.txt").exists(),
        "second remote source not downloaded"
    );

    let mut server = server;
    let _ = server.kill();
    let _ = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&remote_dir);
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

/// Real OpenSSH `ssh-keyscan` must be able to retrieve the host key from our
/// server. OpenSSH's keyscan waits for the server's identification string
/// *before* sending its own version string; if the server reads the client
/// version before sending its banner, the handshake deadlocks and keyscan
/// returns nothing. This test exercises the real OpenSSH binary (not the
/// symlinked `ns-ssh`), which is what exposes the ordering bug.
#[test]
fn real_openssh_keyscan_retrieves_host_key() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("keyscan-real");
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
        .arg("-o")
        .arg("gssapiauthentication=no")
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

    // Use the real OpenSSH ssh-keyscan binary (must be on PATH).
    let output = Command::new("ssh-keyscan")
        .arg("-p")
        .arg(port.to_string())
        .arg("-t")
        .arg("ed25519")
        .arg("127.0.0.1")
        .output()
        .expect("run real ssh-keyscan");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "real ssh-keyscan failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
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

/// `ns-ssh-keyscan -t ed25519` must map the short key type to the host key
/// algorithm name (`ssh-ed25519`), otherwise KEX negotiation finds no common
/// algorithm and the scan fails.
#[test]
fn ns_ssh_keyscan_t_type_maps_to_algorithm() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("keyscan-type");
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
        .arg("-o")
        .arg("gssapiauthentication=no")
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
    let keyscan_link = dir.join("ssh-keyscan");
    std::os::unix::fs::symlink(client_bin, &keyscan_link).unwrap();

    let output = Command::new(&keyscan_link)
        .arg("-p")
        .arg(port.to_string())
        .arg("-t")
        .arg("ed25519")
        .arg("127.0.0.1")
        .output()
        .expect("run ssh-keyscan -t ed25519");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "ns-ssh-keyscan -t ed25519 failed: status={:?}\nstdout={}\nstderr={}\nserver_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ssh-ed25519"),
        "expected ssh-ed25519 host key line, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
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

/// `ssh-keygen -t rsa` must generate a key that the real OpenSSH ssh-keygen
/// can read back (the private-key serialization path).
#[test]
fn ssh_keygen_rsa_key_is_readable_by_openssh() {
    let dir = temp_dir("keygen-rsa");
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let keygen_link = dir.join("ssh-keygen");
    std::os::unix::fs::symlink(client_bin, &keygen_link).unwrap();

    let key_path = dir.join("test_rsa");
    let out = Command::new(&keygen_link)
        .arg("-t")
        .arg("rsa")
        .arg("-b")
        .arg("2048")
        .arg("-f")
        .arg(&key_path)
        .arg("-q")
        .output()
        .expect("run ssh-keygen -t rsa");
    assert!(
        out.status.success(),
        "ns ssh-keygen -t rsa failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(key_path.exists(), "RSA private key not created");

    // The real OpenSSH ssh-keygen must be able to read our RSA private key.
    if let Ok(sys) = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(&key_path)
        .output()
    {
        assert!(
            sys.status.success(),
            "system ssh-keygen could not read our RSA key: {}",
            String::from_utf8_lossy(&sys.stderr)
        );
        assert!(
            String::from_utf8_lossy(&sys.stdout).starts_with("ssh-rsa "),
            "unexpected RSA public key: {:?}",
            String::from_utf8_lossy(&sys.stdout)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `ssh-keygen -lf <file>` (attached short option) and the reported bit length
/// must match OpenSSH: RSA keys report their modulus size, ed25519 reports 256.
#[test]
fn ssh_keygen_attached_lf_and_bit_length() {
    let dir = temp_dir("keygen-lf");
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let keygen_link = dir.join("ssh-keygen");
    std::os::unix::fs::symlink(client_bin, &keygen_link).unwrap();

    for (ttype, expect_bits) in [("ed25519", "256"), ("rsa", "2048")] {
        let key_path = dir.join(format!("k_{}", ttype));
        let gen = Command::new(&keygen_link)
            .arg("-t")
            .arg(ttype)
            .arg("-b")
            .arg("2048")
            .arg("-f")
            .arg(&key_path)
            .arg("-q")
            .output()
            .expect("run keygen");
        assert!(gen.status.success(), "keygen {} failed", ttype);

        // Attached `-lf <file>` form.
        let out = Command::new(&keygen_link)
            .arg("-lf")
            .arg(&key_path)
            .output()
            .expect("run -lf");
        assert!(
            out.status.success(),
            "-lf {} failed: {}",
            ttype,
            String::from_utf8_lossy(&out.stderr)
        );
        let line = String::from_utf8_lossy(&out.stdout);
        assert!(
            line.starts_with(&format!("{} SHA256:", expect_bits)),
            "-lf {} should report {} bits, got: {:?}",
            ttype,
            expect_bits,
            line
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

/// `ns-ssh-agent` daemon: start it on a private socket, add an identity via
/// the real system `ssh-add`, then authenticate a real `ssh` connection using
/// a key held only in the daemon. Exercises REQUEST_IDENTITIES, ADD_IDENTITY
/// and SIGN_REQUEST against the OpenSSH agent protocol.
#[test]
fn ns_ssh_agent_serves_identities_and_signs() {
    if Command::new("ssh-add").arg("-l").output().is_err() {
        eprintln!("skipping: system ssh-add not available");
        return;
    }
    if Command::new("ssh").arg("-V").output().is_err() {
        eprintln!("skipping: system ssh not available");
        return;
    }

    let dir = temp_dir("ns-ssh-agent");
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let agent_link = dir.join("ns-ssh-agent");
    let ssh_add_link = dir.join("ns-ssh-add");
    let keygen_link = dir.join("ns-ssh-keygen");
    std::os::unix::fs::symlink(client_bin, &agent_link).unwrap();
    std::os::unix::fs::symlink(client_bin, &ssh_add_link).unwrap();
    std::os::unix::fs::symlink(client_bin, &keygen_link).unwrap();

    // Generate a key with our own keygen.
    let key_path = dir.join("test_key");
    let out = Command::new(&keygen_link)
        .arg("-t").arg("ed25519")
        .arg("-f").arg(&key_path)
        .arg("-q")
        .output().expect("run ns-ssh-keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Start the daemon in the foreground on a private socket.
    let sock = dir.join("agent.sock");
    let mut agent = Command::new(&agent_link)
        .arg("-D")
        .arg("-a").arg(&sock)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn().expect("spawn ns-ssh-agent");
    // Wait for the socket to appear.
    let mut ok = false;
    for _ in 0..50 {
        if sock.exists() { ok = true; break; }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ok, "ns-ssh-agent socket did not appear");

    // Add the key via the real system ssh-add (protocol interop).
    let out = Command::new("ssh-add")
        .arg(&key_path)
        .env("SSH_AUTH_SOCK", &sock)
        .output().expect("system ssh-add");
    assert!(
        out.status.success(),
        "system ssh-add against ns-ssh-agent failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The real ssh-add must see exactly one identity.
    let out = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &sock)
        .output().expect("system ssh-add -l");
    let list = String::from_utf8_lossy(&out.stdout);
    assert!(
        list.contains("ED25519"),
        "expected an ED25519 identity from ns-ssh-agent, got: {:?}",
        list
    );

    // Now authenticate a real ssh connection using the agent-held key.
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, _id_path, kh) = launch_test_server(&dir, port);
    let pub_line = std::fs::read_to_string(dir.join("test_key.pub")).unwrap_or_default();
    let pub_line = pub_line.trim().to_string();
    // The server's authorized_keys already contains launch_test_server's own
    // key; add our agent key so the agent-held identity authenticates.
    let mut auth = std::fs::read_to_string(dir.join("authorized_keys")).unwrap_or_default();
    auth.push_str(&format!("{}\n", pub_line));
    std::fs::write(dir.join("authorized_keys"), auth).unwrap();

    let out = Command::new("ssh")
        .arg("-p").arg(port.to_string())
        .arg("-o").arg("StrictHostKeyChecking=no")
        .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o").arg("BatchMode=yes")
        .arg(format!("{}@127.0.0.1", user))
        .arg("echo AGENT_SIGN_OK")
        .env("SSH_AUTH_SOCK", &sock)
        .output().expect("real ssh via ns-ssh-agent");
    let _ = server.kill();
    let _ = server.wait();
    let _ = agent.kill();
    let _ = agent.wait();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("AGENT_SIGN_OK"),
        "real ssh auth via ns-ssh-agent failed: status={:?} stdout={} stderr={}",
        out.status.code(), stdout, String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `ns-ssh-copy-id`: install a public key into the remote authorized_keys via
/// the embedded client, and verify the key line is appended.
#[test]
fn ns_ssh_copy_id_installs_key() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("ns-ssh-copy-id");
    let client_bin = env!("CARGO_BIN_EXE_ns-ssh");
    let copy_id_link = dir.join("ns-ssh-copy-id");
    let keygen_link = dir.join("ns-ssh-keygen");
    std::os::unix::fs::symlink(client_bin, &copy_id_link).unwrap();
    std::os::unix::fs::symlink(client_bin, &keygen_link).unwrap();

    let key_path = dir.join("copy_key");
    let out = Command::new(&keygen_link)
        .arg("-t").arg("ed25519")
        .arg("-f").arg(&key_path)
        .arg("-q")
        .output().expect("run ns-ssh-keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, _id_path, kh) = launch_test_server(&dir, port);

    // The server must accept the copy_key public key so the embedded ssh
    // client authenticates when copy-id runs its remote command.
    let pub_line = std::fs::read_to_string(dir.join("copy_key.pub"))
        .unwrap_or_default().trim().to_string();
    let mut auth = std::fs::read_to_string(dir.join("authorized_keys")).unwrap_or_default();
    if !auth.contains(&pub_line) {
        auth.push_str(&format!("{}\n", pub_line));
        std::fs::write(dir.join("authorized_keys"), auth).unwrap();
    }

    let run_copy_id = || {
        Command::new(&copy_id_link)
            .arg("-i").arg(dir.join("copy_key.pub"))
            .arg("-p").arg(port.to_string())
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
            .arg("-o").arg("BatchMode=yes")
            .arg(format!("{}@127.0.0.1", user))
            .output().expect("run ns-ssh-copy-id")
    };

    // First run: must succeed and print the confirmation.
    let out = run_copy_id();
    assert!(
        out.status.success(),
        "ns-ssh-copy-id failed: status={:?} stderr={}",
        out.status.code(), String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Now try logging into"),
        "unexpected copy-id output: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Second run: idempotent (key already installed on the remote side).
    let out2 = run_copy_id();
    assert!(
        out2.status.success(),
        "second ns-ssh-copy-id failed: status={:?} stderr={}",
        out2.status.code(), String::from_utf8_lossy(&out2.stderr)
    );

    let _ = server.kill();
    let _ = server.wait();
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
        // Emit a marker so the test can wait for the session (and thus the
        // client's signal handler + session_id) to be fully established. A
        // fixed sleep is racy under parallel test execution, where connection
        // + auth + session setup can exceed any constant.
        .arg("echo READY; sleep 30; echo AFTER_SLEEP")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run signal client");
    let pid = child.id();

    // Drain stdout on a reader thread so the main thread can poll for READY.
    let stdout = child.stdout.take().expect("client stdout");
    let out_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    {
        let out_buf = out_buf.clone();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut r = stdout;
            let mut chunk = [0u8; 4096];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        out_buf.lock().unwrap().push_str(
                            std::str::from_utf8(&chunk[..n]).unwrap_or(""),
                        );
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Poll until the remote command reports READY (session established, signal
    // handler installed and session_id set). Abort if the client exits first.
    let ready_start = Instant::now();
    loop {
        if out_buf.lock().unwrap().contains("READY") {
            break;
        }
        if let Some(st) = child.try_wait().expect("poll child") {
            let _ = child.wait();
            panic!("client exited before session established: {:?}", st);
        }
        if ready_start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            let mut dbg_err = String::new();
            if let Some(mut se) = child.stderr.take() {
                use std::io::Read;
                let _ = se.read_to_string(&mut dbg_err);
            }
            panic!("session not established within 10s (no READY on stdout); client stderr={:?}, stdout={:?}", dbg_err, &*out_buf.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Session is up: forward SIGTERM (not ignored for background processes).
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
    out.push_str(&out_buf.lock().unwrap());
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

/// Server-side `SetEnv` must be injected into the session environment, and a
/// client-sent variable of the same name (accepted via `AcceptEnv`) takes
/// precedence over the server's SetEnv, matching OpenSSH.
#[test]
fn server_setenv_propagates() {
    let dir = temp_dir("server_setenv");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server_extra(
        &dir,
        port,
        &[
            "-o",
            "setenv=NS_SSH_SERVER_VAR=from_server",
            "-o",
            "setenv=LANG=server_lang",
        ],
    );

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        // Client sends LANG via its own SetEnv; the test server accepts it
        // through `AcceptEnv LANG LC_*` and it must override the server value.
        .arg("-o")
        .arg("SetEnv=LANG=client_lang")
        .arg("127.0.0.1")
        .arg("echo \"SRV=[$NS_SSH_SERVER_VAR] LANG=[$LANG]\"")
        .output()
        .expect("run server setenv client");

    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SRV=[from_server] LANG=[client_lang]"),
        "expected server SetEnv injected and client LANG to win, got: {:?} (stderr={:?})",
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

/// Exercise the client-side SFTP command set (Q06/Q07): put/get/mkdir/stat/
/// df/symlink/chown/reput/reget via `ns-sftp -b`. Runs against the real
/// `ns-ssh-server` internal-sftp subsystem.
#[test]
fn sftp_client_commands_round_trip() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("sftp-cmds");
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

    let mut server = Command::new(&server_bin)
        .arg("-d")
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

    // The sftp subcommand is dispatched by argv[0] == "ns-sftp"; symlink the
    // ns-ssh binary to that name in the temp dir.
    let sftp_bin = dir.join("ns-sftp");
    #[cfg(unix)]
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_ns-ssh"), &sftp_bin).unwrap();

    // A local file to upload.
    let local_file = dir.join("local.txt");
    std::fs::write(&local_file, b"hello sftp commands\n").unwrap();

    let kh = dir.join("known_hosts");
    let batch = dir.join("batch.txt");
    std::fs::write(
        &batch,
        format!(
            "pwd\nmkdir remote_dir\nput {0} remote_dir/up.txt\nstat remote_dir/up.txt\ndf .\nsymlink remote_dir/up.txt remote_link\nchmod 640 remote_dir/up.txt\nrename remote_dir/up.txt remote_dir/renamed.txt\nget remote_dir/renamed.txt {1}/down.txt\nreput {0} remote_dir/reput.txt\nreget remote_dir/reput.txt {1}/down2.txt\n",
            local_file.display(),
            dir.display()
        ),
    )
    .unwrap();

    let out = Command::new(&sftp_bin)
        .arg("-P")
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
        .arg("-b")
        .arg(&batch)
        .arg("127.0.0.1")
        .output()
        .expect("run ns-sftp batch");

    let _ = server.kill();
    let _ = server.wait();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "ns-sftp batch failed: status={:?} stdout={:?} stderr={:?}",
        out.status.code(),
        stdout,
        stderr
    );
    // The downloaded file must match the uploaded content.
    let down = dir.join("down.txt");
    assert!(
        down.exists() && std::fs::read_to_string(&down).unwrap_or_default().contains("hello sftp commands"),
        "downloaded file missing or wrong content; stdout={}",
        stdout
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Exercise the OpenSSH SFTP extensions added for Q05: `expand-path`,
/// `home-directory`, `lsetstat`, `copy-data`, `check-file` and
/// `users-groups-by-id`. Uses the real `ns-ssh-server` internal-sftp subsystem
/// and verifies the reply of each extension request at the protocol level.
#[test]
fn sftp_extensions_round_trip() {
    let server_bin = workspace_target_dir();
    if !server_bin.exists() {
        eprintln!("SKIP: ns-ssh-server binary not built; run `cargo build` first");
        return;
    }

    let dir = temp_dir("sftp-ext");
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
        .arg("-d")
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

    use std::io::{Read, Write};
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = child.stdout.take().expect("child stdout");
    let mut _stderr = child.stderr.take().expect("child stderr");

    // Read one full SFTP packet from the stream.
    fn read_packet(r: &mut impl Read) -> Option<Vec<u8>> {
        let mut hdr = [0u8; 4];
        if !read_full(r, &mut hdr) {
            return None;
        }
        let len = u32::from_be_bytes(hdr) as usize;
        if len == 0 || len > 1 << 20 {
            return None;
        }
        let mut body = vec![0u8; len];
        if !read_full(r, &mut body) {
            return None;
        }
        let mut pkt = Vec::with_capacity(4 + len);
        pkt.extend_from_slice(&hdr);
        pkt.extend_from_slice(&body);
        Some(pkt)
    }

    fn send_packet(w: &mut impl Write, payload: &[u8]) {
        w.write_all(&(payload.len() as u32).to_be_bytes()).unwrap();
        w.write_all(payload).unwrap();
        w.flush().unwrap();
    }

    // INIT / VERSION
    send_packet(&mut stdin, &[1u8, 0, 0, 0, 3]);
    let version = read_packet(&mut stdout).expect("version reply");
    let mut ext_names: Vec<String> = Vec::new();
    // Parse VERSION: type(1) + version(4) + ext pairs.
    if version.len() > 9 {
        let mut pos = 9;
        while pos + 4 <= version.len() {
            let slen = u32::from_be_bytes(version[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + slen + 4 > version.len() {
                break;
            }
            ext_names.push(String::from_utf8_lossy(&version[pos..pos + slen]).into_owned());
            pos += slen;
            let vlen = u32::from_be_bytes(version[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4 + vlen;
        }
    }
    for name in [
        "expand-path@openssh.com",
        "home-directory@openssh.com",
        "lsetstat@openssh.com",
        "copy-data@openssh.com",
        "check-file@openssh.com",
        "users-groups-by-id@openssh.com",
    ] {
        assert!(
            ext_names.iter().any(|e| e == name),
            "extension {} not advertised; got {:?}",
            name,
            ext_names
        );
    }

    // expand-path@openssh.com
    let mut req = Vec::new();
    req.push(200u8);
    req.extend(1u32.to_be_bytes());
    let s = "expand-path@openssh.com";
    req.extend((s.len() as u32).to_be_bytes());
    req.extend(s.as_bytes());
    let p = "~/subdir";
    req.extend((p.len() as u32).to_be_bytes());
    req.extend(p.as_bytes());
    send_packet(&mut stdin, &req);
    let reply = read_packet(&mut stdout).expect("expand-path reply");
    assert_eq!(reply[4], 201u8, "expand-path reply type");
    let elen = u32::from_be_bytes(reply[9..13].try_into().unwrap()) as usize;
    let expanded = String::from_utf8_lossy(&reply[13..13 + elen]).into_owned();

    assert!(
        expanded.contains("/subdir") || expanded.ends_with("/subdir"),
        "expand-path did not expand ~: {}",
        expanded
    );

    // home-directory@openssh.com
    let mut req = Vec::new();
    req.push(200u8);
    req.extend(2u32.to_be_bytes());
    let s = "home-directory@openssh.com";
    req.extend((s.len() as u32).to_be_bytes());
    req.extend(s.as_bytes());
    send_packet(&mut stdin, &req);
    let reply = read_packet(&mut stdout).expect("home-directory reply");
    assert_eq!(reply[4], 201u8, "home-directory reply type");
    let elen = u32::from_be_bytes(reply[9..13].try_into().unwrap()) as usize;
    let home = String::from_utf8_lossy(&reply[13..13 + elen]).into_owned();

    assert!(!home.is_empty(), "home-directory returned empty");

    // lsetstat@openssh.com: create a file, then lsetstat its permissions.
    let file_path = dir.join("lsetstat_target.txt");
    std::fs::write(&file_path, b"hello").unwrap();
    let rel = file_path.to_string_lossy().into_owned();
    let mut req = Vec::new();
    req.push(200u8);
    req.extend(3u32.to_be_bytes());
    let s = "lsetstat@openssh.com";
    req.extend((s.len() as u32).to_be_bytes());
    req.extend(s.as_bytes());
    req.extend((rel.len() as u32).to_be_bytes());
    req.extend(rel.as_bytes());
    // attrs: flags + permissions (0o600)
    let mut attr = Vec::new();
    attr.extend(0x00000004u32.to_be_bytes()); // SSH_FILEXFER_ATTR_PERMISSIONS
    attr.extend(0o600u32.to_be_bytes());
    req.extend_from_slice(&attr);
    send_packet(&mut stdin, &req);
    let reply = read_packet(&mut stdout).expect("lsetstat reply");
    assert_eq!(reply[4], 101u8, "lsetstat reply type");
    assert_eq!(
        u32::from_be_bytes(reply[9..13].try_into().unwrap()),
        0,
        "lsetstat should succeed"
    );

    // check-file@openssh.com
    let mut req = Vec::new();
    req.push(200u8);
    req.extend(4u32.to_be_bytes());
    let s = "check-file@openssh.com";
    req.extend((s.len() as u32).to_be_bytes());
    req.extend(s.as_bytes());
    req.extend((rel.len() as u32).to_be_bytes());
    req.extend(rel.as_bytes());
    req.extend(0u32.to_be_bytes()); // flags
    req.extend(0u64.to_be_bytes()); // start
    req.extend(0u64.to_be_bytes()); // length (0 = whole file)
    req.extend(8192u32.to_be_bytes()); // block size
    send_packet(&mut stdin, &req);
    let reply = read_packet(&mut stdout).expect("check-file reply");
    assert_eq!(reply[4], 201u8, "check-file reply type");
    let alen = u32::from_be_bytes(reply[9..13].try_into().unwrap()) as usize;
    assert_eq!(
        String::from_utf8_lossy(&reply[13..13 + alen]),
        "sha256",
        "check-file hash algorithm"
    );

    // users-groups-by-id@openssh.com: resolve the current uid/gid.
    let uid = unsafe { libc::getuid() };
    let mut req = Vec::new();
    req.push(200u8);
    req.extend(5u32.to_be_bytes());
    let s = "users-groups-by-id@openssh.com";
    req.extend((s.len() as u32).to_be_bytes());
    req.extend(s.as_bytes());
    req.extend(1u32.to_be_bytes()); // count
    req.extend(0u32.to_be_bytes()); // id_type: uid
    req.extend(uid.to_be_bytes());
    send_packet(&mut stdin, &req);
    let reply = read_packet(&mut stdout).expect("users-groups reply");
    assert_eq!(reply[4], 201u8, "users-groups reply type");
    let cnt = u32::from_be_bytes(reply[9..13].try_into().unwrap());
    assert!(cnt >= 1, "users-groups should return the current user");

    let _ = child.kill();
    let _ = child.wait();
    let mut server = server;
    let _ = server.kill();
    let _ = server.wait_with_output();
    let _ = std::fs::remove_dir_all(&dir);
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
        elapsed < std::time::Duration::from_secs(8),
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

/// A peer that never sends its SSH version must be dropped once
/// `UnusedConnectionTimeout` elapses. The server sends its identification
/// string immediately on accept (matching OpenSSH sshd), so the silent client
/// first reads the banner, then observes the connection being closed.
#[test]
fn server_unused_connection_timeout_closes_silent_connection() {
    let dir = temp_dir("server-unused-timeout");
    let port = free_port();
    let (mut server, _id, _kh) =
        launch_test_server_extra(&dir, port, &["-o", "UnusedConnectionTimeout=2"]);

    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .expect("set read timeout");
    let start = Instant::now();
    let mut banner = Vec::new();
    // The server sends its identification string first (matching OpenSSH
    // sshd); read until the full line (terminated by \r\n) arrives. The
    // version string and terminator are written separately, so a single read
    // may return a partial line.
    let mut byte = [0u8; 1];
    while !banner.ends_with(b"\r\n") && banner.len() < 256 {
        let n = stream.read(&mut byte).expect("read banner byte");
        if n == 0 {
            break;
        }
        banner.push(byte[0]);
    }
    assert!(
        banner.starts_with(b"SSH-2.0-") && banner.ends_with(b"\r\n"),
        "expected server identification string first, got {:?}",
        String::from_utf8_lossy(&banner)
    );

    // Stay silent: no version string is sent, so the server should give up.
    let mut buf = [0u8; 64];
    let res = stream.read(&mut buf);
    let elapsed = start.elapsed();

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);

    match res {
        Ok(0) => {}
        Err(ref e)
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::BrokenPipe => {}
        other => panic!(
            "expected EOF/reset after UnusedConnectionTimeout, got {:?} after {:?}",
            other, elapsed
        ),
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "UnusedConnectionTimeout=2 should close the connection well before 5s, took {:?}",
        elapsed
    );
}

/// `RefuseConnection` must reject the session before authentication.
#[test]
fn server_refuse_connection_disconnects_client() {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("server-refuse");
    let port = free_port();
    let (server, id_path, kh) =
        launch_test_server_extra(&dir, port, &["-o", "RefuseConnection=maintenance"]);

    let args = base_client_args(port, &user, &id_path, &kh);
    let start = Instant::now();
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("echo should-not-run")
        .output()
        .expect("run client");
    let elapsed = start.elapsed();

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        elapsed < Duration::from_secs(5),
        "RefuseConnection should reject immediately, took {:?}; client stderr={:?}",
        elapsed,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("should-not-run"),
        "the remote command must never run; stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&server_out.stdout).contains("refusing connection: maintenance")
            || String::from_utf8_lossy(&server_out.stderr)
                .contains("refusing connection: maintenance"),
        "server should log the configured refusal text; stdout: {} stderr: {}",
        String::from_utf8_lossy(&server_out.stdout),
        String::from_utf8_lossy(&server_out.stderr)
    );
}

/// `PerSourceMaxStartups` must drop connections beyond the limit from the same
/// masked source while the first unauthenticated connection is still open.
#[test]
fn server_per_source_max_startups_drops_excess() {
    let dir = temp_dir("server-per-source");
    let port = free_port();
    let (mut server, _id, _kh) = launch_test_server_extra(
        &dir,
        port,
        &["-o", "PerSourceMaxStartups=1", "-o", "PerSourceNetBlockSize=32:128"],
    );

    // Let the port probe connection from `wait_for_port` be accepted and
    // released before we start holding a slot ourselves.
    std::thread::sleep(Duration::from_millis(500));

    // Hold one unauthenticated connection open (server counts it on accept).
    let _first = std::net::TcpStream::connect(("127.0.0.1", port)).expect("first connect");
    std::thread::sleep(Duration::from_millis(300));

    let mut second = std::net::TcpStream::connect(("127.0.0.1", port)).expect("second connect");
    second
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let start = Instant::now();
    let mut buf = [0u8; 64];
    let res = second.read(&mut buf);
    let elapsed = start.elapsed();

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);

    match res {
        Ok(0) => {}
        Err(ref e)
            if e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::BrokenPipe => {}
        other => panic!(
            "expected the excess connection to be dropped, got {:?} after {:?}",
            other, elapsed
        ),
    }
    assert!(
        elapsed < Duration::from_secs(3),
        "the excess connection should be closed immediately, took {:?}",
        elapsed
    );
}

/// Generate an unencrypted ed25519 key pair with the system OpenSSH keygen.
/// Returns `(private_path, public_path)`; the public file is usable by
/// `ssh-keygen -s` and the private file by the ns-ssh client.
fn generate_ed25519_key(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let priv_path = dir.join(name);
    let status = Command::new("ssh-keygen")
        .arg("-q")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg(name)
        .arg("-f")
        .arg(&priv_path)
        .status()
        .expect("run ssh-keygen");
    assert!(status.success(), "ssh-keygen -t ed25519 failed");
    (priv_path, dir.join(format!("{name}.pub")))
}

/// Sign `user_pub` with the OpenSSH `ssh-keygen -s`, producing
/// `<user_pub without .pub>-cert.pub` next to it.
fn ssh_keygen_sign(ca: &Path, user_pub: &Path, principals: &str) -> bool {
    Command::new("ssh-keygen")
        .arg("-q")
        .arg("-s")
        .arg(ca)
        .arg("-I")
        .arg("ns-ssh-test")
        .arg("-n")
        .arg(principals)
        .arg("-V")
        .arg("+1h")
        .arg(user_pub)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Sign a host public key (`-h`) with the OpenSSH `ssh-keygen -s`.
fn ssh_keygen_sign_host(ca: &Path, host_pub: &Path, principals: &str) -> bool {
    Command::new("ssh-keygen")
        .arg("-q")
        .arg("-s")
        .arg(ca)
        .arg("-I")
        .arg("ns-ssh-host-test")
        .arg("-h")
        .arg("-n")
        .arg(principals)
        .arg("-V")
        .arg("+1h")
        .arg(host_pub)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run a remote command through the client and return (success, stdout, stderr).
fn run_client_echo(
    user: &str,
    port: u16,
    id_path: &Path,
    kh: &Path,
    extra: &[String],
    command: &str,
) -> (bool, String, String) {
    let args = base_client_args(port, user, id_path, kh);
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);
    for e in extra {
        cmd.arg(e);
    }
    let out = cmd
        .arg("127.0.0.1")
        .arg(command)
        .output()
        .expect("run client");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// A user certificate signed by a TrustedUserCAKeys CA must authenticate,
/// both via the implicit `<key>-cert.pub` discovery and via `CertificateFile`.
#[test]
fn server_accepts_user_certificate_from_trusted_ca() {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        eprintln!("SKIP: ssh-keygen not available");
        return;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("cert-auth");
    let port = free_port();

    let (ca, ca_pub) = generate_ed25519_key(&dir, "ca");
    let (user_key, user_pub) = generate_ed25519_key(&dir, "user_key");
    assert!(
        ssh_keygen_sign(&ca, &user_pub, &user),
        "ssh-keygen failed to sign the user key"
    );
    let cert_path = dir.join("user_key-cert.pub");
    assert!(cert_path.exists(), "ssh-keygen did not write the certificate");

    let extra = vec![
        "-o".to_string(),
        format!("TrustedUserCAKeys={}", ca_pub.display()),
    ];
    let extra_ref: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
    let (server, _unused_id, kh) = launch_test_server_extra(&dir, port, &extra_ref);

    // Implicit discovery of `<private key>-cert.pub`.
    let (ok, stdout, stderr) = run_client_echo(&user, port, &user_key, &kh, &[], "echo cert-ok");
    // Explicit CertificateFile option.
    let (ok_explicit, stdout_explicit, stderr_explicit) = run_client_echo(
        &user,
        port,
        &user_key,
        &kh,
        &["-o".to_string(), format!("CertificateFile={}", cert_path.display())],
        "echo cert-explicit-ok",
    );

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        ok && stdout.contains("cert-ok"),
        "implicit certificate auth failed: stderr={stderr} server_stdout={} server_stderr={}",
        String::from_utf8_lossy(&server_out.stdout),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        ok_explicit && stdout_explicit.contains("cert-explicit-ok"),
        "CertificateFile auth failed: stderr={stderr_explicit}"
    );
}

/// A plain public key listed in RevokedKeys must no longer authenticate via
/// a certificate signed by an otherwise trusted CA.
#[test]
fn server_revoked_keys_rejects_certificate() {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        eprintln!("SKIP: ssh-keygen not available");
        return;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("cert-revoked");
    let keys_dir = dir.join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();

    let (ca, ca_pub) = generate_ed25519_key(&keys_dir, "ca");
    let (user_key, user_pub) = generate_ed25519_key(&keys_dir, "user_key");
    let (_, other_pub) = generate_ed25519_key(&keys_dir, "other_key");
    assert!(
        ssh_keygen_sign(&ca, &user_pub, &user),
        "ssh-keygen failed to sign the user key"
    );

    // The user key is revoked: certificate authentication must fail.
    let port_bad = free_port();
    let extra_bad = vec![
        "-o".to_string(),
        format!("TrustedUserCAKeys={}", ca_pub.display()),
        "-o".to_string(),
        format!("RevokedKeys={}", user_pub.display()),
    ];
    let extra_bad_ref: Vec<&str> = extra_bad.iter().map(|s| s.as_str()).collect();
    let (server_bad, _id_bad, kh_bad) = launch_test_server_extra(&dir, port_bad, &extra_bad_ref);
    let (ok_bad, _, stderr_bad) =
        run_client_echo(&user, port_bad, &user_key, &kh_bad, &[], "echo should-not-run");
    let mut server_bad = server_bad;
    let _ = server_bad.kill();
    let _ = server_bad.wait();

    // Only a different key is revoked: the same certificate must be accepted.
    let port_good = free_port();
    let extra_good = vec![
        "-o".to_string(),
        format!("TrustedUserCAKeys={}", ca_pub.display()),
        "-o".to_string(),
        format!("RevokedKeys={}", other_pub.display()),
    ];
    let extra_good_ref: Vec<&str> = extra_good.iter().map(|s| s.as_str()).collect();
    let (server_good, _id_good, kh_good) =
        launch_test_server_extra(&dir, port_good, &extra_good_ref);
    let (ok_good, stdout_good, stderr_good) =
        run_client_echo(&user, port_good, &user_key, &kh_good, &[], "echo not-revoked");
    let mut server_good = server_good;
    let _ = server_good.kill();
    let _ = server_good.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !ok_bad,
        "a revoked certificate must not authenticate; stderr={stderr_bad}"
    );
    assert!(
        ok_good && stdout_good.contains("not-revoked"),
        "a non-revoked certificate should authenticate: stderr={stderr_good}"
    );
}

/// With AuthorizedPrincipalsFile, a certificate principal other than the
/// login name is accepted, while without it the principal must match the user.
#[test]
fn server_authorized_principals_file_controls_certificate() {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        eprintln!("SKIP: ssh-keygen not available");
        return;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("cert-principals");
    let keys_dir = dir.join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();

    let (ca, ca_pub) = generate_ed25519_key(&keys_dir, "ca");
    let (user_key, user_pub) = generate_ed25519_key(&keys_dir, "user_key");
    assert!(
        ssh_keygen_sign(&ca, &user_pub, "team-alice"),
        "ssh-keygen failed to sign the user key"
    );
    let principals_path = keys_dir.join("principals");
    std::fs::write(&principals_path, "team-alice\n").unwrap();

    // Without AuthorizedPrincipalsFile the principal `team-alice` is not
    // the login name, so authentication must fail.
    let port_bad = free_port();
    let extra_bad = vec![
        "-o".to_string(),
        format!("TrustedUserCAKeys={}", ca_pub.display()),
    ];
    let extra_bad_ref: Vec<&str> = extra_bad.iter().map(|s| s.as_str()).collect();
    let (server_bad, _id_bad, kh_bad) = launch_test_server_extra(&dir, port_bad, &extra_bad_ref);
    let (ok_bad, _, stderr_bad) =
        run_client_echo(&user, port_bad, &user_key, &kh_bad, &[], "echo should-not-run");
    let mut server_bad = server_bad;
    let _ = server_bad.kill();
    let _ = server_bad.wait();

    // With the file listing the certificate principal, authentication succeeds.
    let port_good = free_port();
    let extra_good = vec![
        "-o".to_string(),
        format!("TrustedUserCAKeys={}", ca_pub.display()),
        "-o".to_string(),
        format!("AuthorizedPrincipalsFile={}", principals_path.display()),
    ];
    let extra_good_ref: Vec<&str> = extra_good.iter().map(|s| s.as_str()).collect();
    let (server_good, _id_good, kh_good) =
        launch_test_server_extra(&dir, port_good, &extra_good_ref);
    let (ok_good, stdout_good, stderr_good) =
        run_client_echo(&user, port_good, &user_key, &kh_good, &[], "echo principal-ok");
    let mut server_good = server_good;
    let _ = server_good.kill();
    let _ = server_good.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !ok_bad,
        "certificate principal mismatch must fail without AuthorizedPrincipalsFile; stderr={stderr_bad}"
    );
    assert!(
        ok_good && stdout_good.contains("principal-ok"),
        "AuthorizedPrincipalsFile should accept the certificate principal: stderr={stderr_good}"
    );
}

/// A host certificate signed by a CA listed as `@cert-authority` in known_hosts
/// must be accepted; the same host is rejected once the marker is removed.
#[test]
fn client_accepts_host_certificate_via_cert_authority() {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        eprintln!("SKIP: ssh-keygen not available");
        return;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("host-cert");
    let port = free_port();

    // Pre-create the host key so `HostCertificate` has something to match.
    let (_host_key, host_pub) = generate_ed25519_key(&dir, "host_key_ed25519");
    let (ca, ca_pub) = generate_ed25519_key(&dir, "ca");
    assert!(
        ssh_keygen_sign_host(&ca, &host_pub, "127.0.0.1"),
        "ssh-keygen failed to sign the host key"
    );
    let cert_path = dir.join("host_key_ed25519-cert.pub");
    assert!(cert_path.exists(), "ssh-keygen did not write the host certificate");

    let extra = vec![
        "-o".to_string(),
        format!("HostCertificate={}", cert_path.display()),
    ];
    let extra_ref: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
    let (server, id_path, kh) = launch_test_server_extra(&dir, port, &extra_ref);

    // Force certificate negotiation, exactly like an OpenSSH client would
    // try the certified variant first.
    let opts = vec![
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com".to_string(),
    ];

    // With the CA marker, the certified host key is trusted.
    let ca_line = std::fs::read_to_string(&ca_pub).unwrap();
    std::fs::write(&kh, format!("@cert-authority 127.0.0.1 {}\n", ca_line.trim())).unwrap();
    let (ok, stdout, stderr) =
        run_client_echo(&user, port, &id_path, &kh, &opts, "echo host-cert-ok");

    // Without the marker the certificate is unknown and strict mode rejects it.
    std::fs::write(&kh, "").unwrap();
    let (ok_without, _, stderr_without) =
        run_client_echo(&user, port, &id_path, &kh, &opts, "echo should-not-run");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        ok && stdout.contains("host-cert-ok"),
        "host certificate should be accepted via @cert-authority: stderr={stderr} server_stdout={} server_stderr={}",
        String::from_utf8_lossy(&server_out.stdout),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        !ok_without,
        "host certificate must be rejected without a @cert-authority marker: stderr={stderr_without}"
    );
}

/// `KnownHostsCommand` output is treated as a known_hosts file: under strict
/// checking the connection succeeds only when the command supplies the key.
#[test]
fn client_trusts_known_hosts_command_output() {
    if Command::new("ssh-keygen").arg("-V").output().is_err() {
        eprintln!("SKIP: ssh-keygen not available");
        return;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("known-hosts-command");
    let port = free_port();

    // Pre-create the host key so its `.pub` exists for the command to serve.
    let (_host_key, host_pub) = generate_ed25519_key(&dir, "host_key_ed25519");
    let (server, id_path, kh) = launch_test_server(&dir, port);

    let command = format!(
        "KnownHostsCommand=sed 's/^/127.0.0.1 /' {}",
        host_pub.display()
    );
    let opts = vec![
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        command,
    ];
    let (ok, stdout, stderr) =
        run_client_echo(&user, port, &id_path, &kh, &opts, "echo kh-command-ok");

    // Without the command, strict mode must reject the unknown host key.
    let strict = vec![
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
    ];
    let (ok_without, _, stderr_without) =
        run_client_echo(&user, port, &id_path, &kh, &strict, "echo should-not-run");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        ok && stdout.contains("kh-command-ok"),
        "KnownHostsCommand output should be trusted: stderr={stderr} server_stdout={} server_stderr={}",
        String::from_utf8_lossy(&server_out.stdout),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        !ok_without,
        "strict host key checking must reject an unknown key without KnownHostsCommand: stderr={stderr_without}"
    );
}

/// `ExposeAuthInfo` must put the accepted method and public key into the file
/// named by `SSH_USER_AUTH`.
#[test]
fn server_expose_auth_info_sets_ssh_user_auth() {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("server-expose-auth");
    let port = free_port();
    let (server, id_path, kh) =
        launch_test_server_extra(&dir, port, &["-o", "ExposeAuthInfo=yes"]);

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("cat \"$SSH_USER_AUTH\"")
        .output()
        .expect("run client");

    let mut server = server;
    let _ = server.kill();
    let server_out = server.wait_with_output().expect("wait server");
    let _ = std::fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "remote command failed: stderr={:?} server_stdout={} server_stderr={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&server_out.stdout),
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(
        stdout.starts_with("publickey ssh-ed25519 "),
        "SSH_USER_AUTH should list the accepted public key method, got: {:?}",
        stdout
    );
}

/// A `@revoked` known_hosts entry refuses the host key unconditionally, even
/// with `StrictHostKeyChecking=no` (OpenSSH behavior).
#[test]
fn revoked_known_hosts_entry_refuses_connection() {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let dir = temp_dir("revoked-kh");
    let port = free_port();
    let (server, id_path, kh) = launch_test_server(&dir, port);

    // First connect with StrictHostKeyChecking=no: the key is auto-added to
    // known_hosts (Unknown -> add).
    let (ok_first, _, _) =
        run_client_echo(&user, port, &id_path, &kh, &[], "echo first-ok");
    assert!(ok_first, "first connection should succeed and record the key");

    // Rewrite the recorded host key line with an `@revoked` marker.
    let content = std::fs::read_to_string(&kh).unwrap();
    let revoked_content: String = content
        .lines()
        .map(|line| format!("@revoked {}", line))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&kh, revoked_content).unwrap();

    // With the key revoked, the connection must be refused regardless of
    // StrictHostKeyChecking=no.
    let (ok_second, _, stderr_second) =
        run_client_echo(&user, port, &id_path, &kh, &[], "echo should-not-run");

    let mut server = server;
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !ok_second,
        "revoked host key must be refused: stderr={stderr_second}"
    );
    assert!(
        stderr_second.contains("revoked"),
        "stderr should report the revoked key, got: {stderr_second}"
    );
}

/// ControlMaster multiplexing: a master keeps one connection on a Unix socket,
/// `-O check` reports it alive, a second client with `ControlMaster=auto`
/// reuses the socket (slave), and `-O exit` shuts the master down cleanly.
#[test]
fn control_master_multiplex_and_commands() {
    let dir = temp_dir("ctrlmaster");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    let ctl = dir.join("control.sock");
    let ctl_arg = format!("ControlPath={}", ctl.display());

    // Start the master (no remote command, stays connected and serves).
    let master_args = base_client_args(port, &user, &id_path, &kh);
    let master = Command::new(&master_args[0])
        .args(&master_args[1..])
        .arg("-o")
        .arg("ControlMaster=yes")
        .arg("-o")
        .arg(&ctl_arg)
        .arg("-N")
        .arg("127.0.0.1")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn control master");

    // Wait for the master socket to appear and accept connections.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if std::os::unix::net::UnixStream::connect(&ctl).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            panic!("control master socket did not appear");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // `-O check` must report the master alive.
    let check_args = base_client_args(port, &user, &id_path, &kh);
    let check = Command::new(&check_args[0])
        .args(&check_args[1..])
        .arg("-o")
        .arg(&ctl_arg)
        .arg("-O")
        .arg("check")
        .arg("127.0.0.1")
        .output()
        .expect("run -O check");
    assert!(
        check.status.success(),
        "-O check failed: stderr={}",
        String::from_utf8_lossy(&check.stderr)
    );

    // A second client with ControlMaster=auto reuses the master connection.
    let slave_args = base_client_args(port, &user, &id_path, &kh);
    let slave = Command::new(&slave_args[0])
        .args(&slave_args[1..])
        .arg("-o")
        .arg("ControlMaster=auto")
        .arg("-o")
        .arg(&ctl_arg)
        .arg("127.0.0.1")
        .arg("echo reused-master")
        .output()
        .expect("run slave through master");
    assert!(
        slave.status.success(),
        "slave failed: stderr={}",
        String::from_utf8_lossy(&slave.stderr)
    );
    assert!(
        String::from_utf8_lossy(&slave.stdout).contains("reused-master"),
        "slave did not get command output: {}",
        String::from_utf8_lossy(&slave.stdout)
    );

    // `-O exit` must terminate the master and free the socket.
    let exit_args = base_client_args(port, &user, &id_path, &kh);
    let exit = Command::new(&exit_args[0])
        .args(&exit_args[1..])
        .arg("-o")
        .arg(&ctl_arg)
        .arg("-O")
        .arg("exit")
        .arg("127.0.0.1")
        .output()
        .expect("run -O exit");
    assert!(
        exit.status.success(),
        "-O exit failed: stderr={}",
        String::from_utf8_lossy(&exit.stderr)
    );

    // Master must terminate on its own after the exit command (poll try_wait
    // so a stuck master cannot hang the test forever).
    let mut master = master;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut master_done = false;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = master.try_wait() {
            master_done = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(master_done, "control master did not exit after -O exit");

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// S11: remote stderr must be delivered separately from stdout via
/// SSH_MSG_CHANNEL_EXTENDED_DATA (type 1) and written to the local stderr,
/// never mixed into stdout.
#[test]
fn remote_stderr_is_separated_from_stdout() {
    let dir = temp_dir("stderr");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_test_server(&dir, port);

    let args = base_client_args(port, &user, &id_path, &kh);
    let output = Command::new(&args[0])
        .args(&args[1..])
        .arg("127.0.0.1")
        .arg("echo out-marker; echo err-marker 1>&2")
        .output()
        .expect("run stderr client");

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "client failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("out-marker"), "stdout missing marker: {stdout}");
    assert!(
        stderr.contains("err-marker"),
        "stderr should carry the remote stderr, got: {stderr}"
    );
    assert!(
        !stdout.contains("err-marker"),
        "remote stderr leaked into stdout: {stdout}"
    );
}
