//! ns-ssl end-to-end tests: verify TLS 1.2/1.3 interop between `ns-ssl` and the
//! real `openssl` in both directions, plus that the project builds without any
//! OpenSSL/OpenSSH dependency.

use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn workspace_target_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../target/debug/ns-ssl")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ns-ssl-it-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Generate a self-signed cert/key with the real openssl (has a SAN so rustls
/// accepts it). Returns (cert_path, key_path).
fn gen_cert(dir: &PathBuf, name: &str) -> (PathBuf, PathBuf) {
    let cert = dir.join(format!("{}.pem", name));
    let key = dir.join(format!("{}_key.pem", name));
    let out = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey").arg("rsa:2048")
        .arg("-keyout").arg(&key)
        .arg("-out").arg(&cert)
        .arg("-days").arg("365")
        .arg("-nodes")
        .arg("-subj").arg("/CN=localhost")
        .arg("-addext").arg("subjectAltName=DNS:localhost")
        .output()
        .expect("run openssl req");
    assert!(out.status.success(), "openssl req failed: {}", String::from_utf8_lossy(&out.stderr));
    (cert, key)
}

/// ns-ssl s_client -> real openssl s_server, over the given TLS version flag.
#[test]
fn ns_ssl_client_interops_with_openssl_server() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("skipping: openssl not available");
        return;
    }
    let dir = temp_dir("client-interop");
    let (cert, key) = gen_cert(&dir, "srv");

    for (flag, expect_proto) in [("", "TLSv1_3"), ("-tls1_2", "TLSv1_2")] {
        let port = free_port();
        let mut srv = Command::new("openssl")
            .arg("s_server")
            .arg("-accept").arg(port.to_string())
            .arg("-cert").arg(&cert)
            .arg("-key").arg(&key)
            .arg("-quiet")
            .arg("-www")
            .args(flag.split_whitespace())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn openssl s_server");
        assert!(wait_for_port(port, Duration::from_secs(10)), "openssl server did not start");

        let bin = workspace_target_dir();
        let mut client = Command::new(&bin)
            .arg("s_client")
            .arg("-connect").arg(format!("127.0.0.1:{}", port))
            .arg("-servername").arg("localhost")
            .arg("-CAfile").arg(&cert)
            .args(flag.split_whitespace())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ns-ssl s_client");
        client
            .stdin
            .take()
            .unwrap()
            .write_all(b"GET / HTTP/1.0\r\n\r\n")
            .unwrap();
        let out = client.wait_with_output().unwrap();
        let _ = srv.kill();
        let _ = srv.wait();

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(expect_proto),
            "ns-ssl client (flag {}) expected {}: status={:?} stdout={} stderr={}",
            flag, expect_proto, out.status.code(), stdout, String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("200"),
            "ns-ssl client (flag {}) did not receive HTTP response: {}",
            flag, stdout
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// real openssl s_client -> ns-ssl s_server, over the given TLS version flag.
#[test]
fn openssl_client_interops_with_ns_ssl_server() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("skipping: openssl not available");
        return;
    }
    let dir = temp_dir("server-interop");
    let (cert, key) = gen_cert(&dir, "srv");
    let bin = workspace_target_dir();

    for (flag, _expect) in [("", ()), ("-tls1_2", ())] {
        let port = free_port();
        let mut srv = Command::new(&bin)
            .arg("s_server")
            .arg("-accept").arg(port.to_string())
            .arg("-cert").arg(&cert)
            .arg("-key").arg(&key)
            .args(flag.split_whitespace())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn ns-ssl s_server");
        assert!(wait_for_port(port, Duration::from_secs(10)), "ns-ssl server did not start");

        let mut client = Command::new("openssl")
            .arg("s_client")
            .arg("-connect").arg(format!("127.0.0.1:{}", port))
            .arg("-servername").arg("localhost")
            .arg("-CAfile").arg(&cert)
            .arg("-quiet")
            .args(flag.split_whitespace())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn openssl s_client");
        client
            .stdin
            .take()
            .unwrap()
            .write_all(b"GET / HTTP/1.0\r\n\r\n")
            .unwrap();
        let out = client.wait_with_output().unwrap();
        let _ = srv.kill();
        let _ = srv.wait();

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success()
                && stderr.contains("verify return:1")
                && stdout.contains("ns-ssl hello"),
            "openssl client (flag {}) to ns-ssl server: status={:?} stdout={} stderr={}",
            flag, out.status.code(), stdout, stderr
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The workspace must not depend on openssl/openssh (pure-rust only).
#[test]
fn no_openssl_or_openssh_dependency() {
    // Inspect the lock file for any openssl/openssh/libssh crate.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lock = manifest.join("../../Cargo.lock");
    let content = std::fs::read_to_string(&lock).unwrap_or_default();
    for bad in ["openssl", "openssh", "libssh", "libcrypto", "libssl"] {
        assert!(
            !content.contains(&format!("name = \"{}\"", bad)),
            "workspace must not depend on {}",
            bad
        );
    }
}
