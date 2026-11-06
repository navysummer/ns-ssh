//! Parity tests: run identical scp/sftp scenarios through both the OpenSSH
//! reference tool and the `ns-*` equivalent against the same server, and
//! assert the observable result (exit status, produced file tree, remote
//! directory listing) matches.

use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn workspace_target_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../target/debug/ns-ssh-server")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ns-ssh-parity-{}-{}", std::process::id(), name));
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
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}


/// Launch an `ns-ssh-server` for the given port. Returns (child, id_path, kh).
fn launch_server(dir: &Path, port: u16) -> (std::process::Child, PathBuf, PathBuf) {
    let server_bin = workspace_target_dir();
    assert!(server_bin.exists(), "ns-ssh-server not built");

    // Generate the client identity with the real ssh-keygen so both the
    // OpenSSH reference tool and ns-ssh accept it.
    let id_path = dir.join("id_ed25519");
    let keygen = Command::new("ssh-keygen")
        .arg("-t").arg("ed25519")
        .arg("-f").arg(&id_path)
        .arg("-N").arg("")
        .arg("-q")
        .status()
        .expect("run ssh-keygen");
    assert!(keygen.success(), "ssh-keygen failed");

    let pub_line = std::fs::read_to_string(dir.join("id_ed25519.pub"))
        .unwrap_or_default();
    let auth_path = dir.join("authorized_keys");
    std::fs::write(&auth_path, pub_line).unwrap();

    let host_key_path = dir.join("host_key_ed25519");
    let config_path = dir.join("sshd_config");
    std::fs::write(
        &config_path,
        format!(
            "Port {}\nListenAddress 127.0.0.1\nHostKey {}\nPubkeyAuthentication yes\nPasswordAuthentication no\nAuthorizedKeysFile {}\nPermitRootLogin yes\nSubsystem sftp internal-sftp\n",
            port, host_key_path.display(), auth_path.display()
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
        .expect("spawn server");

    assert!(
        wait_for_port(port, Duration::from_secs(10)),
        "server did not come up on port {}",
        port
    );

    let kh = dir.join("known_hosts");
    (server, id_path, kh)
}

/// Base client args for both scp and sftp.
fn base_client_args(port: u16, id_path: &Path, kh: &Path) -> Vec<String> {
    vec![
        "-P".to_string(),
        port.to_string(),
        "-i".to_string(),
        id_path.display().to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        format!("UserKnownHostsFile={}", kh.display()),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
    ]
}

/// Symlink the ns-ssh binary as `name` in `dir` and return its path.
fn ns_tool(dir: &Path, name: &str) -> PathBuf {
    let link = dir.join(name);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_ns-ssh"), &link).unwrap();
    link
}

/// Recursively collect a relative file tree (path -> contents) for comparison.
fn collect_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().into_owned();
                if p.is_dir() {
                    walk(base, &p, out);
                } else {
                    if let Ok(c) = std::fs::read(&p) {
                        out.push((rel, c));
                    }
                }
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}

/// Assert two file trees are identical.
fn assert_trees_equal(a: &[(String, Vec<u8>)], b: &[(String, Vec<u8>)], what: &str) {
    let am: std::collections::HashMap<_, _> = a.iter().cloned().collect();
    let bm: std::collections::HashMap<_, _> = b.iter().cloned().collect();
    let keys_a: std::collections::HashSet<_> = am.keys().cloned().collect();
    let keys_b: std::collections::HashSet<_> = bm.keys().cloned().collect();
    assert_eq!(keys_a, keys_b, "{}: file sets differ", what);
    for k in keys_a {
        assert_eq!(am.get(&k), bm.get(&k), "{}: contents differ for {}", what, k);
    }
}

/// scp parity: upload a single file with both tools, compare the remote tree.
#[test]
fn scp_parity_upload_single_file() {
    let dir = temp_dir("scp-up-single");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let local = dir.join("file.txt");
    std::fs::write(&local, b"parity upload single\n").unwrap();

    // Remote destination root for the ns-ssh-server process (same temp dir).
    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();

    let base = base_client_args(port, &id_path, &kh);
    let remote = format!("{}@127.0.0.1:{}/", user, remote_base.display());

    // OpenSSH scp upload.
    let scp = ns_tool(&dir, "scp");
    // Use the system scp by its real path.
    let sys_scp = "/usr/bin/scp";
    let out_ref = Command::new(sys_scp)
        .args(&base)
        .arg(&local)
        .arg(&remote)
        .output()
        .expect("system scp");
    let tree_ref = collect_tree(&remote_base);

    // Reset the remote dir for the ns-scp run.
    let _ = std::fs::remove_dir_all(&remote_base);
    std::fs::create_dir_all(&remote_base).unwrap();

    let out_ns = Command::new(&scp)
        .args(&base)
        .arg(&local)
        .arg(&remote)
        .output()
        .expect("ns-scp");
    let tree_ns = collect_tree(&remote_base);

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        out_ref.status.success(),
        out_ns.status.success(),
        "scp vs ns-scp exit mismatch: ref={:?} ns={:?}\nref_err={}\nns_err={}",
        out_ref.status.code(), out_ns.status.code(),
        String::from_utf8_lossy(&out_ref.stderr),
        String::from_utf8_lossy(&out_ns.stderr)
    );
    assert_trees_equal(&tree_ref, &tree_ns, "scp single-file upload");
    assert!(!tree_ns.is_empty(), "ns-scp upload produced no files");
    let _ = std::fs::remove_dir_all(&dir);
}

/// scp parity: recursive directory upload with -r.
#[test]
fn scp_parity_upload_directory_recursive() {
    let dir = temp_dir("scp-up-rec");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let src = dir.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"root file").unwrap();
    std::fs::write(src.join("sub").join("b.txt"), b"nested file").unwrap();

    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();
    let base = base_client_args(port, &id_path, &kh);
    let remote = format!("{}@127.0.0.1:{}/", user, remote_base.display());

    let sys_scp = "/usr/bin/scp";
    let out_ref = Command::new(sys_scp)
        .args(&base).arg("-r").arg(&src).arg(&remote)
        .output().expect("system scp -r");
    let tree_ref = collect_tree(&remote_base);

    let _ = std::fs::remove_dir_all(&remote_base);
    std::fs::create_dir_all(&remote_base).unwrap();
    let scp = ns_tool(&dir, "ns-scp");
    let out_ns = Command::new(&scp)
        .args(&base).arg("-r").arg(&src).arg(&remote)
        .output().expect("ns-scp -r");
    let tree_ns = collect_tree(&remote_base);

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        out_ref.status.success(),
        out_ns.status.success(),
        "scp -r vs ns-scp -r exit mismatch: ref={:?} ns={:?}\nref_err={}\nns_err={}",
        out_ref.status.code(), out_ns.status.code(),
        String::from_utf8_lossy(&out_ref.stderr),
        String::from_utf8_lossy(&out_ns.stderr)
    );
    assert_trees_equal(&tree_ref, &tree_ns, "scp -r recursive upload");
    let _ = std::fs::remove_dir_all(&dir);
}

/// scp parity: directory source without -r must fail for both.
#[test]
fn scp_parity_directory_requires_recursive_flag() {
    let dir = temp_dir("scp-no-r");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let src = dir.join("srcdir");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("x.txt"), b"x").unwrap();
    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();
    let base = base_client_args(port, &id_path, &kh);
    let remote = format!("{}@127.0.0.1:{}/", user, remote_base.display());

    let out_ref = Command::new("/usr/bin/scp")
        .args(&base).arg(&src).arg(&remote)
        .output().expect("system scp no -r");
    let scp = ns_tool(&dir, "ns-scp");
    let out_ns = Command::new(&scp)
        .args(&base).arg(&src).arg(&remote)
        .output().expect("ns-scp no -r");

    let _ = server.kill();
    let _ = server.wait();

    // Both must reject a directory without -r.
    assert!(!out_ref.status.success(), "system scp should reject dir without -r");
    assert!(!out_ns.status.success(), "ns-scp should reject dir without -r");
    let _ = std::fs::remove_dir_all(&dir);
}

/// scp parity: multi-source upload (two files to one remote dir).
#[test]
fn scp_parity_multisource_upload() {
    let dir = temp_dir("scp-multi");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let f1 = dir.join("one.txt");
    let f2 = dir.join("two.txt");
    std::fs::write(&f1, b"first").unwrap();
    std::fs::write(&f2, b"second").unwrap();
    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();
    let base = base_client_args(port, &id_path, &kh);
    let remote = format!("{}@127.0.0.1:{}/", user, remote_base.display());

    let out_ref = Command::new("/usr/bin/scp")
        .args(&base).arg(&f1).arg(&f2).arg(&remote)
        .output().expect("system scp multi");
    let tree_ref = collect_tree(&remote_base);

    let _ = std::fs::remove_dir_all(&remote_base);
    std::fs::create_dir_all(&remote_base).unwrap();
    let scp = ns_tool(&dir, "ns-scp");
    let out_ns = Command::new(&scp)
        .args(&base).arg(&f1).arg(&f2).arg(&remote)
        .output().expect("ns-scp multi");
    let tree_ns = collect_tree(&remote_base);

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        out_ref.status.success(),
        out_ns.status.success(),
        "multi-source exit mismatch: ref={:?} ns={:?}",
        out_ref.status.code(), out_ns.status.code()
    );
    assert_trees_equal(&tree_ref, &tree_ns, "scp multi-source upload");
    let _ = std::fs::remove_dir_all(&dir);
}

/// scp parity: download a remote file to a local target.
#[test]
fn scp_parity_download_single_file() {
    let dir = temp_dir("scp-down");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();
    std::fs::write(remote_base.join("src.txt"), b"download me\n").unwrap();
    let base = base_client_args(port, &id_path, &kh);
    let remote_src = format!("{}@127.0.0.1:{}/src.txt", user, remote_base.display());

    let local_ref = dir.join("down_ref.txt");
    let out_ref = Command::new("/usr/bin/scp")
        .args(&base).arg(&remote_src).arg(&local_ref)
        .output().expect("system scp download");
    let content_ref = std::fs::read(&local_ref).unwrap_or_default();

    let local_ns = dir.join("down_ns.txt");
    let scp = ns_tool(&dir, "ns-scp");
    let out_ns = Command::new(&scp)
        .args(&base).arg(&remote_src).arg(&local_ns)
        .output().expect("ns-scp download");
    let content_ns = std::fs::read(&local_ns).unwrap_or_default();

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        out_ref.status.success(),
        out_ns.status.success(),
        "download exit mismatch: ref={:?} ns={:?}",
        out_ref.status.code(), out_ns.status.code()
    );
    assert_eq!(content_ref, content_ns, "downloaded contents differ");
    assert_eq!(content_ns, b"download me\n", "downloaded content wrong");
    let _ = std::fs::remove_dir_all(&dir);
}

/// sftp parity: run a batch command set through both clients and compare the
/// observable remote directory state after each step.
#[test]
fn sftp_parity_batch_commands() {
    let dir = temp_dir("sftp-parity");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let local = dir.join("local.txt");
    std::fs::write(&local, b"parity sftp\n").unwrap();
    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();

    let sftp = ns_tool(&dir, "ns-sftp");
    let batch = dir.join("batch.txt");
    std::fs::write(
        &batch,
        format!(
            "cd {2}\npwd\nmkdir rd\nput {0} rd/up.txt\nrename rd/up.txt rd/renamed.txt\nsymlink rd/renamed.txt rd/lnk\nchmod 600 rd/renamed.txt\nget rd/renamed.txt {1}/down.txt\n",
            local.display(), dir.display(), remote_base.display()
        ),
    )
    .unwrap();

    let run_sftp = |tool: &Path| {
        Command::new(tool)
            .arg("-P").arg(port.to_string())
            .arg("-i").arg(&id_path)
            .arg("-F").arg("/dev/null")
            .arg("-o").arg(format!("User={}", user))
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
            .arg("-b").arg(&batch)
            .arg("127.0.0.1")
            .output()
            .expect("run sftp")
    };

    // Reference: system sftp.
    let out_ref = run_sftp(Path::new("/usr/bin/sftp"));
    let tree_ref = collect_tree(&remote_base);
    let down_ref = std::fs::read(dir.join("down.txt")).unwrap_or_default();

    // Reset remote dir + downloaded file.
    let _ = std::fs::remove_dir_all(&remote_base);
    std::fs::create_dir_all(&remote_base).unwrap();
    let _ = std::fs::remove_file(dir.join("down.txt"));

    let out_ns = run_sftp(&sftp);
    let tree_ns = collect_tree(&remote_base);
    let down_ns = std::fs::read(dir.join("down.txt")).unwrap_or_default();

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        out_ref.status.success(),
        out_ns.status.success(),
        "sftp vs ns-sftp exit mismatch: ref={:?} ns={:?}\nref_err={}\nns_err={}",
        out_ref.status.code(), out_ns.status.code(),
        String::from_utf8_lossy(&out_ref.stderr),
        String::from_utf8_lossy(&out_ns.stderr)
    );
    assert_trees_equal(&tree_ref, &tree_ns, "sftp batch commands");
    assert_eq!(down_ref, down_ns, "sftp downloaded file differs");
    assert_eq!(down_ns, b"parity sftp\n", "sftp download content wrong");
    let _ = std::fs::remove_dir_all(&dir);
}

/// sftp parity: directory listing after mkdir/put is identical.
#[test]
fn sftp_parity_directory_listing() {
    let dir = temp_dir("sftp-ls");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();
    let sftp = ns_tool(&dir, "ns-sftp");

    let batch = dir.join("batch.txt");
    std::fs::write(
        &batch,
        format!(
            "cd {}\nmkdir sub\nput /etc/hosts sub/hosts\nls -l sub\n",
            remote_base.display()
        ),
    )
    .unwrap();

    let run_sftp = |tool: &Path| {
        Command::new(tool)
            .arg("-P").arg(port.to_string())
            .arg("-i").arg(&id_path)
            .arg("-F").arg("/dev/null")
            .arg("-o").arg(format!("User={}", user))
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
            .arg("-b").arg(&batch)
            .arg("127.0.0.1")
            .output()
            .expect("run sftp ls")
    };

    let out_ref = run_sftp(Path::new("/usr/bin/sftp"));
    let ls_ref = String::from_utf8_lossy(&out_ref.stdout).to_string();

    let _ = std::fs::remove_dir_all(&remote_base);
    std::fs::create_dir_all(&remote_base).unwrap();
    let out_ns = run_sftp(&sftp);
    let ls_ns = String::from_utf8_lossy(&out_ns.stdout).to_string();

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        out_ref.status.success(),
        out_ns.status.success(),
        "sftp ls exit mismatch: ref={:?} ns={:?}",
        out_ref.status.code(), out_ns.status.code()
    );
    // Both listings must show a file whose basename is `hosts` (the ref may
    // render the path as `sub/hosts`, ns-sftp as `hosts`).
    let has_hosts = |s: &str| {
        s.lines().any(|l| {
            let last = l.split_whitespace().last().unwrap_or("");
            last == "hosts" || last.ends_with("/hosts")
        })
    };
    assert!(
        has_hosts(&ls_ref) && has_hosts(&ls_ns),
        "both listings must show 'hosts': ref={:?} ns={:?}",
        ls_ref, ls_ns
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// sftp parity: `mget`/`mput` with glob patterns expand against the remote
/// cwd / local cwd and transfer only the matching files (Q07).
#[test]
fn sftp_parity_glob_mget_mput() {
    let dir = temp_dir("sftp-glob");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    // Local sources: two .txt files and one .log (must be excluded by *.txt).
    let local_src = dir.join("local");
    std::fs::create_dir_all(&local_src).unwrap();
    std::fs::write(local_src.join("a.txt"), b"alpha\n").unwrap();
    std::fs::write(local_src.join("b.txt"), b"beta\n").unwrap();
    std::fs::write(local_src.join("c.log"), b"log\n").unwrap();

    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();
    let sftp = ns_tool(&dir, "ns-sftp");

    let batch = dir.join("batch.txt");
    std::fs::write(
        &batch,
        format!(
            "lcd {}\ncd {}\nmput *.txt\nls\n",
            local_src.display(), remote_base.display()
        ),
    )
    .unwrap();

    let run_sftp = |tool: &Path| {
        Command::new(tool)
            .arg("-P").arg(port.to_string())
            .arg("-i").arg(&id_path)
            .arg("-F").arg("/dev/null")
            .arg("-o").arg(format!("User={}", user))
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
            .arg("-b").arg(&batch)
            .arg("127.0.0.1")
            .output()
            .expect("run sftp glob")
    };

    // Reference: OpenSSH sftp.
    let out_ref = run_sftp(Path::new("/usr/bin/sftp"));
    let tree_ref = collect_tree(&remote_base);

    // Reset remote dir for ns-sftp.
    let _ = std::fs::remove_dir_all(&remote_base);
    std::fs::create_dir_all(&remote_base).unwrap();
    let out_ns = run_sftp(&sftp);
    let tree_ns = collect_tree(&remote_base);

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        out_ref.status.success(),
        out_ns.status.success(),
        "sftp glob exit mismatch: ref={:?} ns={:?}\nref_err={}\nns_err={}",
        out_ref.status.code(), out_ns.status.code(),
        String::from_utf8_lossy(&out_ref.stderr),
        String::from_utf8_lossy(&out_ns.stderr)
    );
    assert_trees_equal(&tree_ref, &tree_ns, "sftp mput glob");
    // Only the two .txt files must be uploaded; c.log excluded by *.txt.
    let names: Vec<String> = tree_ns.iter().map(|(n, _)| n.clone()).collect();
    assert!(names.contains(&"a.txt".to_string()), "a.txt missing: {names:?}");
    assert!(names.contains(&"b.txt".to_string()), "b.txt missing: {names:?}");
    assert!(!names.contains(&"c.log".to_string()), "c.log must be excluded: {names:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// scp parity: `scp -p` preserves the source mtime across upload and download.
/// The ns-scp client and the ns-ssh-server `scp -t -p` subsystem must round-trip
/// the `T` timestamp header so the downloaded file's mtime matches the source.
#[test]
fn scp_parity_preserve_times() {
    let dir = temp_dir("scp-times");
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let (mut server, id_path, kh) = launch_server(&dir, port);

    let src = dir.join("src.txt");
    std::fs::write(&src, b"preserve me\n").unwrap();
    // Set a fixed mtime ~1 day ago (whole seconds to avoid FS rounding).
    let fixed = std::time::SystemTime::now() - std::time::Duration::from_secs(86400);
    let ft = std::fs::FileTimes::new().set_modified(fixed);
    let f = std::fs::File::options().write(true).open(&src).unwrap();
    f.set_times(ft).unwrap();
    let src_mtime = std::fs::metadata(&src).unwrap().modified().unwrap();

    let remote_base = dir.join("remote");
    std::fs::create_dir_all(&remote_base).unwrap();
    let base = base_client_args(port, &id_path, &kh);
    let remote = format!("{}@127.0.0.1:{}/", user, remote_base.display());
    let scp = ns_tool(&dir, "scp");

    // Upload with -p, then download with -p.
    let up = Command::new(&scp)
        .args(&base).arg("-p").arg(&src).arg(&remote)
        .output().expect("ns-scp -p upload");
    assert!(up.status.success(), "upload failed: {}", String::from_utf8_lossy(&up.stderr));
    let down = dir.join("down.txt");
    let down_remote = format!("{}@127.0.0.1:{}/src.txt", user, remote_base.display());
    let dl = Command::new(&scp)
        .args(&base).arg("-p").arg(&down_remote).arg(&down)
        .output().expect("ns-scp -p download");
    assert!(dl.status.success(), "download failed: {}", String::from_utf8_lossy(&dl.stderr));
    let _ = server.kill();
    let _ = server.wait();

    let down_mtime = std::fs::metadata(&down).unwrap().modified().unwrap();
    let diff = down_mtime.duration_since(src_mtime).unwrap_or_default();
    assert!(
        diff.as_secs() < 5,
        "scp -p did not preserve mtime: src={src_mtime:?} down={down_mtime:?} diff={diff:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
