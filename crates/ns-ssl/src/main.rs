//! `ns-ssl`: a pure-Rust TLS client/server built on rustls, providing an
//! `openssl s_client` / `openssl s_server`-style CLI without depending on
//! OpenSSL. Supports TLS 1.2/1.3, certificate verification, ALPN, and a
//! simple HTTP echo for interop testing against a real `openssl` peer.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(|s| s.as_str()).unwrap_or("s_client");

    let result = match mode {
        "s_client" => run_s_client(&args[1..]),
        "s_server" => run_s_server(&args[1..]),
        "-h" | "--help" | "help" => {
            print_help();
            return;
        }
        other => {
            eprintln!("ns-ssl: unknown mode '{}'", other);
            eprintln!("usage: ns-ssl s_client|s_server [options]");
            std::process::exit(1);
        }
    };
    if let Err(e) = result {
        eprintln!("ns-ssl: {}", e);
        std::process::exit(1);
    }
}

fn print_help() {
    eprintln!(
        "usage: ns-ssl s_client [-connect host:port] [-CAfile file] [-servername name] [-alpn proto,...] [-tls1_2|-tls1_3]\n\
         \x20      ns-ssl s_server [-accept port] [-cert file] [-key file] [-alpn proto,...] [-tls1_2|-tls1_3]"
    );
}

/// Parse a `-flag value` style option list into a map (last value wins).
fn parse_opts(args: &[String]) -> (std::collections::HashMap<String, String>, Vec<String>) {
    let mut opts = std::collections::HashMap::new();
    let mut positionals = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            let key = a.trim_start_matches('-').to_string();
            // Some flags are boolean (no value).
            let bool_flags = ["quiet", "state", "debug", "tls1_2", "tls1_3", "ign_eof", "nocomp"];
            if bool_flags.contains(&key.as_str()) {
                opts.insert(key, "true".to_string());
            } else if i + 1 < args.len() {
                opts.insert(key, args[i + 1].clone());
                i += 1;
            } else {
                opts.insert(key, "".to_string());
            }
        } else {
            positionals.push(a.clone());
        }
        i += 1;
    }
    (opts, positionals)
}

/// Load a certificate chain from a PEM file.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs in {}: {}", path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates in {}", path));
    }
    Ok(certs)
}

/// Load a private key from a PEM file (PKCS#8, PKCS#1, or SEC1).
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key in {}: {}", path, e))?
        .ok_or_else(|| format!("no private key found in {}", path))
}

fn run_s_client(args: &[String]) -> Result<(), String> {
    let (opts, _pos) = parse_opts(args);
    let connect = opts.get("connect").cloned().unwrap_or_else(|| "localhost:4433".to_string());
    let servername = opts.get("servername").cloned()
        .or_else(|| connect.rsplit(':').next().map(|s| s.to_string()))
        .unwrap_or_else(|| "localhost".to_string());

    // Build the client config.
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = opts.get("CAfile") {
        let certs = load_certs(ca)?;
        for c in certs {
            roots.add(c).map_err(|e| format!("add CA cert: {}", e))?;
        }
    } else {
        // Use the system/webpki roots by default.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut versions = rustls::ALL_VERSIONS.to_vec();
    if opts.contains_key("tls1_2") {
        versions.retain(|v| v.version == rustls::ProtocolVersion::TLSv1_2);
    }
    if opts.contains_key("tls1_3") {
        versions.retain(|v| v.version == rustls::ProtocolVersion::TLSv1_3);
    }

    let builder = ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(roots);
    let mut config = if let Some(cert) = opts.get("cert") {
        let key = opts.get("key").cloned().unwrap_or_else(|| cert.clone());
        let certs = load_certs(cert)?;
        let key = load_private_key(&key)?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("client cert: {}", e))?
    } else {
        builder.with_no_client_auth()
    };
    if let Some(alpn) = opts.get("alpn") {
        let protos: Vec<Vec<u8>> = alpn.split(',').map(|p| p.as_bytes().to_vec()).collect();
        config.alpn_protocols = protos;
    }
    let config = Arc::new(config);

    let server_name = ServerName::try_from(servername.clone())
        .map_err(|e| format!("invalid servername '{}': {}", servername, e))?;

    let tcp = TcpStream::connect(&connect).map_err(|e| format!("connect {}: {}", connect, e))?;
    let conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("client conn: {}", e))?;
    let mut tls = StreamOwned::new(conn, tcp);

    // Handshake.
    if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
        return Err(format!("handshake: {}", e));
    }
    if let Some(protocol) = tls.conn.alpn_protocol() {
        println!("ALPN protocol: {}", String::from_utf8_lossy(protocol));
    }
    println!(
        "Protocol  : {:?}",
        tls.conn.protocol_version()
    );
    println!(
        "Cipher    : {:?}",
        tls.conn.negotiated_cipher_suite().map(|c| c.suite())
    );
    println!("Peer certs: {}", tls.conn.peer_certificates().map(|c| c.len()).unwrap_or(0));

    // Read stdin and forward to the server, echo the reply (for test use).
    let mut buf = [0u8; 4096];
    let mut input = std::io::stdin();
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if tls.write_all(&buf[..n]).is_err() {
            break;
        }
        if tls.flush().is_err() {
            break;
        }
        // Read whatever the server sent back.
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(m) => {
                let _ = std::io::stdout().write_all(&buf[..m]);
                let _ = std::io::stdout().flush();
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn run_s_server(args: &[String]) -> Result<(), String> {
    let (opts, _pos) = parse_opts(args);
    let accept = opts.get("accept").cloned().unwrap_or_else(|| "4433".to_string());
    let cert = opts.get("cert").ok_or_else(|| "s_server requires -cert".to_string())?;
    let key = opts.get("key").cloned().unwrap_or_else(|| cert.clone());

    let certs = load_certs(cert)?;
    let key = load_private_key(&key)?;

    let mut versions = rustls::ALL_VERSIONS.to_vec();
    if opts.contains_key("tls1_2") {
        versions.retain(|v| v.version == rustls::ProtocolVersion::TLSv1_2);
    }
    if opts.contains_key("tls1_3") {
        versions.retain(|v| v.version == rustls::ProtocolVersion::TLSv1_3);
    }

    let builder = ServerConfig::builder_with_protocol_versions(&versions);
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("server cert: {}", e))?;
    if let Some(alpn) = opts.get("alpn") {
        let protos: Vec<Vec<u8>> = alpn.split(',').map(|p| p.as_bytes().to_vec()).collect();
        config.alpn_protocols = protos;
    }
    let config = Arc::new(config);

    let addr = format!("127.0.0.1:{}", accept);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("bind {}: {}", addr, e))?;
    eprintln!("ns-ssl: listening on {}", addr);
    for stream in listener.incoming() {
        let Ok(tcp) = stream else { continue };
        let config = Arc::clone(&config);
        std::thread::spawn(move || {
            let _ = handle_server_conn(tcp, config);
        });
    }
    Ok(())
}

fn handle_server_conn(tcp: TcpStream, config: Arc<ServerConfig>) -> Result<(), String> {
    let conn = rustls::ServerConnection::new(config).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
        return Err(format!("handshake: {}", e));
    }
    eprintln!("ns-ssl: client connected, proto={:?}", tls.conn.protocol_version());
    // Echo loop: read a request line, reply with a small HTTP response.
    let mut buf = [0u8; 8192];
    loop {
        let n = match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let request = String::from_utf8_lossy(&buf[..n]);
        if request.starts_with("GET") || request.starts_with("HEAD") {
            let body = b"ns-ssl hello\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if tls.write_all(resp.as_bytes()).is_err() || tls.write_all(body).is_err() {
                break;
            }
            let _ = tls.flush();
            break;
        } else {
            if tls.write_all(&buf[..n]).is_err() {
                break;
            }
            let _ = tls.flush();
        }
    }
    Ok(())
}
