//! Minimal DNS SSHFP (RFC 4255) lookup without external dependencies.
//!
//! Queries the system resolver (from `/etc/resolv.conf`) over UDP and parses
//! the response to extract SSHFP records. Used by `VerifyHostKeyDNS`.

use std::net::UdpSocket;

const DNS_TYPE_SSHFP: u16 = 44;
const DNS_CLASS_IN: u16 = 1;

/// A parsed SSHFP record: (algorithm, fingerprint_type, fingerprint bytes).
pub struct SshfpRecord {
    pub algorithm: u8,
    pub fingerprint_type: u8,
    pub fingerprint: Vec<u8>,
}

fn parse_resolv_conf_nameservers() -> Vec<String> {
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    content
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with("nameserver") {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 2 {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn build_query(hostname: &str) -> Vec<u8> {
    let mut q = Vec::new();
    let id: u16 = 0x1234;
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD bit
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name(hostname, &mut q);
    q.extend_from_slice(&DNS_TYPE_SSHFP.to_be_bytes());
    q.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    q
}

fn skip_name(pkt: &[u8], mut off: usize) -> usize {
    loop {
        if off >= pkt.len() {
            return off;
        }
        let len = pkt[off] as usize;
        if len == 0 {
            return off + 1;
        }
        if len & 0xc0 == 0xc0 {
            return off + 2; // compression pointer
        }
        off += 1 + len;
    }
}

fn parse_response(pkt: &[u8]) -> Vec<SshfpRecord> {
    let mut out = Vec::new();
    if pkt.len() < 12 {
        return out;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let mut off = 12;
    // Skip the question section.
    for _ in 0..qdcount {
        off = skip_name(pkt, off);
        if off + 4 > pkt.len() {
            return out;
        }
        off += 4;
    }
    // Iterate answer records.
    for _ in 0..ancount {
        off = skip_name(pkt, off);
        if off + 10 > pkt.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
        off += 10;
        if off + rdlen > pkt.len() {
            return out;
        }
        if rtype == DNS_TYPE_SSHFP && rdlen >= 2 {
            out.push(SshfpRecord {
                algorithm: pkt[off],
                fingerprint_type: pkt[off + 1],
                fingerprint: pkt[off + 2..off + rdlen].to_vec(),
            });
        }
        off += rdlen;
    }
    out
}

/// Look up SSHFP records for `hostname`. Returns an empty vector if no
/// records are found or if DNS resolution fails.
pub fn lookup_sshfp(hostname: &str) -> Vec<SshfpRecord> {
    let nameservers = parse_resolv_conf_nameservers();
    if nameservers.is_empty() {
        return Vec::new();
    }
    let query = build_query(hostname);
    for ns in nameservers {
        let addr = format!("{}:53", ns);
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => continue,
        };
        if sock.send_to(&query, &addr).is_err() {
            continue;
        }
        let mut buf = [0u8; 4096];
        match sock.recv(&mut buf) {
            Ok(n) => {
                let records = parse_response(&buf[..n]);
                if !records.is_empty() {
                    return records;
                }
            }
            Err(_) => continue,
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_name_multilabel() {
        let mut out = Vec::new();
        encode_dns_name("example.com", &mut out);
        assert_eq!(out, vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn parse_sshfp_response() {
        // Build a synthetic DNS response: header + 1 question + 1 SSHFP answer.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
        pkt.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        pkt.extend_from_slice(&1u16.to_be_bytes()); // ancount
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        encode_dns_name("example.com", &mut pkt);
        pkt.extend_from_slice(&DNS_TYPE_SSHFP.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // Answer: name pointer (0xc00c), type SSHFP, class IN, ttl 300, rdlen 4
        pkt.extend_from_slice(&0xc00cu16.to_be_bytes());
        pkt.extend_from_slice(&DNS_TYPE_SSHFP.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&300u32.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.push(1); // algorithm ssh-dss
        pkt.push(2); // fingerprint type SHA256
        pkt.extend_from_slice(&[0xaa, 0xbb]);

        let records = parse_response(&pkt);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].algorithm, 1);
        assert_eq!(records[0].fingerprint_type, 2);
        assert_eq!(records[0].fingerprint, vec![0xaa, 0xbb]);
    }
}
