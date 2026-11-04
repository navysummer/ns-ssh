//! Minimal DNS SSHFP (RFC 4255) lookup without external dependencies.
//!
//! Queries the system resolver (from `/etc/resolv.conf`) over UDP and parses
//! the response to extract SSHFP records. Used by `VerifyHostKeyDNS`.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const DNS_TYPE_SSHFP: u16 = 44;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_CLASS_IN: u16 = 1;

/// Per-nameserver response timeout. OpenSSH's resolver eventually gives up;
/// an unbounded `recv` here used to hang the handshake forever when the local
/// resolver ignored an SSHFP query (which also made parallel test runs freeze).
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

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

fn build_query(hostname: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD bit
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name(hostname, &mut q);
    q.extend_from_slice(&qtype.to_be_bytes());
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

fn parse_response(pkt: &[u8], expected_id: u16) -> Vec<SshfpRecord> {
    let mut out = Vec::new();
    if pkt.len() < 12 {
        return out;
    }
    // A connected UDP socket only guarantees the source address, not that the
    // datagram is actually the answer to *our* query. Reject responses whose
    // transaction ID differs (spoofing / cross-talk), that are not responses
    // (QR=0), or that carry a server failure code.
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let rcode = flags & 0x000f;
    if id != expected_id || flags & 0x8000 == 0 || rcode != 0 || flags & 0x0200 != 0 {
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

/// Send `query` to a single nameserver and return its raw reply. Returns
/// `None` on any socket/resolution error or timeout.
fn send_query(nameserver: &str, query: &[u8]) -> Option<Vec<u8>> {
    let addr: SocketAddr = (nameserver, 53u16)
        .to_socket_addrs()
        .ok()?
        .next()?;
    // Bind an unconnected socket first only to pick the right address
    // family; connecting it makes the kernel filter datagrams from any
    // other source (a spoofed reply must still guess the random ID).
    let sock = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
    sock.set_read_timeout(Some(DNS_TIMEOUT)).ok()?;
    sock.connect(addr).ok()?;
    sock.send(query).ok()?;
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

/// Read a possibly-compressed name starting at `off`. Returns the dotted name
/// and the offset just past the name at its original location.
fn read_name(pkt: &[u8], off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = off;
    let mut next_off = off;
    let mut jumped = false;
    let mut hops = 0;
    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            if !jumped {
                next_off = pos + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= pkt.len() {
                return None;
            }
            let target = (((len & 0x3f) as usize) << 8) | pkt[pos + 1] as usize;
            if !jumped {
                next_off = pos + 2;
                jumped = true;
            }
            hops += 1;
            // Bound pointer chains so a malformed reply cannot loop forever.
            if hops > 16 {
                return None;
            }
            pos = target;
            continue;
        }
        if pos + 1 + len > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[pos + 1..pos + 1 + len]).to_string());
        pos += 1 + len;
    }
    Some((labels.join("."), next_off))
}

/// Extract the first CNAME target from a DNS response, validating the header
/// the same way as SSHFP replies.
fn parse_cname(pkt: &[u8], expected_id: u16) -> Option<String> {
    if pkt.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let rcode = flags & 0x000f;
    if id != expected_id || flags & 0x8000 == 0 || rcode != 0 || flags & 0x0200 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let mut off = 12;
    for _ in 0..qdcount {
        off = skip_name(pkt, off);
        if off + 4 > pkt.len() {
            return None;
        }
        off += 4;
    }
    for _ in 0..ancount {
        let (_owner, name_end) = read_name(pkt, off)?;
        off = name_end;
        if off + 10 > pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
        off += 10;
        if off + rdlen > pkt.len() {
            return None;
        }
        if rtype == DNS_TYPE_CNAME {
            let (target, _) = read_name(pkt, off)?;
            return Some(target.trim_end_matches('.').to_string());
        }
        off += rdlen;
    }
    None
}

/// Look up SSHFP records for `hostname`. Returns an empty vector if no
/// records are found or if DNS resolution fails.
pub fn lookup_sshfp(hostname: &str) -> Vec<SshfpRecord> {
    let nameservers = parse_resolv_conf_nameservers();
    if nameservers.is_empty() {
        return Vec::new();
    }
    // A random transaction ID makes off-path response spoofing impractical.
    let id: u16 = rand::random();
    let query = build_query(hostname, DNS_TYPE_SSHFP, id);
    for ns in nameservers {
        if let Some(pkt) = send_query(&ns, &query) {
            let records = parse_response(&pkt, id);
            if !records.is_empty() {
                return records;
            }
        }
    }
    Vec::new()
}

/// Resolve the CNAME target of `hostname` via the system resolver configuration.
/// Returns `None` when the name has no CNAME or DNS lookup fails.
pub fn lookup_cname(hostname: &str) -> Option<String> {
    let nameservers = parse_resolv_conf_nameservers();
    if nameservers.is_empty() {
        return None;
    }
    let id: u16 = rand::random();
    let query = build_query(hostname, DNS_TYPE_CNAME, id);
    for ns in nameservers {
        if let Some(pkt) = send_query(&ns, &query) {
            if let Some(target) = parse_cname(&pkt, id) {
                return Some(target);
            }
        }
    }
    None
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

        let records = parse_response(&pkt, 0x1234);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].algorithm, 1);
        assert_eq!(records[0].fingerprint_type, 2);
        assert_eq!(records[0].fingerprint, vec![0xaa, 0xbb]);
    }

    /// A datagram with the wrong transaction ID, or one that is not a response
    /// (QR=0), must be ignored rather than parsed into attacker-chosen records.
    #[test]
    fn parse_sshfp_response_rejects_wrong_id_and_non_response() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0xbeefu16.to_be_bytes());
        pkt.extend_from_slice(&0x8180u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        encode_dns_name("example.com", &mut pkt);
        pkt.extend_from_slice(&DNS_TYPE_SSHFP.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&0xc00cu16.to_be_bytes());
        pkt.extend_from_slice(&DNS_TYPE_SSHFP.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&300u32.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.push(1);
        pkt.push(2);
        pkt.extend_from_slice(&[0xaa, 0xbb]);

        assert!(parse_response(&pkt, 0x1234).is_empty(), "wrong ID accepted");
        // Flip QR off: it is a query echo, not an answer.
        pkt[2] = 0x01;
        assert!(parse_response(&pkt, 0xbeef).is_empty(), "non-response accepted");
    }

    #[test]
    fn parse_cname_response_follows_compression_pointer() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x4321u16.to_be_bytes());
        pkt.extend_from_slice(&0x8180u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        pkt.extend_from_slice(&1u16.to_be_bytes()); // ancount
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        encode_dns_name("old.example.com", &mut pkt);
        pkt.extend_from_slice(&DNS_TYPE_CNAME.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // Answer for the question name (pointer to offset 12).
        pkt.extend_from_slice(&0xc00cu16.to_be_bytes());
        pkt.extend_from_slice(&DNS_TYPE_CNAME.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&300u32.to_be_bytes());
        let rdata_start = pkt.len() + 2;
        pkt.extend_from_slice(&4u16.to_be_bytes());
        // Target: "new" + pointer to the "example.com" suffix in the question.
        pkt.extend_from_slice(&[3, b'n', b'e', b'w']);
        pkt.extend_from_slice(&(0xc000u16 | 16u16).to_be_bytes());
        assert_eq!(rdata_start, pkt.len() - 6);

        assert_eq!(
            parse_cname(&pkt, 0x4321).as_deref(),
            Some("new.example.com")
        );
        // Transaction ID mismatches are ignored.
        assert_eq!(parse_cname(&pkt, 0x9999), None);
    }
}
