//! PROXY protocol version 2 encoder (HAProxy spec).
//!
//! Used only on backends with `send_proxy_protocol = true` (Caddy).
//! Format: 12-byte signature + ver/cmd + fam/proto + len + addresses.

use std::net::{IpAddr, SocketAddr};

/// 12-byte v2 signature: \r\n\r\n\0\r\nQUIT\n
const SIGNATURE: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

/// Encode a PROXY protocol v2 header for a proxied TCP connection.
///
/// Both addresses are canonicalized (`to_canonical`), so IPv4-mapped
/// IPv6 becomes plain IPv4. Mixed families or non-TCP fall back to
/// the minimal `LOCAL` (health-check) header so the backend never stalls.
pub fn encode_ppv2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let src_c = canonical(src);
    let dst_c = canonical(dst);

    match (src_c.ip(), dst_c.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut out = Vec::with_capacity(28);
            out.extend_from_slice(SIGNATURE);
            out.push(0x21); // version 2 + PROXY command
            out.push(0x11); // AF_INET + STREAM
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            out.extend_from_slice(&src_c.port().to_be_bytes());
            out.extend_from_slice(&dst_c.port().to_be_bytes());
            out
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut out = Vec::with_capacity(52);
            out.extend_from_slice(SIGNATURE);
            out.push(0x21);
            out.push(0x21); // AF_INET6 + STREAM
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            out.extend_from_slice(&src_c.port().to_be_bytes());
            out.extend_from_slice(&dst_c.port().to_be_bytes());
            out
        }
        // Mixed families: send LOCAL so the receiver skips address parsing.
        _ => {
            let mut out = Vec::with_capacity(16);
            out.extend_from_slice(SIGNATURE);
            out.push(0x20); // version 2 + LOCAL command
            out.push(0x00); // UNSPEC
            out.extend_from_slice(&0u16.to_be_bytes());
            out
        }
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => addr,
        SocketAddr::V6(v6) => SocketAddr::new(v6.ip().to_canonical(), v6.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port)
    }

    #[test]
    fn encodes_ipv4() {
        let hdr = encode_ppv2(v4([1, 2, 3, 4], 1234), v4([5, 6, 7, 8], 443));
        assert_eq!(hdr.len(), 28);
        assert_eq!(&hdr[..12], SIGNATURE);
        assert_eq!(hdr[12], 0x21);
        assert_eq!(hdr[13], 0x11);
        assert_eq!(&hdr[14..16], &12u16.to_be_bytes());
        assert_eq!(&hdr[16..20], &[1, 2, 3, 4]);
        assert_eq!(&hdr[20..24], &[5, 6, 7, 8]);
        assert_eq!(&hdr[24..26], &1234u16.to_be_bytes());
        assert_eq!(&hdr[26..28], &443u16.to_be_bytes());
    }

    #[test]
    fn encodes_ipv6() {
        let src: SocketAddr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            1234,
        );
        let dst: SocketAddr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            443,
        );
        let hdr = encode_ppv2(src, dst);
        assert_eq!(hdr.len(), 52);
        assert_eq!(hdr[13], 0x21);
        assert_eq!(&hdr[14..16], &36u16.to_be_bytes());
    }

    #[test]
    fn mapped_ipv4_becomes_ipv4() {
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:1234".parse().unwrap();
        let dst = v4([5, 6, 7, 8], 443);
        let hdr = encode_ppv2(mapped, dst);
        // Must be the short AF_INET form, not AF_INET6.
        assert_eq!(hdr.len(), 28);
        assert_eq!(hdr[13], 0x11);
        assert_eq!(&hdr[16..20], &[1, 2, 3, 4]);
    }

    #[test]
    fn mixed_families_fall_back_to_local() {
        let src = v4([1, 2, 3, 4], 1234);
        let dst: SocketAddr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            443,
        );
        let hdr = encode_ppv2(src, dst);
        assert_eq!(hdr.len(), 16);
        assert_eq!(hdr[12], 0x20);
    }
}
