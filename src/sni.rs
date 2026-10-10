//! TLS ClientHello SNI parser.
//!
//! Only extracts the first `host_name` (type 0) from extension 0x0000.
//! Never panics on untrusted input: any truncation or malformed
//! structure yields `None`, and the caller routes to the default backend.

/// Parsed ClientHello metadata: SNI and ALPN protocols.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// Normalized SNI, if present.
    pub sni: Option<String>,
    /// Negotiated ALPN protocol names, if present.
    pub alpn: Vec<String>,
}

impl ClientHelloInfo {
    /// Returns true if the client requested the ACME TLS-ALPN-01 protocol (`acme-tls/1`).
    pub fn is_acme_tls_alpn(&self) -> bool {
        self.alpn.iter().any(|p| p == "acme-tls/1")
    }
}

/// Parse a buffered TLS record and return the normalized SNI, if present.
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    parse_client_hello(buf).sni
}

/// Parse a buffered TLS record and return both SNI and ALPN protocols.
pub fn parse_client_hello(buf: &[u8]) -> ClientHelloInfo {
    let mut info = ClientHelloInfo::default();

    // Need at least: record header (5) + handshake header (4).
    if buf.len() < 9 {
        return info;
    }
    // Record header: ContentType must be Handshake (0x16).
    if buf[0] != 0x16 {
        return info;
    }
    // Handshake header: type must be ClientHello (0x01).
    if buf[5] != 0x01 {
        return info;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let body_end = (5 + record_len).min(buf.len());
    if body_end <= 9 {
        return info;
    }
    let body = &buf[9..body_end];

    let mut cur = Cursor::new(body);
    // ProtocolVersion (2) + Random (32).
    if cur.skip(2 + 32).is_none() {
        return info;
    }
    // Session ID.
    let sid_len = match cur.u8() {
        Some(l) => l as usize,
        None => return info,
    };
    if cur.skip(sid_len).is_none() {
        return info;
    }
    // Cipher suites.
    let cs_len = match cur.u16() {
        Some(l) => l as usize,
        None => return info,
    };
    if cur.skip(cs_len).is_none() {
        return info;
    }
    // Compression methods.
    let comp_len = match cur.u8() {
        Some(l) => l as usize,
        None => return info,
    };
    if cur.skip(comp_len).is_none() {
        return info;
    }
    // Extensions.
    let ext_total = match cur.u16() {
        Some(v) => v as usize,
        None => return info,
    };
    let ext_end = (cur.pos + ext_total).min(cur.data.len());

    while cur.pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([cur.data[cur.pos], cur.data[cur.pos + 1]]);
        let ext_len = u16::from_be_bytes([cur.data[cur.pos + 2], cur.data[cur.pos + 3]]) as usize;
        cur.pos += 4;
        let data_end = (cur.pos + ext_len).min(ext_end);
        if ext_type == 0x0000 {
            if let Some(name) = parse_server_name(cur.data, cur.pos, data_end) {
                info.sni = normalize_sni(&name);
            }
        } else if ext_type == 0x0010 {
            info.alpn = parse_alpn(cur.data, cur.pos, data_end);
        }
        cur.pos = data_end;
    }

    info
}

fn parse_alpn(data: &[u8], start: usize, end: usize) -> Vec<String> {
    if end > data.len() || start + 2 > end {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[start], data[start + 1]]) as usize;
    let mut pos = start + 2;
    let list_end = (pos + list_len).min(end);
    let mut protocols = Vec::new();

    while pos < list_end {
        let proto_len = data[pos] as usize;
        pos += 1;
        if pos + proto_len > list_end {
            break;
        }
        if let Ok(proto) = std::str::from_utf8(&data[pos..pos + proto_len]) {
            protocols.push(proto.to_string());
        }
        pos += proto_len;
    }

    protocols
}

/// Parse the ServerNameList inside extension 0x0000.
///
/// Returns the first entry with name type 0 (host_name).
fn parse_server_name(data: &[u8], start: usize, end: usize) -> Option<Vec<u8>> {
    if end > data.len() || start + 2 > end {
        return None;
    }
    let list_len = u16::from_be_bytes([data[start], data[start + 1]]) as usize;
    let mut pos = start + 2;
    let list_end = (pos + list_len).min(end);
    while pos + 3 <= list_end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        let name_end = pos.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }
        if name_type == 0 {
            return Some(data[pos..name_end].to_vec());
        }
        pos = name_end;
    }
    None
}

/// Normalize raw SNI bytes: ASCII case-fold, single trailing dot trim,
/// strict validation. Returns `None` for anything suspicious.
pub fn normalize_sni(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        // Reject NUL, non-ASCII, controls, space and DEL.
        if b == 0 || !(0x21..=0x7e).contains(&b) {
            return None;
        }
        out.push(b.to_ascii_lowercase());
    }
    // Strip a single trailing dot ("example.com." -> "example.com").
    if out.len() > 1 && out[out.len() - 1] == b'.' {
        out.pop();
    }
    if out.is_empty() {
        return None;
    }
    // Safe: validated ASCII above.
    String::from_utf8(out).ok()
}

/// Simple bounds-checked cursor over a byte slice.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        if self.pos > self.data.len() {
            return None;
        }
        Some(())
    }

    fn u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = *self.data.get(self.pos)? as u16;
        let lo = *self.data.get(self.pos + 1)? as u16;
        self.pos += 2;
        Some((hi << 8) | lo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ClientHello record carrying the given SNI.
    fn build_hello(sni: Option<&str>, greedy_grease: bool) -> Vec<u8> {
        let mut exts: Vec<u8> = Vec::new();
        if greedy_grease {
            // Fake GREASE extension to ensure the loop skips unknown types.
            exts.extend_from_slice(&[0x0a, 0x0a, 0x00, 0x02, 0xaa, 0xbb]);
        }
        if let Some(name) = sni {
            let mut sni_ext: Vec<u8> = Vec::new();
            let mut list: Vec<u8> = Vec::new();
            list.push(0x00); // host_name
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name.as_bytes());
            sni_ext.extend_from_slice(&((list.len()) as u16).to_be_bytes());
            sni_ext.extend_from_slice(&list);
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            exts.extend_from_slice(&sni_ext);
        }

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        body.extend_from_slice(&[0x55u8; 32]); // random
        body.push(0x00); // empty session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one suite
        body.push(0x01); // compression length
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs: Vec<u8> = Vec::new();
        hs.push(0x01); // ClientHello
        let len = body.len() as u32;
        hs.push((len >> 16) as u8);
        hs.push((len >> 8) as u8);
        hs.push(len as u8);
        hs.extend_from_slice(&body);

        let mut rec: Vec<u8> = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        let hello = build_hello(Some("studio.iuharin.ru"), false);
        assert_eq!(parse_sni(&hello).as_deref(), Some("studio.iuharin.ru"));
    }

    #[test]
    fn skips_grease_and_folds_case() {
        let hello = build_hello(Some("EXAMPLE.COM."), true);
        assert_eq!(parse_sni(&hello).as_deref(), Some("example.com"));
    }

    #[test]
    fn no_sni_returns_none() {
        let hello = build_hello(None, false);
        assert_eq!(parse_sni(&hello), None);
    }

    #[test]
    fn non_tls_returns_none() {
        assert_eq!(parse_sni(b"GET / HTTP/1.0\r\n\r\n"), None);
        assert_eq!(parse_sni(&[]), None);
        assert_eq!(parse_sni(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x00]), None);
    }

    #[test]
    fn truncated_returns_none_without_panic() {
        let hello = build_hello(Some("penik.ru"), false);
        for i in 0..hello.len() {
            let _ = parse_sni(&hello[..i]);
        }
    }

    #[test]
    fn rejects_bad_names() {
        assert_eq!(normalize_sni(b""), None);
        assert_eq!(normalize_sni(b"ex\0ample.com"), None);
        assert_eq!(normalize_sni(b"has space.com"), None);
        assert_eq!(normalize_sni(&[0xd0, 0xbf]), None); // non-ASCII
        assert_eq!(normalize_sni(b"EXAMPLE.COM."), Some("example.com".into()));
        // Punycode passes through untouched.
        assert_eq!(
            normalize_sni(b"xn--80akhbyknj4f.ru"),
            Some("xn--80akhbyknj4f.ru".into())
        );
    }
}
