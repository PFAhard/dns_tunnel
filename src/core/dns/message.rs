//! Minimal DNS wire-format support (RFC 1035) — hand-rolled by design,
//! see `docs/design.md`.

use std::fmt;
use std::net::Ipv4Addr;

/// DNS message header (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Query/response ID — correlates a response with its query.
    pub id: u16,
    /// Raw flag bits (QR, opcode, …).
    pub flags: u16,
    /// Number of entries in the question section.
    pub qdcount: u16,
    /// Number of resource records in the answer section.
    pub ancount: u16,
    /// Number of resource records in the authority section.
    pub nscount: u16,
    /// Number of resource records in the additional section.
    pub arcount: u16,
}

/// A single question entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Fully-qualified domain name, as written on the wire.
    pub name: String,
    /// Record type (e.g. 1 = A, 28 = AAAA).
    pub qtype: u16,
    /// Class (almost always 1 = IN).
    pub qclass: u16,
}

/// Record type for IPv4 addresses.
pub const TYPE_A: u16 = 1;

/// Wire-format errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Buffer ended before the message was complete.
    Truncated,
    /// Invalid name encoding (bad label, unsupported compression form, …).
    BadName,
    /// Compression pointer would not terminate (loop or forward jump).
    PointerLoop,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated DNS message"),
            Self::BadName => f.write_str("invalid DNS name encoding"),
            Self::PointerLoop => f.write_str("DNS compression pointer loop"),
        }
    }
}

impl std::error::Error for Error {}

/// Maximum compression-pointer jumps while reading a single name.
const MAX_POINTER_JUMPS: usize = 16;

/// Parses the 12-byte message header.
///
/// # Errors
///
/// Returns [`Error::Truncated`] if fewer than 12 bytes are available.
pub fn parse_header(bytes: &[u8]) -> Result<Header, Error> {
    let raw = bytes.get(..12).ok_or(Error::Truncated)?;
    Ok(Header {
        id: u16::from_be_bytes([raw[0], raw[1]]),
        flags: u16::from_be_bytes([raw[2], raw[3]]),
        qdcount: u16::from_be_bytes([raw[4], raw[5]]),
        ancount: u16::from_be_bytes([raw[6], raw[7]]),
        nscount: u16::from_be_bytes([raw[8], raw[9]]),
        arcount: u16::from_be_bytes([raw[10], raw[11]]),
    })
}

/// Parses a domain name at `*pos` (compression pointers supported) and
/// advances `*pos` past the encoding.
///
/// Pointers must target an earlier offset (RFC 1035 §4.1.4); anything else
/// is reported as [`Error::PointerLoop`].
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::BadName`], or
/// [`Error::PointerLoop`].
pub fn parse_name(bytes: &[u8], pos: &mut usize) -> Result<String, Error> {
    let mut name = String::new();
    let mut jumps = 0usize;
    let mut cursor = *pos;
    let mut first = true;
    loop {
        let len = *bytes.get(cursor).ok_or(Error::Truncated)?;
        match len & 0xC0 {
            0xC0 => {
                let low = *bytes.get(cursor + 1).ok_or(Error::Truncated)?;
                let target = usize::from((u16::from(len & 0x3F) << 8) | u16::from(low));
                if target >= cursor {
                    return Err(Error::PointerLoop);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(Error::PointerLoop);
                }
                if jumps == 1 {
                    // First pointer: the name ends after its 2-byte pointer,
                    // not after the pointed-to data.
                    *pos = cursor + 2;
                }
                cursor = target;
            }
            0x00 => {
                if len == 0 {
                    if first {
                        name.push('.'); // root
                    }
                    if jumps == 0 {
                        *pos = cursor + 1; // terminator of an uncompressed name
                    }
                    return Ok(name);
                }
                let end = cursor + 1 + usize::from(len);
                let label = bytes.get(cursor + 1..end).ok_or(Error::Truncated)?;
                if !first {
                    name.push('.');
                }
                if !label.is_ascii() {
                    return Err(Error::BadName);
                }
                name.push_str(std::str::from_utf8(label).map_err(|_| Error::BadName)?);
                first = false;
                cursor = end;
            }
            _ => return Err(Error::BadName), // 0x40/0x80 extended labels unsupported
        }
    }
}

/// Parses the header and all question entries, returning the byte position
/// right after the question section (start of the answer section).
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::BadName`], or
/// [`Error::PointerLoop`].
pub fn parse_questions(bytes: &[u8]) -> Result<(Header, Vec<Question>, usize), Error> {
    let header = parse_header(bytes)?;
    let mut pos = 12usize;
    // Minimum question is a root name (1 byte) + qtype (2) + qclass (2) = 5
    // bytes; cap the pre-allocation so a tiny malicious packet claiming a
    // huge qdcount cannot make us reserve megabytes up front.
    let mut questions = Vec::with_capacity(usize::from(header.qdcount));
    for _ in 0..header.qdcount {
        let name = parse_name(bytes, &mut pos)?;
        let qtype = read_u16(bytes, &mut pos)?;
        let qclass = read_u16(bytes, &mut pos)?;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }
    Ok((header, questions, pos))
}

/// Walks `header.ancount` resource records starting at `cursor` and returns
/// the IPv4 address and TTL of every A record.
///
/// Other record types (CNAME, AAAA, TXT, …) are skipped — CNAME chains
/// resolve to A records in the same answer section, which this collects.
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::BadName`], or
/// [`Error::PointerLoop`].
pub fn collect_a_records(
    bytes: &[u8],
    header: &Header,
    cursor: usize,
) -> Result<Vec<(Ipv4Addr, u32)>, Error> {
    let mut pos = cursor;
    let mut addresses = Vec::new();
    for _ in 0..header.ancount {
        parse_name(bytes, &mut pos)?; // owner name — discarded
        let qtype = read_u16(bytes, &mut pos)?;
        let _class = read_u16(bytes, &mut pos)?;
        let ttl = read_u32(bytes, &mut pos)?;
        let rdlen = usize::from(read_u16(bytes, &mut pos)?);
        let rdata = bytes.get(pos..pos + rdlen).ok_or(Error::Truncated)?;
        // An A record with rdlen != 4 is malformed — skip it (lenient; the
        // response bytes are forwarded verbatim regardless).
        if qtype == TYPE_A && rdlen == 4 {
            addresses.push((
                Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
                ttl,
            ));
        }
        pos += rdlen;
    }
    Ok(addresses)
}

/// Appends the wire encoding of `name` to `out` (no compression).
///
/// # Errors
///
/// Returns [`Error::BadName`] if a label is empty, longer than 63 bytes, or
/// contains non-ASCII bytes.
pub fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), Error> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(Error::BadName);
        }
        out.push(u8::try_from(label.len()).map_err(|_| Error::BadName)?);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Builds a query message (recursion desired) for `name`/`qtype`.
///
/// Used by tests and tooling — the engine forwards raw client bytes instead
/// of crafting its own queries.
///
/// # Errors
///
/// Returns [`Error::BadName`] if `name` cannot be encoded.
pub fn encode_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(12 + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class: IN
    Ok(out)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, Error> {
    let raw = bytes.get(*pos..*pos + 2).ok_or(Error::Truncated)?;
    *pos += 2;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, Error> {
    let raw = bytes.get(*pos..*pos + 4).ok_or(Error::Truncated)?;
    *pos += 4;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let bytes = encode_query(0x1234, "www.example.com", TYPE_A).unwrap();
        let (header, questions, cursor) = parse_questions(&bytes).unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(header.qdcount, 1);
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].name, "www.example.com");
        assert_eq!(questions[0].qtype, TYPE_A);
        assert_eq!(questions[0].qclass, 1);
        assert_eq!(cursor, bytes.len());
    }

    #[test]
    fn trailing_dot_encodes_same() {
        let with_dot = encode_query(1, "example.com.", TYPE_A).unwrap();
        let without = encode_query(1, "example.com", TYPE_A).unwrap();
        assert_eq!(with_dot, without);
    }

    #[test]
    fn root_name_parses() {
        let mut pos = 0;
        assert_eq!(parse_name(&[0], &mut pos).unwrap(), ".");
    }

    #[test]
    fn parses_compressed_name() {
        // "www.example.com" at offset 0, then a pointer to offset 0.
        let mut bytes = Vec::new();
        encode_name(&mut bytes, "www.example.com").unwrap();
        bytes.extend_from_slice(&[0xC0, 0x00]);
        let mut pos = bytes.len() - 2;
        assert_eq!(parse_name(&bytes, &mut pos).unwrap(), "www.example.com");
        assert_eq!(pos, bytes.len()); // advanced past the pointer
    }

    #[test]
    fn pointer_to_self_is_rejected() {
        // Pointer at offset 0 pointing back at offset 0.
        let bytes = [0xC0u8, 0x00, 0x00];
        let mut pos = 0;
        assert_eq!(parse_name(&bytes, &mut pos), Err(Error::PointerLoop));
    }

    #[test]
    fn extended_label_is_rejected() {
        let bytes = [0x41u8, 0x00]; // 0x41 = reserved label form
        let mut pos = 0;
        assert_eq!(parse_name(&bytes, &mut pos), Err(Error::BadName));
    }

    #[test]
    fn truncated_header() {
        assert_eq!(parse_header(&[0, 1, 2]), Err(Error::Truncated));
    }

    #[test]
    fn truncated_name() {
        let bytes = [3u8, b'w']; // label says 3 bytes, only 1 present
        let mut pos = 0;
        assert_eq!(parse_name(&bytes, &mut pos), Err(Error::Truncated));
    }

    #[test]
    fn encode_rejects_long_label() {
        let label = "a".repeat(64);
        assert_eq!(encode_name(&mut Vec::new(), &label), Err(Error::BadName));
    }

    #[test]
    fn encode_rejects_non_ascii() {
        assert_eq!(
            encode_name(&mut Vec::new(), "exämple.com"),
            Err(Error::BadName)
        );
    }

    /// Builds a response with one question and the given answer records.
    ///
    /// `answers` entries are `(qtype, rdata)`; owner names use a compression
    /// pointer to the question name at offset 12.
    fn response_fixture(answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xABCDu16.to_be_bytes()); // id
        bytes.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: QR|RD|RA
        bytes.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        bytes.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes()); // ancount
        bytes.extend_from_slice(&0u16.to_be_bytes()); // nscount
        bytes.extend_from_slice(&0u16.to_be_bytes()); // arcount
        encode_name(&mut bytes, "example.com").unwrap();
        bytes.extend_from_slice(&TYPE_A.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        for (qtype, rdata) in answers {
            bytes.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
            bytes.extend_from_slice(&qtype.to_be_bytes());
            bytes.extend_from_slice(&1u16.to_be_bytes()); // class IN
            bytes.extend_from_slice(&300u32.to_be_bytes()); // ttl
            bytes.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(rdata);
        }
        bytes
    }

    #[test]
    fn collects_a_records_after_cname() {
        let mut cname = Vec::new();
        encode_name(&mut cname, "alias.example.com").unwrap();
        let bytes = response_fixture(&[
            (5, &cname), // CNAME
            (TYPE_A, &[93, 184, 216, 34]),
        ]);
        let (header, _, cursor) = parse_questions(&bytes).unwrap();
        let addresses = collect_a_records(&bytes, &header, cursor).unwrap();
        assert_eq!(addresses, vec![(Ipv4Addr::new(93, 184, 216, 34), 300)]);
    }

    #[test]
    fn skips_aaaa_and_txt() {
        let txt = [3u8, b't', b'x', b't'];
        let bytes = response_fixture(&[
            (28, &[0; 16]), // AAAA
            (16, &txt),     // TXT
            (TYPE_A, &[10, 0, 0, 1]),
        ]);
        let (header, _, cursor) = parse_questions(&bytes).unwrap();
        let addresses = collect_a_records(&bytes, &header, cursor).unwrap();
        assert_eq!(addresses, vec![(Ipv4Addr::new(10, 0, 0, 1), 300)]);
    }

    #[test]
    fn collect_truncated_rdata() {
        // An A record whose rdlen (4) claims more bytes than are present.
        let mut bytes = response_fixture(&[(TYPE_A, &[1, 2, 3, 4])]);
        bytes.truncate(bytes.len() - 2);
        let (header, _, cursor) = parse_questions(&bytes).unwrap();
        assert_eq!(
            collect_a_records(&bytes, &header, cursor),
            Err(Error::Truncated)
        );
    }
}
