//! Minimal DER walking over one X.509 leaf certificate.
//!
//! REALITY replaces CA validation with an HMAC over the leaf's public key
//! compared against its signature bytes, so all we need from the DER is
//! exactly those two byte strings — a full X.509 parser would be dead weight.
//! Structure per RFC 5280:
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate       SEQUENCE { .. , subjectPublicKeyInfo SEQUENCE {
//!                                algorithm SEQUENCE, subjectPublicKey BIT STRING },
//!                            .. },
//!     signatureAlgorithm   SEQUENCE,
//!     signatureValue       BIT STRING }
//! ```

use super::{malformed, Failure};

/// A parsed TLV element: tag, content slice, and the offset just past it.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    end: usize,
}

fn tlv(buf: &[u8], at: usize) -> Result<Tlv<'_>, Failure> {
    if at >= buf.len() {
        return Err(malformed("DER truncated at element start"));
    }
    let tag = buf[at];
    let mut p = at + 1;
    if p >= buf.len() {
        return Err(malformed("DER truncated at length"));
    }
    let first = buf[p];
    p += 1;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || p + n > buf.len() {
            return Err(malformed("bad DER long-form length"));
        }
        let mut l = 0usize;
        for b in &buf[p..p + n] {
            l = (l << 8) | *b as usize;
        }
        p += n;
        l
    };
    // Checked: with a four-byte long-form length the sum can overflow a
    // 32-bit `usize`, and a wrapped end would pass the bound check.
    let end = p
        .checked_add(len)
        .filter(|end| *end <= buf.len())
        .ok_or_else(|| malformed("DER element overruns the buffer"))?;
    Ok(Tlv {
        tag,
        content: &buf[p..end],
        end,
    })
}

/// The two byte strings REALITY's verification needs.
pub struct CertParts<'a> {
    /// `subjectPublicKey` BIT STRING contents (32 bytes for Ed25519).
    pub spki_key: &'a [u8],
    /// `signatureValue` BIT STRING contents (the last 64 bytes of the DER
    /// for Ed25519 certificates — where the REALITY HMAC lives).
    pub signature: &'a [u8],
    /// The first X.509 extension value, if the leaf has an extensions
    /// sequence. Xray uses that value for its optional ML-DSA-65 REALITY
    /// certificate binding.
    pub first_extension: Option<&'a [u8]>,
}

/// Walk a leaf certificate and extract `CertParts`.
pub fn parse_leaf(cert: &[u8]) -> Result<CertParts<'_>, Failure> {
    let outer = tlv(cert, 0)?;
    if outer.tag != 0x30 {
        return Err(malformed("certificate is not a DER SEQUENCE"));
    }

    // Top-level children: tbs, signatureAlgorithm, signatureValue. The
    // offsets returned by `tlv` over `outer.content` are relative to that
    // content slice, so keep walking that same slice instead of indexing the
    // complete certificate with a relative offset.
    let tbs = tlv(outer.content, 0)?;
    if tbs.tag != 0x30 {
        return Err(malformed("tbsCertificate is not a SEQUENCE"));
    }
    let signature_algorithm = tlv(outer.content, tbs.end)?;
    if signature_algorithm.tag != 0x30 {
        return Err(malformed("signatureAlgorithm is not a SEQUENCE"));
    }
    let sig = tlv(outer.content, signature_algorithm.end)?;
    if sig.tag != 0x03 {
        return Err(malformed("signatureValue is not a BIT STRING"));
    }
    let signature = bit_string_content(sig.content)?;

    // SPKI is the last plain SEQUENCE element of tbsCertificate ([3]
    // extensions have tag 0xa3 and are correctly skipped).
    let tbs_body = tbs.content;
    let mut at = 0usize;
    let mut spki: Option<&[u8]> = None;
    let mut first_extension: Option<&[u8]> = None;
    while at < tbs_body.len() {
        let el = tlv(tbs_body, at)?;
        if el.tag == 0x30 {
            spki = Some(el.content);
        } else if el.tag == 0xa3 && first_extension.is_none() {
            first_extension = parse_first_extension_value(el.content)?;
        }
        at = el.end;
    }
    let spki_body = spki.ok_or_else(|| malformed("no subjectPublicKeyInfo in certificate"))?;

    // SPKI = SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }.
    let mut at = 0usize;
    let mut key: Option<&[u8]> = None;
    while at < spki_body.len() {
        let el = tlv(spki_body, at)?;
        if el.tag == 0x03 {
            key = Some(bit_string_content(el.content)?);
        }
        at = el.end;
    }
    let spki_key = key.ok_or_else(|| malformed("no subjectPublicKey BIT STRING"))?;

    Ok(CertParts {
        spki_key,
        signature,
        first_extension,
    })
}

fn parse_first_extension_value(explicit_extensions: &[u8]) -> Result<Option<&[u8]>, Failure> {
    let extensions = tlv(explicit_extensions, 0)?;
    if extensions.tag != 0x30 || extensions.end != explicit_extensions.len() {
        return Err(malformed(
            "certificate extensions are not a complete SEQUENCE",
        ));
    }
    if extensions.content.is_empty() {
        return Ok(None);
    }
    let extension = tlv(extensions.content, 0)?;
    if extension.tag != 0x30 {
        return Err(malformed("certificate extension is not a SEQUENCE"));
    }

    let mut at = 0usize;
    let oid = tlv(extension.content, at)?;
    if oid.tag != 0x06 {
        return Err(malformed("certificate extension has no OID"));
    }
    at = oid.end;
    if at < extension.content.len() && extension.content[at] == 0x01 {
        at = tlv(extension.content, at)?.end;
    }
    let value = tlv(extension.content, at)?;
    if value.tag != 0x04 || value.end != extension.content.len() {
        return Err(malformed("certificate extension has no OCTET STRING value"));
    }
    Ok(Some(value.content))
}

fn bit_string_content(content: &[u8]) -> Result<&[u8], Failure> {
    let unused = content.first().copied().unwrap_or(0xff);
    if unused != 0 {
        return Err(malformed("BIT STRING has non-zero unused bits"));
    }
    content
        .get(1..)
        .ok_or_else(|| malformed("BIT STRING without content"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else {
            let bytes = (len as u32).to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
            let body = &bytes[first..];
            let mut out = vec![0x80 | body.len() as u8];
            out.extend_from_slice(body);
            out
        }
    }

    fn der(seq_body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        out.extend_from_slice(&length(seq_body.len()));
        out.extend_from_slice(seq_body);
        out
    }

    fn bit_str(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x03, (data.len() + 1) as u8, 0x00];
        out.extend_from_slice(data);
        out
    }

    fn inner(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        out.extend_from_slice(&length(body.len()));
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn extracts_spki_and_signature_from_a_synthetic_cert() {
        let pubkey = [0xabu8; 32];
        let signature = [0xcdu8; 64];

        // SPKI = SEQ { SEQ(algorithm, stub), BIT STRING(key) }
        let spki_body = {
            let alg = inner(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // OID 1.3.101.112
            let mut b = alg;
            b.extend(bit_str(&pubkey));
            b
        };
        // tbs = SEQ { version, serial, spki } (order irrelevant to the walker)
        let tbs_body = {
            let mut b = vec![0xa0, 0x03, 0x02, 0x01, 0x02]; // [0] version
            b.extend(inner(&[0x02, 0x01, 0x00])); // serial 0
            b.extend(inner(&spki_body));
            b
        };
        let mut cert_body = inner(&tbs_body);
        cert_body.extend(inner(&[0x06, 0x03, 0x2b, 0x65, 0x70])); // sig alg
        cert_body.extend(bit_str(&signature));
        let cert = der(&cert_body);

        let parts = parse_leaf(&cert).unwrap();
        assert_eq!(parts.spki_key, pubkey.as_slice());
        assert_eq!(parts.signature, signature.as_slice());
    }

    #[test]
    fn extensions_after_spki_do_not_confuse_the_walk() {
        let pubkey = [0x11u8; 32];
        let signature = [0x22u8; 64];
        let spki_body = {
            let mut b = inner(&[0x06, 0x03, 0x2b, 0x65, 0x70]);
            b.extend(bit_str(&pubkey));
            b
        };
        let spki = inner(&spki_body);
        let mut tbs_body = spki;
        tbs_body.extend(vec![0xa3, 0x02, 0x30, 0x00]); // [3] empty extensions
        let mut cert_body = inner(&tbs_body);
        cert_body.extend(inner(&[0x06, 0x03, 0x2b, 0x65, 0x70]));
        cert_body.extend(bit_str(&signature));
        let cert = der(&cert_body);

        let parts = parse_leaf(&cert).unwrap();
        assert_eq!(parts.spki_key, pubkey.as_slice());
        assert_eq!(parts.signature, signature.as_slice());
    }

    #[test]
    fn extracts_the_first_extension_octet_string() {
        let pubkey = [0x11u8; 32];
        let signature = [0x22u8; 64];
        let extension_value = [0xa5, 0xb6, 0xc7, 0xd8];
        let spki_body = {
            let mut b = inner(&[0x06, 0x03, 0x2b, 0x65, 0x70]);
            b.extend(bit_str(&pubkey));
            b
        };
        let extension = {
            let mut body = vec![0x06, 0x01, 0x2b, 0x04];
            body.extend_from_slice(&length(extension_value.len()));
            body.extend_from_slice(&extension_value);
            inner(&body)
        };
        let extensions = inner(&extension);
        let mut explicit = vec![0xa3];
        explicit.extend_from_slice(&length(extensions.len()));
        explicit.extend_from_slice(&extensions);
        let mut tbs_body = inner(&spki_body);
        tbs_body.extend(explicit);
        let mut cert_body = inner(&tbs_body);
        cert_body.extend(inner(&[0x06, 0x03, 0x2b, 0x65, 0x70]));
        cert_body.extend(bit_str(&signature));

        let cert = der(&cert_body);
        let parts = parse_leaf(&cert).unwrap();
        assert_eq!(parts.first_extension, Some(extension_value.as_slice()));
    }

    #[test]
    fn truncated_der_is_rejected() {
        assert!(parse_leaf(&[0x30, 0x82]).is_err());
        assert!(parse_leaf(&[0x30, 0x10, 0x00]).is_err());
    }
}
