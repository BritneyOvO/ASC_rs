//! X.509 certificates carried in JAR signature blocks (`META-INF/*.{RSA,DSA,EC}`).

use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// One signing certificate, independent of the signature-block file bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub sha256: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub source: String,
}

pub(crate) fn is_signature_block(name: &str) -> bool {
    let Some(file) = name.strip_prefix("META-INF/") else {
        return false;
    };
    if file.contains('/') {
        return false;
    }
    let ext = file.rsplit('.').next().unwrap_or("");
    matches!(ext, "RSA" | "DSA" | "EC" | "rsa" | "dsa" | "ec")
}

/// Certificates embedded in the `<hap sign block>` that sits in front of the
/// central directory. The same certificate may be repeated for each signature
/// scheme; callers deduplicate by fingerprint.
pub(crate) fn hap_certificates(archive: &[u8]) -> Vec<Certificate> {
    let Some(block) = hap_sign_block(archive) else {
        return Vec::new();
    };
    certificates_in("hap sign block", block)
}

fn hap_sign_block(archive: &[u8]) -> Option<&[u8]> {
    let magic = b"<hap sign block>";
    let magic_at = find_last(archive, magic)?;
    if magic_at < 8 {
        return None;
    }
    let size = u64::from_le_bytes(archive[magic_at - 8..magic_at].try_into().ok()?);
    let size = usize::try_from(size).ok()?;
    if size < 8 || magic_at < size {
        return None;
    }
    let start = magic_at - size;
    Some(&archive[start..magic_at - 8])
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

pub(crate) fn certificates_in(source: &str, bytes: &[u8]) -> Vec<Certificate> {
    let mut found = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != 0x30 {
            index += 1;
            continue;
        }
        match X509Certificate::from_der(&bytes[index..]) {
            Ok((rest, cert)) => {
                let der = cert.as_raw();
                if der.is_empty() {
                    index += 1;
                    continue;
                }
                let consumed = bytes.len() - index - rest.len();
                found.push(describe(source, der, &cert));
                index += consumed.max(1);
            }
            Err(_) => index += 1,
        }
    }
    found.sort_by(|left, right| left.sha256.cmp(&right.sha256));
    found.dedup_by(|right, left| right.sha256 == left.sha256);
    found
}

fn describe(source: &str, der: &[u8], cert: &X509Certificate<'_>) -> Certificate {
    let digest = Sha256::digest(der);
    Certificate {
        sha256: hex_pairs(&digest),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        source: source.to_string(),
    }
}

fn hex_pairs(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
