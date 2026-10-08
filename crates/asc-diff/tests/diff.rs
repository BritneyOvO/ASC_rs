use std::path::Path;

use asc_diff::{Archive, ArchiveDiff, Group};

fn store_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut locals = Vec::new();
    let mut central = Vec::new();
    for (name, bytes) in files {
        let name = name.as_bytes();
        let crc = crc32fast::hash(bytes);
        let offset = u32::try_from(locals.len()).unwrap();
        locals.extend_from_slice(b"PK\x03\x04");
        locals.extend_from_slice(&20u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&crc.to_le_bytes());
        locals.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        locals.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        locals.extend_from_slice(&(name.len() as u16).to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(name);
        locals.extend_from_slice(bytes);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        central.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_off = u32::try_from(locals.len()).unwrap();
    let cd_size = u32::try_from(central.len()).unwrap();
    let mut archive = locals;
    archive.extend_from_slice(&central);
    archive.extend_from_slice(b"PK\x05\x06");
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes());
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes());
    archive.extend_from_slice(&cd_size.to_le_bytes());
    archive.extend_from_slice(&cd_off.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
}

fn write_pair(dir: &Path, left: &[(&str, &[u8])], right: &[(&str, &[u8])]) -> (std::path::PathBuf, std::path::PathBuf) {
    let left_path = dir.join("left.zip");
    let right_path = dir.join("right.zip");
    std::fs::write(&left_path, store_zip(left)).unwrap();
    std::fs::write(&right_path, store_zip(right)).unwrap();
    (left_path, right_path)
}

#[test]
fn groups_assets_separately_from_dex_and_keeps_identical_files() {
    let dir = std::env::temp_dir().join(format!("asc-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = write_pair(
        &dir,
        &[
            ("assets/same.txt", b"same"),
            ("assets/old.txt", b"gone"),
            ("assets/changed.txt", b"v1"),
            ("classes.dex", b"dex-v1"),
            ("res/a.xml", b"<a/>"),
            ("META-INF/MANIFEST.MF", b"left-sign"),
        ],
        &[
            ("assets/same.txt", b"same"),
            ("assets/new.txt", b"fresh"),
            ("assets/changed.txt", b"v2"),
            ("classes.dex", b"dex-v2"),
            ("res/a.xml", b"<a/>"),
            ("META-INF/MANIFEST.MF", b"right-sign"),
        ],
    );
    let diff = ArchiveDiff::between(&Archive::open(&left).unwrap(), &Archive::open(&right).unwrap());
    assert_eq!(diff.unchanged_count(), 2);
    assert_eq!(diff.added_count(), 1);
    assert_eq!(diff.removed_count(), 1);
    assert_eq!(diff.changed_count(), 2);
    let assets = diff.groups.iter().find(|group| group.group == Group::Assets).unwrap();
    assert_eq!(assets.unchanged, 1);
    assert_eq!(assets.added[0].name, "assets/new.txt");
    assert_eq!(assets.removed[0].name, "assets/old.txt");
    assert_eq!(assets.changed[0].name, "assets/changed.txt");
    assert_eq!(assets.changed[0].left_size, 2);
    assert_eq!(assets.changed[0].right_size, 2);
    let prefixed = ArchiveDiff::between_prefix(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
        "assets/",
    );
    assert_eq!(prefixed.changed_count(), 1);
    assert!(prefixed.groups.iter().all(|group| group.group == Group::Assets));
    let shown = diff.to_string();
    assert!(shown.contains("assets/changed.txt"), "{shown}");
    assert!(shown.contains("classes.dex"), "{shown}");
    assert!(!shown.contains("META-INF"), "{shown}");
    assert!(shown.contains("certificate: none"), "{shown}");
    assert!(!prefixed.to_string().contains("certificate:"), "{prefixed}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn self_signed(name: &str) -> Vec<u8> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, name);
        dn
    };
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn signature_blocks_compare_certificates_not_file_bytes() {
    let dir = std::env::temp_dir().join(format!("asc-diff-cert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let first = self_signed("alpha");
    let second = self_signed("beta");
    let (left, right) = write_pair(
        &dir,
        &[
            ("assets/a.txt", b"same"),
            ("META-INF/CERT.RSA", first.as_slice()),
            ("META-INF/MANIFEST.MF", b"mf-left"),
        ],
        &[
            ("assets/a.txt", b"same"),
            ("META-INF/CERT.RSA", second.as_slice()),
            ("META-INF/MANIFEST.MF", b"mf-right"),
        ],
    );
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    assert_eq!(diff.changed_count(), 0, "{}", diff);
    assert_eq!(diff.certificates.as_ref().unwrap().removed.len(), 1);
    assert_eq!(diff.certificates.as_ref().unwrap().added.len(), 1);
    let shown = diff.to_string();
    assert!(shown.contains("Subject:"), "{shown}");
    assert!(shown.contains("CN=alpha"), "{shown}");
    assert!(shown.contains("CN=beta"), "{shown}");
    assert!(!shown.contains("MANIFEST.MF"), "{shown}");
    assert!(!shown.contains("~ META-INF/CERT.RSA"), "{shown}");
    assert!(shown.contains("Source: META-INF/CERT.RSA"), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn with_hap_sign(zip: &[u8], cert: &[u8]) -> Vec<u8> {
    let eocd = zip.len() - 22;
    let cd_off = u32::from_le_bytes(zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let size = u64::try_from(cert.len() + 8).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&zip[..cd_off]);
    out.extend_from_slice(cert);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(b"<hap sign block>");
    let new_cd = u32::try_from(out.len()).unwrap();
    out.extend_from_slice(&zip[cd_off..]);
    let new_eocd = out.len() - 22;
    out[new_eocd + 16..new_eocd + 20].copy_from_slice(&new_cd.to_le_bytes());
    out
}

#[test]
fn hap_entries_are_grouped_and_the_sign_block_is_a_certificate() {
    let dir = std::env::temp_dir().join(format!("asc-diff-hap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let alpha = self_signed("alpha");
    let beta = self_signed("beta");
    let left_zip = with_hap_sign(
        &store_zip(&[
            ("module.json", b"{\"v\":1}"),
            ("ets/modules.abc", b"abc-v1"),
            ("libs/arm64-v8a/libapp.so", b"so"),
            ("resources/base/element/string.json", b"[]"),
        ]),
        &alpha,
    );
    let right_zip = with_hap_sign(
        &store_zip(&[
            ("module.json", b"{\"v\":2}"),
            ("ets/modules.abc", b"abc-v1"),
            ("libs/arm64-v8a/libapp.so", b"so2"),
            ("resources/base/element/string.json", b"[]"),
        ]),
        &beta,
    );
    let left = dir.join("left.hap");
    let right = dir.join("right.hap");
    std::fs::write(&left, left_zip).unwrap();
    std::fs::write(&right, right_zip).unwrap();
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    let shown = diff.to_string();
    assert!(shown.contains("module:"), "{shown}");
    assert!(shown.contains("abc:"), "{shown}");
    assert!(shown.contains("lib:"), "{shown}");
    assert!(shown.contains("resources:"), "{shown}");
    assert!(shown.contains("CN=alpha"), "{shown}");
    assert!(shown.contains("CN=beta"), "{shown}");
    assert!(shown.contains("Source: hap sign block"), "{shown}");
    assert!(!shown.contains("hap sign block>"), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}
