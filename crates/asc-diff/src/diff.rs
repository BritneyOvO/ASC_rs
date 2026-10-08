use std::collections::BTreeMap;
use std::fmt;

use crate::archive::{Archive, FileEntry};
use crate::cert::Certificate;

/// Where an archive entry sits. The order of the variants is the report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Manifest,
    Module,
    ResourceTable,
    Resources,
    Dex,
    Abc,
    Native,
    Assets,
    Res,
    Other,
}

impl Group {
    pub fn label(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Module => "module",
            Self::ResourceTable => "resources.arsc",
            Self::Resources => "resources",
            Self::Dex => "dex",
            Self::Abc => "abc",
            Self::Native => "lib",
            Self::Assets => "assets",
            Self::Res => "res",
            Self::Other => "other",
        }
    }

    pub fn of(name: &str) -> Self {
        let file = name.rsplit('/').next().unwrap_or(name);
        if file == "AndroidManifest.xml" || name.ends_with("/AndroidManifest.xml") {
            Self::Manifest
        } else if is_hap_module_file(name) {
            Self::Module
        } else if file == "resources.arsc" {
            Self::ResourceTable
        } else if name.starts_with("resources/") || file == "resources.index" {
            Self::Resources
        } else if file.ends_with(".dex") {
            Self::Dex
        } else if file.ends_with(".abc") {
            Self::Abc
        } else if (name.starts_with("lib/") || name.starts_with("libs/")) && file.ends_with(".so") {
            Self::Native
        } else if name.starts_with("assets/") {
            Self::Assets
        } else if name.starts_with("res/") || name.starts_with("r/") {
            Self::Res
        } else {
            Self::Other
        }
    }
}

/// A path that exists on only one side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileChange {
    pub name: String,
    pub size: u64,
}

/// A path whose uncompressed bytes differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentChange {
    pub name: String,
    pub left_size: u64,
    pub right_size: u64,
}

/// Added, removed, and changed files in one group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDiff {
    pub group: Group,
    pub unchanged: usize,
    pub added: Vec<FileChange>,
    pub removed: Vec<FileChange>,
    pub changed: Vec<ContentChange>,
}

impl GroupDiff {
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.changed.is_empty()
    }
}

/// Signing certificates matched by their SHA-256 fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateDiff {
    pub unchanged: Vec<Certificate>,
    pub added: Vec<Certificate>,
    pub removed: Vec<Certificate>,
}

impl CertificateDiff {
    fn between(left: &[Certificate], right: &[Certificate]) -> Self {
        let mut unchanged = Vec::new();
        let mut removed = Vec::new();
        for cert in left {
            if right.iter().any(|other| other.sha256 == cert.sha256) {
                unchanged.push(cert.clone());
            } else {
                removed.push(cert.clone());
            }
        }
        let added = right
            .iter()
            .filter(|cert| !left.iter().any(|other| other.sha256 == cert.sha256))
            .cloned()
            .collect();
        Self {
            unchanged,
            added,
            removed,
        }
    }

    fn is_empty(&self) -> bool {
        self.unchanged.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }
}

/// File-level difference of two archives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveDiff {
    pub groups: Vec<GroupDiff>,
    /// `None` when this report was limited to a prefix that is not `META-INF`.
    pub certificates: Option<CertificateDiff>,
}

impl ArchiveDiff {
    pub fn between(left: &Archive, right: &Archive) -> Self {
        Self::between_prefix(left, right, "")
    }

    /// Like [`between`](Self::between), but only entries whose path starts with `prefix`.
    pub fn between_prefix(left: &Archive, right: &Archive, prefix: &str) -> Self {
        let left_map = by_name(left.entries(), prefix);
        let right_map = by_name(right.entries(), prefix);
        let mut groups: BTreeMap<Group, GroupDiff> = BTreeMap::new();
        for (name, entry) in &left_map {
            let group = ensure(&mut groups, name);
            match right_map.get(name) {
                None => group.removed.push(FileChange {
                    name: name.to_string(),
                    size: entry.size,
                }),
                Some(other) if other.crc == entry.crc && other.size == entry.size => {
                    group.unchanged += 1;
                }
                Some(other) => group.changed.push(ContentChange {
                    name: name.to_string(),
                    left_size: entry.size,
                    right_size: other.size,
                }),
            }
        }
        for (name, entry) in &right_map {
            if left_map.contains_key(name) {
                continue;
            }
            ensure(&mut groups, name).added.push(FileChange {
                name: name.to_string(),
                size: entry.size,
            });
        }
        for group in groups.values_mut() {
            group.added.sort_by(|left, right| left.name.cmp(&right.name));
            group.removed.sort_by(|left, right| left.name.cmp(&right.name));
            group.changed.sort_by(|left, right| left.name.cmp(&right.name));
        }
        let certificates = wants_certificates(prefix)
            .then(|| CertificateDiff::between(left.certificates(), right.certificates()));
        Self {
            groups: groups.into_values().collect(),
            certificates,
        }
    }

    pub fn added_count(&self) -> usize {
        self.groups.iter().map(|group| group.added.len()).sum()
    }

    pub fn removed_count(&self) -> usize {
        self.groups.iter().map(|group| group.removed.len()).sum()
    }

    pub fn changed_count(&self) -> usize {
        self.groups.iter().map(|group| group.changed.len()).sum()
    }

    pub fn unchanged_count(&self) -> usize {
        self.groups.iter().map(|group| group.unchanged).sum()
    }
}


fn is_hap_module_file(name: &str) -> bool {
    matches!(
        name,
        "module.json" | "config.json" | "pack.info" | "pkgContextInfo.json"
    )
}

fn wants_certificates(prefix: &str) -> bool {
    prefix.is_empty() || "META-INF/".starts_with(prefix) || prefix.starts_with("META-INF/")
}

fn ensure<'a>(groups: &'a mut BTreeMap<Group, GroupDiff>, name: &str) -> &'a mut GroupDiff {
    let kind = Group::of(name);
    groups.entry(kind).or_insert(GroupDiff {
        group: kind,
        unchanged: 0,
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
    })
}

fn by_name<'a>(entries: &'a [FileEntry], prefix: &str) -> BTreeMap<&'a str, &'a FileEntry> {
    entries
        .iter()
        .filter(|entry| entry.name.starts_with(prefix))
        .map(|entry| (entry.name.as_str(), entry))
        .collect()
}

impl fmt::Display for ArchiveDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "changed {}, added {}, removed {}, unchanged {}",
            self.changed_count(),
            self.added_count(),
            self.removed_count(),
            self.unchanged_count()
        )?;
        for group in &self.groups {
            if !group.has_changes() && group.unchanged == 0 {
                continue;
            }
            writeln!(
                formatter,
                "{}: changed {}, added {}, removed {}, unchanged {}",
                group.group.label(),
                group.changed.len(),
                group.added.len(),
                group.removed.len(),
                group.unchanged
            )?;
            for entry in &group.removed {
                writeln!(formatter, "  - {} ({} bytes)", entry.name, entry.size)?;
            }
            for entry in &group.added {
                writeln!(formatter, "  + {} ({} bytes)", entry.name, entry.size)?;
            }
            for entry in &group.changed {
                writeln!(
                    formatter,
                    "  ~ {}  {} -> {} bytes",
                    entry.name, entry.left_size, entry.right_size
                )?;
            }
        }
        if let Some(certificates) = &self.certificates {
            write_certificates(formatter, certificates)?;
        }
        Ok(())
    }
}

fn write_certificates(formatter: &mut fmt::Formatter<'_>, diff: &CertificateDiff) -> fmt::Result {
    if diff.is_empty() {
        return writeln!(formatter, "certificate: none");
    }
    writeln!(
        formatter,
        "certificate: added {}, removed {}, unchanged {}",
        diff.added.len(),
        diff.removed.len(),
        diff.unchanged.len()
    )?;
    for cert in &diff.removed {
        writeln!(formatter, "  - {}", cert.sha256)?;
        write_cert_body(formatter, cert)?;
    }
    for cert in &diff.added {
        writeln!(formatter, "  + {}", cert.sha256)?;
        write_cert_body(formatter, cert)?;
    }
    for cert in &diff.unchanged {
        writeln!(formatter, "  = {}", cert.sha256)?;
        write_cert_body(formatter, cert)?;
    }
    Ok(())
}

fn write_cert_body(formatter: &mut fmt::Formatter<'_>, cert: &Certificate) -> fmt::Result {
    writeln!(formatter, "    Subject: {}", cert.subject)?;
    writeln!(formatter, "    Issuer: {}", cert.issuer)?;
    writeln!(formatter, "    Serial: {}", cert.serial)?;
    writeln!(
        formatter,
        "    Valid: {} .. {}",
        cert.not_before, cert.not_after
    )?;
    writeln!(formatter, "    Source: {}", cert.source)
}



#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::Group;
    use crate::Archive;

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
        let diff = crate::ArchiveDiff::between(&Archive::open(&left).unwrap(), &Archive::open(&right).unwrap());
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
        let prefixed = crate::ArchiveDiff::between_prefix(
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
        let diff = crate::ArchiveDiff::between(
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
        let diff = crate::ArchiveDiff::between(
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
}
