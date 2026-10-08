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
