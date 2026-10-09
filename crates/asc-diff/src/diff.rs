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
    pub native: Option<NativeDiff>,
}

/// ELF comparison for one shared object whose bytes changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeDiff {
    Elf {
        diff: asc_so::ElfDiff,
        disassembly: Vec<asc_so::DisasmBlock>,
        /// Present when a file's section headers and program headers disagreed.
        link_notes: Vec<String>,
    },
    Unreadable(String),
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
        let left_paths = resource_names(left);
        let right_paths = resource_names(right);
        let left_map = by_name(left.entries(), prefix, &left_paths);
        let right_map = by_name(right.entries(), prefix, &right_paths);
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
                    native: native_diff(left, right, name),
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
            group
                .added
                .sort_by(|left, right| left.name.cmp(&right.name));
            group
                .removed
                .sort_by(|left, right| left.name.cmp(&right.name));
            group
                .changed
                .sort_by(|left, right| left.name.cmp(&right.name));
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

fn native_diff(left: &Archive, right: &Archive, name: &str) -> Option<NativeDiff> {
    if Group::of(name) != Group::Native {
        return None;
    }
    let parsed = match (left.read(name), right.read(name)) {
        (Ok(left_bytes), Ok(right_bytes)) => {
            match (
                asc_so::ElfInfo::parse(&left_bytes),
                asc_so::ElfInfo::parse(&right_bytes),
            ) {
                (Ok(left_elf), Ok(right_elf)) => {
                    let diff = left_elf.diff(&right_elf);
                    let disassembly = asc_so::disassemble_changes(
                        &left_bytes,
                        &right_bytes,
                        &left_elf,
                        &right_elf,
                    );
                    let link_notes = link_notes(&left_elf, &right_elf);
                    NativeDiff::Elf {
                        diff,
                        disassembly,
                        link_notes,
                    }
                }
                (Err(err), _) | (_, Err(err)) => NativeDiff::Unreadable(err.to_string()),
            }
        }
        (Err(err), _) | (_, Err(err)) => NativeDiff::Unreadable(err.to_string()),
    };
    Some(parsed)
}

fn link_notes(left: &asc_so::ElfInfo, right: &asc_so::ElfInfo) -> Vec<String> {
    if left.program_headers_preferred || right.program_headers_preferred {
        vec!["link: program headers override sections".to_string()]
    } else {
        Vec::new()
    }
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

fn resource_names(archive: &Archive) -> BTreeMap<String, String> {
    let Ok(bytes) = archive.read("resources.arsc") else {
        return BTreeMap::new();
    };
    asc_apk::resource_paths(&bytes).unwrap_or_default()
}

fn by_name<'a>(
    entries: &'a [FileEntry],
    prefix: &str,
    paths: &BTreeMap<String, String>,
) -> BTreeMap<String, &'a FileEntry> {
    let mut out = BTreeMap::new();
    for entry in entries {
        let restored = paths
            .get(&entry.name)
            .map(String::as_str)
            .unwrap_or(entry.name.as_str());
        if !prefix.is_empty() && !entry.name.starts_with(prefix) && !restored.starts_with(prefix) {
            continue;
        }
        let key = if out.contains_key(restored) {
            disambiguate(&out, &entry.name)
        } else {
            restored.to_string()
        };
        out.insert(key, entry);
    }
    out
}

fn disambiguate(taken: &BTreeMap<String, &FileEntry>, original: &str) -> String {
    if !taken.contains_key(original) {
        return original.to_string();
    }
    let mut index = 2u32;
    loop {
        let candidate = format!("{original}#{index}");
        if !taken.contains_key(&candidate) {
            return candidate;
        }
        index = index.saturating_add(1);
    }
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
                if let Some(native) = &entry.native {
                    write_native(formatter, native)?;
                }
            }
        }
        if let Some(certificates) = &self.certificates {
            write_certificates(formatter, certificates)?;
        }
        Ok(())
    }
}

fn write_native(formatter: &mut fmt::Formatter<'_>, native: &NativeDiff) -> fmt::Result {
    match native {
        NativeDiff::Unreadable(err) => writeln!(formatter, "    elf: {err}"),
        NativeDiff::Elf {
            diff,
            disassembly,
            link_notes,
        } if diff.is_empty() && disassembly.is_empty() && link_notes.is_empty() => {
            writeln!(formatter, "    elf: symbols unchanged")
        }
        NativeDiff::Elf {
            diff,
            disassembly,
            link_notes,
        } => {
            for note in link_notes {
                writeln!(formatter, "    {note}")?;
            }
            if diff.is_empty() && disassembly.is_empty() {
                return writeln!(formatter, "    elf: symbols unchanged");
            }
            for (name, left, right) in &diff.header {
                writeln!(formatter, "    {name}: {left} -> {right}")?;
            }
            for name in &diff.needed_removed {
                writeln!(formatter, "    needed - {name}")?;
            }
            for name in &diff.needed_added {
                writeln!(formatter, "    needed + {name}")?;
            }
            for name in &diff.imports_removed {
                writeln!(formatter, "    import - {name}")?;
            }
            for name in &diff.imports_added {
                writeln!(formatter, "    import + {name}")?;
            }
            for name in &diff.exports_removed {
                writeln!(formatter, "    export - {name}")?;
            }
            for name in &diff.exports_added {
                writeln!(formatter, "    export + {name}")?;
            }
            for block in disassembly {
                writeln!(formatter, "    disasm {}", block.title)?;
                for line in &block.left {
                    writeln!(formatter, "      < {line}")?;
                }
                for line in &block.right {
                    writeln!(formatter, "      > {line}")?;
                }
            }
            Ok(())
        }
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
