//! Standalone DEX images. The file is mapped once. Resource substitution runs
//! only when `Options::resources` names a `resources.arsc`.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

use memmap2::Mmap;

use super::{
    dump_ddc_image, dump_smali_image, logical_offsets, normalize_dex041, present_ref_line,
    ClassRank, DumpCtx, Engine, Options,
};
use crate::{Error, Result};
use asc_dex::{find_in_dex_resolved, smali_class, Dex};

pub(super) struct Mapped {
    _file: File,
    map: Mmap,
}

impl Mapped {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.map
    }
}

pub(super) fn has_dex_magic(path: &Path) -> Result<bool> {
    let mut file = open_file(path)?;
    let mut magic = [0u8; 8];
    let read = file.read(&mut magic).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    Ok(is_dex_magic(&magic[..read]))
}

pub(super) fn open(path: &Path) -> Result<Option<Mapped>> {
    let mut file = open_file(path)?;
    let mut magic = [0u8; 8];
    let read = file.read(&mut magic).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    if !is_dex_magic(&magic[..read]) {
        return Ok(None);
    }
    // SAFETY: `file` is stored next to the map, so the descriptor outlives the
    // mapping, and this process does not remap the same range.
    let map = unsafe { Mmap::map(&file) }.map_err(|source| Error::IoPath {
        action: "map",
        path: path.display().to_string(),
        source,
    })?;
    Ok(Some(Mapped { _file: file, map }))
}

pub(super) fn list_classes(
    path: &Path,
    data: &[u8],
    prefix: Option<&str>,
    options: &Options,
) -> Result<Vec<String>> {
    let label = dex_label(path);
    let mut names = Vec::new();
    for (_name, buf) in logical_parts(&label, data)? {
        names.extend(Dex::parse(buf.as_ref())?.class_descriptors(prefix)?);
    }
    if options.debug {
        eprintln!("[DEX] '{label}' class_count={}", names.len());
    }
    Ok(names)
}

pub(super) fn class_source(
    path: &Path,
    data: &[u8],
    descriptor: &str,
    options: &Options,
) -> Result<String> {
    // Smali does not rewrite tokens, but a supplied table is still checked so
    // a bad --resources fails the same way it does for ddc and dump.
    let resources = external_arsc(options)?;
    let label = dex_label(path);
    let mut hit = None;
    for (name, buf) in logical_parts(&label, data)? {
        if Dex::parse(buf.as_ref())?.find_class_def(descriptor)?.is_some() {
            hit = Some(buf);
            if options.debug {
                eprintln!("[DEBUG] Hit DEX: {name}");
            }
            break;
        }
    }
    let Some(dex_buf) = hit else {
        bail!("Class {descriptor} not found in DEX.");
    };
    let text = match options.engine {
        Engine::Smali => smali_class(dex_buf.as_ref(), descriptor)?,
        Engine::Ddc => {
            crate::ddc_engine::decompile_one(dex_buf.into_owned(), descriptor)?
        }
    };
    if options.engine == Engine::Smali {
        return Ok(text);
    }
    Ok(resources.rewrite_code(&text).into_owned())
}

pub(super) fn find_refs(
    path: &Path,
    data: &[u8],
    query: &asc_dex::RefQuery,
    options: &Options,
) -> Result<Vec<String>> {
    let resources = external_arsc(options)?;
    let label = dex_label(path);
    let mut lines = Vec::new();
    for (name, buf) in logical_parts(&label, data)? {
        lines.extend(find_in_dex_resolved(&name, buf.as_ref(), query, &|text| {
            resources.rewrite_plain(text)
        })?);
    }
    Ok(lines
        .into_iter()
        .map(|line| present_ref_line(&resources, query, &line))
        .collect())
}

pub(super) fn dump(
    path: &Path,
    data: &[u8],
    out_dir: &Path,
    options: &Options,
) -> Result<super::DumpStats> {
    fs::create_dir_all(out_dir)?;
    let resources = external_arsc(options)?;
    let label = dex_label(path);
    let parts = logical_parts(&label, data)?;
    let claims = Mutex::new(HashMap::<std::path::PathBuf, ClassRank>::new());
    let dirs = Mutex::new(HashSet::<std::path::PathBuf>::new());
    let mut errors = 0usize;
    for (index, (_name, buf)) in parts.into_iter().enumerate() {
        let logical = u32::try_from(index)
            .map_err(|_| Error::new("too many DEX images in one entry"))?;
        let rank = ClassRank {
            module: 0,
            kind: 0,
            ordinal: 1,
            tie: 0,
            logical,
        };
        let job = DumpCtx {
            label: &label,
            out_dir,
            options,
            claims: &claims,
            dirs: &dirs,
            resources: &resources,
        };
        let owned = buf.into_owned();
        errors += if options.engine == Engine::Ddc {
            dump_ddc_image(owned, rank, &job)?
        } else {
            dump_smali_image(owned, rank, &job)?
        };
    }
    let classes = claims.lock().expect("mutex poisoned").len();
    Ok(super::DumpStats { classes, errors })
}

fn open_file(path: &Path) -> Result<File> {
    File::open(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })
}

fn is_dex_magic(magic: &[u8]) -> bool {
    magic.len() >= 8
        && magic.starts_with(b"dex\n")
        && magic[4].is_ascii_digit()
        && magic[5].is_ascii_digit()
        && magic[6].is_ascii_digit()
        && magic[7] == 0
}

fn external_arsc(options: &Options) -> Result<crate::arsc::ResourceTable> {
    let Some(path) = &options.resources else {
        return Ok(crate::arsc::ResourceTable::default());
    };
    if !path.is_file() {
        bail!("{} must be a resources.arsc file", path.display());
    }
    let bytes = fs::read(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    crate::arsc::ResourceTable::parse(&bytes)
        .map_err(|err| Error::context(path.display().to_string(), err))
}

fn dex_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "classes.dex".to_string())
}

fn logical_parts<'a>(name: &str, data: &'a [u8]) -> Result<Vec<(String, Cow<'a, [u8]>)>> {
    let offsets = logical_offsets(data);
    if offsets.len() <= 1 {
        return Ok(vec![(name.to_string(), Cow::Borrowed(data))]);
    }
    let mut out = Vec::with_capacity(offsets.len());
    for (index, offset) in offsets.into_iter().enumerate() {
        let ordinal = index + 1;
        out.push((
            format!("{name}!classes{ordinal}.dex"),
            Cow::Owned(normalize_dex041(data, offset)?),
        ));
    }
    Ok(out)
}
