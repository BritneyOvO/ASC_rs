//! APK access without a full inflate-and-index pass.
//!
//! DEX members are discovered from the ZIP central directory, inflated only
//! when a command needs them, and searched in parallel.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use flate2::read::DeflateDecoder;
use memmap2::Mmap;

use crate::{Error, Result};
use asc_axml::manifest_xml as decode_manifest;
use asc_dex::bytes;
use asc_dex::{
    find_in_dex_resolved, normalize_dalvik_class, normalize_prefix, smali_class, smali_class_def,
    Dex, RefQuery,
};

/// Ceiling on one inflated ZIP entry. A real DEX stays far below it, and a
/// crafted entry can never make the reader allocate without bound.
const MAX_INFLATED_BYTES: u64 = 1 << 30;

/// Which decompiler writes method bodies for `getclass` and `dump`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Engine {
    /// Structured Java via ddc (`ddc-dec` / `jdc-core`).
    #[default]
    Ddc,
    /// Baksmali text for the one class ASC already found.
    Smali,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub threads: usize,
    pub debug: bool,
    pub engine: Engine,
    /// `resources.arsc` for a bare DEX file. Archive inputs ignore this and
    /// keep using the table stored in the package. `None` leaves a bare DEX
    /// unresolved.
    pub resources: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
            engine: Engine::Ddc,
            resources: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DumpStats {
    pub classes: usize,
    pub errors: usize,
}

#[derive(Clone, Debug)]
struct DexEntry {
    name: String,
    uncomp_size: u64,
    comp_size: u64,
    local_header_off: u64,
    method: u16,
    crc: u32,
    cd_index: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ClassRank {
    module: u8,
    kind: u8,
    ordinal: u32,
    tie: u32,
    logical: u32,
}

struct ZipEntry {
    name: Vec<u8>,
    crc: u32,
    method: u16,
    comp_size: u64,
    uncomp_size: u64,
    local_header_off: u64,
}

pub fn list_classes(path: &Path, prefix: Option<&str>, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let prefix = match prefix {
        Some(value) => Some(normalize_prefix(value)?),
        None => None,
    };
    if let Some(data) = read_bare_dex(path)? {
        return list_bare_dex(path, data, prefix.as_deref(), options);
    }
    reject_external_resources(options)?;
    let started = Instant::now();
    let (_file, map) = open_apk(path)?;
    let entries = parse_cd_dex_entries(&map)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let prefix_ref = prefix.as_deref();
    let names = run_indexed(entries.len(), options.threads, |index| {
        let entry = &entries[index];
        let data = inflate_dex(&map, entry)?;
        let mut names = Vec::new();
        for (_name, buf) in logical_buffers(&entry.name, data)? {
            let dex = Dex::parse(&buf)?;
            names.extend(dex.class_descriptors(prefix_ref)?);
        }
        if options.debug {
            eprintln!("[APK] '{}' class_count={}", entry.name, names.len());
        }
        Ok(names)
    })?;
    let mut flat = Vec::new();
    for group in names {
        flat.extend(group);
    }
    if options.debug {
        eprintln!(
            "[APK] listclass total={:.2} us count={} workers={}",
            started.elapsed().as_secs_f64() * 1_000_000.0,
            flat.len(),
            options.threads.min(entries.len())
        );
    }
    Ok(flat)
}

pub fn get_class_source(path: &Path, class_name: &str, options: &Options) -> Result<String> {
    check_threads(options.threads)?;
    let descriptor = normalize_dalvik_class(class_name)?;
    if let Some(data) = read_bare_dex(path)? {
        return class_source_dex(path, data, &descriptor, options);
    }
    reject_external_resources(options)?;
    let started = Instant::now();
    let (_file, map) = open_apk(path)?;
    let mut entries = parse_cd_dex_entries(&map)?;
    sort_by_load_order(&mut entries);
    if options.debug {
        eprintln!(
            "[APK] scan setup={:.2} us entries={}",
            started.elapsed().as_secs_f64() * 1_000_000.0,
            entries.len()
        );
    }
    let (hit, resources) = std::thread::scope(|scope| {
        let load = scope.spawn(|| load_resource_table(&map));
        let hit = find_defining_dex(&map, &entries, descriptor.as_bytes(), options);
        (hit, load.join().expect("resource table loader panicked"))
    });
    let Some((dex_name, dex_buf)) = hit? else {
        bail!("Class {descriptor} not found in APK.");
    };
    if options.debug {
        eprintln!("[DEBUG] Hit DEX: {dex_name}");
    }
    // One image. Other DEX files stay compressed in the ZIP until a later
    // query names a class they define.
    let text = match options.engine {
        Engine::Smali => smali_class(&dex_buf, &descriptor)?,
        Engine::Ddc => crate::ddc_engine::decompile_one(dex_buf, &descriptor)?,
    };
    // Smali stays assemblable. Resource substitution is for the Java path.
    let source = if options.engine == Engine::Smali {
        text
    } else {
        resources.rewrite_code(&text).into_owned()
    };
    if options.debug {
        eprintln!(
            "[DEBUG] Total Execution Time: {:.2} us",
            started.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(source)
}

pub fn dump_apk(path: &Path, out_dir: &Path, options: &Options) -> Result<DumpStats> {
    check_threads(options.threads)?;
    let started = Instant::now();
    if let Some(data) = read_bare_dex(path)? {
        return dump_bare_dex(path, data, out_dir, options);
    }
    reject_external_resources(options)?;
    fs::create_dir_all(out_dir)?;
    let (_file, map) = open_apk(path)?;
    let resources = load_resource_table(&map);
    let xml = manifest_text(&map, &resources)?;
    fs::write(out_dir.join("AndroidManifest.xml"), xml)?;
    let mut entries = parse_cd_dex_entries(&map)?;
    if entries.is_empty() {
        return Ok(DumpStats::default());
    }
    if options.engine == Engine::Ddc {
        sort_by_load_order(&mut entries);
        return dump_with_ddc(&map, &entries, out_dir, options, &resources, started);
    }
    let ranks: Vec<(u8, u8, u32, u32)> = entries.iter().map(load_key).collect();
    let claims = Mutex::new(HashMap::<PathBuf, ClassRank>::new());
    let dirs = Mutex::new(HashSet::<PathBuf>::new());
    let errors = run_indexed(entries.len(), options.threads, |index| {
        dump_dex_entry(
            &map,
            &entries[index],
            out_dir,
            options,
            ranks[index],
            &claims,
            &dirs,
            &resources,
        )
    })?;
    let total = DumpStats {
        classes: claims.lock().expect("mutex poisoned").len(),
        errors: errors.into_iter().sum(),
    };
    if options.debug {
        eprintln!(
            "[APK] dump total={:.2} us classes={} errors={} workers={}",
            started.elapsed().as_secs_f64() * 1_000_000.0,
            total.classes,
            total.errors,
            options.threads.min(entries.len())
        );
    }
    Ok(total)
}

fn dump_dex_entry(
    apk: &[u8],
    entry: &DexEntry,
    out_dir: &Path,
    options: &Options,
    rank_base: (u8, u8, u32, u32),
    claims: &Mutex<HashMap<PathBuf, ClassRank>>,
    dirs: &Mutex<HashSet<PathBuf>>,
    resources: &crate::arsc::ResourceTable,
) -> Result<usize> {
    let data = inflate_dex(apk, entry)?;
    let mut errors = 0usize;
    for (logical, (_name, buf)) in logical_buffers(&entry.name, data)?.into_iter().enumerate() {
        let rank = ClassRank {
            module: rank_base.0,
            kind: rank_base.1,
            ordinal: rank_base.2,
            tie: rank_base.3,
            logical: logical as u32,
        };
        let job = DumpCtx {
            label: &entry.name,
            out_dir,
            options,
            claims,
            dirs,
            resources,
        };
        errors += dump_smali_image(buf, rank, &job)?;
    }
    if options.debug {
        eprintln!("[APK] '{}' decompile errors={errors}", entry.name);
    }
    Ok(errors)
}

fn dump_with_ddc(
    apk: &[u8],
    entries: &[DexEntry],
    out_dir: &Path,
    options: &Options,
    resources: &crate::arsc::ResourceTable,
    started: Instant,
) -> Result<DumpStats> {
    let ranks: Vec<(u8, u8, u32, u32)> = entries.iter().map(load_key).collect();
    let claims = Mutex::new(HashMap::<PathBuf, ClassRank>::new());
    let dirs = Mutex::new(HashSet::<PathBuf>::new());
    // One DEX image at a time. The thread budget decompiles classes inside
    // that image, so a large classesN.dex does not run single-threaded
    // while the other workers sit idle.
    let mut errors = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        errors += dump_dex_entry_ddc(
            apk,
            entry,
            out_dir,
            options,
            ranks[index],
            &claims,
            &dirs,
            resources,
        )?;
    }
    let total = DumpStats {
        classes: claims.lock().expect("mutex poisoned").len(),
        errors,
    };
    if options.debug {
        eprintln!(
            "[APK] dump ddc total={:.2} us classes={} errors={} workers={}",
            started.elapsed().as_secs_f64() * 1_000_000.0,
            total.classes,
            total.errors,
            options.threads.min(entries.len())
        );
    }
    Ok(total)
}

fn dump_dex_entry_ddc(
    apk: &[u8],
    entry: &DexEntry,
    out_dir: &Path,
    options: &Options,
    rank_base: (u8, u8, u32, u32),
    claims: &Mutex<HashMap<PathBuf, ClassRank>>,
    dirs: &Mutex<HashSet<PathBuf>>,
    resources: &crate::arsc::ResourceTable,
) -> Result<usize> {
    let data = inflate_dex(apk, entry)?;
    let mut errors = 0usize;
    for (logical, (_name, buf)) in logical_buffers(&entry.name, data)?.into_iter().enumerate() {
        let rank = ClassRank {
            module: rank_base.0,
            kind: rank_base.1,
            ordinal: rank_base.2,
            tie: rank_base.3,
            logical: logical as u32,
        };
        let job = DumpCtx {
            label: &entry.name,
            out_dir,
            options,
            claims,
            dirs,
            resources,
        };
        errors += dump_ddc_image(buf, rank, &job)?;
    }
    if options.debug {
        eprintln!("[APK] '{}' decompile errors={errors}", entry.name);
    }
    Ok(errors)
}

struct DumpCtx<'a> {
    label: &'a str,
    out_dir: &'a Path,
    options: &'a Options,
    claims: &'a Mutex<HashMap<PathBuf, ClassRank>>,
    dirs: &'a Mutex<HashSet<PathBuf>>,
    resources: &'a crate::arsc::ResourceTable,
}

fn dump_smali_image(buf: Vec<u8>, rank: ClassRank, job: &DumpCtx<'_>) -> Result<usize> {
    let dex = Dex::parse(&buf)?;
    let mut errors = 0usize;
    for index in 0..dex.header.class_defs_size {
        let def = dex.class_def(index)?;
        let class_desc = match dex.type_desc(def.class_idx) {
            Ok(desc) => desc,
            Err(err) => {
                errors += 1;
                if job.options.debug {
                    eprintln!(
                        "[APK] '{}' class_idx={} type error: {err}",
                        job.label, def.class_idx
                    );
                }
                continue;
            }
        };
        match smali_class_def(&dex, &def) {
            Ok(source) => {
                let dest = class_output_path(job.out_dir, &class_desc, "smali");
                publish_class(job.claims, job.dirs, &dest, rank, &source, false)?;
            }
            Err(err) => {
                errors += 1;
                if job.options.debug {
                    eprintln!(
                        "[APK] '{}' {class_desc} decompile error: {err}",
                        job.label
                    );
                }
            }
        }
    }
    Ok(errors)
}

fn dump_ddc_image(buf: Vec<u8>, rank: ClassRank, job: &DumpCtx<'_>) -> Result<usize> {
    let image = crate::ddc_engine::Image::open(buf)?;
    let names = image.top_level();
    let class_errors = AtomicUsize::new(0);
    run_indexed(names.len(), job.options.threads, |index| {
        let internal = &names[index];
        let rendered =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| image.render(internal)));
        match rendered {
            Ok(Ok(source)) => {
                let rewritten = job.resources.rewrite_code(&source);
                let descriptor = crate::ddc_engine::internal_to_descriptor(internal);
                let dest = class_output_path(job.out_dir, &descriptor, "java");
                publish_class(job.claims, job.dirs, &dest, rank, rewritten.as_ref(), true)?;
                Ok(())
            }
            Ok(Err(err)) => {
                class_errors.fetch_add(1, Ordering::Relaxed);
                if job.options.debug {
                    eprintln!("[APK] '{}' {internal} decompile error: {err}", job.label);
                }
                Ok(())
            }
            Err(_) => {
                class_errors.fetch_add(1, Ordering::Relaxed);
                if job.options.debug {
                    eprintln!("[APK] '{}' {internal} decompile panicked", job.label);
                }
                Ok(())
            }
        }
    })?;
    Ok(class_errors.load(Ordering::Relaxed))
}

fn publish_class(
    claims: &Mutex<HashMap<PathBuf, ClassRank>>,
    dirs: &Mutex<HashSet<PathBuf>>,
    dest: &Path,
    rank: ClassRank,
    source: &str,
    direct: bool,
) -> Result<()> {
    if claims
        .lock()
        .expect("mutex poisoned")
        .get(dest)
        .is_some_and(|prev| *prev < rank)
    {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        let mut known = dirs.lock().expect("mutex poisoned");
        if !known.contains(parent) {
            fs::create_dir_all(parent)?;
            known.insert(parent.to_path_buf());
        }
    }
    // DEX images are written in load order, so a direct write cannot lose
    // to a better rank still in flight. Parallel images still stage a temp
    // file and rename it under the claim lock.
    if direct {
        fs::write(dest, source)?;
        claims
            .lock()
            .expect("mutex poisoned")
            .insert(dest.to_path_buf(), rank);
        return Ok(());
    }
    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("class.java");
    let tmp = dest.with_file_name(format!(
        ".{file_name}.{}.{}.{}.{}.{}",
        rank.module, rank.kind, rank.ordinal, rank.tie, rank.logical
    ));
    fs::write(&tmp, source)?;
    let mut claims = claims.lock().expect("mutex poisoned");
    if claims.get(dest).is_some_and(|prev| *prev < rank) {
        drop(claims);
        let _ = fs::remove_file(&tmp);
        return Ok(());
    }
    fs::rename(&tmp, dest)?;
    claims.insert(dest.to_path_buf(), rank);
    Ok(())
}

fn load_key(entry: &DexEntry) -> (u8, u8, u32, u32) {
    let module = module_rank(&entry.name);
    if let Some(ordinal) = classes_ordinal(&entry.name) {
        (module, 0, ordinal, entry.cd_index)
    } else {
        (module, 1, entry.cd_index, 0)
    }
}

/// APK root entries and the app bundle's `base` module load before feature modules.
fn module_rank(name: &str) -> u8 {
    if !name.contains('/') || name.starts_with("base/") {
        0
    } else {
        1
    }
}

fn classes_ordinal(name: &str) -> Option<u32> {
    let file = name.rsplit('/').next().unwrap_or(name);
    let stem = file.strip_suffix(".dex")?;
    if stem == "classes" {
        return Some(1);
    }
    let digits = stem.strip_prefix("classes")?;
    if digits.is_empty()
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    digits.parse::<u32>().ok().filter(|ordinal| *ordinal >= 2)
}

fn sort_by_load_order(entries: &mut [DexEntry]) {
    entries.sort_by(|left, right| {
        load_key(left)
            .cmp(&load_key(right))
            .then(left.local_header_off.cmp(&right.local_header_off))
            .then(left.name.cmp(&right.name))
    });
}

/// Maps a descriptor to an output file.
///
/// Sanitizing alone is not injective: `La.b;` and `La_b;` both become `a_b`, and
/// one class would silently overwrite the other. A part that has to be changed
/// gets a suffix derived from the original, so distinct descriptors stay
/// distinct files.
fn class_output_path(out_dir: &Path, descriptor: &str, extension: &str) -> PathBuf {
    let trimmed = descriptor
        .strip_prefix('L')
        .unwrap_or(descriptor)
        .trim_end_matches(';');
    let mut dest = out_dir.to_path_buf();
    let parts: Vec<&str> = trimmed.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let name = sanitize_part(part);
        if index + 1 == parts.len() {
            dest.push(format!("{name}.{extension}"));
        } else {
            dest.push(name);
        }
    }
    dest
}

/// Keeps the characters a filesystem path can hold as they are, and replaces
/// the rest. A changed part carries a short hash of the original.
fn sanitize_part(part: &str) -> String {
    let safe: String = part
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '$' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if safe == part && !safe.is_empty() {
        return safe;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in part.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{safe}~{hash:08x}")
}

pub fn find_refs(path: &Path, query: &RefQuery, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let started = Instant::now();
    if let Some(data) = read_bare_dex(path)? {
        return find_bare_dex(path, data, query, options);
    }
    reject_external_resources(options)?;
    let (_file, map) = open_apk(path)?;
    let mut entries = parse_cd_dex_entries(&map)?;
    entries.sort_by(|left, right| {
        left.comp_size
            .cmp(&right.comp_size)
            .then(left.name.cmp(&right.name))
            .then(left.local_header_off.cmp(&right.local_header_off))
    });
    let resources = load_resource_table(&map);
    let groups = run_indexed(entries.len(), options.threads, |index| {
        let entry = &entries[index];
        let t0 = Instant::now();
        let data = inflate_dex(&map, entry)?;
        let inflated = t0.elapsed();
        let mut lines = Vec::new();
        for (name, buf) in logical_buffers(&entry.name, data)? {
            lines.extend(find_in_dex_resolved(&name, &buf, query, &|text| {
                resources.rewrite_plain(text)
            })?);
        }
        if options.debug {
            eprintln!(
                "[APK] '{}' inflate={:.2} us process={:.2} us",
                entry.name,
                inflated.as_secs_f64() * 1_000_000.0,
                t0.elapsed().as_secs_f64() * 1_000_000.0 - inflated.as_secs_f64() * 1_000_000.0
            );
        }
        Ok(lines)
    })?;
    if options.debug {
        eprintln!(
            "[APK] findrefs total={:.2} us count={} workers={}",
            started.elapsed().as_secs_f64() * 1_000_000.0,
            entries.len(),
            options.threads.min(entries.len().max(1))
        );
    }
    Ok(groups
        .into_iter()
        .flatten()
        .map(|line| present_ref_line(&resources, query, &line))
        .collect())
}

pub fn manifest_xml(path: &Path) -> Result<String> {
    let (_file, map) = open_apk(path)?;
    let resources = load_resource_table(&map);
    manifest_text(&map, &resources)
}

fn manifest_text(apk: &[u8], resources: &crate::arsc::ResourceTable) -> Result<String> {
    let bytes = read_zip_entry(apk, "AndroidManifest.xml")?;
    let mut xml = resources.annotate(&decode_manifest(&bytes)?);
    if !xml.ends_with('\n') {
        xml.push('\n');
    }
    Ok(xml)
}

fn load_resource_table(apk: &[u8]) -> crate::arsc::ResourceTable {
    let Ok(entries) = all_zip_entries(apk) else {
        eprintln!("warning: resource references are unavailable: unreadable central directory");
        return crate::arsc::ResourceTable::default();
    };    let mut table = crate::arsc::ResourceTable::default();
    for name in [
        b"resources.arsc".as_slice(),
        b"base/resources.arsc".as_slice(),
    ] {
        let Some(entry) = entries.iter().find(|entry| entry.name.as_slice() == name) else {
            continue;
        };
        let label = String::from_utf8_lossy(&entry.name).into_owned();
        match inflate_entry(apk, entry) {
            Ok(bytes) => match crate::arsc::ResourceTable::parse(&bytes) {
                Ok(parsed) => table.extend(parsed),
                Err(err) => eprintln!("warning: {label}: {err}"),
            },
            Err(err) => eprintln!("warning: {label}: {err}"),
        }
    }
    for entry in &entries {
        if let Ok(name) = std::str::from_utf8(&entry.name) {
            table.note_res_path(name);
        }
    }
    table
}

fn present_ref_line(
    resources: &crate::arsc::ResourceTable,
    query: &RefQuery,
    line: &str,
) -> String {
    if matches!(query, RefQuery::String(_)) {
        return line.to_string();
    }
    let Some((head, tail)) = line.split_once("matched=(") else {
        return line.to_string();
    };
    let Some(body) = tail.strip_suffix(')') else {
        return line.to_string();
    };
    format!("{head}matched=({})", resources.rewrite_code(body))
}

fn all_zip_entries(apk: &[u8]) -> Result<Vec<ZipEntry>> {
    let (start, end) = cd_bounds(apk)?;
    walk_central_directory(apk, start, end)
}

fn inflate_entry(apk: &[u8], entry: &ZipEntry) -> Result<Vec<u8>> {
    let name = String::from_utf8_lossy(&entry.name).into_owned();
    inflate_bytes(
        apk,
        ZipBytes {
            name: &name,
            method: entry.method,
            crc: entry.crc,
            compressed_size: entry.comp_size,
            uncompressed_size: entry.uncomp_size,
            header_offset: entry.local_header_off,
        },
    )
}

fn check_threads(threads: usize) -> Result<()> {
    if threads == 0 {
        bail!("Worker count must be greater than zero");
    }
    Ok(())
}

/// True when `path` is a standalone DEX image, not a ZIP container.
pub fn is_dex(path: &Path) -> Result<bool> {
    let mut file = File::open(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    let mut magic = [0u8; 8];
    let read = file.read(&mut magic).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    Ok(is_bare_dex_magic(&magic[..read]))
}

fn read_bare_dex(path: &Path) -> Result<Option<Vec<u8>>> {
    if !is_dex(path)? {
        return Ok(None);
    }
    fs::read(path)
        .map(Some)
        .map_err(|source| Error::IoPath {
            action: "open",
            path: path.display().to_string(),
            source,
        })
}

fn is_bare_dex_magic(magic: &[u8]) -> bool {
    magic.len() >= 8
        && magic.starts_with(b"dex\n")
        && magic[4].is_ascii_digit()
        && magic[5].is_ascii_digit()
        && magic[6].is_ascii_digit()
        && magic[7] == 0
}

fn reject_external_resources(options: &Options) -> Result<()> {
    if options.resources.is_some() {
        bail!("--resources is only used with a bare DEX or ABC file");
    }
    Ok(())
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
        .map_err(|err| Error::new(format!("{}: {err}", path.display())))
}

fn dex_label(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("classes.dex")
        .to_string()
}

fn list_bare_dex(
    path: &Path,
    data: Vec<u8>,
    prefix: Option<&str>,
    options: &Options,
) -> Result<Vec<String>> {
    let label = dex_label(path);
    let mut names = Vec::new();
    for (_name, buf) in logical_buffers(&label, data)? {
        names.extend(Dex::parse(&buf)?.class_descriptors(prefix)?);
    }
    if options.debug {
        eprintln!("[DEX] '{label}' class_count={}", names.len());
    }
    Ok(names)
}

fn class_source_dex(
    path: &Path,
    data: Vec<u8>,
    descriptor: &str,
    options: &Options,
) -> Result<String> {
    let label = dex_label(path);
    let mut hit = None;
    for (name, buf) in logical_buffers(&label, data)? {
        if Dex::parse(&buf)?.find_class_def(descriptor)?.is_some() {
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
        Engine::Smali => smali_class(&dex_buf, descriptor)?,
        Engine::Ddc => crate::ddc_engine::decompile_one(dex_buf, descriptor)?,
    };
    if options.engine == Engine::Smali {
        return Ok(text);
    }
    Ok(external_arsc(options)?.rewrite_code(&text).into_owned())
}

fn find_bare_dex(
    path: &Path,
    data: Vec<u8>,
    query: &RefQuery,
    options: &Options,
) -> Result<Vec<String>> {
    let resources = external_arsc(options)?;
    let label = dex_label(path);
    let mut lines = Vec::new();
    for (name, buf) in logical_buffers(&label, data)? {
        lines.extend(find_in_dex_resolved(&name, &buf, query, &|text| {
            resources.rewrite_plain(text)
        })?);
    }
    Ok(lines
        .into_iter()
        .map(|line| present_ref_line(&resources, query, &line))
        .collect())
}

fn dump_bare_dex(
    path: &Path,
    data: Vec<u8>,
    out_dir: &Path,
    options: &Options,
) -> Result<DumpStats> {
    fs::create_dir_all(out_dir)?;
    let resources = external_arsc(options)?;
    let label = dex_label(path);
    let buffers = logical_buffers(&label, data)?;
    let claims = Mutex::new(HashMap::<PathBuf, ClassRank>::new());
    let dirs = Mutex::new(HashSet::<PathBuf>::new());
    let mut errors = 0usize;
    for (index, (_name, buf)) in buffers.into_iter().enumerate() {
        let rank = ClassRank {
            module: 0,
            kind: 0,
            ordinal: 1,
            tie: 0,
            logical: index as u32,
        };
        let job = DumpCtx {
            label: &label,
            out_dir,
            options,
            claims: &claims,
            dirs: &dirs,
            resources: &resources,
        };
        errors += if options.engine == Engine::Ddc {
            dump_ddc_image(buf, rank, &job)?
        } else {
            dump_smali_image(buf, rank, &job)?
        };
    }
    let classes = claims.lock().expect("mutex poisoned").len();
    Ok(DumpStats { classes, errors })
}

fn open_apk(path: &Path) -> Result<(File, Mmap)> {
    let file = File::open(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    // SAFETY: `file` is returned with the map, so the descriptor outlives the
    // mapping, and this process does not remap the same range.
    let map = unsafe { Mmap::map(&file) }.map_err(|source| Error::IoPath {
        action: "map",
        path: path.display().to_string(),
        source,
    })?;
    Ok((file, map))
}

fn find_defining_dex(
    apk: &[u8],
    entries: &[DexEntry],
    target: &[u8],
    options: &Options,
) -> Result<Option<(String, Vec<u8>)>> {
    if entries.is_empty() {
        return Ok(None);
    }
    let workers = options.threads.min(entries.len()).max(1);
    let best_idx = AtomicUsize::new(usize::MAX);
    let best: Mutex<Option<(usize, String, Vec<u8>)>> = Mutex::new(None);
    let error: Mutex<Option<(usize, Error)>> = Mutex::new(None);
    let cursor = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                if index >= entries.len() {
                    break;
                }
                if index >= best_idx.load(Ordering::Relaxed) {
                    continue;
                }
                match inflate_and_hit(apk, &entries[index], target) {
                    Ok(Some((name, buf))) => {
                        best_idx.fetch_min(index, Ordering::Relaxed);
                        let mut slot = best.lock().expect("mutex poisoned");
                        if slot.as_ref().map(|item| index < item.0).unwrap_or(true) {
                            *slot = Some((index, name, buf));
                        }
                        if options.debug {
                            eprintln!("[APK] '{}' hit=true", entries[index].name);
                        }
                    }
                    Ok(None) => {
                        if options.debug {
                            eprintln!("[APK] '{}' hit=false", entries[index].name);
                        }
                    }
                    Err(err) => {
                        let mut slot = error.lock().expect("mutex poisoned");
                        if slot.as_ref().map(|item| index < item.0).unwrap_or(true) {
                            *slot = Some((index, err));
                        }
                    }
                }
            });
        }
    });
    let best = best.into_inner().expect("mutex poisoned");
    if let Some((index, err)) = error.into_inner().expect("mutex poisoned") {
        if best.as_ref().map(|item| index < item.0).unwrap_or(true) {
            return Err(err);
        }
    }
    Ok(best.map(|(_, name, buf)| (name, buf)))
}

fn inflate_and_hit(
    apk: &[u8],
    entry: &DexEntry,
    target: &[u8],
) -> Result<Option<(String, Vec<u8>)>> {
    let data = inflate_dex(apk, entry)?;
    for (name, buf) in logical_buffers(&entry.name, data)? {
        let dex = Dex::parse(&buf)?;
        if dex.defines_class(target)? {
            return Ok(Some((name, buf)));
        }
    }
    Ok(None)
}

fn run_indexed<T, F>(len: usize, threads: usize, work: F) -> Result<Vec<T>>
where
    T: Send,
    F: Fn(usize) -> Result<T> + Sync,
{
    if len == 0 {
        return Ok(Vec::new());
    }
    let workers = threads.min(len).max(1);
    let results: Mutex<Vec<Option<T>>> = Mutex::new((0..len).map(|_| None).collect());
    let error: Mutex<Option<Error>> = Mutex::new(None);
    let cursor = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                if error.lock().expect("mutex poisoned").is_some() {
                    break;
                }
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                if index >= len {
                    break;
                }
                match work(index) {
                    Ok(value) => results.lock().expect("mutex poisoned")[index] = Some(value),
                    Err(err) => {
                        let mut slot = error.lock().expect("mutex poisoned");
                        if slot.is_none() {
                            *slot = Some(err);
                        }
                        break;
                    }
                }
            });
        }
    });
    if let Some(err) = error.into_inner().expect("mutex poisoned") {
        return Err(err);
    }
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            value.ok_or_else(|| Error::new(format!("missing worker result {index}")))
        })
        .collect()
}

struct ZipBytes<'a> {
    name: &'a str,
    method: u16,
    crc: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    header_offset: u64,
}

fn inflate_dex(apk: &[u8], entry: &DexEntry) -> Result<Vec<u8>> {
    inflate_bytes(
        apk,
        ZipBytes {
            name: &entry.name,
            method: entry.method,
            crc: entry.crc,
            compressed_size: entry.comp_size,
            uncompressed_size: entry.uncomp_size,
            header_offset: entry.local_header_off,
        },
    )
}

fn inflate_bytes(apk: &[u8], entry: ZipBytes<'_>) -> Result<Vec<u8>> {
    let ZipBytes {
        name,
        method,
        crc,
        compressed_size,
        uncompressed_size,
        header_offset,
    } = entry;
    let off = usize::try_from(header_offset)
        .map_err(|_| Error::new(format!("zip offset for {name} exceeds this platform")))?;
    // A crafted ZIP64 offset must not wrap the addition before it is checked.
    let sig_end = off
        .checked_add(4)
        .ok_or_else(|| Error::new(format!("zip offset for {name} exceeds this platform")))?;
    let sig = apk
        .get(off..sig_end)
        .ok_or_else(|| Error::new("bad local header signature"))?;
    if sig != b"PK\x03\x04" {
        bail!("bad local header signature");
    }
    let name_len = bytes::u16_at(apk, off + 26)? as usize;
    let extra_len = bytes::u16_at(apk, off + 28)? as usize;
    let data_off = off + 30 + name_len + extra_len;
    let comp_len = usize::try_from(compressed_size)
        .map_err(|_| Error::new(format!("compressed size for {name} exceeds this platform")))?;
    let data_end = data_off
        .checked_add(comp_len)
        .ok_or_else(|| Error::new(format!("truncated zip entry {name}")))?;
    let comp = apk
        .get(data_off..data_end)
        .ok_or_else(|| Error::new(format!("truncated zip entry {name}")))?;
    let data = match method {
        0 => comp.to_vec(),
        8 => {
            // Deflate never expands more than 1032 times its input, so a larger
            // declared size is a lie and the ratio bound is used instead. The
            // hard ceiling keeps a crafted entry from allocating without bound.
            let ratio_bound = (comp.len() as u64).saturating_mul(1032);
            let declared = if uncompressed_size == 0 {
                ratio_bound
            } else {
                uncompressed_size
            };
            let limit = declared.min(MAX_INFLATED_BYTES);
            let mut out = Vec::new();
            DeflateDecoder::new(comp)
                .take(limit + 1)
                .read_to_end(&mut out)?;
            if out.len() as u64 > limit {
                bail!("zip entry {name} inflates past {limit} bytes");
            }
            out
        }
        other => bail!("unsupported compression method: {other}"),
    };
    if uncompressed_size != 0 && data.len() as u64 != uncompressed_size {
        bail!(
            "size mismatch: expect {uncompressed_size}, got {}",
            data.len()
        );
    }
    // Packers often store CRC 0. A recorded mismatch is reported and the bytes are still used.
    if crc != 0 {
        let actual = crc32fast::hash(&data);
        if actual != crc {
            eprintln!("warning: crc mismatch for {name}: stored {crc:08x}, computed {actual:08x}");
        }
    }
    Ok(data)
}

fn logical_buffers(name: &str, data: Vec<u8>) -> Result<Vec<(String, Vec<u8>)>> {
    let offsets = logical_offsets(&data);
    if offsets.len() <= 1 {
        return Ok(vec![(name.to_string(), data)]);
    }
    let mut out = Vec::with_capacity(offsets.len());
    for (index, offset) in offsets.into_iter().enumerate() {
        out.push((
            format!("{name}!classes{}.dex", index + 1),
            normalize_dex041(&data, offset)?,
        ));
    }
    Ok(out)
}

fn logical_offsets(data: &[u8]) -> Vec<usize> {
    if data.len() < 0x70 || &data[..8] != b"dex\n041\0" {
        return vec![0];
    }
    let mut offsets = Vec::new();
    let mut off = 0usize;
    while off + 0x70 <= data.len() && data.get(off..off + 8) == Some(b"dex\n041\0".as_slice()) {
        let Ok(file_size) = bytes::u32_at(data, off + 0x20) else {
            break;
        };
        if file_size < 0x70 || off + file_size as usize > data.len() {
            break;
        }
        offsets.push(off);
        off += file_size as usize;
    }
    if offsets.is_empty() {
        vec![0]
    } else {
        offsets
    }
}

fn normalize_dex041(data: &[u8], header_off: usize) -> Result<Vec<u8>> {
    if header_off == 0 {
        return Ok(data.to_vec());
    }
    let mut header_size = bytes::u32_at(data, header_off + 0x24).unwrap_or(0x70) as usize;
    if header_size < 0x70 || header_off + header_size > data.len() {
        header_size = 0x70;
    }
    let mut out = data.to_vec();
    out[..header_size].copy_from_slice(&data[header_off..header_off + header_size]);
    Ok(out)
}

fn parse_cd_dex_entries(apk: &[u8]) -> Result<Vec<DexEntry>> {
    let (cd_off, cd_end) = cd_bounds(apk)?;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let walked = walk_central_directory(apk, cd_off, cd_end);
    if let Ok(records) = &walked {
        for (index, entry) in records.iter().enumerate() {
            if let Some(dex) = root_dex(entry, index as u32) {
                if seen.insert(dex.name.clone()) {
                    entries.push(dex);
                }
            }
        }
    }
    // A directory record the walk could not reach still leaves the DEX bytes in
    // the archive, and the scan below finds them by name.
    append_classes_heuristic(apk, cd_off, cd_end, &mut entries, &mut seen)?;
    match walked {
        Ok(_) => Ok(entries),
        Err(err) if entries.is_empty() => Err(err),
        Err(err) => {
            eprintln!("warning: {err}");
            Ok(entries)
        }
    }
}

fn root_dex(entry: &ZipEntry, cd_index: u32) -> Option<DexEntry> {
    if !is_code_dex(&entry.name) {
        return None;
    }
    Some(DexEntry {
        name: String::from_utf8_lossy(&entry.name).into_owned(),
        uncomp_size: entry.uncomp_size,
        comp_size: entry.comp_size,
        local_header_off: entry.local_header_off,
        method: entry.method,
        crc: entry.crc,
        cd_index,
    })
}

/// APK dex files sit at the archive root. App bundles keep them in `<module>/dex/`.
fn is_code_dex(name: &[u8]) -> bool {
    let Some(slash) = name.iter().rposition(|byte| *byte == b'/') else {
        return name.ends_with(b".dex");
    };
    let file = &name[slash + 1..];
    if file == b".dex" || !file.ends_with(b".dex") {
        return false;
    }
    let parent = &name[..slash];
    parent == b"dex" || parent.ends_with(b"/dex")
}

fn append_classes_heuristic(
    apk: &[u8],
    cd_off: usize,
    cd_end: usize,
    entries: &mut Vec<DexEntry>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    let window = &apk[cd_off..cd_end];
    let mut search = 0usize;
    while let Some(rel) = find_subsequence(&window[search..], b"classes") {
        let at = cd_off + search + rel;
        search += rel + b"classes".len();
        if at < 46 {
            continue;
        }
        let header = at - 46;
        if header < cd_off {
            continue;
        }
        // Most probes land on bytes that are not a record at all; the ones that
        // fail to parse are simply not a candidate.
        let Ok((Some(entry), _)) = read_cd_record(apk, header, cd_end) else {
            continue;
        };
        if let Some(dex) = root_dex(&entry, u32::MAX) {
            if seen.insert(dex.name.clone()) {
                entries.push(dex);
            }
        }
    }
    Ok(())
}

fn cd_bounds(apk: &[u8]) -> Result<(usize, usize)> {
    let eocd = find_eocd(apk).ok_or_else(|| Error::new("EOCD not found"))?;
    let cd_size_32 = bytes::u32_at(apk, eocd + 12)?;
    let cd_off_32 = bytes::u32_at(apk, eocd + 16)?;
    let (cd_off, cd_size) = if cd_size_32 == u32::MAX || cd_off_32 == u32::MAX {
        zip64_cd_bounds(apk, eocd)?
    } else {
        (u64::from(cd_off_32), u64::from(cd_size_32))
    };
    let start =
        usize::try_from(cd_off).map_err(|_| Error::new("central directory offset is too large"))?;
    let size =
        usize::try_from(cd_size).map_err(|_| Error::new("central directory size is too large"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::new("central directory exceeds file"))?;
    if end > apk.len() {
        bail!("central directory exceeds file");
    }
    Ok((start, end))
}

fn zip64_cd_bounds(apk: &[u8], eocd: usize) -> Result<(u64, u64)> {
    if eocd < 20 || apk.get(eocd - 20..eocd - 16) != Some(b"PK\x06\x07") {
        bail!("ZIP64 locator not found");
    }
    let loc = eocd - 20;
    let eocd64 = bytes::u64_at(apk, loc + 8)?;
    let at = usize::try_from(eocd64).map_err(|_| Error::new("ZIP64 EOCD offset is too large"))?;
    // Bound the record before any relative read, so a wild offset cannot wrap.
    let end = at
        .checked_add(56)
        .ok_or_else(|| Error::new("ZIP64 EOCD offset is too large"))?;
    if end > apk.len() || apk.get(at..at + 4) != Some(b"PK\x06\x06") {
        bail!("ZIP64 EOCD not found");
    }
    let cd_size = bytes::u64_at(apk, at + 40)?;
    let cd_off = bytes::u64_at(apk, at + 48)?;
    Ok((cd_off, cd_size))
}

fn walk_central_directory(apk: &[u8], cd_off: usize, cd_end: usize) -> Result<Vec<ZipEntry>> {
    let mut entries = Vec::new();
    let mut ptr = cd_off;
    while ptr + 46 <= cd_end {
        let (maybe, next) = read_cd_record(apk, ptr, cd_end)?;
        if let Some(entry) = maybe {
            entries.push(entry);
        }
        if next <= ptr {
            bail!("central directory record at {ptr:#x} does not advance");
        }
        ptr = next;
    }
    Ok(entries)
}

/// Reads one central directory record.
///
/// A record that cannot be trusted is an error rather than a stop condition:
/// stopping quietly would drop every entry after it, which reads as "the
/// archive has no such file" instead of "the directory is damaged".
fn read_cd_record(
    apk: &[u8],
    header: usize,
    cd_end: usize,
) -> Result<(Option<ZipEntry>, usize)> {
    if header + 46 > cd_end {
        bail!("central directory record at {header:#x} runs past the directory");
    }
    if apk.get(header..header + 4) != Some(b"PK\x01\x02") {
        bail!("central directory record at {header:#x} has a bad signature");
    }
    let method = bytes::u16_at(apk, header + 10)?;
    let crc = bytes::u32_at(apk, header + 16)?;
    let comp_size = u64::from(bytes::u32_at(apk, header + 20)?);
    let uncomp_size = u64::from(bytes::u32_at(apk, header + 24)?);
    let name_len = bytes::u16_at(apk, header + 28)? as usize;
    let extra_len = bytes::u16_at(apk, header + 30)? as usize;
    let comment_len = bytes::u16_at(apk, header + 32)? as usize;
    let disk = bytes::u16_at(apk, header + 34)?;
    let local_off = u64::from(bytes::u32_at(apk, header + 42)?);
    let name_start = header + 46;
    let extra_start = name_start + name_len;
    let extra_end = extra_start + extra_len;
    let next = extra_end + comment_len;
    if next > cd_end || next > apk.len() {
        bail!("central directory record at {header:#x} runs past the archive");
    }
    let (uncomp_size, comp_size, local_off, disk) = zip64_resolve(
        &apk[extra_start..extra_end],
        uncomp_size,
        comp_size,
        local_off,
        disk,
    )?;
    if disk != 0 {
        // Multi disk archives are not supported; keep walking past the entry.
        return Ok((None, next));
    }
    Ok((
        Some(ZipEntry {
            name: apk[name_start..name_start + name_len].to_vec(),
            crc,
            method,
            comp_size,
            uncomp_size,
            local_header_off: local_off,
        }),
        next,
    ))
}

fn zip64_resolve(
    extra: &[u8],
    mut uncomp: u64,
    mut comp: u64,
    mut local_off: u64,
    disk: u16,
) -> Result<(u64, u64, u64, u32)> {
    let need_uncomp = uncomp == u64::from(u32::MAX);
    let need_comp = comp == u64::from(u32::MAX);
    let need_off = local_off == u64::from(u32::MAX);
    let need_disk = disk == u16::MAX;
    if !need_uncomp && !need_comp && !need_off && !need_disk {
        return Ok((uncomp, comp, local_off, u32::from(disk)));
    }
    let data = zip64_extra(extra)?;
    let mut pos = 0usize;
    if need_uncomp {
        uncomp = zip64_u64(data, &mut pos)?;
    }
    if need_comp {
        comp = zip64_u64(data, &mut pos)?;
    }
    if need_off {
        local_off = zip64_u64(data, &mut pos)?;
    }
    let resolved_disk = if need_disk {
        if pos + 4 > data.len() {
            bail!("truncated ZIP64 extra field");
        }
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
    } else {
        u32::from(disk)
    };
    Ok((uncomp, comp, local_off, resolved_disk))
}

fn zip64_extra(extra: &[u8]) -> Result<&[u8]> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let size = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start
            .checked_add(size)
            .ok_or_else(|| Error::new("truncated ZIP64 extra field"))?;
        if end > extra.len() {
            bail!("truncated ZIP64 extra field");
        }
        if id == 0x0001 {
            return Ok(&extra[start..end]);
        }
        pos = end;
    }
    bail!("ZIP64 extra field is missing");
}

fn zip64_u64(data: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos + 8 > data.len() {
        bail!("truncated ZIP64 extra field");
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_le_bytes(buf))
}

fn read_zip_entry(apk: &[u8], wanted: &str) -> Result<Vec<u8>> {
    let (cd_off, cd_end) = cd_bounds(apk)?;
    let mut chosen: Option<(u8, ZipEntry)> = None;
    for entry in walk_central_directory(apk, cd_off, cd_end)? {
        let Some(rank) = manifest_rank(&entry.name, wanted.as_bytes()) else {
            continue;
        };
        let replace = chosen
            .as_ref()
            .map(|(prev, _)| rank < *prev)
            .unwrap_or(true);
        if replace {
            chosen = Some((rank, entry));
        }
    }
    let Some((_, entry)) = chosen else {
        bail!("AndroidManifest.xml not found");
    };
    let name = String::from_utf8_lossy(&entry.name).into_owned();
    inflate_bytes(
        apk,
        ZipBytes {
            name: &name,
            method: entry.method,
            crc: entry.crc,
            compressed_size: entry.comp_size,
            uncompressed_size: entry.uncomp_size,
            header_offset: entry.local_header_off,
        },
    )
}

fn manifest_rank(name: &[u8], wanted: &[u8]) -> Option<u8> {
    if name == wanted {
        return Some(0);
    }
    if wanted != b"AndroidManifest.xml" {
        return None;
    }
    if name == b"base/manifest/AndroidManifest.xml" {
        return Some(1);
    }
    if name.ends_with(b"/manifest/AndroidManifest.xml") {
        Some(2)
    } else {
        None
    }
}

/// Finds the end of central directory record.
///
/// The archive comment may hold any bytes, including this signature, so a
/// candidate is only trusted when its declared comment length reaches the end
/// of the file. A candidate that merely fits is kept as a fallback for archives
/// with trailing bytes after the record.
fn find_eocd(apk: &[u8]) -> Option<usize> {
    if apk.len() < 22 {
        return None;
    }
    let search_start = apk.len().saturating_sub(65536 + 22);
    let tail = &apk[search_start..];
    let mut fallback = None;
    for rel in (0..tail.len().saturating_sub(3)).rev() {
        if &tail[rel..rel + 4] != b"PK\x05\x06" {
            continue;
        }
        let at = search_start + rel;
        if at + 22 > apk.len() {
            continue;
        }
        let comment_len = u16::from_le_bytes([apk[at + 20], apk[at + 21]]) as usize;
        let end = at + 22 + comment_len;
        if end == apk.len() {
            return Some(at);
        }
        if end < apk.len() && fallback.is_none() {
            fallback = Some(at);
        }
    }
    fallback
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{
        cd_bounds, find_eocd, inflate_bytes, parse_cd_dex_entries, walk_central_directory,
        zip64_cd_bounds, ZipBytes,
    };

    /// An end of central directory record with the given archive comment.
    ///
    /// The record is `PK\x05\x06`, four `u16` disk/entry fields, the central
    /// directory size and offset, then the comment length.
    fn eocd_with_comment(comment: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        archive.extend_from_slice(b"PK\x05\x06");
        archive.extend_from_slice(&[0u8; 8]); // disk, entries on disk, entries total
        archive.extend_from_slice(&0u32.to_le_bytes()); // central directory size
        archive.extend_from_slice(&0u32.to_le_bytes()); // central directory offset
        archive.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        archive.extend_from_slice(comment);
        archive
    }

    #[test]
    fn a_wild_zip64_local_offset_is_an_error_not_an_overflow() {
        let data = vec![0u8; 64];
        let entry = ZipBytes {
            name: "classes.dex",
            method: 0,
            crc: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            header_offset: u64::MAX,
        };
        let err = inflate_bytes(&data, entry).unwrap_err();
        assert!(err.to_string().contains("exceeds this platform"), "{err}");
    }

    #[test]
    fn a_wild_zip64_eocd_offset_is_an_error_not_an_overflow() {
        let mut data = vec![0u8; 42];
        data[0..4].copy_from_slice(b"PK\x06\x07");
        data[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        data[20..24].copy_from_slice(b"PK\x05\x06");
        let err = zip64_cd_bounds(&data, 20).unwrap_err();
        assert!(err.to_string().contains("ZIP64 EOCD offset"), "{err}");
    }

    #[test]
    fn distinct_descriptors_never_share_an_output_path() {
        use super::class_output_path;
        use std::path::Path;
        // `La.b;` and `La_b;` sanitize to the same stem without the hash.
        let left = class_output_path(Path::new("out"), "La.b;", "java");
        let right = class_output_path(Path::new("out"), "La_b;", "java");
        assert_ne!(left, right, "{left:?} {right:?}");
        // A descriptor that needs no change keeps its plain name.
        assert_eq!(
            class_output_path(Path::new("out"), "Lcom/example/Foo$Bar;", "java"),
            Path::new("out/com/example/Foo$Bar.java")
        );
    }

    #[test]
    fn a_comment_holding_the_eocd_signature_does_not_shadow_the_record() {
        let comment = b"see PK\x05\x06 inside";
        let archive = eocd_with_comment(comment);
        assert_eq!(find_eocd(&archive), Some(0), "comment={comment:?}");
    }

    #[test]
    fn a_damaged_central_directory_record_is_an_error() {
        let mut archive = vec![0u8; 46];
        archive[0..4].copy_from_slice(b"XXXX");
        archive.extend_from_slice(b"PK\x05\x06");
        archive.extend_from_slice(&[0u8; 8]);
        archive.extend_from_slice(&46u32.to_le_bytes()); // central directory size
        archive.extend_from_slice(&0u32.to_le_bytes()); // central directory offset
        archive.extend_from_slice(&0u16.to_le_bytes()); // comment length
        let (start, end) = cd_bounds(&archive).unwrap();
        assert_eq!((start, end), (0, 46));
        let Err(err) = walk_central_directory(&archive, start, end) else {
            panic!("a damaged record must be reported");
        };
        assert!(err.to_string().contains("bad signature"), "{err}");
        assert!(parse_cd_dex_entries(&archive).is_err());
    }

    #[test]
    fn a_lying_uncompressed_size_bounds_the_inflation() {
        let payload = vec![0u8; 1 << 20];
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        // A local file header, then the stream. The record claims 16 bytes.
        let mut archive = vec![0u8; 30];
        archive[0..4].copy_from_slice(b"PK\x03\x04");
        archive.extend_from_slice(&compressed);
        let entry = ZipBytes {
            name: "classes.dex",
            method: 8,
            crc: 0,
            compressed_size: compressed.len() as u64,
            uncompressed_size: 16,
            header_offset: 0,
        };
        let err = inflate_bytes(&archive, entry).unwrap_err();
        assert!(err.to_string().contains("inflates past"), "{err}");
    }
}
