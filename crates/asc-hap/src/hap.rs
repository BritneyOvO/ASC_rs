//! HAP commands. Each `.abc` member is inflated at the moment a query reads it.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use flate2::read::DeflateDecoder;
use memmap2::Mmap;

use crate::{Error, Result};
use asc_abc::{class_names, class_text_optional, find_members, find_strings_resolved, find_types};

#[derive(Clone, Debug)]
pub struct Options {
    pub threads: usize,
    pub debug: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DumpStats {
    pub classes: usize,
    pub errors: usize,
}

#[derive(Clone, Copy)]
pub enum Query<'a> {
    String(&'a str),
    Type(&'a str),
    Method {
        name: Option<&'a str>,
        class_name: Option<&'a str>,
    },
    Field {
        name: Option<&'a str>,
        class_name: Option<&'a str>,
    },
}

pub(crate) struct ZipEntry {
    pub(crate) name: String,
    crc: u32,
    method: u16,
    pub(crate) comp_size: u64,
    pub(crate) uncomp_size: u64,
    local_header_off: u64,
    index: u32,
}

pub fn is_hap(path: &Path) -> Result<bool> {
    let (_file, map) = match open_hap(path) {
        Ok(opened) => opened,
        Err(Error::Message(message)) if message.contains("EOCD") => return Ok(false),
        Err(err) => return Err(err),
    };
    let entries = zip_entries(&map)?;
    Ok(entries.iter().any(|entry| is_hap_marker(&entry.name)))
}

pub fn list_classes(path: &Path, prefix: Option<&str>, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let (_file, map) = open_hap(path)?;
    let entries = abc_entries(&map)?;
    let groups = run_indexed(entries.len(), options.threads, |index| {
        let bytes = inflate(&map, &entries[index])?;
        class_names(&bytes, prefix).map_err(Error::from)
    })?;
    let mut names = Vec::new();
    for group in groups {
        names.extend(group);
    }
    Ok(names)
}

pub fn get_class_source(path: &Path, class_name: &str, options: &Options) -> Result<String> {
    check_threads(options.threads)?;
    let (_file, map) = open_hap(path)?;
    let entries = zip_entries(&map)?;
    for entry in ranked_code(&entries) {
        let bytes = inflate(&map, entry)?;
        if let Some(text) = class_text_optional(&bytes, class_name)? {
            if options.debug {
                eprintln!("[HAP] hit {}", entry.name);
            }
            if text.as_bytes().contains(&b'$') {
                let resources = crate::resources::HapResources::index(&map, &entries);
                return Ok(resources.annotate(&text).into_owned());
            }
            return Ok(text);
        }
    }
    bail!("Class {class_name} not found in HAP.");
}

pub fn module_json(path: &Path) -> Result<String> {
    let files = package_files(path)?;
    let mut out = String::new();
    for (name, text) in files {
        out.push_str("===== ");
        out.push_str(&name);
        out.push_str(" =====\n");
        out.push_str(&text);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

fn package_files(path: &Path) -> Result<Vec<(String, String)>> {
    let (_file, map) = open_hap(path)?;
    let entries = zip_entries(&map)?;
    let resources = crate::resources::HapResources::index(&map, &entries);
    package_texts(&map, &entries, &resources)
}

fn package_texts(
    map: &Mmap,
    entries: &[ZipEntry],
    resources: &crate::resources::HapResources,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    if let Some(entry) = choose_manifest(entries) {
        files.push((
            entry.name.clone(),
            resources.annotate(&read_text(map, entry)?).into_owned(),
        ));
    }
    if let Some(entry) = choose_pack_info(entries) {
        files.push((
            entry.name.clone(),
            resources.annotate(&read_text(map, entry)?).into_owned(),
        ));
    }
    if files.is_empty() {
        bail!("module.json and pack.info not found in HAP");
    }
    Ok(files)
}

fn read_text(map: &Mmap, entry: &ZipEntry) -> Result<String> {
    let bytes = inflate(map, entry)?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.starts_with('\u{feff}') {
        text.remove(0);
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

pub fn find_refs(path: &Path, query: Query<'_>, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let (_file, map) = open_hap(path)?;
    let stored = zip_entries(&map)?;
    let groups = match query {
        Query::String(pattern) => find_string_refs(&map, &stored, pattern, options)?,
        Query::Type(pattern) => scan_code(&map, stored, options, |name, bytes| {
            find_types(bytes, name, pattern).map_err(Error::from)
        })?,
        Query::Method { name, class_name } => scan_code(&map, stored, options, |entry, bytes| {
            find_members(bytes, entry, true, name.unwrap_or(".*"), class_name).map_err(Error::from)
        })?,
        Query::Field { name, class_name } => scan_code(&map, stored, options, |entry, bytes| {
            find_members(bytes, entry, false, name.unwrap_or(".*"), class_name).map_err(Error::from)
        })?,
    };
    let mut lines = Vec::new();
    for group in groups {
        lines.extend(group);
    }
    Ok(lines)
}

fn find_string_refs(
    map: &Mmap,
    stored: &[ZipEntry],
    pattern: &str,
    options: &Options,
) -> Result<Vec<Vec<String>>> {
    let code = ranked_code(stored);
    let (resources, inflated) = std::thread::scope(|scope| {
        let load = scope.spawn(|| crate::resources::HapResources::index(map, stored));
        let inflated = run_indexed(code.len(), options.threads, |index| {
            let entry = code[index];
            inflate(map, entry).map(|bytes| (entry.name.clone(), bytes))
        });
        (load.join().expect("resource index panicked"), inflated)
    });
    let inflated = inflated?;
    run_indexed(inflated.len(), options.threads, |index| {
        let (name, bytes) = &inflated[index];
        find_strings_resolved(bytes, name, pattern, &|raw| {
            resolve_literal(&resources, raw)
        })
        .map_err(Error::from)
    })
}

fn resolve_literal(resources: &crate::resources::HapResources, bytes: &[u8]) -> Option<String> {
    if !bytes.contains(&b'$') {
        return None;
    }
    let shown = String::from_utf8_lossy(bytes);
    let resolved = resources.annotate(shown.as_ref());
    if resolved.as_ref() == shown.as_ref() {
        None
    } else {
        Some(resolved.into_owned())
    }
}

fn scan_code<F>(
    map: &Mmap,
    stored: Vec<ZipEntry>,
    options: &Options,
    work: F,
) -> Result<Vec<Vec<String>>>
where
    F: Fn(&str, &[u8]) -> Result<Vec<String>> + Sync,
{
    let entries = code_entries(stored);
    run_indexed(entries.len(), options.threads, |index| {
        let entry = &entries[index];
        let bytes = inflate(map, entry)?;
        work(&entry.name, &bytes)
    })
}

pub fn dump_hap(path: &Path, out_dir: &Path, options: &Options) -> Result<DumpStats> {
    check_threads(options.threads)?;
    fs::create_dir_all(out_dir)?;
    let (_file, map) = open_hap(path)?;
    let stored = zip_entries(&map)?;
    let resources = crate::resources::HapResources::index(&map, &stored);
    for (name, text) in package_texts(&map, &stored, &resources)? {
        let file_name = Path::new(&name)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("module.json"));
        fs::write(out_dir.join(file_name), text)?;
    }
    let mut classes = 0usize;
    for entry in code_entries(stored) {
        let bytes = inflate(&map, &entry)?;
        for name in class_names(&bytes, None)? {
            let Some(text) = class_text_optional(&bytes, &name)? else {
                continue;
            };
            let dest = class_output_path(out_dir, &name);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(dest, resources.annotate(&text).as_bytes())?;
            classes += 1;
        }
        if options.debug {
            eprintln!("[HAP] dumped {}", entry.name);
        }
    }
    Ok(DumpStats { classes, errors: 0 })
}

fn abc_entries(data: &[u8]) -> Result<Vec<ZipEntry>> {
    Ok(code_entries(zip_entries(data)?))
}

fn code_entries(entries: Vec<ZipEntry>) -> Vec<ZipEntry> {
    let mut entries: Vec<ZipEntry> = entries
        .into_iter()
        .filter(|entry| is_code_abc(&entry.name))
        .collect();
    entries.sort_by(code_cmp);
    entries
}

fn ranked_code(entries: &[ZipEntry]) -> Vec<&ZipEntry> {
    let mut ranked: Vec<&ZipEntry> = entries
        .iter()
        .filter(|entry| is_code_abc(&entry.name))
        .collect();
    ranked.sort_by(|left, right| code_cmp(left, right));
    ranked
}

fn code_cmp(left: &ZipEntry, right: &ZipEntry) -> std::cmp::Ordering {
    abc_rank(&left.name)
        .cmp(&abc_rank(&right.name))
        .then(left.index.cmp(&right.index))
}

fn abc_rank(name: &str) -> u8 {
    if name == "ets/modules.abc" {
        0
    } else if name.starts_with("ets/") || name.contains("/ets/") {
        1
    } else if name.starts_with("js/") || name.contains("/js/") || name.starts_with("assets/js/") {
        2
    } else {
        3
    }
}

fn is_code_abc(name: &str) -> bool {
    name.ends_with(".abc") && !name.ends_with('/')
}

fn is_hap_marker(name: &str) -> bool {
    // `config.json` is only a manifest fallback after the file is already a
    // HAP. Android apps ship the same name under assets/, so it cannot mark
    // the container by itself.
    is_code_abc(name) || is_hap_identity(name)
}

fn is_hap_identity(name: &str) -> bool {
    matches!(name, "module.json" | "pack.info")
        || name.ends_with("/module.json")
        || name.ends_with("/pack.info")
}

fn choose_manifest(entries: &[ZipEntry]) -> Option<&ZipEntry> {
    entries
        .iter()
        .filter(|entry| manifest_rank(&entry.name).is_some())
        .min_by_key(|entry| (manifest_rank(&entry.name).unwrap_or(u8::MAX), entry.index))
}

fn choose_pack_info(entries: &[ZipEntry]) -> Option<&ZipEntry> {
    entries
        .iter()
        .filter(|entry| pack_info_rank(&entry.name).is_some())
        .min_by_key(|entry| (pack_info_rank(&entry.name).unwrap_or(u8::MAX), entry.index))
}

fn manifest_rank(name: &str) -> Option<u8> {
    match name {
        "module.json" => Some(0),
        "config.json" => Some(1),
        other if other.ends_with("/module.json") => Some(2),
        other if other.ends_with("/config.json") => Some(3),
        _ => None,
    }
}

fn pack_info_rank(name: &str) -> Option<u8> {
    match name {
        "pack.info" => Some(0),
        other if other.ends_with("/pack.info") => Some(1),
        _ => None,
    }
}

fn class_output_path(out_dir: &Path, descriptor: &str) -> PathBuf {
    let trimmed = descriptor
        .strip_prefix('L')
        .unwrap_or(descriptor)
        .strip_suffix(';')
        .unwrap_or(descriptor);
    let mut path = out_dir.to_path_buf();
    if trimmed.is_empty() {
        path.push("class.ets");
        return path;
    }
    for part in trimmed.split('/') {
        let safe: String = part
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' || ch == '-' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        path.push(if safe.is_empty() { "_" } else { &safe });
    }
    path.set_extension("ets");
    path
}

fn check_threads(threads: usize) -> Result<()> {
    if threads == 0 {
        bail!("threads must be >= 1");
    }
    Ok(())
}

fn open_hap(path: &Path) -> Result<(File, Mmap)> {
    let file = File::open(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    // SAFETY: `file` is returned with the map, so the descriptor outlives it.
    let map = unsafe { Mmap::map(&file) }.map_err(|source| Error::IoPath {
        action: "map",
        path: path.display().to_string(),
        source,
    })?;
    Ok((file, map))
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
        .expect("mutex poisoned")
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

pub(crate) fn inflate(hap: &[u8], entry: &ZipEntry) -> Result<Vec<u8>> {
    inflate_bytes(
        hap,
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

fn inflate_bytes(hap: &[u8], entry: ZipBytes<'_>) -> Result<Vec<u8>> {
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
    if hap.get(off..off + 4) != Some(b"PK\x03\x04") {
        bail!("bad local header signature");
    }
    let name_len = u16_at(hap, off + 26)? as usize;
    let extra_len = u16_at(hap, off + 28)? as usize;
    let data_off = off + 30 + name_len + extra_len;
    let comp_len = usize::try_from(compressed_size)
        .map_err(|_| Error::new(format!("compressed size for {name} exceeds this platform")))?;
    let data_end = data_off
        .checked_add(comp_len)
        .ok_or_else(|| Error::new(format!("truncated zip entry {name}")))?;
    let comp = hap
        .get(data_off..data_end)
        .ok_or_else(|| Error::new(format!("truncated zip entry {name}")))?;
    let data = match method {
        0 => comp.to_vec(),
        8 => {
            let mut decoder = DeflateDecoder::new(comp);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
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
    if crc != 0 {
        let actual = crc32fast::hash(&data);
        if actual != crc {
            eprintln!("warning: crc mismatch for {name}: stored {crc:08x}, computed {actual:08x}");
        }
    }
    Ok(data)
}

fn zip_entries(data: &[u8]) -> Result<Vec<ZipEntry>> {
    let (start, end) = cd_bounds(data)?;
    let mut entries = Vec::new();
    let mut ptr = start;
    let mut index = 0u32;
    while ptr + 46 <= end {
        let Some((maybe, next)) = read_cd_record(data, ptr, end)? else {
            break;
        };
        if let Some(mut entry) = maybe {
            entry.index = index;
            index += 1;
            entries.push(entry);
        }
        if next <= ptr {
            break;
        }
        ptr = next;
    }
    Ok(entries)
}

fn cd_bounds(data: &[u8]) -> Result<(usize, usize)> {
    let eocd = find_eocd(data).ok_or_else(|| Error::new("EOCD not found"))?;
    let cd_size_32 = u32_at(data, eocd + 12)?;
    let cd_off_32 = u32_at(data, eocd + 16)?;
    let (cd_off, cd_size) = if cd_size_32 == u32::MAX || cd_off_32 == u32::MAX {
        zip64_cd_bounds(data, eocd)?
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
    if end > data.len() {
        bail!("central directory exceeds file");
    }
    Ok((start, end))
}

fn zip64_cd_bounds(data: &[u8], eocd: usize) -> Result<(u64, u64)> {
    if eocd < 20 || data.get(eocd - 20..eocd - 16) != Some(b"PK\x06\x07") {
        bail!("ZIP64 locator not found");
    }
    let loc = eocd - 20;
    let eocd64 = u64_at(data, loc + 8)?;
    let at = usize::try_from(eocd64).map_err(|_| Error::new("ZIP64 EOCD offset is too large"))?;
    if data.get(at..at + 4) != Some(b"PK\x06\x06") || at + 56 > data.len() {
        bail!("ZIP64 EOCD not found");
    }
    Ok((u64_at(data, at + 48)?, u64_at(data, at + 40)?))
}

fn read_cd_record(
    data: &[u8],
    header: usize,
    cd_end: usize,
) -> Result<Option<(Option<ZipEntry>, usize)>> {
    if header + 46 > cd_end || data.get(header..header + 4) != Some(b"PK\x01\x02") {
        return Ok(None);
    }
    let method = u16_at(data, header + 10)?;
    let crc = u32_at(data, header + 16)?;
    let comp_size = u64::from(u32_at(data, header + 20)?);
    let uncomp_size = u64::from(u32_at(data, header + 24)?);
    let name_len = u16_at(data, header + 28)? as usize;
    let extra_len = u16_at(data, header + 30)? as usize;
    let comment_len = u16_at(data, header + 32)? as usize;
    let disk = u16_at(data, header + 34)?;
    let local_off = u64::from(u32_at(data, header + 42)?);
    let name_start = header + 46;
    let extra_start = name_start + name_len;
    let extra_end = extra_start + extra_len;
    let next = extra_end + comment_len;
    if next > cd_end || next > data.len() {
        return Ok(None);
    }
    let (uncomp_size, comp_size, local_off, disk) = zip64_resolve(
        &data[extra_start..extra_end],
        uncomp_size,
        comp_size,
        local_off,
        disk,
    )?;
    if disk != 0 {
        return Ok(Some((None, next)));
    }
    Ok(Some((
        Some(ZipEntry {
            name: String::from_utf8_lossy(&data[name_start..name_start + name_len]).into_owned(),
            crc,
            method,
            comp_size,
            uncomp_size,
            local_header_off: local_off,
            index: 0,
        }),
        next,
    )))
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

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let search_start = data.len().saturating_sub(65536 + 22);
    let tail = &data[search_start..];
    tail.windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|rel| search_start + rel)
}

fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data
        .get(off..off + 2)
        .ok_or_else(|| Error::new(format!("truncated read at {off:#x}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data
        .get(off..off + 4)
        .ok_or_else(|| Error::new(format!("truncated read at {off:#x}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], off: usize) -> Result<u64> {
    let bytes = data
        .get(off..off + 8)
        .ok_or_else(|| Error::new(format!("truncated read at {off:#x}")))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::{
        dump_hap, find_refs, get_class_source, is_hap, list_classes, module_json, Options, Query,
    };

    fn options() -> Options {
        Options {
            threads: 2,
            debug: false,
        }
    }

    fn uleb(mut value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn panda_str(text: &str) -> Vec<u8> {
        let mut out = uleb(((text.len() as u32) << 1) | 1);
        out.extend_from_slice(text.as_bytes());
        out.push(0);
        out
    }

    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn sample_abc() -> Vec<u8> {
        let mut buf = vec![0u8; 60];
        buf[..8].copy_from_slice(b"PANDA\0\0\0");
        buf[12] = 2;
        let count_off = buf.len() as u32;
        buf.extend(panda_str("$string:app_name"));
        let main_off = buf.len() as u32;
        buf.extend(panda_str("main"));
        let hello_off = buf.len() as u32;
        buf.extend(panda_str("hello"));
        let label_off = buf.len() as u32;
        buf.extend(panda_str("$string:app_name"));
        let foreign_off = buf.len() as u32;
        buf.extend(panda_str("Lpanda/Object;"));
        let foreign_size = buf.len() as u32 - foreign_off;
        let class_off = buf.len() as u32;
        buf.extend(panda_str("Ldemo/App;"));
        push_u32(&mut buf, foreign_off);
        buf.extend(uleb(1));
        buf.extend(uleb(1));
        buf.extend(uleb(1));
        buf.push(0);
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 1);
        push_u32(&mut buf, count_off);
        buf.extend(uleb(1));
        buf.push(0);
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 0);
        push_u32(&mut buf, main_off);
        buf.extend(uleb(0x0009));
        buf.push(0);
        let proto_off = buf.len() as u32;
        push_u16(&mut buf, 0x0001);
        let class_idx_off = buf.len() as u32;
        push_u32(&mut buf, class_off);
        push_u32(&mut buf, 0x0005);
        let proto_idx_off = buf.len() as u32;
        push_u32(&mut buf, proto_off);
        let region_off = buf.len() as u32;
        push_u32(&mut buf, class_off);
        push_u32(&mut buf, class_idx_off);
        push_u32(&mut buf, 2);
        push_u32(&mut buf, class_idx_off);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 1);
        push_u32(&mut buf, proto_idx_off);
        let class_index_off = buf.len() as u32;
        push_u32(&mut buf, class_off);
        push_u32(&mut buf, foreign_off);
        let array_off = buf.len() as u32;
        push_u32(&mut buf, 4);
        buf.push(0x05);
        push_u32(&mut buf, hello_off);
        buf.push(0x05);
        push_u32(&mut buf, label_off);
        let literal_idx_off = buf.len() as u32;
        push_u32(&mut buf, array_off);
        let file_size = buf.len() as u32;
        put_u32(&mut buf, 16, file_size);
        put_u32(&mut buf, 20, foreign_off);
        put_u32(&mut buf, 24, foreign_size);
        put_u32(&mut buf, 28, 2);
        put_u32(&mut buf, 32, class_index_off);
        put_u32(&mut buf, 44, 1);
        put_u32(&mut buf, 48, literal_idx_off);
        put_u32(&mut buf, 52, 1);
        put_u32(&mut buf, 56, region_off);
        buf
    }

    fn zip_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut local = Vec::new();
        let mut central = Vec::new();
        for (name, data) in files {
            let name_bytes = name.as_bytes();
            let offset = local.len() as u32;
            let crc = crc32fast::hash(data);
            local.extend_from_slice(&0x04034b50u32.to_le_bytes());
            local.extend_from_slice(&20u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&crc.to_le_bytes());
            local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name_bytes);
            local.extend_from_slice(data);
            central.extend_from_slice(&0x02014b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name_bytes);
        }
        let cd_off = local.len() as u32;
        let cd_size = central.len() as u32;
        let mut out = local;
        out.extend(central);
        out.extend_from_slice(&0x06054b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_classes_and_module_json_from_a_hap() {
        let abc = sample_abc();
        let manifest = br#"{"module":{"name":"entry","type":"entry","description":"$string:app_name","icon":"$media:icon"}}"#;
        let strings = br#"{"string":[{"name":"app_name","value":"Hello"}]}"#;
        let pack = br#"{"summary":{"app":{"bundleName":"com.example.hap"}}}"#;
        let hap = zip_stored(&[
            ("js/default.abc", abc.as_slice()),
            ("module.json", manifest),
            ("pack.info", pack),
            ("resources/base/element/string.json", strings),
            (
                "resources/zh_CN/element/string.json",
                br#"{"string":[{"name":"app_name","value":"Nihao"}]}"#,
            ),
            ("resources/base/media/icon.png", b"png"),
            ("ets/modules.abc", abc.as_slice()),
        ]);
        let dir = std::env::temp_dir().join(format!("asc-hap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("entry.hap");
        std::fs::write(&path, hap).unwrap();
        assert!(is_hap(&path).unwrap());
        let apk_like = dir.join("config-only.apk");
        std::fs::write(
            &apk_like,
            zip_stored(&[("assets/dva_splits/config.json", br#"{"splits":[]}"#)]),
        )
        .unwrap();
        assert!(!is_hap(&apk_like).unwrap());
        let names = list_classes(&path, Some("Ldemo"), &options()).unwrap();
        assert_eq!(
            names,
            vec!["Ldemo/App;".to_string(), "Ldemo/App;".to_string()]
        );
        let text = get_class_source(&path, "demo.App", &options()).unwrap();
        assert!(text.contains("public static void main();"), "{text}");
        assert!(text.contains("public i32 Hello;"), "{text}");
        assert!(!text.contains("$string:"), "{text}");
        let json = module_json(&path).unwrap();
        assert!(json.contains("===== module.json ====="), "{json}");
        assert!(json.contains("\"name\":\"entry\""), "{json}");
        assert!(json.contains("\"description\":\"Hello\""), "{json}");
        assert!(
            json.contains("\"icon\":\"resources/base/media/icon.png\""),
            "{json}"
        );
        assert!(json.contains("===== pack.info ====="), "{json}");
        assert!(json.contains("com.example.hap"), "{json}");
        let lines = find_refs(&path, Query::String("hello"), &options()).unwrap();
        assert!(lines[0].starts_with("ets/modules.abc"), "{lines:?}");
        let labels = find_refs(&path, Query::String("Hello"), &options()).unwrap();
        assert!(
            labels.iter().any(|line| line.contains("matched=(Hello)")),
            "{labels:?}"
        );
        let raw = find_refs(&path, Query::String(r"\$string:app_name"), &options()).unwrap();
        assert!(
            raw.iter().any(|line| line.contains("matched=(Hello)")),
            "{raw:?}"
        );
        let out = dir.join("out");
        let stats = dump_hap(&path, &out, &options()).unwrap();
        assert_eq!(stats.classes, 4);
        assert!(out.join("module.json").is_file());
        assert!(std::fs::read_to_string(out.join("pack.info"))
            .unwrap()
            .contains("com.example.hap"));
        assert!(out.join("demo/App.ets").is_file());
        let dumped = std::fs::read_to_string(out.join("demo/App.ets")).unwrap();
        assert!(dumped.contains("public i32 Hello;"), "{dumped}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
