//! APK access without a full inflate-and-index pass.
//!
//! DEX members are discovered from the ZIP central directory, inflated only
//! when a command needs them, and searched in parallel.

use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use flate2::read::DeflateDecoder;
use memmap2::Mmap;
use std::io::Read;

use crate::axml::manifest_xml as decode_manifest;
use crate::decompile::decompile_class;
use crate::dex::{normalize_dalvik_class, normalize_prefix, Dex};
use crate::findrefs::{find_in_dex, RefQuery};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct Options {
    pub threads: usize,
    pub debug: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
        }
    }
}

#[derive(Clone, Debug)]
struct DexEntry {
    name: String,
    uncomp_size: u32,
    comp_size: u32,
    local_header_off: u32,
    method: u16,
}

pub fn list_classes(path: &Path, prefix: Option<&str>, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let prefix = match prefix {
        Some(value) => Some(normalize_prefix(value)?),
        None => None,
    };
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
    let started = Instant::now();
    let (_file, map) = open_apk(path)?;
    let mut entries = parse_cd_dex_entries(&map)?;
    entries.sort_by(|left, right| {
        left.comp_size
            .cmp(&right.comp_size)
            .then(left.name.cmp(&right.name))
            .then(left.local_header_off.cmp(&right.local_header_off))
    });
    if options.debug {
        eprintln!(
            "[APK] scan setup={:.2} us entries={}",
            started.elapsed().as_secs_f64() * 1_000_000.0,
            entries.len()
        );
    }
    let hit = find_defining_dex(&map, &entries, descriptor.as_bytes(), options)?;
    let Some((dex_name, dex_buf)) = hit else {
        bail!("Class {descriptor} not found in APK.");
    };
    if options.debug {
        eprintln!("[DEBUG] Hit DEX: {dex_name}");
    }
    let source = decompile_class(&dex_buf, &descriptor)?;
    if options.debug {
        eprintln!(
            "[DEBUG] Total Execution Time: {:.2} us",
            started.elapsed().as_secs_f64() * 1_000_000.0
        );
    }
    Ok(source)
}

pub fn find_refs(path: &Path, query: &RefQuery, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let started = Instant::now();
    let (_file, map) = open_apk(path)?;
    let mut entries = parse_cd_dex_entries(&map)?;
    entries.sort_by(|left, right| {
        left.comp_size
            .cmp(&right.comp_size)
            .then(left.name.cmp(&right.name))
            .then(left.local_header_off.cmp(&right.local_header_off))
    });
    let groups = run_indexed(entries.len(), options.threads, |index| {
        let entry = &entries[index];
        let t0 = Instant::now();
        let data = inflate_dex(&map, entry)?;
        let inflated = t0.elapsed();
        let mut lines = Vec::new();
        for (name, buf) in logical_buffers(&entry.name, data)? {
            lines.extend(find_in_dex(&name, &buf, query)?);
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
    Ok(groups.into_iter().flatten().collect())
}

pub fn manifest_xml(path: &Path) -> Result<String> {
    let (_file, map) = open_apk(path)?;
    let bytes = read_zip_entry(&map, "AndroidManifest.xml")?;
    let mut xml = decode_manifest(&bytes)?;
    if !xml.ends_with('\n') {
        xml.push('\n');
    }
    Ok(xml)
}

fn check_threads(threads: usize) -> Result<()> {
    if threads == 0 {
        bail!("Worker count must be greater than zero");
    }
    Ok(())
}

fn open_apk(path: &Path) -> Result<(File, Mmap)> {
    let file = File::open(path)
        .map_err(|err| Error::new(format!("failed to open {}: {err}", path.display())))?;
    let map = unsafe { Mmap::map(&file) }
        .map_err(|err| Error::new(format!("failed to map {}: {err}", path.display())))?;
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
                        let mut slot = best.lock().unwrap();
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
                        let mut slot = error.lock().unwrap();
                        if slot.as_ref().map(|item| index < item.0).unwrap_or(true) {
                            *slot = Some((index, err));
                        }
                    }
                }
            });
        }
    });
    let best = best.into_inner().unwrap();
    if let Some((index, err)) = error.into_inner().unwrap() {
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
                if error.lock().unwrap().is_some() {
                    break;
                }
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                if index >= len {
                    break;
                }
                match work(index) {
                    Ok(value) => results.lock().unwrap()[index] = Some(value),
                    Err(err) => {
                        let mut slot = error.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(err);
                        }
                        break;
                    }
                }
            });
        }
    });
    if let Some(err) = error.into_inner().unwrap() {
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

fn inflate_dex(apk: &[u8], entry: &DexEntry) -> Result<Vec<u8>> {
    let off = entry.local_header_off as usize;
    let sig = apk
        .get(off..off + 4)
        .ok_or_else(|| Error::new("bad local header signature"))?;
    if sig != b"PK\x03\x04" {
        bail!("bad local header signature");
    }
    let name_len = crate::bytes::u16_at(apk, off + 26)? as usize;
    let extra_len = crate::bytes::u16_at(apk, off + 28)? as usize;
    let data_off = off + 30 + name_len + extra_len;
    let data_end = data_off + entry.comp_size as usize;
    let comp = apk
        .get(data_off..data_end)
        .ok_or_else(|| Error::new(format!("truncated zip entry {}", entry.name)))?;
    let data = match entry.method {
        0 => comp.to_vec(),
        8 => {
            let mut decoder = DeflateDecoder::new(comp);
            let mut out = Vec::with_capacity(entry.uncomp_size as usize);
            decoder.read_to_end(&mut out)?;
            out
        }
        other => bail!("unsupported compression method: {other}"),
    };
    if entry.uncomp_size != 0 && data.len() != entry.uncomp_size as usize {
        bail!(
            "size mismatch: expect {}, got {}",
            entry.uncomp_size,
            data.len()
        );
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
        let Ok(file_size) = crate::bytes::u32_at(data, off + 0x20) else {
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
    let mut header_size = crate::bytes::u32_at(data, header_off + 0x24).unwrap_or(0x70) as usize;
    if header_size < 0x70 || header_off + header_size > data.len() {
        header_size = 0x70;
    }
    let mut out = data.to_vec();
    out[..header_size].copy_from_slice(&data[header_off..header_off + header_size]);
    Ok(out)
}

fn parse_cd_dex_entries(apk: &[u8]) -> Result<Vec<DexEntry>> {
    let eocd = find_eocd(apk).ok_or_else(|| Error::new("EOCD not found"))?;
    let cd_size = crate::bytes::u32_at(apk, eocd + 12)? as usize;
    let cd_off = crate::bytes::u32_at(apk, eocd + 16)? as usize;
    let cd_end = cd_off + cd_size;
    if cd_end > apk.len() {
        bail!("central directory exceeds file");
    }
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let window = &apk[cd_off..cd_end];
    let mut search = 0usize;
    while let Some(rel) = find_subsequence(&window[search..], b"classes") {
        let at = cd_off + search + rel;
        search += rel + 7;
        if at < 46 {
            continue;
        }
        let header = at - 46;
        if header < cd_off || apk.get(header..header + 4) != Some(b"PK\x01\x02".as_slice()) {
            continue;
        }
        if let Some(entry) = read_cd_entry(apk, header, cd_end)? {
            if seen.insert(entry.name.clone()) {
                entries.push(entry);
            }
        }
    }
    if !entries.is_empty() {
        return Ok(entries);
    }
    let mut ptr = cd_off;
    while ptr + 46 <= cd_end {
        if apk.get(ptr..ptr + 4) != Some(b"PK\x01\x02".as_slice()) {
            break;
        }
        let name_len = crate::bytes::u16_at(apk, ptr + 28)? as usize;
        let extra_len = crate::bytes::u16_at(apk, ptr + 30)? as usize;
        let comment_len = crate::bytes::u16_at(apk, ptr + 32)? as usize;
        if let Some(entry) = read_cd_entry(apk, ptr, cd_end)? {
            entries.push(entry);
        }
        ptr = ptr + 46 + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

fn read_cd_entry(apk: &[u8], header: usize, cd_end: usize) -> Result<Option<DexEntry>> {
    let name_len = crate::bytes::u16_at(apk, header + 28)? as usize;
    let name_start = header + 46;
    let name_end = name_start + name_len;
    if name_end > cd_end || name_end > apk.len() {
        return Ok(None);
    }
    let name_bytes = &apk[name_start..name_end];
    if !name_bytes.ends_with(b".dex") || name_bytes.contains(&b'/') {
        return Ok(None);
    }
    Ok(Some(DexEntry {
        name: String::from_utf8_lossy(name_bytes).into_owned(),
        uncomp_size: crate::bytes::u32_at(apk, header + 24)?,
        comp_size: crate::bytes::u32_at(apk, header + 20)?,
        local_header_off: crate::bytes::u32_at(apk, header + 42)?,
        method: crate::bytes::u16_at(apk, header + 10)?,
    }))
}

fn read_zip_entry(apk: &[u8], wanted: &str) -> Result<Vec<u8>> {
    let eocd = find_eocd(apk).ok_or_else(|| Error::new("EOCD not found"))?;
    let cd_size = crate::bytes::u32_at(apk, eocd + 12)? as usize;
    let cd_off = crate::bytes::u32_at(apk, eocd + 16)? as usize;
    let cd_end = cd_off + cd_size;
    let mut ptr = cd_off;
    while ptr + 46 <= cd_end {
        if apk.get(ptr..ptr + 4) != Some(b"PK\x01\x02".as_slice()) {
            break;
        }
        let name_len = crate::bytes::u16_at(apk, ptr + 28)? as usize;
        let extra_len = crate::bytes::u16_at(apk, ptr + 30)? as usize;
        let comment_len = crate::bytes::u16_at(apk, ptr + 32)? as usize;
        let name = &apk[ptr + 46..ptr + 46 + name_len];
        if name == wanted.as_bytes() {
            let entry = DexEntry {
                name: wanted.to_string(),
                uncomp_size: crate::bytes::u32_at(apk, ptr + 24)?,
                comp_size: crate::bytes::u32_at(apk, ptr + 20)?,
                local_header_off: crate::bytes::u32_at(apk, ptr + 42)?,
                method: crate::bytes::u16_at(apk, ptr + 10)?,
            };
            return inflate_dex(apk, &entry);
        }
        ptr = ptr + 46 + name_len + extra_len + comment_len;
    }
    bail!("AndroidManifest.xml not found in APK");
}

fn find_eocd(apk: &[u8]) -> Option<usize> {
    if apk.len() < 22 {
        return None;
    }
    let search_start = apk.len().saturating_sub(65536 + 22);
    let tail = &apk[search_start..];
    tail.windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|rel| search_start + rel)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
