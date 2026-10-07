//! Cross-reference search.
//!
//! String and type queries are resolved against the id tables. Instruction
//! offsets are mapped back to methods with 16-byte buckets, then accepted only
//! when the bytes from the method start land exactly on that opcode.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use regex::bytes::RegexBuilder;

use crate::bytes::u32_at;
use crate::dex::Dex;
use crate::opcodes::{op_len, payload_len};
use crate::Result;

#[derive(Clone, Debug)]
pub struct MemberSel {
    pub class_name: Option<String>,
    pub fuzzy_class: bool,
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub enum RefQuery {
    String(String),
    Type(String),
    Method(MemberSel),
    Field(MemberSel),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    String,
    Type,
    Method,
    Field,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Type => "type",
            Self::Method => "method",
            Self::Field => "field",
        }
    }
}

enum MemberQuery {
    NameOnly {
        pattern: String,
    },
    PreciseClass {
        class_desc: String,
        name: Option<String>,
    },
    FuzzyClass {
        class_pattern: String,
        name: Option<String>,
    },
}

struct MemberIndex {
    by_class: HashMap<u32, Vec<u32>>,
}

struct InsnSpan {
    start: usize,
    end: usize,
}

struct InsnLocator {
    data_len: usize,
    maps: HashMap<u32, Vec<u32>>,
    bounds: HashMap<u32, InsnSpan>,
    code_start: usize,
    code_end: usize,
}

pub fn find_in_dex(dex_name: &str, data: &[u8], query: &RefQuery) -> Result<Vec<String>> {
    find_in_dex_inner(dex_name, data, query, None)
}

/// Same as [`find_in_dex`], but string hits are tested and printed after `resolve`.
///
/// A string pool entry can be a resource token such as `@string/app_name`. The
/// container passes the resource table in so a search for the real value still hits.
pub fn find_in_dex_resolved(
    dex_name: &str,
    data: &[u8],
    query: &RefQuery,
    resolve: &dyn Fn(&str) -> String,
) -> Result<Vec<String>> {
    find_in_dex_inner(dex_name, data, query, Some(resolve))
}

fn find_in_dex_inner(
    dex_name: &str,
    data: &[u8],
    query: &RefQuery,
    resolve: Option<&dyn Fn(&str) -> String>,
) -> Result<Vec<String>> {
    let dex = Dex::parse(data)?;
    let (kind, idxs) = resolve_query(&dex, query, resolve)?;
    if idxs.is_empty() {
        return Ok(Vec::new());
    }
    let locator = InsnLocator::parse(&dex)?;
    let hits = scan(data, &locator, kind, &idxs);
    let mut grouped: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (methods, matched) in hits {
        let Some(methods) = methods else {
            continue;
        };
        for method in methods {
            grouped.entry(method).or_default().insert(matched);
        }
    }
    let mut lines = Vec::new();
    for (method_idx, matched) in grouped {
        let method = dex.format_method(method_idx)?;
        let rendered = matched
            .into_iter()
            .map(|idx| format_matched(&dex, kind, idx, resolve))
            .collect::<Result<Vec<_>>>()?
            .join("; ");
        lines.push(format!("{dex_name} | {method} | matched=({rendered})"));
    }
    Ok(lines)
}

fn resolve_query(
    dex: &Dex,
    query: &RefQuery,
    resolve: Option<&dyn Fn(&str) -> String>,
) -> Result<(Kind, HashSet<u32>)> {
    match query {
        RefQuery::String(pattern) => Ok((Kind::String, locate_strings(dex, pattern, resolve)?)),
        RefQuery::Type(pattern) => Ok((Kind::Type, locate_types(dex, pattern)?)),
        RefQuery::Method(sel) => Ok((Kind::Method, locate_members(dex, sel, true)?)),
        RefQuery::Field(sel) => Ok((Kind::Field, locate_members(dex, sel, false)?)),
    }
}

fn format_matched(
    dex: &Dex,
    kind: Kind,
    idx: u32,
    resolve: Option<&dyn Fn(&str) -> String>,
) -> Result<String> {
    match kind {
        Kind::String => {
            let raw = dex.string(idx)?;
            Ok(match resolve {
                Some(resolve) if has_at_ref(raw.as_bytes()) => resolve(&raw),
                _ => raw,
            })
        }
        Kind::Type => dex.type_desc(idx),
        Kind::Method => dex.format_method(idx),
        Kind::Field => dex.format_field(idx),
    }
}

/// Whether a string pool entry carries a resource token.
///
/// `@` always marks one. `?` only does when it opens a real reference
/// (`?attr/name`, `?0x7f010000`); a bare `?` is ordinary text — a URL query, a
/// question mark, a stored regex — and paying for a `resolve` call on every
/// such match is wasted work.
fn has_at_ref(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'@' => return true,
            b'?' => {
                if opens_resource_ref(bytes, index + 1) {
                    return true;
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    false
}

/// What may follow `@` or `?`: `0x...`, or `type/name` and `type:name/entry`.
fn opens_resource_ref(bytes: &[u8], mut at: usize) -> bool {
    if bytes.get(at) == Some(&b'+') {
        at += 1;
    }
    if bytes.get(at) == Some(&b'0') && matches!(bytes.get(at + 1), Some(b'x' | b'X')) {
        return bytes
            .get(at + 2)
            .is_some_and(|byte| byte.is_ascii_hexdigit());
    }
    let Some(&first) = bytes.get(at) else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    while bytes
        .get(at)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        at += 1;
    }
    matches!(bytes.get(at), Some(b'/' | b':'))
}

fn byte_regex(pattern: &str) -> Result<regex::bytes::Regex> {
    Ok(RegexBuilder::new(pattern)
        .unicode(false)
        .dot_matches_new_line(true)
        .build()?)
}

fn anchored_regex(pattern: &str) -> Result<regex::bytes::Regex> {
    byte_regex(&format!(r"\A(?:{pattern})\z"))
}

fn locate_strings(
    dex: &Dex,
    pattern: &str,
    resolve: Option<&dyn Fn(&str) -> String>,
) -> Result<HashSet<u32>> {
    let size = dex.header.string_ids_size;
    if size == 0 || pattern.is_empty() {
        return Ok(HashSet::new());
    }
    let regex = byte_regex(pattern)?;
    let mut found = HashSet::new();
    for idx in 0..size {
        let bytes = dex.string_bytes(idx)?;
        if regex.is_match(bytes) {
            found.insert(idx);
            continue;
        }
        let Some(resolve) = resolve else {
            continue;
        };
        if !has_at_ref(bytes) {
            continue;
        }
        let shown = String::from_utf8_lossy(bytes);
        let resolved = resolve(shown.as_ref());
        if resolved != shown && regex.is_match(resolved.as_bytes()) {
            found.insert(idx);
        }
    }
    Ok(found)
}

fn locate_types(dex: &Dex, pattern: &str) -> Result<HashSet<u32>> {
    if pattern.is_empty() {
        return Ok(HashSet::new());
    }
    let strings = locate_strings(dex, pattern, None)?;
    let mut by_string: HashMap<u32, Vec<u32>> = HashMap::new();
    for type_idx in 0..dex.header.type_ids_size {
        let string_idx = dex.type_string_idx(type_idx)?;
        by_string.entry(string_idx).or_default().push(type_idx);
    }
    let mut found = HashSet::new();
    for string_idx in strings {
        if let Some(types) = by_string.get(&string_idx) {
            found.extend(types.iter().copied());
        }
    }
    Ok(found)
}

fn member_section(dex: &Dex, methods: bool) -> Result<(usize, u32)> {
    let (off, size) = if methods {
        (dex.header.method_ids_off, dex.header.method_ids_size)
    } else {
        (dex.header.field_ids_off, dex.header.field_ids_size)
    };
    let bytes = (size as usize)
        .checked_mul(8)
        .ok_or_else(|| crate::Error::new("member id section is too large"))?;
    let end = (off as usize)
        .checked_add(bytes)
        .ok_or_else(|| crate::Error::new("member id section is too large"))?;
    if end > dex.data.len() {
        bail!("member id section is out of range");
    }
    Ok((off as usize, size))
}

fn build_member_index(dex: &Dex, methods: bool) -> Result<MemberIndex> {
    let (off, size) = member_section(dex, methods)?;
    let mut by_class: HashMap<u32, Vec<u32>> = HashMap::new();
    for idx in 0..size {
        let at = off + idx as usize * 8;
        let class_idx = u32::from(crate::bytes::u16_at(dex.data, at)?);
        by_class.entry(class_idx).or_default().push(idx);
    }
    Ok(MemberIndex { by_class })
}

fn member_name(dex: &Dex, methods: bool, idx: u32) -> Result<String> {
    if methods {
        dex.string(dex.method_id(idx)?.name_idx)
    } else {
        dex.string(dex.field_id(idx)?.name_idx)
    }
}

fn locate_members(dex: &Dex, sel: &MemberSel, methods: bool) -> Result<HashSet<u32>> {
    let kind = if methods { Kind::Method } else { Kind::Field };
    let query = member_query(kind, sel)?;
    let size = if methods {
        dex.header.method_ids_size
    } else {
        dex.header.field_ids_size
    };
    member_section(dex, methods)?;
    match query {
        MemberQuery::NameOnly { pattern } => {
            let regex = anchored_regex(&pattern)?;
            let mut found = HashSet::new();
            for idx in 0..size {
                if regex.is_match(member_name(dex, methods, idx)?.as_bytes()) {
                    found.insert(idx);
                }
            }
            Ok(found)
        }
        MemberQuery::PreciseClass { class_desc, name } => {
            let index = build_member_index(dex, methods)?;
            let Some(type_idx) = dex.find_type_idx(class_desc.as_bytes())? else {
                return Ok(HashSet::new());
            };
            let Some(ids) = index.by_class.get(&type_idx) else {
                return Ok(HashSet::new());
            };
            filter_exact(dex, methods, ids, name.as_deref())
        }
        MemberQuery::FuzzyClass {
            class_pattern,
            name,
        } => {
            let index = build_member_index(dex, methods)?;
            let types = locate_types(dex, &class_pattern)?;
            let mut ids = Vec::new();
            for type_idx in types {
                if let Some(found) = index.by_class.get(&type_idx) {
                    ids.extend(found.iter().copied());
                }
            }
            let Some(name) = name else {
                return Ok(ids.into_iter().collect());
            };
            let regex = anchored_regex(&name)?;
            let mut found = HashSet::new();
            for id in ids {
                if regex.is_match(member_name(dex, methods, id)?.as_bytes()) {
                    found.insert(id);
                }
            }
            Ok(found)
        }
    }
}

fn filter_exact(dex: &Dex, methods: bool, ids: &[u32], name: Option<&str>) -> Result<HashSet<u32>> {
    let Some(name) = name else {
        return Ok(ids.iter().copied().collect());
    };
    let mut found = HashSet::new();
    for id in ids {
        if member_name(dex, methods, *id)? == name {
            found.insert(*id);
        }
    }
    Ok(found)
}

fn member_query(kind: Kind, sel: &MemberSel) -> Result<MemberQuery> {
    let name = sel
        .name
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let class_name = sel.class_name.as_deref().filter(|value| !value.is_empty());
    match (class_name, name) {
        (None, None) => {
            bail!(
                "{} query needs at least one of class or {} name",
                kind.name(),
                kind.name()
            )
        }
        (None, Some(pattern)) => Ok(MemberQuery::NameOnly { pattern }),
        (Some(class_name), name) if sel.fuzzy_class => Ok(MemberQuery::FuzzyClass {
            class_pattern: fuzzy_class(class_name),
            name,
        }),
        (Some(class_name), name) => Ok(MemberQuery::PreciseClass {
            class_desc: crate::dex::normalize_dalvik_class(class_name)?,
            name,
        }),
    }
}

fn fuzzy_class(name: &str) -> String {
    if name.contains('.') && !name.contains('/') {
        name.replace('.', "/")
    } else {
        name.to_string()
    }
}

impl InsnLocator {
    fn parse(dex: &Dex) -> Result<Self> {
        let mut locator = Self {
            data_len: dex.data.len(),
            maps: HashMap::new(),
            bounds: HashMap::new(),
            code_start: 0,
            code_end: 0,
        };
        let items = dex.map_items()?;
        let class_data = items.iter().find(|item| item.type_ == 0x2000);
        if dex.header.map_off != 0 && items.iter().any(|item| item.type_ == 0x2000) {
            if let Some(item) = class_data {
                let mut pos = item.offset as usize;
                for _ in 0..item.size {
                    let (class_data, next) = crate::dex::parse_class_data(dex.data, pos)?;
                    locator.add_methods(dex.data, &class_data)?;
                    pos = next;
                }
            }
        } else {
            for index in 0..dex.header.class_defs_size {
                let def = dex.class_def(index)?;
                if def.class_data_off == 0 {
                    continue;
                }
                let (class_data, _) =
                    crate::dex::parse_class_data(dex.data, def.class_data_off as usize)?;
                locator.add_methods(dex.data, &class_data)?;
            }
        }
        if let (Some(min), Some(max)) = (locator.maps.keys().min(), locator.maps.keys().max()) {
            locator.code_start = (*min as usize) << 4;
            locator.code_end = ((*max as usize) + 1) << 4;
        }
        Ok(locator)
    }

    fn add_methods(&mut self, data: &[u8], class_data: &crate::dex::ClassData) -> Result<()> {
        for method in class_data.methods() {
            self.add_method(data, method.code_off, method.method_idx)?;
        }
        Ok(())
    }

    fn add_method(&mut self, data: &[u8], code_off: u32, method_idx: u32) -> Result<()> {
        if code_off == 0 {
            return Ok(());
        }
        let pos = code_off as usize;
        let insn_size = u32_at(data, pos + 12)? as usize;
        if insn_size == 0 {
            return Ok(());
        }
        let insn_off = pos + 16;
        let insn_bytes = insn_size * 2;
        if insn_off + insn_bytes > data.len() {
            bail!("code item out of range at {code_off:#x}");
        }
        let start_bucket = (insn_off >> 4) as u32;
        let end_bucket = ((insn_off + insn_bytes - 1) >> 4) as u32;
        self.bounds.insert(
            method_idx,
            InsnSpan {
                start: insn_off,
                end: insn_off + insn_bytes,
            },
        );
        for bucket in start_bucket..=end_bucket {
            let slot = self.maps.entry(bucket).or_default();
            if !slot.contains(&method_idx) {
                slot.push(method_idx);
            }
        }
        Ok(())
    }

    fn locate(&self, data: &[u8], offsets: &[usize]) -> Vec<Option<Vec<u32>>> {
        let mut cursor: HashMap<u32, usize> = HashMap::new();
        let mut out = Vec::with_capacity(offsets.len());
        for &offset in offsets {
            let Some(methods) = self.maps.get(&((offset >> 4) as u32)) else {
                out.push(None);
                continue;
            };
            let mut matched = Vec::new();
            for &method in methods {
                let Some(span) = self.bounds.get(&method) else {
                    continue;
                };
                if offset < span.start || offset >= span.end {
                    continue;
                }
                let remembered = cursor.get(&method).copied().unwrap_or(span.start);
                let start = if remembered <= offset {
                    remembered
                } else {
                    span.start
                };
                if instructions_cover(data, start, offset) {
                    cursor.insert(method, offset);
                    matched.push(method);
                }
            }
            if matched.is_empty() {
                out.push(None);
            } else {
                out.push(Some(matched));
            }
        }
        out
    }
}

fn instructions_cover(data: &[u8], start: usize, end: usize) -> bool {
    if end < start || end > data.len() || start > data.len() {
        return false;
    }
    let mut pos = start;
    while pos < end {
        if let Some(nbytes) = payload_len(data, pos) {
            let Some(next) = pos.checked_add(nbytes) else {
                return false;
            };
            if next > end {
                return false;
            }
            pos = next;
            continue;
        }
        let opcode = data[pos];
        let units = op_len(opcode);
        if units == 0 {
            return false;
        }
        let nbytes = units * 2;
        if pos + nbytes > end {
            return false;
        }
        pos += nbytes;
    }
    true
}

fn scan(
    data: &[u8],
    locator: &InsnLocator,
    kind: Kind,
    idxs: &HashSet<u32>,
) -> Vec<(Option<Vec<u32>>, u32)> {
    if idxs.is_empty() || locator.code_start >= locator.code_end {
        return Vec::new();
    }
    let end = locator.code_end.min(data.len()).min(locator.data_len);
    let start = locator.code_start.min(end);
    let mut hits = Vec::new();
    match kind {
        Kind::String => {
            scan_group(data, start, end, &[0x1a], 2, idxs, &mut hits);
            scan_group(data, start, end, &[0x1b], 4, idxs, &mut hits);
            hits.sort_by_key(|hit| hit.0);
        }
        Kind::Type => scan_group(
            data,
            start,
            end,
            &[0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25],
            2,
            idxs,
            &mut hits,
        ),
        Kind::Field => scan_group(
            data,
            start,
            end,
            &[
                0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            ],
            2,
            idxs,
            &mut hits,
        ),
        Kind::Method => scan_group(
            data,
            start,
            end,
            &[
                0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xfa, 0xfb,
            ],
            2,
            idxs,
            &mut hits,
        ),
    }
    let offsets: Vec<usize> = hits.iter().map(|hit| hit.0).collect();
    let methods = locator.locate(data, &offsets);
    methods
        .into_iter()
        .zip(hits.into_iter().map(|hit| hit.1))
        .collect()
}

fn scan_group(
    data: &[u8],
    start: usize,
    end: usize,
    opcodes: &[u8],
    width: usize,
    idxs: &HashSet<u32>,
    hits: &mut Vec<(usize, u32)>,
) {
    if end < start + 2 + width {
        return;
    }
    let mut wanted = [false; 256];
    for opcode in opcodes {
        wanted[*opcode as usize] = true;
    }
    let last = end - 2 - width;
    for pos in start..=last {
        if !wanted[data[pos] as usize] {
            continue;
        }
        let idx = if width == 4 {
            u32::from_le_bytes([data[pos + 2], data[pos + 3], data[pos + 4], data[pos + 5]])
        } else {
            u32::from(u16::from_le_bytes([data[pos + 2], data[pos + 3]]))
        };
        if idxs.contains(&idx) {
            hits.push((pos, idx));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::has_at_ref;

    #[test]
    fn only_real_resource_tokens_look_like_references() {
        for token in [
            "@string/app_name",
            "@0x7f010000",
            "?attr/colorPrimary",
            "?0x7f010000",
            "prefix @mipmap/icon suffix",
            // `@` is always a marker, even where nothing follows it.
            "@",
            "a@b",
        ] {
            assert!(has_at_ref(token.as_bytes()), "{token}");
        }
        for plain in ["colou?r", "https://example.com/a?b=c", "what?", "?", "?nope"] {
            assert!(!has_at_ref(plain.as_bytes()), "{plain}");
        }
    }
}
