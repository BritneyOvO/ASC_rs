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

const NO_METHOD: u32 = u32::MAX;
/// Methods that share one `code_item` live in `shared`; the bucket stores this bit.
const SHARED_BIT: u32 = 1 << 31;

struct InsnLocator {
    data_len: usize,
    /// Bucket index of `table[0]`.
    base_bucket: u32,
    /// One cell per 16-byte bucket: `NO_METHOD`, a method index, or `SHARED_BIT | shared index`.
    table: Vec<u32>,
    shared: Vec<Vec<u32>>,
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

/// Turns a class name into a literal substring pattern.
///
/// Dotted names are read as package separators, but only when the name uses no
/// slash at all: an Ark ES class descriptor really does contain dots. The rest
/// is escaped, so `Foo$Bar` matches the inner class instead of reading `$` as
/// an end of text anchor.
fn fuzzy_class(name: &str) -> String {
    let slashed = if name.contains('.') && !name.contains('/') {
        name.replace('.', "/")
    } else {
        name.to_string()
    };
    regex::escape(&slashed)
}

impl InsnLocator {
    fn parse(dex: &Dex) -> Result<Self> {
        let mut entries = Vec::new();
        let mut bounds = HashMap::new();
        let items = dex.map_items()?;
        let class_data = items.iter().find(|item| item.type_ == 0x2000);
        if dex.header.map_off != 0 && items.iter().any(|item| item.type_ == 0x2000) {
            if let Some(item) = class_data {
                let mut pos = item.offset as usize;
                for _ in 0..item.size {
                    let (class_data, next) = crate::dex::parse_class_data(dex.data, pos)?;
                    collect_methods(dex.data, &class_data, &mut entries, &mut bounds)?;
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
                collect_methods(dex.data, &class_data, &mut entries, &mut bounds)?;
            }
        }
        let mut locator = Self {
            data_len: dex.data.len(),
            base_bucket: 0,
            table: Vec::new(),
            shared: Vec::new(),
            bounds,
            code_start: 0,
            code_end: 0,
        };
        if entries.is_empty() {
            return Ok(locator);
        }
        let min_bucket = entries.iter().map(|entry| entry.0 >> 4).min().unwrap_or(0);
        let max_bucket = entries
            .iter()
            .map(|entry| (entry.0 + entry.1 - 1) >> 4)
            .max()
            .unwrap_or(0);
        let len = usize::try_from(max_bucket - min_bucket + 1)
            .map_err(|_| crate::Error::new("code item region is too large"))?;
        locator.base_bucket = min_bucket;
        locator.table = vec![NO_METHOD; len];
        locator.code_start = (min_bucket as usize) << 4;
        locator.code_end = ((max_bucket as usize) + 1) << 4;
        for (insn_off, size, method_idx) in entries {
            let start = ((insn_off >> 4) - min_bucket) as usize;
            let end = (((insn_off + size - 1) >> 4) - min_bucket) as usize;
            // A free range is one fill. Overlap is per bucket so a later method
            // does not claim instructions that belong to an earlier one.
            if locator.table[start..=end]
                .iter()
                .all(|value| *value == NO_METHOD)
            {
                locator.table[start..=end].fill(method_idx);
                continue;
            }
            for bucket in start..=end {
                match locator.table[bucket] {
                    NO_METHOD => locator.table[bucket] = method_idx,
                    old if old == method_idx => {}
                    old if old & SHARED_BIT != 0 => {
                        let list = &mut locator.shared[(old & !SHARED_BIT) as usize];
                        if !list.contains(&method_idx) {
                            list.push(method_idx);
                        }
                    }
                    old => {
                        locator.shared.push(vec![old, method_idx]);
                        locator.table[bucket] = SHARED_BIT | (locator.shared.len() as u32 - 1);
                    }
                }
            }
        }
        Ok(locator)
    }

    fn locate(&self, data: &[u8], offsets: &[usize]) -> Vec<Option<Vec<u32>>> {
        let mut cursor: HashMap<u32, usize> = HashMap::new();
        let mut out = Vec::with_capacity(offsets.len());
        for &offset in offsets {
            let mut matched = Vec::new();
            match self.bucket(offset) {
                Bucket::Empty => {}
                Bucket::One(method) => {
                    self.accept(data, offset, method, &mut cursor, &mut matched);
                }
                Bucket::Shared(index) => {
                    if let Some(methods) = self.shared.get(index) {
                        for &method in methods {
                            self.accept(data, offset, method, &mut cursor, &mut matched);
                        }
                    }
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

    fn bucket(&self, offset: usize) -> Bucket {
        let Some(bucket) = u32::try_from(offset >> 4).ok() else {
            return Bucket::Empty;
        };
        if bucket < self.base_bucket {
            return Bucket::Empty;
        }
        let index = (bucket - self.base_bucket) as usize;
        match self.table.get(index).copied().unwrap_or(NO_METHOD) {
            NO_METHOD => Bucket::Empty,
            value if value & SHARED_BIT != 0 => Bucket::Shared((value & !SHARED_BIT) as usize),
            value => Bucket::One(value),
        }
    }

    fn accept(
        &self,
        data: &[u8],
        offset: usize,
        method: u32,
        cursor: &mut HashMap<u32, usize>,
        matched: &mut Vec<u32>,
    ) {
        let Some(span) = self.bounds.get(&method) else {
            return;
        };
        if offset < span.start || offset >= span.end {
            return;
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
}

enum Bucket {
    Empty,
    One(u32),
    Shared(usize),
}

fn collect_methods(
    data: &[u8],
    class_data: &crate::dex::ClassData,
    entries: &mut Vec<(u32, u32, u32)>,
    bounds: &mut HashMap<u32, InsnSpan>,
) -> Result<()> {
    for method in class_data.methods() {
        if method.code_off == 0 || method.method_idx & SHARED_BIT != 0 {
            continue;
        }
        let pos = method.code_off as usize;
        let insn_size = u32_at(data, pos + 12)? as usize;
        if insn_size == 0 {
            continue;
        }
        let insn_off = pos + 16;
        let insn_bytes = insn_size * 2;
        if insn_off + insn_bytes > data.len() {
            bail!("code item out of range at {:#x}", method.code_off);
        }
        let (Ok(insn_off), Ok(insn_bytes)) = (u32::try_from(insn_off), u32::try_from(insn_bytes))
        else {
            bail!("code item out of range at {:#x}", method.code_off);
        };
        bounds.insert(
            method.method_idx,
            InsnSpan {
                start: insn_off as usize,
                end: insn_off as usize + insn_bytes as usize,
            },
        );
        entries.push((insn_off, insn_bytes, method.method_idx));
    }
    Ok(())
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
    let region = &data[start..end];
    let hits = if idxs.len() <= MEMMEM_MAX_TARGETS {
        scan_by_operand(region, start, kind, idxs)
    } else {
        scan_by_opcode(region, start, kind, idxs)
    };
    let offsets: Vec<usize> = hits.iter().map(|hit| hit.0).collect();
    let methods = locator.locate(data, &offsets);
    methods
        .into_iter()
        .zip(hits.into_iter().map(|hit| hit.1))
        .collect()
}

/// Operand width of `opcode` for this query. `0` means the opcode is not one we search.
fn opcode_width(kind: Kind, opcode: u8) -> u8 {
    match kind {
        Kind::String => match opcode {
            0x1a => 2,
            0x1b => 4,
            _ => 0,
        },
        Kind::Type => {
            if matches!(opcode, 0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25) {
                2
            } else {
                0
            }
        }
        Kind::Field => {
            if (0x52..=0x6d).contains(&opcode) {
                2
            } else {
                0
            }
        }
        Kind::Method => {
            if (0x6e..=0x72).contains(&opcode)
                || (0x74..=0x78).contains(&opcode)
                || opcode == 0xfa
                || opcode == 0xfb
            {
                2
            } else {
                0
            }
        }
    }
}

/// At most this many targets: searching each operand with `memmem` beats one sweep.
const MEMMEM_MAX_TARGETS: usize = 8;

fn scan_by_operand(
    region: &[u8],
    base: usize,
    kind: Kind,
    idxs: &HashSet<u32>,
) -> Vec<(usize, u32)> {
    let mut hits = Vec::new();
    for &idx in idxs {
        let narrow = (idx as u16).to_le_bytes();
        let wide = idx.to_le_bytes();
        let needles: [(&[u8], u8); 2] = [(&narrow, 2), (&wide, 4)];
        for (needle, width) in needles {
            if width == 2 && idx > u32::from(u16::MAX) {
                continue;
            }
            if width == 4 && kind != Kind::String {
                continue;
            }
            let finder = memchr::memmem::Finder::new(needle);
            // Resume one byte later. A self-overlapping needle would otherwise
            // skip the real operand after a hit that landed one byte early.
            let mut from = 0;
            while let Some(rel) = finder.find(&region[from..]) {
                let pos = from + rel;
                from = pos + 1;
                if pos >= 2 && opcode_width(kind, region[pos - 2]) == width {
                    hits.push((base + pos - 2, idx));
                }
            }
        }
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn scan_by_opcode(
    region: &[u8],
    base: usize,
    kind: Kind,
    idxs: &HashSet<u32>,
) -> Vec<(usize, u32)> {
    let mut hits = Vec::new();
    if kind == Kind::String {
        for index in memchr::memchr2_iter(0x1a, 0x1b, region) {
            push_candidate(region, base, kind, idxs, index, &mut hits);
        }
        return hits;
    }
    let mut highs: Vec<u8> = idxs.iter().map(|idx| (idx >> 8) as u8).collect();
    highs.sort_unstable();
    highs.dedup();
    if !prefilter_is_selective(&highs) {
        linear_sweep(region, base, kind, idxs, &mut hits);
        return hits;
    }
    match highs.as_slice() {
        [a] => {
            for index in memchr::memchr_iter(*a, region) {
                if index >= 3 {
                    push_candidate(region, base, kind, idxs, index - 3, &mut hits);
                }
            }
        }
        [a, b] => {
            for index in memchr::memchr2_iter(*a, *b, region) {
                if index >= 3 {
                    push_candidate(region, base, kind, idxs, index - 3, &mut hits);
                }
            }
        }
        [a, b, c] => {
            for index in memchr::memchr3_iter(*a, *b, *c, region) {
                if index >= 3 {
                    push_candidate(region, base, kind, idxs, index - 3, &mut hits);
                }
            }
        }
        _ => linear_sweep(region, base, kind, idxs, &mut hits),
    }
    hits
}

fn prefilter_is_selective(highs: &[u8]) -> bool {
    highs.len() <= 3 && !highs.iter().any(|byte| *byte == 0x00 || *byte == 0xff)
}

fn push_candidate(
    region: &[u8],
    base: usize,
    kind: Kind,
    idxs: &HashSet<u32>,
    index: usize,
    hits: &mut Vec<(usize, u32)>,
) {
    let width = opcode_width(kind, region[index]);
    if width == 0 {
        return;
    }
    let idx = if width == 2 {
        let Some(bytes) = region.get(index + 2..index + 4) else {
            return;
        };
        u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))
    } else {
        let Some(bytes) = region.get(index + 2..index + 6) else {
            return;
        };
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    if idxs.contains(&idx) {
        hits.push((base + index, idx));
    }
}

fn linear_sweep(
    region: &[u8],
    base: usize,
    kind: Kind,
    idxs: &HashSet<u32>,
    hits: &mut Vec<(usize, u32)>,
) {
    let mut widths = [0u8; 256];
    for (opcode, width) in widths.iter_mut().enumerate() {
        *width = opcode_width(kind, opcode as u8);
    }
    for (index, byte) in region.iter().enumerate() {
        if widths[*byte as usize] == 0 {
            continue;
        }
        push_candidate(region, base, kind, idxs, index, hits);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{byte_regex, fuzzy_class, has_at_ref};

    #[test]
    fn operand_and_opcode_scans_find_the_same_string() {
        // const-string v0, string@1 at offset 0, then padding, then const-string/jumbo.
        let mut region = vec![0x1a, 0x00, 0x01, 0x00, 0, 0, 0, 0];
        region.extend_from_slice(&[0x1b, 0x00, 0x02, 0x00, 0x00, 0x00]);
        let idxs: HashSet<u32> = [1, 2].into_iter().collect();
        let by_operand = super::scan_by_operand(&region, 10, super::Kind::String, &idxs);
        let by_opcode = super::scan_by_opcode(&region, 10, super::Kind::String, &idxs);
        assert_eq!(by_operand, vec![(10, 1), (18, 2)]);
        assert_eq!(by_opcode, vec![(10, 1), (18, 2)]);
    }

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

    #[test]
    fn a_fuzzy_class_name_matches_its_inner_class_literally() {
        // `$` and `(` in a mangled name are text, not pattern syntax.
        let pattern = fuzzy_class("Azeroth2$mDefault$2");
        let regex = byte_regex(&pattern).unwrap();
        assert!(regex.is_match(b"Lcom/kwai/Azeroth2$mDefault$2;"));
        assert!(regex.is_match(b"Lcom/kwai/Other(Azeroth2$mDefault$2);"));
        assert!(!regex.is_match(b"Lcom/kwai/Azeroth2XmDefaultY2;"));
    }

    #[test]
    fn a_dotted_fuzzy_class_name_is_read_as_a_package_path() {
        let pattern = fuzzy_class("com.example.Foo");
        let regex = byte_regex(&pattern).unwrap();
        assert!(regex.is_match(b"Lcom/example/Foo;"));
    }
}
