//! On-demand `resources.arsc` lookup used to fill manifest and DEX references.
//!
//! Default configurations win over qualified ones, matching an unqualified
//! `@string/name`.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::Result;

#[derive(Default)]
pub struct ResourceTable {
    by_id: HashMap<u32, Slot>,
    by_name: HashMap<(String, String), Slot>,
    /// Package names this table declares. `@android:type/name` names a package
    /// the table does not own, so it must not be resolved against it.
    packages: HashSet<String>,
}

struct Slot {
    value: String,
    default_config: bool,
    /// The value is already a Java literal (a number, boolean, or colour), so
    /// the code writer must not quote it.
    literal: bool,
}

enum RefToken {
    Id(u32),
    Name {
        package: Option<String>,
        type_name: String,
        entry: String,
    },
}

impl ResourceTable {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 || u16_at(data, 0)? != 0x0002 {
            bail!("resources.arsc is not a resource table");
        }
        let header_size = u16_at(data, 2)? as usize;
        let mut table = Self::default();
        let mut global = Vec::new();
        let mut pos = header_size.max(12);
        while pos + 8 <= data.len() {
            let kind = u16_at(data, pos)?;
            let size = u32_at(data, pos + 4)? as usize;
            if size < 8 || pos + size > data.len() {
                break;
            }
            let chunk = &data[pos..pos + size];
            match kind {
                0x0001 => global = parse_pool(chunk)?,
                0x0200 => table.parse_package(chunk, &global)?,
                _ => {}
            }
            pos += size;
        }
        table.resolve_reference_values();
        Ok(table)
    }

    pub fn note_res_path(&mut self, zip_name: &str) {
        let Some(rest) = zip_name.strip_prefix("res/") else {
            return;
        };
        let mut parts = rest.split('/');
        let Some(dir) = parts.next() else {
            return;
        };
        let Some(file) = parts.next() else {
            return;
        };
        if parts.next().is_some() {
            return;
        }
        let type_name = dir.split('-').next().unwrap_or(dir);
        let stem = file.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(file);
        let stem = stem.strip_suffix(".9").unwrap_or(stem);
        if type_name.is_empty() || stem.is_empty() {
            return;
        }
        let key = (type_name.to_string(), stem.to_string());
        if self.by_name.contains_key(&key) {
            return;
        }
        self.by_name.insert(
            key,
            Slot {
                value: zip_name.to_string(),
                default_config: dir == type_name,
                literal: false,
            },
        );
    }

    /// Replace resource ids and `R$type;->name` fields in decompiled DEX text.
    ///
    /// Text with no resource marker is returned borrowed, so a dump does not copy it.
    pub fn rewrite_code<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        if !self.may_rewrite_code(text) {
            return std::borrow::Cow::Borrowed(text);
        }
        std::borrow::Cow::Owned(self.rewrite_code_slow(text))
    }

    fn rewrite_code_slow(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut index = 0;
        let mut in_string = false;
        let mut escaped = false;
        while index < chars.len() {
            if in_string {
                if escaped {
                    out.push(chars[index]);
                    escaped = false;
                    index += 1;
                    continue;
                }
                if chars[index] == '\\' {
                    out.push('\\');
                    escaped = true;
                    index += 1;
                    continue;
                }
                if chars[index] == '"' {
                    in_string = false;
                    out.push('"');
                    index += 1;
                    continue;
                }
                if chars[index] == '@' || chars[index] == '?' {
                    if let Some((len, token)) = parse_ref(&chars[index..]) {
                        if let Some(slot) = self.lookup(&token) {
                            out.push_str(&escape_code(&slot.value));
                            index += len;
                            continue;
                        }
                    }
                }
                out.push(chars[index]);
                index += 1;
                continue;
            }
            if chars[index] == '"' {
                in_string = true;
                out.push('"');
                index += 1;
                continue;
            }
            if chars[index] == 'R' && chars.get(index + 1) == Some(&'$') {
                if let Some((start, len, type_name, entry)) = parse_r_field(&chars, index) {
                    if let Some(slot) = self.lookup(&RefToken::Name {
                        package: None,
                        type_name,
                        entry,
                    }) {
                        drop_chars(&mut out, index - start);
                        out.push_str(&quote_code(&slot.value, slot.literal));
                        index += len;
                        continue;
                    }
                }
            }
            if let Some((len, id)) = parse_code_number(&chars, index) {
                if let Some(slot) = self.by_id.get(&id) {
                    out.push_str(&quote_code(&slot.value, slot.literal));
                    index += len;
                    continue;
                }
            }
            if chars[index] == '@' || chars[index] == '?' {
                if let Some((len, token)) = parse_ref(&chars[index..]) {
                    if let Some(slot) = self.lookup(&token) {
                        out.push_str(&quote_code(&slot.value, slot.literal));
                        index += len;
                        continue;
                    }
                }
            }
            out.push(chars[index]);
            index += 1;
        }
        out
    }

    pub fn annotate(&self, text: &str) -> String {
        if self.by_id.is_empty() && self.by_name.is_empty() || !has_at_ref(text.as_bytes()) {
            return text.to_string();
        }
        self.replace_at_refs(text, xml_escape)
    }

    /// Replace `@type/name` tokens in a DEX string payload. The value is inserted raw.
    pub fn rewrite_plain(&self, text: &str) -> String {
        if self.by_id.is_empty() && self.by_name.is_empty() || !has_at_ref(text.as_bytes()) {
            return text.to_string();
        }
        self.replace_at_refs(text, |value| value.to_string())
    }

    fn may_rewrite_code(&self, text: &str) -> bool {
        if self.by_id.is_empty() && self.by_name.is_empty() {
            return false;
        }
        // Package id occupies the top byte, so a real resource id is at least
        // 0x01000000 (8 decimal digits). Shorter consts cannot be table keys.
        let bytes = text.as_bytes();
        let mut digits = 0u8;
        let mut prev = 0u8;
        for &byte in bytes {
            if !self.by_id.is_empty() && byte.is_ascii_digit() {
                digits = digits.saturating_add(1);
                if digits >= 8 {
                    return true;
                }
            } else {
                digits = 0;
            }
            if byte == b'@' || byte == b'?' || (prev == b'R' && byte == b'$') {
                return true;
            }
            if !self.by_id.is_empty() && prev == b'0' && (byte == b'x' || byte == b'X') {
                return true;
            }
            prev = byte;
        }
        false
    }

    fn replace_at_refs(&self, text: &str, render: impl Fn(&str) -> String) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut index = 0;
        while index < chars.len() {
            if chars[index] == '@' || chars[index] == '?' {
                if let Some((len, token)) = parse_ref(&chars[index..]) {
                    if let Some(slot) = self.lookup(&token) {
                        out.push_str(&render(&slot.value));
                    } else {
                        out.extend(chars[index..index + len].iter().copied());
                    }
                    index += len;
                    continue;
                }
            }
            out.push(chars[index]);
            index += 1;
        }
        out
    }

    fn lookup(&self, token: &RefToken) -> Option<&Slot> {
        let slot = match token {
            RefToken::Id(id) => self.by_id.get(id),
            RefToken::Name {
                package,
                type_name,
                entry,
            } => {
                // `@android:string/ok` belongs to another package. Resolving it
                // against this table would return the app's own `string/ok`.
                if package
                    .as_ref()
                    .is_some_and(|name| !self.packages.contains(name))
                {
                    return None;
                }
                self.by_name.get(&(type_name.clone(), entry.clone()))
            }
        }?;
        if slot.value.is_empty() {
            None
        } else {
            Some(slot)
        }
    }

    fn parse_package(&mut self, chunk: &[u8], global: &[String]) -> Result<()> {
        if chunk.len() < 288 && chunk.len() < 284 {
            bail!("truncated resource package");
        }
        let header_size = u16_at(chunk, 2)? as usize;
        let package_id = u32_at(chunk, 8)?;
        if chunk.len() < 280 {
            bail!("truncated resource package");
        }
        // The package header carries a 128 code unit UTF-16LE name at offset 12.
        if let Some(name) = read_package_name(&chunk[12..268]) {
            self.packages.insert(name);
        }
        let type_off = u32_at(chunk, 268)? as usize;
        let key_off = u32_at(chunk, 276)? as usize;
        if type_off >= chunk.len() || key_off >= chunk.len() {
            bail!("resource package string pools are out of range");
        }
        let type_pool = parse_pool(&chunk[type_off..])?;
        let key_pool = parse_pool(&chunk[key_off..])?;
        let mut pos = header_size;
        while pos + 8 <= chunk.len() {
            let kind = u16_at(chunk, pos)?;
            let size = u32_at(chunk, pos + 4)? as usize;
            if size < 8 || pos + size > chunk.len() {
                break;
            }
            if kind == 0x0201 {
                self.parse_type(
                    &chunk[pos..pos + size],
                    package_id,
                    &type_pool,
                    &key_pool,
                    global,
                )?;
            }
            pos += size;
        }
        Ok(())
    }

    fn parse_type(
        &mut self,
        chunk: &[u8],
        package_id: u32,
        type_pool: &[String],
        key_pool: &[String],
        global: &[String],
    ) -> Result<()> {
        if chunk.len() < 20 {
            return Ok(());
        }
        let header_size = u16_at(chunk, 2)? as usize;
        let id = chunk[8];
        let flags = chunk[9];
        let entry_count = u32_at(chunk, 12)? as usize;
        let entries_start = u32_at(chunk, 16)? as usize;
        let default_config = is_default_config(chunk);
        let type_index = usize::from(id).saturating_sub(1);
        let Some(type_name) = type_pool.get(type_index) else {
            return Ok(());
        };
        for index in 0..entry_count {
            let Some((entry_index, entry_at)) =
                entry_offset(chunk, header_size, entries_start, flags, index)
            else {
                continue;
            };
            let Some((key, value, literal)) = read_entry(chunk, entry_at, global) else {
                continue;
            };
            let Some(entry_name) = key_pool.get(key as usize) else {
                continue;
            };
            let res_id = (package_id << 24) | (u32::from(id) << 16) | (entry_index as u32);
            self.insert(
                res_id,
                type_name,
                entry_name,
                value,
                default_config,
                literal,
            );
        }
        Ok(())
    }

    pub fn extend(&mut self, other: Self) {
        for (id, slot) in other.by_id {
            insert_slot(&mut self.by_id, id, slot);
        }
        for (key, slot) in other.by_name {
            insert_slot(&mut self.by_name, key, slot);
        }
    }

    fn insert(
        &mut self,
        id: u32,
        type_name: &str,
        entry: &str,
        value: String,
        default_config: bool,
        literal: bool,
    ) {
        insert_slot(
            &mut self.by_id,
            id,
            Slot {
                value: value.clone(),
                default_config,
                literal,
            },
        );
        insert_slot(
            &mut self.by_name,
            (type_name.to_string(), entry.to_string()),
            Slot {
                value,
                default_config,
                literal,
            },
        );
    }

    fn resolve_reference_values(&mut self) {
        let mut name_keys: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for ((type_name, entry), slot) in &self.by_name {
            if hex_resource_id(&slot.value).is_some() {
                name_keys
                    .entry(slot.value.clone())
                    .or_default()
                    .push((type_name.clone(), entry.clone()));
            }
        }
        let ids: Vec<u32> = self.by_id.keys().copied().collect();
        for id in ids {
            let Some(current) = self.by_id.get(&id).map(|slot| slot.value.clone()) else {
                continue;
            };
            let Some(target_id) = hex_resource_id(&current) else {
                continue;
            };
            let Some(target) = self.by_id.get(&target_id) else {
                continue;
            };
            if target.value.starts_with('@') {
                continue;
            }
            let resolved = target.value.clone();
            let resolved_literal = target.literal;
            if let Some(slot) = self.by_id.get_mut(&id) {
                slot.value = resolved.clone();
                slot.literal = resolved_literal;
            }
            let Some(keys) = name_keys.get(&current) else {
                continue;
            };
            for key in keys {
                if let Some(slot) = self.by_name.get_mut(key) {
                    slot.value = resolved.clone();
                    slot.literal = resolved_literal;
                }
            }
        }
    }
}

/// Picks the value to keep when several configurations define one resource.
///
/// The table is read in file order, so the rule has to be order independent:
/// a default configuration wins over a qualified one, a default that arrives
/// later replaces a qualified value that arrived earlier, and between two
/// equally qualified values the first is kept.
fn insert_slot<K: Eq + std::hash::Hash>(map: &mut HashMap<K, Slot>, key: K, slot: Slot) {
    match map.get(&key) {
        Some(old) if old.default_config => {}
        Some(_) if slot.default_config => {
            map.insert(key, slot);
        }
        Some(_) => {}
        None => {
            map.insert(key, slot);
        }
    }
}

fn entry_offset(
    chunk: &[u8],
    header_size: usize,
    entries_start: usize,
    flags: u8,
    index: usize,
) -> Option<(usize, usize)> {
    if flags & 0x01 != 0 {
        let at = header_size + index * 4;
        let entry_index = u16_at(chunk, at).ok()? as usize;
        let offset = u16_at(chunk, at + 2).ok()? as usize;
        return Some((entry_index, entries_start + offset * 4));
    }
    if flags & 0x02 != 0 {
        let at = header_size + index * 2;
        let offset = u16_at(chunk, at).ok()?;
        if offset == 0xffff {
            return None;
        }
        return Some((index, entries_start + usize::from(offset) * 4));
    }
    let rel = u32_at(chunk, header_size + index * 4).ok()?;
    if rel == 0xffff_ffff {
        None
    } else {
        Some((index, entries_start + rel as usize))
    }
}

fn read_entry(chunk: &[u8], at: usize, global: &[String]) -> Option<(u32, String, bool)> {
    if at + 8 > chunk.len() {
        return None;
    }
    let size = u16_at(chunk, at).ok()? as usize;
    let flags = u16_at(chunk, at + 2).ok()?;
    let key = u32_at(chunk, at + 4).ok()?;
    if flags & 0x0001 != 0 || size < 8 {
        return None;
    }
    let value_at = at + size;
    if value_at + 8 > chunk.len() {
        return None;
    }
    let data_type = *chunk.get(value_at + 3)?;
    let data = u32_at(chunk, value_at + 4).ok()?;
    render_value(data_type, data, global).map(|(value, literal)| (key, value, literal))
}

/// Renders one `Res_value`. The flag says whether the text is already a Java
/// literal, which is what decides whether the code writer quotes it.
fn render_value(data_type: u8, data: u32, global: &[String]) -> Option<(String, bool)> {
    match data_type {
        0x00 => None,
        0x01 => Some((format!("@0x{data:08x}"), false)),
        0x03 => global.get(data as usize).cloned().map(|text| (text, false)),
        0x04 => Some((f32::from_bits(data).to_string(), true)),
        0x10 => Some((i32::from_le_bytes(data.to_le_bytes()).to_string(), true)),
        0x11 => Some((format!("{data:#x}"), true)),
        0x12 => Some((
            if data == 0 {
                "false".to_string()
            } else {
                "true".to_string()
            },
            true,
        )),
        0x1c..=0x1f => Some((format!("#{data:08x}"), true)),
        _ => Some((format!("@0x{data:08x}"), false)),
    }
}

/// Maps a packaged file path to the resource name stored in `resources.arsc`.
///
/// `aapt2` path shortening rewrites `res/drawable-hdpi/icon.png` to something
/// like `r/d/c.png`. The table still has the type, configuration, and entry
/// name, so the shortened path can be put back. A path that does not name a
/// file resource is left out. Two entries that would restore to the same path
/// are left out as well, so a later diff does not merge unrelated files.
/// File-path restoration and `0x7f......` resource ids from one `resources.arsc`.
#[derive(Clone, Debug, Default)]
pub struct CompiledResources {
    pub paths: BTreeMap<String, String>,
    /// Resource id to `type/name`, without the leading `@`.
    pub symbols: BTreeMap<u32, String>,
}

pub fn resource_paths(data: &[u8]) -> Result<BTreeMap<String, String>> {
    Ok(compiled_resources(data)?.paths)
}

/// Reads shortened file paths and resource id names from `resources.arsc`.
pub fn compiled_resources(data: &[u8]) -> Result<CompiledResources> {
    if data.len() < 12 || u16_at(data, 0)? != 0x0002 {
        bail!("resources.arsc is not a resource table");
    }
    let header_size = usize::from(u16_at(data, 2)?);
    let mut pairs = Vec::new();
    let mut symbols = BTreeMap::new();
    let mut global = Vec::new();
    let mut pos = header_size.max(12);
    while pos + 8 <= data.len() {
        let kind = u16_at(data, pos)?;
        let size = usize::try_from(u32_at(data, pos + 4)?).unwrap_or(0);
        if size < 8 || pos + size > data.len() {
            break;
        }
        let chunk = &data[pos..pos + size];
        match kind {
            0x0001 => global = parse_pool(chunk)?,
            0x0200 => collect_package_paths(chunk, &global, &mut pairs, &mut symbols)?,
            _ => {}
        }
        pos += size;
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, restored) in &pairs {
        *counts.entry(restored.clone()).or_default() += 1;
    }
    let paths = pairs
        .into_iter()
        .filter(|(_, restored)| counts.get(restored) == Some(&1))
        .collect();
    Ok(CompiledResources { paths, symbols })
}

fn collect_package_paths(
    chunk: &[u8],
    global: &[String],
    pairs: &mut Vec<(String, String)>,
    symbols: &mut BTreeMap<u32, String>,
) -> Result<()> {
    if chunk.len() < 284 {
        return Ok(());
    }
    let header_size = usize::from(u16_at(chunk, 2)?);
    let type_off = usize::try_from(u32_at(chunk, 268)?).unwrap_or(usize::MAX);
    let key_off = usize::try_from(u32_at(chunk, 276)?).unwrap_or(usize::MAX);
    if type_off >= chunk.len() || key_off >= chunk.len() {
        return Ok(());
    }
    let type_pool = parse_pool(&chunk[type_off..])?;
    let key_pool = parse_pool(&chunk[key_off..])?;
    let package_id = u32_at(chunk, 8)?;
    let mut pos = header_size;
    while pos + 8 <= chunk.len() {
        let kind = u16_at(chunk, pos)?;
        let size = usize::try_from(u32_at(chunk, pos + 4)?).unwrap_or(0);
        if size < 8 || pos + size > chunk.len() {
            break;
        }
        if kind == 0x0201 {
            collect_type_paths(
                &chunk[pos..pos + size],
                &type_pool,
                &key_pool,
                global,
                package_id,
                pairs,
                symbols,
            );
        }
        pos += size;
    }
    Ok(())
}

fn collect_type_paths(
    chunk: &[u8],
    type_pool: &[String],
    key_pool: &[String],
    global: &[String],
    package_id: u32,
    pairs: &mut Vec<(String, String)>,
    symbols: &mut BTreeMap<u32, String>,
) {
    if chunk.len() < 20 {
        return;
    }
    let header_size = usize::from(u16_at(chunk, 2).unwrap_or(0));
    let id = chunk[8];
    let flags = chunk[9];
    let Ok(entry_count) = usize::try_from(u32_at(chunk, 12).unwrap_or(0)) else {
        return;
    };
    let Ok(entries_start) = usize::try_from(u32_at(chunk, 16).unwrap_or(0)) else {
        return;
    };
    let type_index = usize::from(id).saturating_sub(1);
    let Some(type_name) = type_pool.get(type_index) else {
        return;
    };
    if type_name.is_empty() || type_name.contains('/') {
        return;
    }
    let qualifiers = config_qualifiers(chunk);
    for index in 0..entry_count {
        let Some((entry_index, entry_at)) =
            entry_offset(chunk, header_size, entries_start, flags, index)
        else {
            continue;
        };
        let Some(key) = entry_key(chunk, entry_at) else {
            continue;
        };
        let Some(entry_name) = key_pool.get(usize::try_from(key).unwrap_or(usize::MAX)) else {
            continue;
        };
        if entry_name.is_empty() || entry_name.contains('/') {
            continue;
        }
        if let Ok(index) = u32::try_from(entry_index) {
            let res_id = (package_id << 24) | (u32::from(id) << 16) | index;
            symbols
                .entry(res_id)
                .or_insert_with(|| format!("{type_name}/{entry_name}"));
        }
        let Some((.., value, _)) = read_entry(chunk, entry_at, global) else {
            continue;
        };
        let Some(zip_path) = resource_zip_path(&value) else {
            continue;
        };
        let restored = restored_path(type_name, &qualifiers, entry_name, extension(zip_path));
        if restored != zip_path {
            pairs.push((zip_path.to_string(), restored));
        }
    }
}

fn entry_key(chunk: &[u8], at: usize) -> Option<u32> {
    if at + 8 > chunk.len() {
        return None;
    }
    u32_at(chunk, at + 4).ok()
}

fn resource_zip_path(value: &str) -> Option<&str> {
    let path = value.strip_prefix('/').unwrap_or(value);
    if path.starts_with("res/") || path.starts_with("r/") {
        Some(path)
    } else {
        None
    }
}

fn extension(path: &str) -> &str {
    let file = path.rsplit('/').next().unwrap_or(path);
    if file.ends_with(".9.png") {
        ".9.png"
    } else {
        file.rfind('.').map(|index| &file[index..]).unwrap_or("")
    }
}

fn restored_path(type_name: &str, qualifiers: &str, entry: &str, extension: &str) -> String {
    if qualifiers.is_empty() {
        format!("res/{type_name}/{entry}{extension}")
    } else {
        format!("res/{type_name}-{qualifiers}/{entry}{extension}")
    }
}

/// Android resource directory qualifiers for one `ResTable_config`.
///
/// The config sits at byte 20 of a `ResTable_type`. Fields past `size` are absent.
fn config_qualifiers(chunk: &[u8]) -> String {
    let size = usize::try_from(u32_at(chunk, 20).unwrap_or(0)).unwrap_or(0);
    if size < 4 || 20 + size > chunk.len() {
        return String::new();
    }
    let config = &chunk[20..20 + size];
    let mut parts = Vec::new();
    let mcc = config_u16(config, 4);
    let mnc = config_u16(config, 6);
    if mcc != 0 {
        parts.push(format!("mcc{mcc}"));
    }
    if mnc != 0 {
        parts.push(format!("mnc{mnc}"));
    }
    if let Some(locale) = locale_qualifier(config) {
        parts.push(locale);
    }
    let screen_layout = config_u8(config, 28);
    match screen_layout & 0xc0 {
        0x40 => parts.push("ldltr".to_string()),
        0x80 => parts.push("ldrtl".to_string()),
        _ => {}
    }
    let smallest = config_u16(config, 30);
    if smallest != 0 {
        parts.push(format!("sw{smallest}dp"));
    }
    let width_dp = config_u16(config, 32);
    let height_dp = config_u16(config, 34);
    if width_dp != 0 {
        parts.push(format!("w{width_dp}dp"));
    }
    if height_dp != 0 {
        parts.push(format!("h{height_dp}dp"));
    }
    match screen_layout & 0x0f {
        0x01 => parts.push("small".to_string()),
        0x02 => parts.push("normal".to_string()),
        0x03 => parts.push("large".to_string()),
        0x04 => parts.push("xlarge".to_string()),
        _ => {}
    }
    match screen_layout & 0x30 {
        0x10 => parts.push("notlong".to_string()),
        0x20 => parts.push("long".to_string()),
        _ => {}
    }
    let layout2 = config_u8(config, 48);
    match layout2 & 0x03 {
        1 => parts.push("notround".to_string()),
        2 => parts.push("round".to_string()),
        _ => {}
    }
    let color_mode = config_u8(config, 49);
    match color_mode & 0x03 {
        1 => parts.push("nowidecg".to_string()),
        2 => parts.push("widecg".to_string()),
        _ => {}
    }
    match color_mode & 0x0c {
        0x04 => parts.push("lowdr".to_string()),
        0x08 => parts.push("highdr".to_string()),
        _ => {}
    }
    match config_u8(config, 12) {
        1 => parts.push("port".to_string()),
        2 => parts.push("land".to_string()),
        3 => parts.push("square".to_string()),
        _ => {}
    }
    match config_u8(config, 29) & 0x0f {
        0x02 => parts.push("desk".to_string()),
        0x03 => parts.push("car".to_string()),
        0x04 => parts.push("television".to_string()),
        0x05 => parts.push("appliance".to_string()),
        0x06 => parts.push("watch".to_string()),
        0x07 => parts.push("vrheadset".to_string()),
        _ => {}
    }
    match config_u8(config, 29) & 0x30 {
        0x10 => parts.push("notnight".to_string()),
        0x20 => parts.push("night".to_string()),
        _ => {}
    }
    match config_u16(config, 14) {
        0 => {}
        120 => parts.push("ldpi".to_string()),
        160 => parts.push("mdpi".to_string()),
        213 => parts.push("tvdpi".to_string()),
        240 => parts.push("hdpi".to_string()),
        320 => parts.push("xhdpi".to_string()),
        480 => parts.push("xxhdpi".to_string()),
        640 => parts.push("xxxhdpi".to_string()),
        0xfffe => parts.push("anydpi".to_string()),
        0xffff => parts.push("nodpi".to_string()),
        other => parts.push(format!("{other}dpi")),
    }
    match config_u8(config, 13) {
        1 => parts.push("notouch".to_string()),
        2 => parts.push("stylus".to_string()),
        3 => parts.push("finger".to_string()),
        _ => {}
    }
    let input_flags = config_u8(config, 18);
    match input_flags & 0x03 {
        1 => parts.push("keysexposed".to_string()),
        2 => parts.push("keyshidden".to_string()),
        3 => parts.push("keyssoft".to_string()),
        _ => {}
    }
    match config_u8(config, 16) {
        1 => parts.push("nokeys".to_string()),
        2 => parts.push("qwerty".to_string()),
        3 => parts.push("12key".to_string()),
        _ => {}
    }
    match input_flags & 0x0c {
        0x04 => parts.push("navexposed".to_string()),
        0x08 => parts.push("navhidden".to_string()),
        _ => {}
    }
    match config_u8(config, 17) {
        1 => parts.push("nonav".to_string()),
        2 => parts.push("dpad".to_string()),
        3 => parts.push("trackball".to_string()),
        4 => parts.push("wheel".to_string()),
        _ => {}
    }
    let screen_width = config_u16(config, 20);
    let screen_height = config_u16(config, 22);
    if screen_width != 0 || screen_height != 0 {
        parts.push(format!("{screen_width}x{screen_height}"));
    }
    let sdk = config_u16(config, 24);
    let minor = config_u16(config, 26);
    if sdk != 0 {
        if minor == 0 {
            parts.push(format!("v{sdk}"));
        } else {
            parts.push(format!("v{sdk}.{minor}"));
        }
    }
    parts.join("-")
}

fn config_u8(config: &[u8], offset: usize) -> u8 {
    config.get(offset).copied().unwrap_or(0)
}

fn config_u16(config: &[u8], offset: usize) -> u16 {
    config
        .get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .unwrap_or(0)
}

fn locale_qualifier(config: &[u8]) -> Option<String> {
    let locale = u32::from(config_u16(config, 8)) | (u32::from(config_u16(config, 10)) << 16);
    let script = config.get(36..40).unwrap_or(&[]);
    let variant = config.get(40..48).unwrap_or(&[]);
    let language = unpack_locale_chars([config_u8(config, 8), config_u8(config, 9)], b'a');
    let region = unpack_locale_chars([config_u8(config, 10), config_u8(config, 11)], b'0');
    let script = ascii_field(script);
    let variant = ascii_field(variant);
    if locale == 0 && script.is_empty() && variant.is_empty() {
        return None;
    }
    if script.is_empty() && variant.is_empty() {
        if language.is_empty() {
            return None;
        }
        if region.is_empty() {
            return Some(language);
        }
        return Some(format!("{language}-r{region}"));
    }
    let mut tag = String::from("b+");
    tag.push_str(if language.is_empty() {
        "und"
    } else {
        &language
    });
    if !script.is_empty() {
        tag.push('+');
        tag.push_str(&script);
    }
    if !region.is_empty() {
        tag.push('+');
        tag.push_str(&region);
    }
    if !variant.is_empty() {
        tag.push('+');
        tag.push_str(&variant);
    }
    Some(tag)
}

fn unpack_locale_chars(bytes: [u8; 2], base: u8) -> String {
    if bytes[0] & 0x80 != 0 {
        let first = u32::from(bytes[1] & 0x1f);
        let second = u32::from((bytes[1] & 0xe0) >> 5) + u32::from((bytes[0] & 0x03) << 3);
        let third = u32::from((bytes[0] & 0x7c) >> 2);
        return [first, second, third]
            .into_iter()
            .filter_map(|value| u8::try_from(u32::from(base) + value).ok())
            .map(char::from)
            .collect();
    }
    bytes
        .into_iter()
        .filter(|byte| *byte != 0)
        .map(char::from)
        .collect()
}

fn ascii_field(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .map(char::from)
        .collect()
}

/// Whether a `ResTable_type` carries the unqualified configuration.
///
/// Every qualifier counts: density, uiMode (night), sdkVersion, orientation,
/// and the rest. Looking only at mcc/mnc/locale would call a `-xhdpi` or
/// `-night` chunk a default, and that chunk would then displace the real one.
fn is_default_config(chunk: &[u8]) -> bool {
    if chunk.len() < 24 {
        return true;
    }
    // `ResTable_type` has a 20 byte header, then a `ResTable_config` that
    // starts with its own size. The size includes those four bytes.
    let size = u32_at(chunk, 20).unwrap_or(0) as usize;
    if size < 4 || 20 + size > chunk.len() {
        return true;
    }
    chunk[24..20 + size].iter().all(|byte| *byte == 0)
}

fn parse_ref(chars: &[char]) -> Option<(usize, RefToken)> {
    if chars.first() != Some(&'@') && chars.first() != Some(&'?') {
        return None;
    }
    let mut index = 1;
    if chars.get(index) == Some(&'+') {
        index += 1;
    }
    if chars.get(index) == Some(&'0') && matches!(chars.get(index + 1), Some('x' | 'X')) {
        index += 2;
        let start = index;
        while chars.get(index).is_some_and(|ch| ch.is_ascii_hexdigit()) {
            index += 1;
        }
        if index == start {
            return None;
        }
        let hex: String = chars[start..index].iter().collect();
        let id = u32::from_str_radix(&hex, 16).ok()?;
        return Some((index, RefToken::Id(id)));
    }
    let (name_end, first) = read_ref_ident(chars, index)?;
    index = name_end;
    if chars.get(index) == Some(&':') {
        // `@package:type/name`: the leading ident names a package.
        index += 1;
        let (type_end, type_name) = read_ident(chars, index)?;
        if chars.get(type_end) != Some(&'/') {
            return None;
        }
        let (entry_end, entry) = read_ident(chars, type_end + 1)?;
        return Some((
            entry_end,
            RefToken::Name {
                package: Some(first),
                type_name,
                entry,
            },
        ));
    }
    if chars.get(index) != Some(&'/') {
        return None;
    }
    let (entry_end, entry) = read_ident(chars, index + 1)?;
    Some((
        entry_end,
        RefToken::Name {
            package: None,
            type_name: first,
            entry,
        },
    ))
}

/// The 128 UTF-16 code units at the start of a `ResTable_package` header.
fn read_package_name(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for pair in bytes.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(*pair);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if units.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&units))
    }
}

fn has_at_ref(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte == b'@' || *byte == b'?')
}

fn read_ident(chars: &[char], start: usize) -> Option<(usize, String)> {
    read_ident_with(chars, start, false)
}

/// The leading identifier of a reference, which may carry dots when it names a
/// package (`@com.example.app:string/name`).
fn read_ref_ident(chars: &[char], start: usize) -> Option<(usize, String)> {
    read_ident_with(chars, start, true)
}

fn read_ident_with(chars: &[char], start: usize, dots: bool) -> Option<(usize, String)> {
    let mut index = start;
    while chars
        .get(index)
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || (dots && *ch == '.'))
    {
        index += 1;
    }
    if index == start {
        None
    } else {
        Some((index, chars[start..index].iter().collect()))
    }
}

fn hex_resource_id(value: &str) -> Option<u32> {
    let hex = value.strip_prefix("@0x")?;
    u32::from_str_radix(hex, 16).ok()
}

fn parse_pool(chunk: &[u8]) -> Result<Vec<String>> {
    if chunk.len() < 28 || u16_at(chunk, 0)? != 0x0001 {
        bail!("truncated resource string pool");
    }
    let header_size = u16_at(chunk, 2)? as usize;
    let count = u32_at(chunk, 8)? as usize;
    let flags = u32_at(chunk, 16)?;
    let strings_start = u32_at(chunk, 20)? as usize;
    if header_size < 28 || header_size > chunk.len() || strings_start > chunk.len() {
        bail!("truncated resource string pool");
    }
    // The offset table has to fit before the count can size an allocation.
    let index_bytes = count
        .checked_mul(4)
        .ok_or_else(|| crate::Error::new("resource string pool is too large"))?;
    if header_size
        .checked_add(index_bytes)
        .map(|end| end > chunk.len())
        .unwrap_or(true)
    {
        bail!("truncated resource string pool");
    }
    let utf8 = flags & (1 << 8) != 0;
    let mut strings = Vec::with_capacity(count);
    for index in 0..count {
        let rel = u32_at(chunk, header_size + index * 4)? as usize;
        let at = strings_start + rel;
        strings.push(if utf8 {
            read_utf8(chunk, at)?
        } else {
            read_utf16(chunk, at)?
        });
    }
    Ok(strings)
}

fn read_utf8(data: &[u8], mut off: usize) -> Result<String> {
    let (_, width) = read_len8(data, off)?;
    off += width;
    let (nbytes, width) = read_len8(data, off)?;
    off += width;
    let bytes = data
        .get(off..off + nbytes)
        .ok_or_else(|| crate::Error::new("truncated resource string"))?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn read_len8(data: &[u8], off: usize) -> Result<(usize, usize)> {
    let byte = *data
        .get(off)
        .ok_or_else(|| crate::Error::new("truncated resource string"))?;
    if byte & 0x80 != 0 {
        let next = *data
            .get(off + 1)
            .ok_or_else(|| crate::Error::new("truncated resource string"))?;
        Ok((((usize::from(byte & 0x7f)) << 8) | usize::from(next), 2))
    } else {
        Ok((usize::from(byte), 1))
    }
}

fn read_utf16(data: &[u8], off: usize) -> Result<String> {
    let first = u16_at(data, off)?;
    let (chars, skip) = if first & 0x8000 != 0 {
        let second = u16_at(data, off + 2)?;
        (
            ((usize::from(first & 0x7fff)) << 16) | usize::from(second),
            4,
        )
    } else {
        (usize::from(first), 2)
    };
    let start = off + skip;
    // The length prefix must not size an allocation the buffer cannot back.
    if chars > data.len().saturating_sub(start) / 2 {
        bail!("truncated resource string");
    }
    let mut units = Vec::with_capacity(chars);
    for index in 0..chars {
        units.push(u16_at(data, start + index * 2)?);
    }
    Ok(String::from_utf16_lossy(&units))
}

fn parse_r_field(chars: &[char], r_at: usize) -> Option<(usize, usize, String, String)> {
    let (type_end, type_name) = read_ident(chars, r_at + 2)?;
    if chars.get(type_end) != Some(&';')
        || chars.get(type_end + 1) != Some(&'-')
        || chars.get(type_end + 2) != Some(&'>')
    {
        return None;
    }
    let (name_end, entry) = read_ident(chars, type_end + 3)?;
    let mut start = r_at;
    while start > 0 {
        let ch = chars[start - 1];
        if ch.is_ascii_alphanumeric()
            || ch == '/'
            || ch == '_'
            || ch == '$'
            || ch == '.'
            || ch == 'L'
        {
            start -= 1;
        } else {
            break;
        }
    }
    Some((start, name_end - r_at, type_name, entry))
}

fn parse_code_number(chars: &[char], index: usize) -> Option<(usize, u32)> {
    if index > 0 {
        let prev = chars[index - 1];
        if prev.is_ascii_alphanumeric() || prev == '_' {
            return None;
        }
    }
    let mut cursor = index;
    let hex = chars.get(cursor) == Some(&'0') && matches!(chars.get(cursor + 1), Some('x' | 'X'));
    if hex {
        cursor += 2;
        let digits = cursor;
        while chars.get(cursor).is_some_and(|ch| ch.is_ascii_hexdigit()) {
            cursor += 1;
        }
        if cursor == digits {
            return None;
        }
        // A Java suffix belongs to the literal: `0x7f010000L` is a long, not a
        // resource id followed by `L`.
        if ends_with_java_suffix(chars, cursor) {
            return None;
        }
        let text: String = chars[digits..cursor].iter().collect();
        return u32::from_str_radix(&text, 16)
            .ok()
            .map(|id| (cursor - index, id));
    }
    if !chars.get(index).is_some_and(|ch| ch.is_ascii_digit()) {
        return None;
    }
    while chars.get(cursor).is_some_and(|ch| ch.is_ascii_digit()) {
        cursor += 1;
    }
    if cursor - index > 10 || ends_with_java_suffix(chars, cursor) {
        return None;
    }
    let text: String = chars[index..cursor].iter().collect();
    text.parse::<u32>().ok().map(|id| (cursor - index, id))
}

/// Whether the char after a run of digits is a Java literal suffix, or a `.`
/// that would turn the number into a floating point literal.
fn ends_with_java_suffix(chars: &[char], cursor: usize) -> bool {
    match chars.get(cursor) {
        Some('l' | 'L' | 'f' | 'F' | 'd' | 'D' | '.') => true,
        // An identifier char turns the digits into a larger token.
        Some(ch) => ch.is_ascii_alphanumeric() || *ch == '_',
        None => false,
    }
}

fn drop_chars(out: &mut String, count: usize) {
    let keep = out.chars().count().saturating_sub(count);
    *out = out.chars().take(keep).collect();
}

fn escape_code(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch => out.push(ch),
        }
    }
    out
}

/// Writes a resource value into code. Only a value the table itself typed as a
/// number, boolean, or colour is already a literal; a string resource that
/// happens to read `1234` or `#ff0000` still needs its quotes.
fn quote_code(value: &str, literal: bool) -> String {
    if literal {
        return value.to_string();
    }
    format!("\"{}\"", escape_code(value))
}

fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            ch => out.push(ch),
        }
    }
    out
}

fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data
        .get(off..off + 2)
        .ok_or_else(|| crate::Error::new(format!("truncated resource read at {off:#x}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data
        .get(off..off + 4)
        .ok_or_else(|| crate::Error::new(format!("truncated resource read at {off:#x}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::ResourceTable;

    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn utf8_pool(strings: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for text in strings {
            offsets.push(body.len() as u32);
            body.push(text.chars().count() as u8);
            body.push(text.len() as u8);
            body.extend_from_slice(text.as_bytes());
            body.push(0);
        }
        let header_size = 28;
        let strings_start = header_size + strings.len() * 4;
        let mut pool = vec![0u8; strings_start];
        put_u16(&mut pool, 0, 0x0001);
        put_u16(&mut pool, 2, header_size as u16);
        put_u32(&mut pool, 8, strings.len() as u32);
        put_u32(&mut pool, 16, 1 << 8);
        put_u32(&mut pool, 20, strings_start as u32);
        for (index, offset) in offsets.iter().enumerate() {
            put_u32(&mut pool, header_size + index * 4, *offset);
        }
        pool.extend(body);
        let len = pool.len() as u32;
        put_u32(&mut pool, 4, len);
        pool
    }

    /// One `ResTable_type` with a single entry, under a config whose only
    /// qualifier is `density`.
    fn type_chunk(density: u16, data_type: u8, data: u32) -> Vec<u8> {
        let config_size = 28u32;
        let header_size = 20 + config_size as usize;
        let entries_start = header_size + 4;
        let mut chunk = vec![0u8; entries_start + 16];
        put_u16(&mut chunk, 0, 0x0201);
        put_u16(&mut chunk, 2, header_size as u16);
        chunk[8] = 1;
        put_u32(&mut chunk, 12, 1);
        put_u32(&mut chunk, 16, entries_start as u32);
        put_u32(&mut chunk, 20, config_size);
        put_u16(&mut chunk, 20 + 14, density); // ResTable_config.density
        put_u32(&mut chunk, header_size, 0);
        put_u16(&mut chunk, entries_start, 8);
        put_u32(&mut chunk, entries_start + 4, 0);
        put_u16(&mut chunk, entries_start + 8, 8);
        chunk[entries_start + 11] = data_type;
        put_u32(&mut chunk, entries_start + 12, data);
        let len = chunk.len() as u32;
        put_u32(&mut chunk, 4, len);
        chunk
    }

    fn string_type_chunk() -> Vec<u8> {
        type_chunk(0, 0x03, 0)
    }

    fn arsc_table(global: Vec<u8>, mut package: Vec<u8>) -> Vec<u8> {
        let package_len = package.len() as u32;
        put_u32(&mut package, 4, package_len);
        let mut table = vec![0u8; 12];
        put_u16(&mut table, 0, 0x0002);
        put_u16(&mut table, 2, 12);
        put_u32(&mut table, 8, 1);
        table.extend(global);
        table.extend(package);
        let table_len = table.len() as u32;
        put_u32(&mut table, 4, table_len);
        table
    }

    /// A package header whose own name is `com.example.app`, so cross package
    /// references can be exercised.
    fn example_package(type_pool: Vec<u8>, key_pool: Vec<u8>) -> Vec<u8> {
        let mut package = vec![0u8; 288];
        put_u16(&mut package, 0, 0x0200);
        put_u16(&mut package, 2, 288);
        put_u32(&mut package, 8, 0x7f);
        for (index, unit) in "com.example.app".encode_utf16().enumerate() {
            let at = 12 + index * 2;
            package[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        let type_off = package.len();
        package.extend(type_pool);
        let key_off = package.len();
        package.extend(key_pool);
        put_u32(&mut package, 268, type_off as u32);
        put_u32(&mut package, 276, key_off as u32);
        package
    }

    /// A table with one `string/app_name` entry per variant, written in the
    /// order given as `(value, density)`.
    fn arsc_with_string_variants(variants: &[(&str, u16)]) -> Vec<u8> {
        let values: Vec<&str> = variants.iter().map(|(value, _)| *value).collect();
        let global = utf8_pool(&values);
        let mut package = example_package(utf8_pool(&["string"]), utf8_pool(&["app_name"]));
        for (index, (_, density)) in variants.iter().enumerate() {
            package.extend(type_chunk(*density, 0x03, index as u32));
        }
        arsc_table(global, package)
    }

    /// A table with one entry of an arbitrary `Res_value` type.
    fn arsc_with_single(type_name: &str, key_name: &str, data_type: u8, data: u32) -> Vec<u8> {
        let global = utf8_pool(&[]);
        let mut package = example_package(utf8_pool(&[type_name]), utf8_pool(&[key_name]));
        package.extend(type_chunk(0, data_type, data));
        arsc_table(global, package)
    }

    fn sample_arsc() -> Vec<u8> {
        let global = utf8_pool(&["Hello"]);
        let types = utf8_pool(&["string"]);
        let keys = utf8_pool(&["app_name"]);
        let mut package = vec![0u8; 288];
        put_u16(&mut package, 0, 0x0200);
        put_u16(&mut package, 2, 288);
        put_u32(&mut package, 8, 0x7f);
        let type_off = package.len();
        package.extend(types);
        let key_off = package.len();
        package.extend(keys);
        put_u32(&mut package, 268, type_off as u32);
        put_u32(&mut package, 276, key_off as u32);
        package.extend(string_type_chunk());
        arsc_table(global, package)
    }

    #[test]
    fn fills_string_references_from_the_table() {
        let table = ResourceTable::parse(&sample_arsc()).unwrap();
        let xml = r#"<application android:label="@string/app_name" android:icon="@0x7f010000" />"#;
        let filled = table.annotate(xml);
        assert!(filled.contains("android:label=\"Hello\""), "{filled}");
        assert!(filled.contains("android:icon=\"Hello\""), "{filled}");
        let code =
            table.rewrite_code("v0 = 2130771968;\n    sget v1, Lcom/example/R$string;->app_name\n");
        assert!(code.contains("v0 = \"Hello\";"), "{code}");
        assert!(code.contains("sget v1, \"Hello\""), "{code}");
        let quoted = table.rewrite_code("v0 = \"2130771968\";\nv1 = \"@string/app_name\";\n");
        assert!(quoted.contains("\"2130771968\""), "{quoted}");
        assert!(quoted.contains("v1 = \"Hello\";"), "{quoted}");
        assert_eq!(table.rewrite_plain("@string/app_name"), "Hello");
        assert_eq!(table.rewrite_plain("plain"), "plain");
        assert_eq!(table.rewrite_code("v0 = 1;\n"), "v0 = 1;\n");
        let hex = table.rewrite_code("v0 = 0x7f010000;");
        assert!(hex.contains("\"Hello\""), "{hex}");
        // A Java literal suffix is part of the number, not a following `L`.
        for untouched in [
            "v0 = 2130771968L;\n",
            "v0 = 0x7f010000L;\n",
            "v0 = 2130771968f;\n",
            "v0 = 0x7f010000.toLong();\n",
            "v0 = 2130771968_0;\n",
        ] {
            assert_eq!(table.rewrite_code(untouched), untouched, "{untouched}");
        }
        let empty = ResourceTable::default();
        let untouched = "v0 = 2130771968;\n    sget v1, Lcom/example/R$string;->app_name\n";
        assert_eq!(empty.rewrite_code(untouched), untouched);
    }

    #[test]
    fn short_resource_paths_restore_the_entry_name() {
        let global = utf8_pool(&["r/d/c.xml"]);
        let mut package = example_package(utf8_pool(&["drawable"]), utf8_pool(&["icon"]));
        package.extend(type_chunk(240, 0x03, 0));
        let paths = super::resource_paths(&arsc_table(global, package)).unwrap();
        assert_eq!(
            paths.get("r/d/c.xml").map(String::as_str),
            Some("res/drawable-hdpi/icon.xml")
        );
    }

    /// A resource table whose only chunk is a global string pool. `body` holds
    /// the offset table and string data after the 28 byte pool header.
    fn arsc_with_pool(count: u32, body: &[u8], utf8: bool) -> Vec<u8> {
        let header_size = 28usize;
        let mut pool = vec![0u8; header_size];
        put_u16(&mut pool, 0, 0x0001);
        put_u16(&mut pool, 2, header_size as u16);
        put_u32(&mut pool, 8, count);
        put_u32(&mut pool, 16, if utf8 { 1 << 8 } else { 0 });
        // One offset entry, so tests that read a string can point it at zero.
        put_u32(&mut pool, 20, (header_size + 4) as u32);
        pool.extend_from_slice(body);
        let len = pool.len() as u32;
        put_u32(&mut pool, 4, len);

        let mut table = vec![0u8; 12];
        put_u16(&mut table, 0, 0x0002);
        put_u16(&mut table, 2, 12);
        put_u32(&mut table, 8, 1);
        table.extend(pool);
        let len = table.len() as u32;
        put_u32(&mut table, 4, len);
        table
    }

    #[test]
    fn a_pool_with_no_room_for_its_offsets_is_rejected() {
        // The count alone used to size the allocation before any read.
        let table = arsc_with_pool(u32::MAX, &[], true);
        let Err(err) = ResourceTable::parse(&table) else {
            panic!("a pool with no room for its offsets must be rejected");
        };
        assert!(err.to_string().contains("string pool"), "{err}");
    }

    #[test]
    fn a_utf16_length_is_bound_to_the_buffer() {
        // The length prefix claims 2 GiB of UTF-16 units in a 36 byte file.
        let mut body = vec![0u8; 4];
        put_u32(&mut body, 0, 0);
        body.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let table = arsc_with_pool(1, &body, false);
        let Err(err) = ResourceTable::parse(&table) else {
            panic!("a length the buffer cannot back must be rejected");
        };
        assert!(err.to_string().contains("resource string"), "{err}");
    }

    #[test]
    fn a_density_variant_does_not_displace_the_default() {
        // The default value comes first, an xhdpi variant with a different
        // value second. The variant is not a default, so it must not win.
        let table = ResourceTable::parse(&arsc_with_string_variants(&[("day", 0), ("dense", 320)]))
            .unwrap();
        assert_eq!(table.rewrite_plain("@string/app_name"), "day");
    }

    #[test]
    fn a_late_default_still_beats_an_earlier_variant() {
        let table = ResourceTable::parse(&arsc_with_string_variants(&[("dense", 320), ("day", 0)]))
            .unwrap();
        assert_eq!(table.rewrite_plain("@string/app_name"), "day");
    }

    #[test]
    fn a_numeric_string_resource_keeps_its_quotes() {
        for value in ["257429317626902", "#ff0000", "true"] {
            let table = ResourceTable::parse(&arsc_with_string_variants(&[(value, 0)])).unwrap();
            let code = table.rewrite_code("sget v0, Lcom/example/R$string;->app_name\n");
            assert!(code.contains(&format!("\"{value}\"")), "{value}: {code}");
        }
    }

    #[test]
    fn an_integer_resource_stays_a_literal() {
        let table = ResourceTable::parse(&arsc_with_single("integer", "count", 0x10, 42)).unwrap();
        let code = table.rewrite_code("sget v0, Lcom/example/R$integer;->count\n");
        assert!(code.contains("sget v0, 42"), "{code}");
    }

    #[test]
    fn a_reference_to_another_package_is_left_alone() {
        let table = ResourceTable::parse(&arsc_with_string_variants(&[("local", 0)])).unwrap();
        assert_eq!(table.rewrite_plain("@string/app_name"), "local");
        // `android` is not a package of this table, so the reference stays even
        // though a same named `string/app_name` exists here.
        assert_eq!(
            table.rewrite_plain("@android:string/app_name"),
            "@android:string/app_name"
        );
        assert_eq!(
            table.rewrite_plain("@com.example.app:string/app_name"),
            "local"
        );
    }
}
