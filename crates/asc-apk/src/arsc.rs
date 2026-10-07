//! On-demand `resources.arsc` lookup used to fill manifest and DEX references.
//!
//! Default configurations win over qualified ones, matching an unqualified
//! `@string/name`.

use std::collections::HashMap;

use crate::Result;

#[derive(Default)]
pub struct ResourceTable {
    by_id: HashMap<u32, Slot>,
    by_name: HashMap<(String, String), Slot>,
}

struct Slot {
    value: String,
    default_config: bool,
}

enum RefToken {
    Id(u32),
    Name { type_name: String, entry: String },
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
                        if let Some(value) = self.lookup(&token) {
                            out.push_str(&escape_code(value));
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
                    if let Some(value) = self.lookup(&RefToken::Name { type_name, entry }) {
                        drop_chars(&mut out, index - start);
                        out.push_str(&quote_code(value));
                        index += len;
                        continue;
                    }
                }
            }
            if let Some((len, id)) = parse_code_number(&chars, index) {
                if let Some(value) = self.by_id.get(&id).map(|slot| slot.value.as_str()) {
                    out.push_str(&quote_code(value));
                    index += len;
                    continue;
                }
            }
            if chars[index] == '@' || chars[index] == '?' {
                if let Some((len, token)) = parse_ref(&chars[index..]) {
                    if let Some(value) = self.lookup(&token) {
                        out.push_str(&quote_code(value));
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
                    if let Some(value) = self.lookup(&token) {
                        out.push_str(&render(value));
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

    fn lookup(&self, token: &RefToken) -> Option<&str> {
        let value = match token {
            RefToken::Id(id) => self.by_id.get(id).map(|slot| slot.value.as_str()),
            RefToken::Name { type_name, entry } => self
                .by_name
                .get(&(type_name.clone(), entry.clone()))
                .map(|slot| slot.value.as_str()),
        }?;
        if value.is_empty() {
            None
        } else {
            Some(value)
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
            let Some((key, value)) = read_entry(chunk, entry_at, global) else {
                continue;
            };
            let Some(entry_name) = key_pool.get(key as usize) else {
                continue;
            };
            let res_id = (package_id << 24) | (u32::from(id) << 16) | (entry_index as u32);
            self.insert(res_id, type_name, entry_name, value, default_config);
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
    ) {
        insert_slot(
            &mut self.by_id,
            id,
            Slot {
                value: value.clone(),
                default_config,
            },
        );
        insert_slot(
            &mut self.by_name,
            (type_name.to_string(), entry.to_string()),
            Slot {
                value,
                default_config,
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
            if let Some(slot) = self.by_id.get_mut(&id) {
                slot.value = resolved.clone();
            }
            let Some(keys) = name_keys.get(&current) else {
                continue;
            };
            for key in keys {
                if let Some(slot) = self.by_name.get_mut(key) {
                    slot.value = resolved.clone();
                }
            }
        }
    }
}

fn insert_slot<K: Eq + std::hash::Hash>(map: &mut HashMap<K, Slot>, key: K, slot: Slot) {
    match map.get(&key) {
        Some(old) if old.default_config && !slot.default_config => {}
        Some(old) if !old.default_config && !slot.default_config => {}
        _ => {
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

fn read_entry(chunk: &[u8], at: usize, global: &[String]) -> Option<(u32, String)> {
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
    render_value(data_type, data, global).map(|value| (key, value))
}

fn render_value(data_type: u8, data: u32, global: &[String]) -> Option<String> {
    match data_type {
        0x00 => None,
        0x01 => Some(format!("@0x{data:08x}")),
        0x03 => global.get(data as usize).cloned(),
        0x04 => Some(f32::from_bits(data).to_string()),
        0x10 => Some(i32::from_le_bytes(data.to_le_bytes()).to_string()),
        0x11 => Some(format!("{data:#x}")),
        0x12 => Some(if data == 0 {
            "false".to_string()
        } else {
            "true".to_string()
        }),
        0x1c..=0x1f => Some(format!("#{data:08x}")),
        _ => Some(format!("@0x{data:08x}")),
    }
}

fn is_default_config(chunk: &[u8]) -> bool {
    if chunk.len() < 28 {
        return true;
    }
    let size = u32_at(chunk, 20).unwrap_or(0) as usize;
    if size < 16 || 20 + size > chunk.len() {
        return true;
    }
    let mcc = u16_at(chunk, 24).unwrap_or(1);
    let mnc = u16_at(chunk, 26).unwrap_or(1);
    mcc == 0 && mnc == 0 && chunk[28] == 0 && chunk[30] == 0
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
    let (type_end, type_name) = read_ident(chars, index)?;
    index = type_end;
    if chars.get(index) == Some(&':') {
        index += 1;
        let (name_end, entry) = read_ident(chars, index)?;
        if chars.get(name_end) != Some(&'/') {
            return None;
        }
        let (entry_end, real_entry) = read_ident(chars, name_end + 1)?;
        return Some((
            entry_end,
            RefToken::Name {
                type_name: entry,
                entry: real_entry,
            },
        ));
    }
    if chars.get(index) != Some(&'/') {
        return None;
    }
    let (entry_end, entry) = read_ident(chars, index + 1)?;
    Some((entry_end, RefToken::Name { type_name, entry }))
}

fn has_at_ref(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte == b'@' || *byte == b'?')
}

fn read_ident(chars: &[char], start: usize) -> Option<(usize, String)> {
    let mut index = start;
    while chars
        .get(index)
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
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

fn quote_code(value: &str) -> String {
    if value == "true" || value == "false" || value.starts_with('#') || value.parse::<i64>().is_ok()
    {
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

    fn string_type_chunk() -> Vec<u8> {
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
        put_u32(&mut chunk, header_size, 0);
        put_u16(&mut chunk, entries_start, 8);
        put_u32(&mut chunk, entries_start + 4, 0);
        put_u16(&mut chunk, entries_start + 8, 8);
        chunk[entries_start + 11] = 0x03;
        put_u32(&mut chunk, entries_start + 12, 0);
        let len = chunk.len() as u32;
        put_u32(&mut chunk, 4, len);
        chunk
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
}
