//! Harmony `resources/` lookup. `$string:`, `$media:` and `$profile:` references
//! are replaced in `module.json`, `pack.info`, class text, and string literals.

use std::collections::HashMap;

use crate::hap::{inflate, ZipEntry};
use memmap2::Mmap;

struct Slot {
    value: String,
    base: bool,
}

#[derive(Default)]
pub struct HapResources {
    values: HashMap<(String, String), Slot>,
}

impl HapResources {
    pub fn index(map: &Mmap, entries: &[ZipEntry]) -> Self {
        let mut resources = Self::default();
        for entry in entries {
            let Some((kind, name, base)) = resource_key(&entry.name) else {
                continue;
            };
            let value = if kind == "profile" && entry.uncomp_size <= 8192 {
                inflate(map, entry)
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_else(|_| entry.name.clone())
            } else if kind == "media" || kind == "profile" {
                entry.name.clone()
            } else {
                match inflate(map, entry) {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        for (item_name, item_value) in json_named_values(&text) {
                            resources.insert(&kind, &item_name, item_value, base);
                        }
                        continue;
                    }
                    Err(err) => {
                        eprintln!("warning: {}: {err}", entry.name);
                        continue;
                    }
                }
            };
            resources.insert(&kind, &name, value, base);
        }
        resources
    }

    pub fn annotate<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        if self.values.is_empty() || !text.as_bytes().contains(&b'$') {
            return std::borrow::Cow::Borrowed(text);
        }
        std::borrow::Cow::Owned(self.annotate_slow(text))
    }

    fn annotate_slow(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut index = 0;
        while index < chars.len() {
            if chars[index] == '$' {
                if let Some((len, kind, name)) = parse_dollar(&chars[index..]) {
                    if let Some(value) = self
                        .values
                        .get(&(kind, name))
                        .map(|slot| slot.value.as_str())
                    {
                        out.push_str(&json_escape(value));
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

    fn insert(&mut self, kind: &str, name: &str, value: String, base: bool) {
        let key = (kind.to_string(), name.to_string());
        match self.values.get(&key) {
            Some(old) if old.base && !base => {}
            Some(old) if !old.base && !base => {}
            _ => {
                self.values.insert(key, Slot { value, base });
            }
        }
    }
}

fn resource_key(path: &str) -> Option<(String, String, bool)> {
    let rest = path.strip_prefix("resources/")?;
    let mut parts = rest.split('/');
    let config = parts.next()?;
    let group = parts.next()?;
    let file = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let base = config == "base" || config.starts_with("base-");
    let stem = file.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(file);
    match group {
        "media" => Some(("media".to_string(), stem.to_string(), base)),
        "profile" => Some(("profile".to_string(), stem.to_string(), base)),
        "element" => Some((stem.to_string(), String::new(), base)),
        _ => None,
    }
}

fn json_named_values(text: &str) -> Vec<(String, String)> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut pending_name = None;
    let mut pending_value = None;
    let mut pairs = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                pending_name = None;
                pending_value = None;
                index += 1;
            }
            b'}' => {
                if let (Some(name), Some(value)) = (pending_name.take(), pending_value.take()) {
                    pairs.push((name, value));
                }
                index += 1;
            }
            b'"' => {
                let Some(key) = read_json_string(bytes, &mut index) else {
                    index += 1;
                    continue;
                };
                skip_ws(bytes, &mut index);
                if bytes.get(index) != Some(&b':') {
                    continue;
                }
                index += 1;
                skip_ws(bytes, &mut index);
                if key == "name" {
                    pending_name = read_json_atom(bytes, &mut index);
                } else if key == "value" {
                    pending_value = read_json_atom(bytes, &mut index);
                } else {
                    let _ = read_json_atom(bytes, &mut index);
                }
            }
            _ => index += 1,
        }
    }
    pairs
}

fn read_json_atom(bytes: &[u8], index: &mut usize) -> Option<String> {
    skip_ws(bytes, index);
    match bytes.get(*index)? {
        b'"' => read_json_string(bytes, index),
        b't' if bytes.get(*index..*index + 4) == Some(b"true") => {
            *index += 4;
            Some("true".to_string())
        }
        b'f' if bytes.get(*index..*index + 5) == Some(b"false") => {
            *index += 5;
            Some("false".to_string())
        }
        b'-' | b'0'..=b'9' => {
            let start = *index;
            if bytes[*index] == b'-' {
                *index += 1;
            }
            while bytes
                .get(*index)
                .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'.')
            {
                *index += 1;
            }
            Some(String::from_utf8_lossy(&bytes[start..*index]).into_owned())
        }
        _ => None,
    }
}

fn read_json_string(bytes: &[u8], index: &mut usize) -> Option<String> {
    if bytes.get(*index) != Some(&b'"') {
        return None;
    }
    *index += 1;
    let mut out = String::new();
    while *index < bytes.len() {
        let byte = bytes[*index];
        *index += 1;
        match byte {
            b'"' => return Some(out),
            b'\\' => {
                let escaped = *bytes.get(*index)?;
                *index += 1;
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'u' => {
                        let hex = bytes.get(*index..*index + 4)?;
                        let code = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
                        out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        *index += 4;
                    }
                    other => out.push(other as char),
                }
            }
            byte => out.push(byte as char),
        }
    }
    None
}

fn skip_ws(bytes: &[u8], index: &mut usize) {
    while bytes
        .get(*index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        *index += 1;
    }
}

fn parse_dollar(chars: &[char]) -> Option<(usize, String, String)> {
    if chars.first() != Some(&'$') {
        return None;
    }
    let (type_end, kind) = read_ident(chars, 1)?;
    if chars.get(type_end) != Some(&':') {
        return None;
    }
    let (name_end, name) = read_ident(chars, type_end + 1)?;
    Some((name_end, kind, name))
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

fn json_escape(value: &str) -> String {
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
