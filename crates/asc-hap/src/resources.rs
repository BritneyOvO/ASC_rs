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

/// Reads a JSON string body. Bytes stay bytes, so a multi byte UTF-8 sequence
/// survives; escapes are decoded, including `\uXXXX` surrogate pairs.
fn read_json_string(bytes: &[u8], index: &mut usize) -> Option<String> {
    if bytes.get(*index) != Some(&b'"') {
        return None;
    }
    *index += 1;
    let mut out: Vec<u8> = Vec::new();
    while *index < bytes.len() {
        let byte = bytes[*index];
        *index += 1;
        match byte {
            b'"' => return Some(String::from_utf8_lossy(&out).into_owned()),
            b'\\' => {
                let escaped = *bytes.get(*index)?;
                *index += 1;
                match escaped {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'u' => read_json_escape(bytes, index, &mut out)?,
                    other => out.push(other),
                }
            }
            byte => out.push(byte),
        }
    }
    None
}

/// Decodes one `\uXXXX` escape, joining a surrogate pair when it is followed by
/// its low half.
fn read_json_escape(bytes: &[u8], index: &mut usize, out: &mut Vec<u8>) -> Option<()> {
    let unit = read_json_hex4(bytes, index)?;
    if !(0xd800..=0xdbff).contains(&unit) {
        push_json_char(out, u32::from(unit));
        return Some(());
    }
    let mut at = *index;
    let low = if bytes.get(at) == Some(&b'\\') && bytes.get(at + 1) == Some(&b'u') {
        at += 2;
        read_json_hex4(bytes, &mut at).filter(|low| (0xdc00..=0xdfff).contains(low))
    } else {
        None
    };
    match low {
        Some(low) => {
            *index = at;
            let code = 0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
            push_json_char(out, code);
        }
        // An unpaired surrogate has no UTF-8 form.
        None => push_json_char(out, 0xfffd),
    }
    Some(())
}

fn read_json_hex4(bytes: &[u8], index: &mut usize) -> Option<u16> {
    let hex = bytes.get(*index..*index + 4)?;
    let value = u16::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
    *index += 4;
    Some(value)
}

fn push_json_char(out: &mut Vec<u8>, code: u32) {
    let ch = char::from_u32(code).unwrap_or('\u{fffd}');
    let mut buf = [0u8; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
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

#[cfg(test)]
mod tests {
    use super::json_named_values;

    fn pairs(json: &str) -> Vec<(String, String)> {
        json_named_values(json)
    }

    #[test]
    fn a_non_ascii_value_survives_the_scan() {
        let found = pairs(r#"{"string":[{"name":"app_name","value":"中文测试值"}]}"#);
        assert_eq!(
            found,
            vec![("app_name".to_string(), "中文测试值".to_string())]
        );
    }

    #[test]
    fn a_surrogate_pair_becomes_one_code_point() {
        let found = pairs(r#"{"string":[{"name":"emoji","value":"\ud83d\ude00"}]}"#);
        assert_eq!(found, vec![("emoji".to_string(), "😀".to_string())]);
    }

    #[test]
    fn an_unpaired_surrogate_becomes_a_replacement_character() {
        let found = pairs(r#"{"string":[{"name":"broken","value":"\ud83d"}]}"#);
        assert_eq!(found, vec![("broken".to_string(), "\u{fffd}".to_string())]);
    }

    #[test]
    fn control_escapes_are_decoded() {
        let found = pairs(r#"{"string":[{"name":"tab","value":"a\tb\fc"}]}"#);
        assert_eq!(found, vec![("tab".to_string(), "a\tb\u{c}c".to_string())]);
    }
}
