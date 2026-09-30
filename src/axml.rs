//! Android binary XML decoder, enough to print AndroidManifest.xml.

use crate::bytes::{u16_at, u32_at};
use crate::Result;

pub fn manifest_xml(data: &[u8]) -> Result<String> {
    if data.len() < 8 {
        bail!("AndroidManifest.xml is not a valid binary XML");
    }
    let kind = u16_at(data, 0)?;
    if kind != 0x0003 {
        bail!("AndroidManifest.xml is not a valid binary XML");
    }
    let header_size = u16_at(data, 2)? as usize;
    let file_size = u32_at(data, 4)? as usize;
    let limit = file_size.min(data.len());
    let mut pos = header_size.max(8);
    let mut pool = Vec::new();
    let mut roots = Vec::new();
    let mut stack: Vec<Node> = Vec::new();
    let mut namespaces: Vec<(String, String)> = Vec::new();
    let mut pending_ns: Vec<(String, String)> = Vec::new();

    while pos + 8 <= limit {
        let kind = u16_at(data, pos)?;
        let size = u32_at(data, pos + 4)? as usize;
        if size < 8 || pos + size > limit {
            break;
        }
        let chunk = &data[pos..pos + size];
        match kind {
            0x0001 => pool = parse_string_pool(chunk)?,
            0x0100 => {
                let (prefix, uri) = read_namespace(chunk, &pool)?;
                namespaces.push((prefix.clone(), uri.clone()));
                pending_ns.push((prefix, uri));
            }
            0x0101 => {
                namespaces.pop();
            }
            0x0102 => {
                let mut node = read_element(chunk, &pool, &namespaces)?;
                for (prefix, uri) in pending_ns.drain(..) {
                    let key = if prefix.is_empty() {
                        "xmlns".to_string()
                    } else {
                        format!("xmlns:{prefix}")
                    };
                    node.attrs.insert(0, (key, xml_escape(&uri)));
                }
                stack.push(node);
            }
            0x0103 => {
                if let Some(node) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    } else {
                        roots.push(node);
                    }
                }
            }
            0x0104 => {
                if let Some(node) = stack.last_mut() {
                    if let Some(text) = read_cdata(chunk, &pool) {
                        if !node.text.is_empty() {
                            node.text.push(' ');
                        }
                        node.text.push_str(&text);
                    }
                }
            }
            _ => {}
        }
        pos += size;
    }
    while let Some(node) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(node);
        } else {
            roots.push(node);
        }
    }
    if roots.is_empty() {
        bail!("AndroidManifest.xml is not a valid binary XML");
    }
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    for root in &roots {
        write_node(&mut out, root, 0);
    }
    Ok(out)
}

#[derive(Default)]
struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
    text: String,
}

fn parse_string_pool(chunk: &[u8]) -> Result<Vec<String>> {
    if chunk.len() < 28 {
        bail!("truncated string pool");
    }
    let header_size = u16_at(chunk, 2)? as usize;
    let count = u32_at(chunk, 8)? as usize;
    let flags = u32_at(chunk, 16)?;
    let strings_start = u32_at(chunk, 20)? as usize;
    if header_size < 28 || header_size > chunk.len() {
        bail!("truncated string pool");
    }
    let index_bytes = count
        .checked_mul(4)
        .ok_or_else(|| crate::Error::new("string pool is too large"))?;
    if header_size
        .checked_add(index_bytes)
        .map(|end| end > chunk.len())
        .unwrap_or(true)
    {
        bail!("truncated string pool");
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

fn read_len8(data: &[u8], off: usize) -> Result<(usize, usize)> {
    let byte = *data
        .get(off)
        .ok_or_else(|| crate::Error::new("truncated string pool"))?;
    if byte & 0x80 != 0 {
        let next = *data
            .get(off + 1)
            .ok_or_else(|| crate::Error::new("truncated string pool"))?;
        Ok((((usize::from(byte & 0x7f)) << 8) | usize::from(next), 2))
    } else {
        Ok((usize::from(byte), 1))
    }
}

fn read_utf8(data: &[u8], mut off: usize) -> Result<String> {
    let (_, n) = read_len8(data, off)?;
    off += n;
    let (nbytes, n) = read_len8(data, off)?;
    off += n;
    let bytes = data
        .get(off..off + nbytes)
        .ok_or_else(|| crate::Error::new("truncated string pool"))?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
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
    let available = data.len().saturating_sub(start) / 2;
    if chars > available {
        bail!("truncated string pool");
    }
    let mut units = Vec::with_capacity(chars);
    for index in 0..chars {
        units.push(u16_at(data, start + index * 2)?);
    }
    Ok(String::from_utf16_lossy(&units))
}

fn pool_get(pool: &[String], idx: u32) -> String {
    if idx == 0xffff_ffff {
        return String::new();
    }
    pool.get(idx as usize).cloned().unwrap_or_default()
}

fn read_namespace(chunk: &[u8], pool: &[String]) -> Result<(String, String)> {
    if chunk.len() < 24 {
        bail!("truncated namespace");
    }
    Ok((
        pool_get(pool, u32_at(chunk, 16)?),
        pool_get(pool, u32_at(chunk, 20)?),
    ))
}

fn read_element(chunk: &[u8], pool: &[String], namespaces: &[(String, String)]) -> Result<Node> {
    if chunk.len() < 36 {
        bail!("truncated xml element");
    }
    let header_size = u16_at(chunk, 2)? as usize;
    let ns = u32_at(chunk, header_size)?;
    let name = u32_at(chunk, header_size + 4)?;
    let attribute_start = u16_at(chunk, header_size + 8)? as usize;
    let attribute_size = u16_at(chunk, header_size + 10)? as usize;
    let attribute_count = u16_at(chunk, header_size + 12)? as usize;
    let mut node = Node {
        name: qualified(pool, ns, name, namespaces),
        ..Node::default()
    };
    if attribute_size == 0 {
        return Ok(node);
    }
    let base = header_size + attribute_start;
    for index in 0..attribute_count {
        let at = base + index * attribute_size;
        if at + 20 > chunk.len() {
            break;
        }
        let ans = u32_at(chunk, at)?;
        let aname = u32_at(chunk, at + 4)?;
        let raw = u32_at(chunk, at + 8)?;
        let data_type = chunk[at + 15];
        let data = u32_at(chunk, at + 16)?;
        node.attrs.push((
            qualified(pool, ans, aname, namespaces),
            attr_value(pool, raw, data_type, data),
        ));
    }
    Ok(node)
}

fn read_cdata(chunk: &[u8], pool: &[String]) -> Option<String> {
    if chunk.len() < 28 {
        return None;
    }
    let raw = u32_at(chunk, 16).ok()?;
    if raw == 0xffff_ffff {
        return None;
    }
    Some(pool_get(pool, raw))
}

fn qualified(pool: &[String], ns: u32, name: u32, namespaces: &[(String, String)]) -> String {
    let local = pool_get(pool, name);
    if ns == 0xffff_ffff {
        return local;
    }
    let uri = pool_get(pool, ns);
    let prefix = namespaces
        .iter()
        .rev()
        .find(|(_, item)| item == &uri)
        .map(|(prefix, _)| prefix.as_str())
        .unwrap_or("ns");
    if prefix.is_empty() {
        local
    } else {
        format!("{prefix}:{local}")
    }
}

fn attr_value(pool: &[String], raw: u32, data_type: u8, data: u32) -> String {
    if raw != 0xffff_ffff {
        return xml_escape(&pool_get(pool, raw));
    }
    match data_type {
        0x00 => String::new(),
        0x03 => xml_escape(&pool_get(pool, data)),
        0x10 => format!("{}", data as i32),
        0x11 => format!("{data:#x}"),
        0x12 => {
            if data == 0 {
                "false".to_string()
            } else {
                "true".to_string()
            }
        }
        0x04 => format!("{}", f32::from_bits(data)),
        0x1c | 0x1d | 0x1e | 0x1f => format!("#{data:08x}"),
        _ => format!("@{data:#x}"),
    }
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

fn write_node(out: &mut String, node: &Node, indent: usize) {
    let pad = "    ".repeat(indent);
    out.push_str(&pad);
    out.push('<');
    out.push_str(&node.name);
    for (key, value) in &node.attrs {
        out.push(' ');
        out.push_str(key);
        out.push_str("=\"");
        out.push_str(value);
        out.push('"');
    }
    if node.children.is_empty() && node.text.is_empty() {
        out.push_str(" />\n");
        return;
    }
    out.push_str(">\n");
    if !node.text.is_empty() {
        out.push_str(&pad);
        out.push_str("    ");
        out.push_str(&xml_escape(&node.text));
        out.push('\n');
    }
    for child in &node.children {
        write_node(out, child, indent + 1);
    }
    out.push_str(&pad);
    out.push_str("</");
    out.push_str(&node.name);
    out.push_str(">\n");
}

#[cfg(test)]
mod tests {
    use super::manifest_xml;

    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn encode_utf8_string(value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(value.chars().count() as u8);
        out.push(value.len() as u8);
        out.extend_from_slice(value.as_bytes());
        out.push(0);
        out
    }

    fn encode_pool(strings: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for value in strings {
            offsets.push(data.len() as u32);
            data.extend(encode_utf8_string(value));
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let strings_start = 28 + strings.len() as u32 * 4;
        let mut buf = Vec::new();
        push_u16(&mut buf, 0x0001);
        push_u16(&mut buf, 28);
        push_u32(&mut buf, strings_start + data.len() as u32);
        push_u32(&mut buf, strings.len() as u32);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 1 << 8);
        push_u32(&mut buf, strings_start);
        push_u32(&mut buf, 0);
        for offset in offsets {
            push_u32(&mut buf, offset);
        }
        buf.extend_from_slice(&data);
        buf
    }

    fn namespace(kind: u16, prefix: u32, uri: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u16(&mut buf, kind);
        push_u16(&mut buf, 16);
        push_u32(&mut buf, 24);
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0xffff_ffff);
        push_u32(&mut buf, prefix);
        push_u32(&mut buf, uri);
        buf
    }

    fn element(ns: u32, name: u32, attrs: &[(u32, u32, u32)]) -> Vec<u8> {
        let size = 16 + 20 + attrs.len() * 20;
        let mut buf = Vec::new();
        push_u16(&mut buf, 0x0102);
        push_u16(&mut buf, 16);
        push_u32(&mut buf, size as u32);
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0xffff_ffff);
        push_u32(&mut buf, ns);
        push_u32(&mut buf, name);
        push_u16(&mut buf, 20);
        push_u16(&mut buf, 20);
        push_u16(&mut buf, attrs.len() as u16);
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 0);
        for (ans, aname, raw) in attrs {
            push_u32(&mut buf, *ans);
            push_u32(&mut buf, *aname);
            push_u32(&mut buf, *raw);
            push_u16(&mut buf, 8);
            buf.push(0);
            buf.push(0x03);
            push_u32(&mut buf, *raw);
        }
        buf
    }

    fn end_element(ns: u32, name: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u16(&mut buf, 0x0103);
        push_u16(&mut buf, 16);
        push_u32(&mut buf, 24);
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0xffff_ffff);
        push_u32(&mut buf, ns);
        push_u32(&mut buf, name);
        buf
    }

    #[test]
    fn decodes_a_small_manifest() {
        let strings = [
            "android",
            "http://schemas.android.com/apk/res/android",
            "manifest",
            "package",
            "com.example",
            "application",
            "label",
            "Demo",
        ];
        let mut body = encode_pool(&strings);
        body.extend(namespace(0x0100, 0, 1));
        body.extend(element(0xffff_ffff, 2, &[(0xffff_ffff, 3, 4)]));
        body.extend(element(0xffff_ffff, 5, &[(1, 6, 7)]));
        body.extend(end_element(0xffff_ffff, 5));
        body.extend(end_element(0xffff_ffff, 2));
        body.extend(namespace(0x0101, 0, 1));
        let mut file = Vec::new();
        push_u16(&mut file, 0x0003);
        push_u16(&mut file, 8);
        push_u32(&mut file, (8 + body.len()) as u32);
        file.extend(body);
        let xml = manifest_xml(&file).unwrap();
        assert!(xml.contains("package=\"com.example\""), "{xml}");
        assert!(xml.contains("android:label=\"Demo\""), "{xml}");
        assert!(
            xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""),
            "{xml}"
        );
    }

    fn cdata(raw: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u16(&mut buf, 0x0104);
        push_u16(&mut buf, 16);
        push_u32(&mut buf, 28);
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0xffff_ffff);
        push_u32(&mut buf, raw);
        buf
    }

    #[test]
    fn text_nodes_are_escaped_once() {
        let strings = ["manifest", "A&B"];
        let mut body = encode_pool(&strings);
        body.extend(element(0xffff_ffff, 0, &[]));
        body.extend(cdata(1));
        body.extend(end_element(0xffff_ffff, 0));
        let mut file = Vec::new();
        push_u16(&mut file, 0x0003);
        push_u16(&mut file, 8);
        push_u32(&mut file, (8 + body.len()) as u32);
        file.extend(body);
        let xml = manifest_xml(&file).unwrap();
        assert!(xml.contains("A&amp;B"), "{xml}");
        assert!(!xml.contains("A&amp;amp;B"), "{xml}");
    }
}
