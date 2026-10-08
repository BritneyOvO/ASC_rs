//! Android manifest decoder for binary XML and app-bundle protobuf XML.

#[macro_use]
mod error;

mod attrs;
mod bytes;

pub use error::{Error, Result};

use bytes::{u16_at, u32_at};

/// Nesting a real manifest never approaches this. It only exists so that a
/// crafted one cannot drive the recursive decoder and printer into a stack
/// overflow, which aborts the process instead of returning an error.
const MAX_DEPTH: usize = 256;

pub fn manifest_xml(data: &[u8]) -> Result<String> {
    if data.len() >= 8 && u16_at(data, 0)? == 0x0003 {
        return binary_manifest_xml(data);
    }
    proto_manifest_xml(data)
}

fn binary_manifest_xml(data: &[u8]) -> Result<String> {
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
    let mut resource_ids = Vec::new();
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
            0x0180 => resource_ids = parse_resource_map(chunk),
            0x0100 => {
                let (prefix, uri) = read_namespace(chunk, &pool)?;
                namespaces.push((prefix.clone(), uri.clone()));
                pending_ns.push((prefix, uri));
            }
            0x0101 => {
                namespaces.pop();
            }
            0x0102 => {
                if stack.len() >= MAX_DEPTH {
                    bail!("AndroidManifest.xml is nested too deeply");
                }
                let mut node = read_element(chunk, &pool, &namespaces, &resource_ids)?;
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

fn parse_resource_map(chunk: &[u8]) -> Vec<u32> {
    let mut ids = Vec::new();
    let mut at = 8usize;
    while at + 4 <= chunk.len() {
        ids.push(u32_at(chunk, at).unwrap_or(0));
        at += 4;
    }
    ids
}

fn attr_local_name(pool: &[String], name_idx: u32, resource_ids: &[u32]) -> String {
    let pool_name = pool_get(pool, name_idx);
    let Some(index) = usize::try_from(name_idx).ok() else {
        return pool_name;
    };
    let Some(&rid) = resource_ids.get(index) else {
        return pool_name;
    };
    if let Some(name) = attrs::android_attr_name(rid) {
        return name.to_string();
    }
    if pool_name.is_empty() {
        format!("attr_0x{rid:08x}")
    } else {
        pool_name
    }
}

fn read_element(
    chunk: &[u8],
    pool: &[String],
    namespaces: &[(String, String)],
    resource_ids: &[u32],
) -> Result<Node> {
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
        let local = attr_local_name(pool, aname, resource_ids);
        node.attrs.push((
            qualify_local(pool, ans, &local, namespaces),
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

fn qualify_local(
    pool: &[String],
    ns: u32,
    local: &str,
    namespaces: &[(String, String)],
) -> String {
    if ns == 0xffff_ffff {
        return local.to_string();
    }
    let uri = pool_get(pool, ns);
    let prefix = namespaces
        .iter()
        .rev()
        .find(|(_, item)| item == &uri)
        .map(|(prefix, _)| prefix.as_str())
        .unwrap_or("ns");
    if prefix.is_empty() {
        local.to_string()
    } else {
        format!("{prefix}:{local}")
    }
}

fn qualified(pool: &[String], ns: u32, name: u32, namespaces: &[(String, String)]) -> String {
    let local = pool_get(pool, name);
    qualify_local(pool, ns, &local, namespaces)
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

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

fn proto_manifest_xml(data: &[u8]) -> Result<String> {
    let node = parse_xml_node(data, 0)?;
    let Some(element) = node.element else {
        bail!("AndroidManifest.xml is not a valid protobuf XML");
    };
    let root = element_to_node(&element, &[])?;
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    write_node(&mut out, &root, 0);
    Ok(out)
}

fn element_to_node(element: &ProtoElement, inherited: &[(String, String)]) -> Result<Node> {
    element_to_node_at(element, inherited, 0)
}

fn element_to_node_at(
    element: &ProtoElement,
    inherited: &[(String, String)],
    depth: usize,
) -> Result<Node> {
    if depth >= MAX_DEPTH {
        bail!("AndroidManifest.xml is nested too deeply");
    }
    let mut prefixes = inherited.to_vec();
    let mut attrs = Vec::new();
    for (prefix, uri) in &element.namespaces {
        let key = if prefix.is_empty() {
            "xmlns".to_string()
        } else {
            format!("xmlns:{prefix}")
        };
        attrs.push((key, xml_escape(uri)));
        prefixes.push((prefix.clone(), uri.clone()));
    }
    for attr in &element.attributes {
        let key = qualify_name(&prefixes, &attr.namespace_uri, &attr.name);
        let raw = if attr.value.is_empty() {
            attr.compiled.clone()
        } else {
            attr.value.clone()
        };
        attrs.push((key, xml_escape(&raw)));
    }
    let mut node = Node {
        name: qualify_name(&prefixes, &element.namespace_uri, &element.name),
        attrs,
        children: Vec::new(),
        text: String::new(),
    };
    for child in &element.children {
        if let Some(text) = &child.text {
            if text.chars().any(|ch| !ch.is_whitespace()) {
                if !node.text.is_empty() {
                    node.text.push(' ');
                }
                node.text.push_str(text);
            }
        }
        if let Some(inner) = &child.element {
            node.children.push(element_to_node_at(inner, &prefixes, depth + 1)?);
        }
    }
    Ok(node)
}

fn qualify_name(prefixes: &[(String, String)], namespace_uri: &str, name: &str) -> String {
    if namespace_uri.is_empty() {
        return name.to_string();
    }
    let prefix = prefixes
        .iter()
        .rev()
        .find(|(_, uri)| uri == namespace_uri)
        .map(|(prefix, _)| prefix.as_str())
        .unwrap_or(if namespace_uri == ANDROID_NS {
            "android"
        } else {
            ""
        });
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}:{name}")
    }
}

struct ProtoNode {
    element: Option<ProtoElement>,
    text: Option<String>,
}

struct ProtoElement {
    namespaces: Vec<(String, String)>,
    namespace_uri: String,
    name: String,
    attributes: Vec<ProtoAttr>,
    children: Vec<ProtoNode>,
}

struct ProtoAttr {
    namespace_uri: String,
    name: String,
    value: String,
    compiled: String,
}

fn parse_xml_node(data: &[u8], depth: usize) -> Result<ProtoNode> {
    if depth >= MAX_DEPTH {
        bail!("AndroidManifest.xml is nested too deeply");
    }
    let mut node = ProtoNode {
        element: None,
        text: None,
    };
    let mut cursor = Cursor::new(data);
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 2) => node.element = Some(parse_xml_element(cursor.read_bytes()?, depth)?),
            (2, 2) => node.text = Some(cursor.read_string()?),
            (_, wire) => cursor.skip(wire)?,
        }
    }
    Ok(node)
}

fn parse_xml_element(data: &[u8], depth: usize) -> Result<ProtoElement> {
    let mut element = ProtoElement {
        namespaces: Vec::new(),
        namespace_uri: String::new(),
        name: String::new(),
        attributes: Vec::new(),
        children: Vec::new(),
    };
    let mut cursor = Cursor::new(data);
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 2) => element
                .namespaces
                .push(parse_namespace(cursor.read_bytes()?)?),
            (2, 2) => element.namespace_uri = cursor.read_string()?,
            (3, 2) => element.name = cursor.read_string()?,
            (4, 2) => element
                .attributes
                .push(parse_attribute(cursor.read_bytes()?)?),
            (5, 2) => element
                .children
                .push(parse_xml_node(cursor.read_bytes()?, depth + 1)?),
            (_, wire) => cursor.skip(wire)?,
        }
    }
    if element.name.is_empty() {
        bail!("AndroidManifest.xml is not a valid protobuf XML");
    }
    Ok(element)
}

fn parse_namespace(data: &[u8]) -> Result<(String, String)> {
    let mut prefix = String::new();
    let mut uri = String::new();
    let mut cursor = Cursor::new(data);
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 2) => prefix = cursor.read_string()?,
            (2, 2) => uri = cursor.read_string()?,
            (_, wire) => cursor.skip(wire)?,
        }
    }
    Ok((prefix, uri))
}

fn parse_attribute(data: &[u8]) -> Result<ProtoAttr> {
    let mut attr = ProtoAttr {
        namespace_uri: String::new(),
        name: String::new(),
        value: String::new(),
        compiled: String::new(),
    };
    let mut cursor = Cursor::new(data);
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 2) => attr.namespace_uri = cursor.read_string()?,
            (2, 2) => attr.name = cursor.read_string()?,
            (3, 2) => attr.value = cursor.read_string()?,
            (6, 2) => attr.compiled = format_item(cursor.read_bytes()?)?,
            (_, wire) => cursor.skip(wire)?,
        }
    }
    Ok(attr)
}

fn format_item(data: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(data);
    let mut rendered = String::new();
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 2) => rendered = format_reference(cursor.read_bytes()?)?,
            (2, 2) | (3, 2) => rendered = format_wrapped_string(cursor.read_bytes()?)?,
            (4, 2) => rendered = format_styled_string(cursor.read_bytes()?)?,
            (5, 2) => rendered = format_file_reference(cursor.read_bytes()?)?,
            (6, 2) => {
                cursor.skip(2)?;
            }
            (7, 2) => rendered = format_primitive(cursor.read_bytes()?)?,
            (_, wire) => cursor.skip(wire)?,
        }
    }
    Ok(rendered)
}

fn format_wrapped_string(data: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(data);
    let mut value = String::new();
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 2) => value = cursor.read_string()?,
            (_, wire) => cursor.skip(wire)?,
        }
    }
    Ok(value)
}

fn format_styled_string(data: &[u8]) -> Result<String> {
    format_wrapped_string(data)
}

fn format_file_reference(data: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(data);
    let mut path = String::new();
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 2) => path = cursor.read_string()?,
            (_, wire) => cursor.skip(wire)?,
        }
    }
    Ok(path)
}

fn format_reference(data: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(data);
    let mut kind = 0u64;
    let mut id = 0u64;
    let mut name = String::new();
    let mut private = false;
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        match (field, wire) {
            (1, 0) => kind = cursor.read_varint()?,
            (2, 0) => id = cursor.read_varint()?,
            (3, 2) => name = cursor.read_string()?,
            (4, 0) => private = cursor.read_varint()? != 0,
            (_, wire) => cursor.skip(wire)?,
        }
    }
    if name.starts_with('@') || name.starts_with('?') {
        return Ok(name);
    }
    let sigil = if kind == 1 { "?" } else { "@" };
    let star = if private { "*" } else { "" };
    if !name.is_empty() {
        return Ok(format!("{sigil}{star}{name}"));
    }
    if id != 0 {
        return Ok(format!("{sigil}{star}{id:#x}"));
    }
    Ok(String::new())
}

fn format_primitive(data: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(data);
    let mut rendered = String::new();
    while cursor.remaining() {
        let (field, wire) = cursor.read_key()?;
        rendered = match (field, wire) {
            (1, 2) | (2, 2) => {
                cursor.skip(2)?;
                String::new()
            }
            (3, 5) => f32::from_bits(cursor.read_fixed32()?).to_string(),
            (6, 0) => {
                let bits = u32::try_from(cursor.read_varint()? & 0xffff_ffff).unwrap_or(u32::MAX);
                i32::from_le_bytes(bits.to_le_bytes()).to_string()
            }
            (7, 0) => format!("{:#x}", cursor.read_varint()?),
            (8, 0) => {
                if cursor.read_varint()? == 0 {
                    "false".to_string()
                } else {
                    "true".to_string()
                }
            }
            (9, 0) => format!("#{:08x}", cursor.read_varint()?),
            (10, 0) => format!("#{:06x}", cursor.read_varint()? & 0x00ff_ffff),
            (11, 0) => format!("#{:04x}", cursor.read_varint()? & 0xffff),
            (12, 0) => format!("#{:03x}", cursor.read_varint()? & 0x0fff),
            (_, wire) => {
                cursor.skip(wire)?;
                rendered
            }
        };
    }
    Ok(rendered)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> bool {
        self.pos < self.data.len()
    }

    fn read_key(&mut self) -> Result<(u32, u32)> {
        let key = self.read_varint()?;
        let field = u32::try_from(key >> 3).unwrap_or(u32::MAX);
        Ok((field, (key & 7) as u32))
    }

    fn read_varint(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        for _ in 0..10 {
            let byte = *self
                .data
                .get(self.pos)
                .ok_or_else(|| crate::Error::new("truncated protobuf"))?;
            self.pos += 1;
            let piece = u64::from(byte & 0x7f);
            if shift == 63 && piece > 1 {
                bail!("protobuf varint is too long");
            }
            result |= piece << shift;
            if byte < 0x80 {
                return Ok(result);
            }
            shift += 7;
        }
        bail!("protobuf varint is too long");
    }

    fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.read_varint()?)
            .map_err(|_| crate::Error::new("protobuf length is too large"))?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| crate::Error::new("truncated protobuf"))?;
        if end > self.data.len() {
            bail!("truncated protobuf");
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| crate::Error::new("protobuf string is not utf-8"))
    }

    fn read_fixed32(&mut self) -> Result<u32> {
        let end = self
            .pos
            .checked_add(4)
            .ok_or_else(|| crate::Error::new("truncated protobuf"))?;
        if end > self.data.len() {
            bail!("truncated protobuf");
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(u32::from_le_bytes(buf))
    }

    fn skip(&mut self, wire: u32) -> Result<()> {
        match wire {
            0 => {
                self.read_varint()?;
            }
            1 => self.advance(8)?,
            2 => {
                self.read_bytes()?;
            }
            5 => self.advance(4)?,
            _ => bail!("unsupported protobuf wire type {wire}"),
        }
        Ok(())
    }

    fn advance(&mut self, len: usize) -> Result<()> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| crate::Error::new("truncated protobuf"))?;
        if end > self.data.len() {
            bail!("truncated protobuf");
        }
        self.pos = end;
        Ok(())
    }
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
    use super::{manifest_xml, MAX_DEPTH};

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

    #[test]
    fn an_obfuscated_framework_attribute_uses_its_resource_id() {
        assert_eq!(super::attrs::android_attr_name(0x0101_0003), Some("name"));
        let strings = ["manifest", "a"];
        let mut body = encode_pool(&strings);
        let mut map = Vec::new();
        push_u16(&mut map, 0x0180);
        push_u16(&mut map, 8);
        push_u32(&mut map, 16);
        push_u32(&mut map, 0);
        push_u32(&mut map, 0x0101_0003);
        body.extend(map);
        body.extend(element(0xffff_ffff, 0, &[(0xffff_ffff, 1, 1)]));
        body.extend(end_element(0xffff_ffff, 0));
        let mut file = Vec::new();
        push_u16(&mut file, 0x0003);
        push_u16(&mut file, 8);
        push_u32(&mut file, (8 + body.len()) as u32);
        file.extend(body);
        let xml = manifest_xml(&file).unwrap();
        assert!(xml.contains("name=\"a\""), "{xml}");
        assert!(!xml.contains("a=\"a\""), "{xml}");
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

    fn proto_bytes(field: u32, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let key = u64::from(field) << 3 | 2;
        write_varint(&mut out, key);
        write_varint(&mut out, value.len() as u64);
        out.extend_from_slice(value);
        out
    }

    fn proto_str(field: u32, value: &str) -> Vec<u8> {
        proto_bytes(field, value.as_bytes())
    }

    fn write_varint(out: &mut Vec<u8>, mut value: u64) {
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
    }

    #[test]
    fn decodes_protobuf_manifest() {
        let mut namespace = proto_str(1, "android");
        namespace.extend(proto_str(2, "http://schemas.android.com/apk/res/android"));
        let mut package = proto_str(2, "package");
        package.extend(proto_str(3, "com.example"));
        let reference = proto_str(3, "mipmap/ic_launcher");
        let icon_item = proto_bytes(1, &reference);
        let mut icon = proto_str(1, "http://schemas.android.com/apk/res/android");
        icon.extend(proto_str(2, "icon"));
        icon.extend(proto_bytes(6, &icon_item));
        let mut boolean = Vec::new();
        write_varint(&mut boolean, 8 << 3);
        write_varint(&mut boolean, 1);
        let primitive = proto_bytes(7, &boolean);
        let mut backup = proto_str(1, "http://schemas.android.com/apk/res/android");
        backup.extend(proto_str(2, "allowBackup"));
        backup.extend(proto_bytes(6, &primitive));
        let mut application = proto_str(3, "application");
        application.extend(proto_bytes(4, &icon));
        application.extend(proto_bytes(4, &backup));
        let application = proto_bytes(1, &application);
        let mut manifest = proto_bytes(1, &namespace);
        manifest.extend(proto_str(3, "manifest"));
        manifest.extend(proto_bytes(4, &package));
        manifest.extend(proto_bytes(5, &application));
        let root = proto_bytes(1, &manifest);
        let xml = manifest_xml(&root).unwrap();
        assert!(
            xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""),
            "{xml}"
        );
        assert!(xml.contains("package=\"com.example\""), "{xml}");
        assert!(
            xml.contains("android:icon=\"@mipmap/ic_launcher\""),
            "{xml}"
        );
        assert!(xml.contains("android:allowBackup=\"true\""), "{xml}");
        assert!(xml.contains("<application"), "{xml}");
    }

    #[test]
    fn deep_binary_nesting_is_rejected() {
        let strings = ["manifest"];
        let mut body = encode_pool(&strings);
        let depth = MAX_DEPTH + 4;
        for _ in 0..depth {
            body.extend(element(0xffff_ffff, 0, &[]));
        }
        for _ in 0..depth {
            body.extend(end_element(0xffff_ffff, 0));
        }
        let mut file = Vec::new();
        push_u16(&mut file, 0x0003);
        push_u16(&mut file, 8);
        push_u32(&mut file, (8 + body.len()) as u32);
        file.extend(body);
        let err = manifest_xml(&file).unwrap_err();
        assert!(err.to_string().contains("nested too deeply"), "{err}");
    }

    #[test]
    fn deep_protobuf_nesting_is_rejected() {
        let mut element = proto_str(3, "a");
        for _ in 0..MAX_DEPTH + 4 {
            let node = proto_bytes(1, &element);
            let mut parent = proto_str(3, "a");
            parent.extend(proto_bytes(5, &node));
            element = parent;
        }
        let root = proto_bytes(1, &element);
        let err = manifest_xml(&root).unwrap_err();
        assert!(err.to_string().contains("nested too deeply"), "{err}");
    }
}
