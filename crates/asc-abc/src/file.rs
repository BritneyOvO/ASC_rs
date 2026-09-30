//! Panda ABC reader. Class-index offsets stay in the file; names are decoded per query.
//!
//! The class index is sorted by UTF-16 length, then by MUTF-8 bytes. A name lookup
//! uses that order so it can binary-search without building a side table.

use regex::bytes::RegexBuilder;

use crate::Result;

const HEADER_SIZE: usize = 60;
const REGION_SIZE: usize = 40;

type LiteralResolve<'a> = dyn Fn(&[u8]) -> Option<String> + 'a;

#[derive(Clone, Debug)]
struct Header {
    foreign_off: u32,
    foreign_size: u32,
    num_classes: u32,
    class_idx_off: u32,
    num_literalarrays: u32,
    literalarray_idx_off: u32,
    num_indexes: u32,
    index_section_off: u32,
}

pub struct Abc<'a> {
    data: &'a [u8],
    header: Header,
}

struct Name<'a> {
    utf16_len: u32,
    bytes: &'a [u8],
    encoded_len: usize,
}

struct Region {
    class_idx_size: u32,
    class_idx_off: u32,
    proto_idx_size: u32,
    proto_idx_off: u32,
}

impl<'a> Abc<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE || &data[..8] != b"PANDA\0\0\0" {
            bail!("invalid ABC header");
        }
        let header = Header {
            foreign_off: u32_at(data, 20)?,
            foreign_size: u32_at(data, 24)?,
            num_classes: u32_at(data, 28)?,
            class_idx_off: u32_at(data, 32)?,
            num_literalarrays: u32_at(data, 44)?,
            literalarray_idx_off: u32_at(data, 48)?,
            num_indexes: u32_at(data, 52)?,
            index_section_off: u32_at(data, 56)?,
        };
        let file_size = u32_at(data, 16)? as usize;
        if file_size < HEADER_SIZE || file_size > data.len() {
            bail!("ABC file_size {file_size} does not match the buffer");
        }
        check_index(
            data,
            header.class_idx_off,
            header.num_classes,
            "class index",
        )?;
        Ok(Self {
            data: &data[..file_size],
            header,
        })
    }

    pub fn class_names(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for index in 0..self.header.num_classes {
            let name = self.class_name(index)?;
            if let Some(prefix) = prefix {
                if !name.bytes.starts_with(prefix.as_bytes()) {
                    continue;
                }
            }
            names.push(String::from_utf8_lossy(name.bytes).into_owned());
        }
        Ok(names)
    }

    pub fn class_text(&self, query: &str) -> Result<String> {
        self.class_text_optional(query)?
            .ok_or_else(|| crate::Error::new(format!("Class {query} not found in ABC.")))
    }

    pub fn class_text_optional(&self, query: &str) -> Result<Option<String>> {
        let Some(off) = self.find_class_off(query)? else {
            return Ok(None);
        };
        Ok(Some(self.render_class(off)?))
    }

    pub fn find_types(&self, file: &str, pattern: &str) -> Result<Vec<String>> {
        let regex = byte_regex(pattern, false)?;
        let mut lines = Vec::new();
        for index in 0..self.header.num_classes {
            let name = self.class_name(index)?;
            if regex.is_match(name.bytes) {
                let text = String::from_utf8_lossy(name.bytes);
                lines.push(format!("{file} | {text}"));
            }
        }
        Ok(lines)
    }

    pub fn find_strings(&self, file: &str, pattern: &str) -> Result<Vec<String>> {
        self.collect_strings(file, pattern, None)
    }

    /// String hits are tested against the raw literal and against `resolve(raw)`.
    ///
    /// Return `None` when the literal is unchanged. HAP uses that for literals
    /// that contain no `$`, so a miss does not allocate a string.
    pub fn find_strings_resolved(
        &self,
        file: &str,
        pattern: &str,
        resolve: &LiteralResolve<'_>,
    ) -> Result<Vec<String>> {
        self.collect_strings(file, pattern, Some(resolve))
    }

    fn collect_strings(
        &self,
        file: &str,
        pattern: &str,
        resolve: Option<&LiteralResolve<'_>>,
    ) -> Result<Vec<String>> {
        let regex = byte_regex(pattern, false)?;
        let mut lines = Vec::new();
        let count = self.literal_count()?;
        for index in 0..count {
            let array_off = self.literal_array_off(index)? as usize;
            for text in literal_strings(self.data, array_off)? {
                let raw_hit = regex.is_match(text.bytes);
                if resolve.is_none() && !raw_hit {
                    continue;
                }
                let resolved = resolve.and_then(|resolve| resolve(text.bytes));
                let resolved_hit = resolved
                    .as_ref()
                    .is_some_and(|value| regex.is_match(value.as_bytes()));
                if !raw_hit && !resolved_hit {
                    continue;
                }
                let printed =
                    resolved.unwrap_or_else(|| String::from_utf8_lossy(text.bytes).into_owned());
                lines.push(format!("{file} | literal#{index} | matched=({printed})"));
            }
        }
        Ok(lines)
    }

    pub fn find_members(
        &self,
        file: &str,
        methods: bool,
        pattern: &str,
        class_name: Option<&str>,
    ) -> Result<Vec<String>> {
        let regex = byte_regex(pattern, true)?;
        let mut lines = Vec::new();
        let indexes: Vec<u32> = if let Some(class_name) = class_name {
            match self.find_class_off(class_name)? {
                Some(off) => vec![off],
                None => return Ok(lines),
            }
        } else {
            (0..self.header.num_classes)
                .map(|index| self.class_off(index))
                .collect::<Result<Vec<_>>>()?
        };
        for off in indexes {
            if self.is_foreign(off) {
                continue;
            }
            let class_name = self.string_at(off as usize)?;
            let rendered = String::from_utf8_lossy(class_name.bytes);
            for member in self.member_names(off, methods)? {
                if regex.is_match(member.as_bytes()) {
                    lines.push(format!("{file} | {rendered}->{member}"));
                }
            }
        }
        Ok(lines)
    }

    fn find_class_off(&self, query: &str) -> Result<Option<u32>> {
        for candidate in descriptor_candidates(query) {
            if let Some(off) = self.find_descriptor(&candidate)? {
                return Ok(Some(off));
            }
        }
        Ok(None)
    }

    fn find_descriptor(&self, query: &str) -> Result<Option<u32>> {
        if self.header.num_classes == 0 {
            return Ok(None);
        }
        let query_len = u32::try_from(query.encode_utf16().count()).unwrap_or(u32::MAX);
        let query_bytes = query.as_bytes();
        let mut left: i64 = 0;
        let mut right = self.header.num_classes as i64 - 1;
        while left <= right {
            let mid = ((left + right) >> 1) as u32;
            let name = self.class_name(mid)?;
            let order = name
                .utf16_len
                .cmp(&query_len)
                .then_with(|| name.bytes.cmp(query_bytes));
            match order {
                std::cmp::Ordering::Equal => return Ok(Some(self.class_off(mid)?)),
                std::cmp::Ordering::Less => left = mid as i64 + 1,
                std::cmp::Ordering::Greater => right = mid as i64 - 1,
            }
        }
        Ok(None)
    }

    fn class_off(&self, index: u32) -> Result<u32> {
        u32_at(
            self.data,
            self.header.class_idx_off as usize + index as usize * 4,
        )
    }

    fn class_name(&self, index: u32) -> Result<Name<'a>> {
        self.string_at(self.class_off(index)? as usize)
    }

    fn is_foreign(&self, off: u32) -> bool {
        let begin = self.header.foreign_off;
        let end = begin.saturating_add(self.header.foreign_size);
        off >= begin && off < end
    }

    fn render_class(&self, off: u32) -> Result<String> {
        let name = self.string_at(off as usize)?;
        let shown = String::from_utf8_lossy(name.bytes);
        if self.is_foreign(off) {
            return Ok(format!("class {shown}; external\n"));
        }
        let mut pos = off as usize + name.encoded_len;
        let super_off = u32_at(self.data, pos)?;
        pos += 4;
        let access = read_uleb(self.data, &mut pos)?;
        let num_fields = read_uleb(self.data, &mut pos)?;
        let num_methods = read_uleb(self.data, &mut pos)?;
        pos = skip_tags(self.data, pos, TagKind::Class)?;
        let mut out = format!("{}class {shown}", access_prefix(access));
        if super_off != 0 {
            let super_name = self.string_at(super_off as usize)?;
            out.push_str(" extends ");
            out.push_str(&String::from_utf8_lossy(super_name.bytes));
        }
        out.push_str(" {\n");
        for _ in 0..num_fields {
            let (field, next) = self.read_field(pos)?;
            out.push_str(&field);
            pos = next;
        }
        for _ in 0..num_methods {
            let (method, next) = self.read_method(pos)?;
            out.push_str(&method);
            pos = next;
        }
        out.push_str("}\n");
        Ok(out)
    }

    fn read_field(&self, pos: usize) -> Result<(String, usize)> {
        let class_idx = u16_at(self.data, pos)?;
        let type_idx = u16_at(self.data, pos + 2)?;
        let name_off = u32_at(self.data, pos + 4)? as usize;
        let mut next = pos + 8;
        let access = read_uleb(self.data, &mut next)?;
        next = skip_tags(self.data, next, TagKind::Field)?;
        let region = self.region_covering(pos)?;
        let ty = self.field_type(&region, type_idx)?;
        let name = self.string_at(name_off)?;
        let _ = class_idx;
        Ok((
            format!(
                "    {}{ty} {};\n",
                access_prefix(access),
                String::from_utf8_lossy(name.bytes)
            ),
            next,
        ))
    }

    fn read_method(&self, pos: usize) -> Result<(String, usize)> {
        let class_idx = u16_at(self.data, pos)?;
        let proto_idx = u16_at(self.data, pos + 2)?;
        let name_off = u32_at(self.data, pos + 4)? as usize;
        let mut next = pos + 8;
        let access = read_uleb(self.data, &mut next)?;
        next = skip_tags(self.data, next, TagKind::Method)?;
        let region = self.region_covering(pos)?;
        let proto_off = region_slot(
            self.data,
            region.proto_idx_off,
            region.proto_idx_size,
            proto_idx,
            "proto",
        )?;
        let proto_region = self.region_covering(proto_off as usize)?;
        let (ret, params) = self.proto_types(proto_off as usize, &proto_region)?;
        let name = self.string_at(name_off)?;
        let _ = class_idx;
        Ok((
            format!(
                "    {}{ret} {}({});\n",
                access_prefix(access),
                String::from_utf8_lossy(name.bytes),
                params.join(", ")
            ),
            next,
        ))
    }

    fn field_type(&self, region: &Region, index: u16) -> Result<String> {
        let raw = region_slot(
            self.data,
            region.class_idx_off,
            region.class_idx_size,
            index,
            "type",
        )?;
        if (raw as usize) < HEADER_SIZE {
            return Ok(primitive_name(raw).to_string());
        }
        let name = self.string_at(raw as usize)?;
        Ok(String::from_utf8_lossy(name.bytes).into_owned())
    }

    fn proto_types(&self, proto_off: usize, region: &Region) -> Result<(String, Vec<String>)> {
        let mut pos = proto_off;
        let mut nibbles = Vec::new();
        loop {
            let word = u16_at(self.data, pos)?;
            pos += 2;
            let mut ended = false;
            for shift in [0, 4, 8, 12] {
                let nibble = (word >> shift) & 0x0f;
                if nibble == 0 {
                    ended = true;
                    break;
                }
                nibbles.push(nibble);
            }
            if ended {
                break;
            }
        }
        if nibbles.is_empty() {
            bail!("ABC proto at {proto_off:#x} has no return type");
        }
        let mut refs = Vec::new();
        for nibble in &nibbles {
            if *nibble == 0x0d {
                let index = u16_at(self.data, pos)?;
                pos += 2;
                refs.push(self.field_type(region, index)?);
            }
        }
        let mut ref_iter = refs.into_iter();
        let mut render = |nibble: u16| -> String {
            if nibble == 0x0d {
                ref_iter.next().unwrap_or_else(|| "ref".to_string())
            } else {
                shorty_name(nibble).to_string()
            }
        };
        let ret = render(nibbles[0]);
        let params = nibbles[1..].iter().copied().map(render).collect();
        Ok((ret, params))
    }

    fn region_covering(&self, off: usize) -> Result<Region> {
        let base = self.header.index_section_off as usize;
        for index in 0..self.header.num_indexes {
            let at = base + index as usize * REGION_SIZE;
            let start = u32_at(self.data, at)?;
            let end = u32_at(self.data, at + 4)?;
            if (off as u32) >= start && (off as u32) < end {
                return Ok(Region {
                    class_idx_size: u32_at(self.data, at + 8)?,
                    class_idx_off: u32_at(self.data, at + 12)?,
                    proto_idx_size: u32_at(self.data, at + 32)?,
                    proto_idx_off: u32_at(self.data, at + 36)?,
                });
            }
        }
        bail!("ABC index region not found for {off:#x}");
    }

    fn member_names(&self, class_off: u32, methods: bool) -> Result<Vec<String>> {
        let name = self.string_at(class_off as usize)?;
        let mut pos = class_off as usize + name.encoded_len + 4;
        let _access = read_uleb(self.data, &mut pos)?;
        let num_fields = read_uleb(self.data, &mut pos)?;
        let num_methods = read_uleb(self.data, &mut pos)?;
        pos = skip_tags(self.data, pos, TagKind::Class)?;
        let mut found = Vec::new();
        for _ in 0..num_fields {
            let name_off = u32_at(self.data, pos + 4)? as usize;
            pos += 8;
            let _access = read_uleb(self.data, &mut pos)?;
            pos = skip_tags(self.data, pos, TagKind::Field)?;
            if !methods {
                let member = self.string_at(name_off)?;
                found.push(String::from_utf8_lossy(member.bytes).into_owned());
            }
        }
        for _ in 0..num_methods {
            let name_off = u32_at(self.data, pos + 4)? as usize;
            pos += 8;
            let _access = read_uleb(self.data, &mut pos)?;
            pos = skip_tags(self.data, pos, TagKind::Method)?;
            if methods {
                let member = self.string_at(name_off)?;
                found.push(String::from_utf8_lossy(member.bytes).into_owned());
            }
        }
        Ok(found)
    }

    fn literal_count(&self) -> Result<u32> {
        let count = self.header.num_literalarrays;
        let off = self.header.literalarray_idx_off;
        if count == 0 || count == u32::MAX || off == 0 || off == u32::MAX {
            return Ok(0);
        }
        match check_index(self.data, off, count, "literal array index") {
            Ok(()) => Ok(count),
            Err(_) => Ok(0),
        }
    }

    fn literal_array_off(&self, index: u32) -> Result<u32> {
        u32_at(
            self.data,
            self.header.literalarray_idx_off as usize + index as usize * 4,
        )
    }

    fn string_at(&self, off: usize) -> Result<Name<'a>> {
        let (tagged, len) = read_uleb_at(self.data, off)?;
        let start = off + len;
        let bytes = read_until_nul(self.data, start)?;
        Ok(Name {
            utf16_len: tagged >> 1,
            bytes,
            encoded_len: start + bytes.len() + 1 - off,
        })
    }
}

#[derive(Clone, Copy)]
enum TagKind {
    Class,
    Field,
    Method,
}

fn literal_strings(data: &[u8], off: usize) -> Result<Vec<Name<'_>>> {
    let count = u32_at(data, off)? as usize;
    let mut pos = off + 4;
    let mut out = Vec::new();
    let mut index = 0;
    while index + 1 < count {
        let tag = *data
            .get(pos)
            .ok_or_else(|| crate::Error::new("truncated ABC literal"))?;
        pos += 1;
        match tag {
            0x02 | 0x03 | 0x17 => pos += 4,
            0x04 => pos += 8,
            0x01 | 0x08 | 0x19 | 0xff => pos += 1,
            0x09 => pos += 2,
            0x05 | 0x06 | 0x07 | 0x16 | 0x18 | 0x1a | 0x1b | 0x1c => {
                let str_off = u32_at(data, pos)? as usize;
                pos += 4;
                if tag == 0x05 {
                    let (tagged, len) = read_uleb_at(data, str_off)?;
                    let start = str_off + len;
                    let bytes = read_until_nul(data, start)?;
                    out.push(Name {
                        utf16_len: tagged >> 1,
                        bytes,
                        encoded_len: 0,
                    });
                }
            }
            0x15 => {
                let n = u32_at(data, pos)? as usize;
                pos += 4;
                for _ in 0..n {
                    let str_off = u32_at(data, pos)? as usize;
                    pos += 4;
                    let (tagged, len) = read_uleb_at(data, str_off)?;
                    let start = str_off + len;
                    let bytes = read_until_nul(data, start)?;
                    out.push(Name {
                        utf16_len: tagged >> 1,
                        bytes,
                        encoded_len: 0,
                    });
                }
                break;
            }
            _ => break,
        }
        index += 2;
    }
    Ok(out)
}

fn skip_tags(data: &[u8], mut pos: usize, kind: TagKind) -> Result<usize> {
    loop {
        let tag = *data
            .get(pos)
            .ok_or_else(|| crate::Error::new("truncated ABC tagged value"))?;
        pos += 1;
        if tag == 0 {
            return Ok(pos);
        }
        pos = match (kind, tag) {
            (TagKind::Class, 0x01) => {
                let count = read_uleb(data, &mut pos)? as usize;
                pos + count * 2
            }
            (TagKind::Class, 0x02) | (TagKind::Method, 0x02) => pos + 1,
            (TagKind::Field, 0x01) => skip_sleb(data, pos)?,
            (TagKind::Class, 0x03..=0x07)
            | (TagKind::Field, 0x02..=0x06)
            | (TagKind::Method, 0x01 | 0x03..=0x09) => pos + 4,
            _ => bail!("unknown ABC tag {tag:#x}"),
        };
    }
}

fn region_slot(data: &[u8], off: u32, size: u32, index: u16, what: &str) -> Result<u32> {
    if u32::from(index) >= size {
        bail!("ABC {what} index {index} is out of range");
    }
    u32_at(data, off as usize + usize::from(index) * 4)
}

fn access_prefix(flags: u32) -> String {
    let mut out = String::new();
    for (bit, name) in [
        (0x0001, "public "),
        (0x0002, "private "),
        (0x0004, "protected "),
        (0x0008, "static "),
        (0x0010, "final "),
        (0x0200, "interface "),
        (0x0400, "abstract "),
    ] {
        if flags & bit != 0 {
            out.push_str(name);
        }
    }
    out
}

fn primitive_name(code: u32) -> &'static str {
    match code & 0x0f {
        0x00 => "u1",
        0x01 => "i8",
        0x02 => "u8",
        0x03 => "i16",
        0x04 => "u16",
        0x05 => "i32",
        0x06 => "u32",
        0x07 => "f32",
        0x08 => "f64",
        0x09 => "i64",
        0x0a => "u64",
        _ => "any",
    }
}

fn shorty_name(code: u16) -> &'static str {
    match code {
        0x01 => "void",
        0x02 => "u1",
        0x03 => "i8",
        0x04 => "u8",
        0x05 => "i16",
        0x06 => "u16",
        0x07 => "i32",
        0x08 => "u32",
        0x09 => "f32",
        0x0a => "f64",
        0x0b => "i64",
        0x0c => "u64",
        0x0e => "any",
        _ => "unknown",
    }
}

fn descriptor_candidates(query: &str) -> Vec<String> {
    let mut out = vec![query.to_string()];
    let normalized = if query.starts_with('L') && query.ends_with(';') {
        query.replace('.', "/")
    } else {
        let body = query.replace('.', "/");
        format!("L{body};")
    };
    if normalized != query {
        out.push(normalized);
    }
    out
}

fn byte_regex(pattern: &str, anchored: bool) -> Result<regex::bytes::Regex> {
    let pattern = if anchored {
        format!(r"\A(?:{pattern})\z")
    } else {
        pattern.to_string()
    };
    Ok(RegexBuilder::new(&pattern)
        .unicode(false)
        .dot_matches_new_line(true)
        .build()?)
}

fn check_index(data: &[u8], off: u32, count: u32, what: &str) -> Result<()> {
    let bytes = (count as usize)
        .checked_mul(4)
        .ok_or_else(|| crate::Error::new(format!("ABC {what} is too large")))?;
    let end = (off as usize)
        .checked_add(bytes)
        .ok_or_else(|| crate::Error::new(format!("ABC {what} is too large")))?;
    if end > data.len() {
        bail!("ABC {what} is out of range");
    }
    Ok(())
}

fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data
        .get(off..off + 2)
        .ok_or_else(|| crate::Error::new(format!("truncated ABC read at {off:#x}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data
        .get(off..off + 4)
        .ok_or_else(|| crate::Error::new(format!("truncated ABC read at {off:#x}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_uleb_at(data: &[u8], off: usize) -> Result<(u32, usize)> {
    let mut pos = off;
    let value = read_uleb(data, &mut pos)?;
    Ok((value, pos - off))
}

fn read_uleb(data: &[u8], pos: &mut usize) -> Result<u32> {
    let mut result = 0u32;
    let mut shift = 0;
    for _ in 0..5 {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| crate::Error::new("truncated ABC uleb128"))?;
        *pos += 1;
        let piece = u32::from(byte & 0x7f);
        if piece > (u32::MAX >> shift) {
            bail!("ABC uleb128 is too long");
        }
        result |= piece << shift;
        if byte < 0x80 {
            return Ok(result);
        }
        shift += 7;
    }
    bail!("ABC uleb128 is too long");
}

fn skip_sleb(data: &[u8], mut pos: usize) -> Result<usize> {
    for _ in 0..5 {
        let byte = *data
            .get(pos)
            .ok_or_else(|| crate::Error::new("truncated ABC sleb128"))?;
        pos += 1;
        if byte < 0x80 {
            return Ok(pos);
        }
    }
    bail!("ABC sleb128 is too long");
}

fn read_until_nul(data: &[u8], start: usize) -> Result<&[u8]> {
    let rest = data
        .get(start..)
        .ok_or_else(|| crate::Error::new("truncated ABC string"))?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| crate::Error::new("unterminated ABC string"))?;
    Ok(&rest[..end])
}

pub fn class_names(data: &[u8], prefix: Option<&str>) -> Result<Vec<String>> {
    Abc::parse(data)?.class_names(prefix)
}

pub fn class_text(data: &[u8], name: &str) -> Result<String> {
    Abc::parse(data)?.class_text(name)
}

pub fn class_text_optional(data: &[u8], name: &str) -> Result<Option<String>> {
    Abc::parse(data)?.class_text_optional(name)
}

pub fn find_strings(data: &[u8], file: &str, pattern: &str) -> Result<Vec<String>> {
    Abc::parse(data)?.find_strings(file, pattern)
}

pub fn find_strings_resolved(
    data: &[u8],
    file: &str,
    pattern: &str,
    resolve: &LiteralResolve<'_>,
) -> Result<Vec<String>> {
    Abc::parse(data)?.find_strings_resolved(file, pattern, resolve)
}

pub fn find_types(data: &[u8], file: &str, pattern: &str) -> Result<Vec<String>> {
    Abc::parse(data)?.find_types(file, pattern)
}

pub fn find_members(
    data: &[u8],
    file: &str,
    methods: bool,
    pattern: &str,
    class_name: Option<&str>,
) -> Result<Vec<String>> {
    Abc::parse(data)?.find_members(file, methods, pattern, class_name)
}

#[cfg(test)]
mod tests {
    use super::{class_names, class_text, find_members, find_strings, find_strings_resolved};

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
        buf.extend(panda_str("count"));
        let main_off = buf.len() as u32;
        buf.extend(panda_str("main"));
        let hello_off = buf.len() as u32;
        buf.extend(panda_str("hello"));
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
        push_u32(&mut buf, 2);
        buf.push(0x05);
        push_u32(&mut buf, hello_off);
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

    #[test]
    fn lists_and_reads_one_class_without_an_index() {
        let data = sample_abc();
        assert_eq!(
            class_names(&data, Some("Ldemo")).unwrap(),
            vec!["Ldemo/App;".to_string()]
        );
        let text = class_text(&data, "demo.App").unwrap();
        assert!(
            text.contains("class Ldemo/App; extends Lpanda/Object;"),
            "{text}"
        );
        assert!(text.contains("public i32 count;"), "{text}");
        assert!(text.contains("public static void main();"), "{text}");
        let strings = find_strings(&data, "app.abc", "hello").unwrap();
        assert_eq!(
            strings,
            vec!["app.abc | literal#0 | matched=(hello)".to_string()]
        );
        let resolved = find_strings_resolved(&data, "app.abc", "Hello", &|bytes| {
            if bytes == b"hello" {
                Some("Hello".to_string())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(
            resolved,
            vec!["app.abc | literal#0 | matched=(Hello)".to_string()]
        );
        let methods = find_members(&data, "app.abc", true, "main", Some("Ldemo/App;")).unwrap();
        assert_eq!(methods, vec!["app.abc | Ldemo/App;->main".to_string()]);
    }
}
