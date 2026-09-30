use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::Compression;

pub fn uleb(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    while value > 127 {
        result.push(((value & 127) as u8) | 128);
        value >>= 7;
    }
    result.push(value as u8);
    result
}

struct DexBuilder {
    buf: Vec<u8>,
    sections: Vec<(u16, u32, u32)>,
}

impl DexBuilder {
    fn new() -> Self {
        Self {
            buf: vec![0; 112],
            sections: vec![(0, 1, 0)],
        }
    }

    fn section(&mut self, kind: u16, size: u32, data: &[u8], align: usize) -> usize {
        let pad = (align - (self.buf.len() % align)) % align;
        self.buf.extend(std::iter::repeat(0).take(pad));
        let off = self.buf.len();
        self.sections.push((kind, size, off as u32));
        self.buf.extend_from_slice(data);
        off
    }

    fn finish(
        mut self,
        strings: usize,
        string_ids: usize,
        type_count: u32,
        type_ids: usize,
        proto_count: u32,
        proto_ids: usize,
        field_count: u32,
        field_ids: usize,
        method_count: u32,
        method_ids: usize,
        class_count: u32,
        class_defs: usize,
        data_off: usize,
    ) -> Vec<u8> {
        let pad = (4 - (self.buf.len() % 4)) % 4;
        self.buf.extend(std::iter::repeat(0).take(pad));
        let map_off = self.buf.len();
        self.sections.push((0x1000, 1, map_off as u32));
        self.buf
            .extend_from_slice(&(self.sections.len() as u32).to_le_bytes());
        for (kind, count, offset) in &self.sections {
            self.buf.extend_from_slice(&kind.to_le_bytes());
            self.buf.extend_from_slice(&0u16.to_le_bytes());
            self.buf.extend_from_slice(&count.to_le_bytes());
            self.buf.extend_from_slice(&offset.to_le_bytes());
        }
        self.buf[..8].copy_from_slice(b"dex\n035\0");
        let file_len = self.buf.len() as u32;
        put_u32(&mut self.buf, 32, file_len);
        put_u32(&mut self.buf, 36, 112);
        put_u32(&mut self.buf, 40, 0x1234_5678);
        put_u32(&mut self.buf, 52, map_off as u32);
        let fields = [
            strings as u32,
            string_ids as u32,
            type_count,
            type_ids as u32,
            proto_count,
            proto_ids as u32,
            field_count,
            field_ids as u32,
            method_count,
            method_ids as u32,
            class_count,
            class_defs as u32,
            (self.buf.len() - data_off) as u32,
            data_off as u32,
        ];
        for (index, value) in fields.iter().enumerate() {
            put_u32(&mut self.buf, 56 + index * 4, *value);
        }
        self.buf
    }
}

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u16s_u32(buf: &mut [u8], off: usize, class_idx: u16, mid: u16, name: u32) {
    buf[off..off + 2].copy_from_slice(&class_idx.to_le_bytes());
    buf[off + 2..off + 4].copy_from_slice(&mid.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&name.to_le_bytes());
}

pub fn make_dex() -> Vec<u8> {
    make_marked_dex(b"token")
}

pub fn make_marked_dex(token: &[u8]) -> Vec<u8> {
    let strings: [&[u8]; 6] = [
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"V",
        b"first",
        b"second",
        token,
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &vec![0; 4 * strings.len()], 4);
    let type_ids = builder.section(2, 3, &pack_u32s(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let mut methods = Vec::new();
    put_method(&mut methods, 0, 0, 3);
    put_method(&mut methods, 0, 0, 4);
    let method_ids = builder.section(5, 2, &methods, 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_off = builder.buf.len();
    let string_ids = write_string_payload(&mut builder, string_ids, &strings);
    let code_body = {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&[0x1a, 0x00, 0x05, 0x00, 0x0e, 0x00]);
        body
    };
    let code = builder.section(0x2001, 1, &code_body, 4);
    let mut class_data = vec![0, 0, 2, 0];
    class_data.extend_from_slice(&[0x00, 0x09]);
    class_data.extend(uleb(code));
    class_data.extend_from_slice(&[0x01, 0x09]);
    class_data.extend(uleb(code));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);
    put_u32(&mut builder.buf, class_defs, 0);
    put_u32(&mut builder.buf, class_defs + 4, 1);
    put_u32(&mut builder.buf, class_defs + 8, 1);
    put_u32(&mut builder.buf, class_defs + 12, 0);
    put_u32(&mut builder.buf, class_defs + 16, 0xffff_ffff);
    put_u32(&mut builder.buf, class_defs + 20, 0);
    put_u32(&mut builder.buf, class_defs + 24, class_data_off as u32);
    put_u32(&mut builder.buf, class_defs + 28, 0);
    let _ = string_ids;
    builder.finish(
        strings.len(),
        string_ids,
        3,
        type_ids,
        1,
        proto_ids,
        0,
        0,
        2,
        method_ids,
        1,
        class_defs,
        data_off,
    )
}

fn write_string_payload(builder: &mut DexBuilder, string_ids: usize, strings: &[&[u8]]) -> usize {
    let mut blob = Vec::new();
    for value in strings {
        blob.extend(uleb(value.len()));
        blob.extend_from_slice(value);
        blob.push(0);
    }
    let start = builder.section(0x2002, strings.len() as u32, &blob, 1);
    let mut at = start;
    for (index, value) in strings.iter().enumerate() {
        put_u32(&mut builder.buf, string_ids + index * 4, at as u32);
        at += uleb(value.len()).len() + value.len() + 1;
    }
    string_ids
}

fn pack_u32s(values: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn put_method(buf: &mut Vec<u8>, class_idx: u16, proto: u16, name: u32) {
    let off = buf.len();
    buf.extend_from_slice(&[0; 8]);
    put_u16s_u32(buf, off, class_idx, proto, name);
}

pub fn make_invoke_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] = [
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"V",
        b"run",
        b"Lexample/Target;",
        b"callToMethod",
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &vec![0; 4 * strings.len()], 4);
    let type_ids = builder.section(2, 4, &pack_u32s(&[0, 1, 2, 4]), 4);
    let proto_ids = builder.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let mut methods = Vec::new();
    put_method(&mut methods, 0, 0, 3);
    put_method(&mut methods, 3, 0, 5);
    let method_ids = builder.section(5, 2, &methods, 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_off = builder.buf.len();
    write_string_payload(&mut builder, string_ids, &strings);
    let mut code_body = Vec::new();
    code_body.extend_from_slice(&0u16.to_le_bytes());
    code_body.extend_from_slice(&0u16.to_le_bytes());
    code_body.extend_from_slice(&0u16.to_le_bytes());
    code_body.extend_from_slice(&0u16.to_le_bytes());
    code_body.extend_from_slice(&0u32.to_le_bytes());
    code_body.extend_from_slice(&4u32.to_le_bytes());
    code_body.extend_from_slice(&[0x71, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00]);
    let code = builder.section(0x2001, 1, &code_body, 4);
    let mut class_data = vec![0, 0, 1, 0, 0, 0x09];
    class_data.extend(uleb(code));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);
    put_u32(&mut builder.buf, class_defs, 0);
    put_u32(&mut builder.buf, class_defs + 4, 1);
    put_u32(&mut builder.buf, class_defs + 8, 1);
    put_u32(&mut builder.buf, class_defs + 16, 0xffff_ffff);
    put_u32(&mut builder.buf, class_defs + 24, class_data_off as u32);
    builder.finish(
        strings.len(),
        string_ids,
        4,
        type_ids,
        1,
        proto_ids,
        0,
        0,
        2,
        method_ids,
        1,
        class_defs,
        data_off,
    )
}

pub fn make_field_dex() -> Vec<u8> {
    make_field_named_dex(b"a")
}

pub fn make_field_named_dex(field: &[u8]) -> Vec<u8> {
    let strings: [&[u8]; 6] = [
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"Lexample/Target;",
        b"L",
        b"getA",
        field,
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &vec![0; 4 * strings.len()], 4);
    let type_ids = builder.section(2, 3, &pack_u32s(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &pack_u32s(&[3, 2, 0]), 4);
    let mut field = Vec::new();
    put_method(&mut field, 0, 2, 5);
    let field_ids = builder.section(4, 1, &field, 4);
    let mut methods = Vec::new();
    put_method(&mut methods, 0, 0, 4);
    let method_ids = builder.section(5, 1, &methods, 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_off = builder.buf.len();
    write_string_payload(&mut builder, string_ids, &strings);
    let mut code_body = Vec::new();
    code_body.extend_from_slice(&1u16.to_le_bytes());
    code_body.extend_from_slice(&1u16.to_le_bytes());
    code_body.extend_from_slice(&0u16.to_le_bytes());
    code_body.extend_from_slice(&0u16.to_le_bytes());
    code_body.extend_from_slice(&0u32.to_le_bytes());
    code_body.extend_from_slice(&3u32.to_le_bytes());
    code_body.extend_from_slice(&[0x54, 0x00, 0x00, 0x00, 0x11, 0x00]);
    let code = builder.section(0x2001, 1, &code_body, 4);
    let mut class_data = vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01];
    class_data.extend(uleb(code));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);
    put_u32(&mut builder.buf, class_defs, 0);
    put_u32(&mut builder.buf, class_defs + 4, 1);
    put_u32(&mut builder.buf, class_defs + 8, 1);
    put_u32(&mut builder.buf, class_defs + 16, 0xffff_ffff);
    put_u32(&mut builder.buf, class_defs + 24, class_data_off as u32);
    builder.finish(
        strings.len(),
        string_ids,
        3,
        type_ids,
        1,
        proto_ids,
        1,
        field_ids,
        1,
        method_ids,
        1,
        class_defs,
        data_off,
    )
}

pub fn make_class_only_dex(descriptors: &[&str], base: u32, version: &[u8]) -> Vec<u8> {
    let header_size = if version == b"041" { 0x78 } else { 0x70 };
    let encoded: Vec<Vec<u8>> = descriptors
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect();
    let mut buf = vec![0u8; header_size];
    let string_ids = buf.len();
    buf.extend(std::iter::repeat(0).take(4 * encoded.len()));
    let type_ids = buf.len();
    buf.extend(std::iter::repeat(0).take(4 * encoded.len()));
    let class_defs = buf.len();
    buf.extend(std::iter::repeat(0).take(32 * encoded.len()));
    let data_off = buf.len();
    for (index, value) in encoded.iter().enumerate() {
        let string_off = base + buf.len() as u32;
        put_u32(&mut buf, string_ids + index * 4, string_off);
        put_u32(&mut buf, type_ids + index * 4, index as u32);
        put_u32(&mut buf, class_defs + index * 32, index as u32);
        put_u32(&mut buf, class_defs + index * 32 + 4, 1);
        put_u32(&mut buf, class_defs + index * 32 + 8, 0xffff_ffff);
        put_u32(&mut buf, class_defs + index * 32 + 16, 0xffff_ffff);
        buf.push(value.len() as u8);
        buf.extend_from_slice(value);
        buf.push(0);
    }
    buf[..4].copy_from_slice(b"dex\n");
    buf[4..7].copy_from_slice(version);
    buf[7] = 0;
    let file_len = buf.len() as u32;
    put_u32(&mut buf, 0x20, file_len);
    put_u32(&mut buf, 0x24, header_size as u32);
    put_u32(&mut buf, 0x28, 0x1234_5678);
    let fields = [
        encoded.len() as u32,
        base + string_ids as u32,
        encoded.len() as u32,
        base + type_ids as u32,
        0,
        0,
        0,
        0,
        0,
        0,
        encoded.len() as u32,
        base + class_defs as u32,
        (buf.len() - data_off) as u32,
        base + data_off as u32,
    ];
    for (index, value) in fields.iter().enumerate() {
        put_u32(&mut buf, 0x38 + index * 4, *value);
    }
    if version == b"041" {
        put_u32(&mut buf, 0x74, base);
    }
    buf
}

pub fn make_dex041_container() -> Vec<u8> {
    let first = make_class_only_dex(&["Lalpha/First;", "Lshared/Duplicate;"], 0, b"041");
    let second = make_class_only_dex(
        &["Lbeta/Second;", "Lshared/Duplicate;"],
        first.len() as u32,
        b"041",
    );
    let mut data = first;
    let split = data.len();
    data.extend_from_slice(&second);
    let total = data.len() as u32;
    put_u32(&mut data, 0x70, total);
    put_u32(&mut data, split + 0x70, total);
    data
}

pub fn zip_archive(files: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
    let mut locals = Vec::new();
    let mut central = Vec::new();
    let mut offset = 0u32;
    for (name, data) in files {
        let name_bytes = name.as_bytes();
        let (method, comp) = if deflate {
            (8u16, deflate_bytes(data))
        } else {
            (0u16, data.to_vec())
        };
        let crc = crc32fast::hash(data);
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name_bytes);
        local.extend_from_slice(&comp);

        let mut cd = Vec::new();
        cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&offset.to_le_bytes());
        cd.extend_from_slice(name_bytes);
        offset += local.len() as u32;
        locals.extend_from_slice(&local);
        central.extend_from_slice(&cd);
    }
    let cd_off = locals.len() as u32;
    let cd_size = central.len() as u32;
    let mut out = locals;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn deflate_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn code_item(insns: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&((insns.len() / 2) as u32).to_le_bytes());
    body.extend_from_slice(insns);
    body
}

fn one_method_dex(strings: &[&[u8]], method_name: u32, insns: &[u8]) -> Vec<u8> {
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &vec![0; 4 * strings.len()], 4);
    let type_ids = builder.section(2, 3, &pack_u32s(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let mut methods = Vec::new();
    put_method(&mut methods, 0, 0, method_name);
    let method_ids = builder.section(5, 1, &methods, 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_off = builder.buf.len();
    write_string_payload(&mut builder, string_ids, strings);
    let code = builder.section(0x2001, 1, &code_item(insns), 4);
    let mut class_data = vec![0, 0, 1, 0, 0, 0x09];
    class_data.extend(uleb(code));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);
    put_u32(&mut builder.buf, class_defs, 0);
    put_u32(&mut builder.buf, class_defs + 4, 1);
    put_u32(&mut builder.buf, class_defs + 8, 1);
    put_u32(&mut builder.buf, class_defs + 16, 0xffff_ffff);
    put_u32(&mut builder.buf, class_defs + 24, class_data_off as u32);
    builder.finish(
        strings.len(),
        string_ids,
        3,
        type_ids,
        1,
        proto_ids,
        0,
        0,
        1,
        method_ids,
        1,
        class_defs,
        data_off,
    )
}

pub fn make_payload_dex(kind: u8) -> Vec<u8> {
    let payload: [u8; 12] = match kind {
        1 => [0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
        2 => [0x00, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
        _ => [0x00, 0x03, 0x04, 0x00, 0x01, 0, 0, 0, 1, 2, 3, 4],
    };
    let mut insns = payload.to_vec();
    insns.extend_from_slice(&[0x1a, 0x00, 0x03, 0x00, 0x0e, 0x00]);
    one_method_dex(
        &[
            b"Lexample/Test;",
            b"Ljava/lang/Object;",
            b"V",
            b"token",
            b"after",
        ],
        4,
        &insns,
    )
}

pub fn make_reordered_string_dex() -> Vec<u8> {
    let strings: [&[u8]; 5] = [
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"V",
        b"mytoken",
        b"m",
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &vec![0; 4 * strings.len()], 4);
    let type_ids = builder.section(2, 3, &pack_u32s(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let mut methods = Vec::new();
    put_method(&mut methods, 0, 0, 4);
    let method_ids = builder.section(5, 1, &methods, 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_off = builder.buf.len();
    let physical = [3usize, 0, 1, 2, 4];
    let mut blob = Vec::new();
    let mut relative = vec![0u32; strings.len()];
    for index in physical {
        relative[index] = blob.len() as u32;
        blob.extend(uleb(strings[index].len()));
        blob.extend_from_slice(strings[index]);
        blob.push(0);
    }
    let start = builder.section(0x2002, strings.len() as u32, &blob, 1);
    for (index, offset) in relative.iter().enumerate() {
        put_u32(
            &mut builder.buf,
            string_ids + index * 4,
            start as u32 + offset,
        );
    }
    let code = builder.section(
        0x2001,
        1,
        &code_item(&[0x1a, 0x00, 0x03, 0x00, 0x0e, 0x00]),
        4,
    );
    let mut class_data = vec![0, 0, 1, 0, 0, 0x09];
    class_data.extend(uleb(code));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);
    put_u32(&mut builder.buf, class_defs, 0);
    put_u32(&mut builder.buf, class_defs + 4, 1);
    put_u32(&mut builder.buf, class_defs + 8, 1);
    put_u32(&mut builder.buf, class_defs + 16, 0xffff_ffff);
    put_u32(&mut builder.buf, class_defs + 24, class_data_off as u32);
    builder.finish(
        strings.len(),
        string_ids,
        3,
        type_ids,
        1,
        proto_ids,
        0,
        0,
        1,
        method_ids,
        1,
        class_defs,
        data_off,
    )
}

pub fn make_bucket_overlap_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] = [
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"V",
        b"kept",
        b"wide",
        b"token",
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &[0; 24], 4);
    let type_ids = builder.section(2, 3, &pack_u32s(&[0, 1, 2]), 4);
    let proto_ids = builder.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let mut methods = Vec::new();
    put_method(&mut methods, 0, 0, 3);
    put_method(&mut methods, 0, 0, 4);
    let method_ids = builder.section(5, 2, &methods, 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_off = builder.buf.len();
    write_string_payload(&mut builder, string_ids, &strings);
    let wide_code = builder.section(0x2001, 1, &code_item(&[0x00, 0x00, 0x00, 0x00]), 4);
    let kept_code = builder.section(
        0x2001,
        1,
        &code_item(&[0x1a, 0x00, 0x05, 0x00, 0x0e, 0x00]),
        4,
    );
    let covered = (builder.buf.len() - (wide_code + 16)) / 2;
    put_u32(&mut builder.buf, wide_code + 12, covered as u32);
    let mut class_data = vec![0, 0, 2, 0];
    class_data.extend_from_slice(&[0x00, 0x09]);
    class_data.extend(uleb(kept_code));
    class_data.extend_from_slice(&[0x01, 0x09]);
    class_data.extend(uleb(wide_code));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);
    put_u32(&mut builder.buf, class_defs, 0);
    put_u32(&mut builder.buf, class_defs + 4, 1);
    put_u32(&mut builder.buf, class_defs + 8, 1);
    put_u32(&mut builder.buf, class_defs + 16, 0xffff_ffff);
    put_u32(&mut builder.buf, class_defs + 24, class_data_off as u32);
    builder.finish(
        strings.len(),
        string_ids,
        3,
        type_ids,
        1,
        proto_ids,
        0,
        0,
        2,
        method_ids,
        1,
        class_defs,
        data_off,
    )
}

pub fn make_array_dex() -> Vec<u8> {
    let strings: [&[u8]; 5] = [
        b"Lexample/Test;",
        b"Ljava/lang/Object;",
        b"V",
        b"[[I",
        b"run",
    ];
    let mut builder = DexBuilder::new();
    let string_ids = builder.section(1, strings.len() as u32, &[0; 20], 4);
    let type_ids = builder.section(2, 4, &pack_u32s(&[0, 1, 2, 3]), 4);
    let proto_ids = builder.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let mut methods = Vec::new();
    put_method(&mut methods, 0, 0, 4);
    let method_ids = builder.section(5, 1, &methods, 4);
    let class_defs = builder.section(6, 1, &[0; 32], 4);
    let data_off = builder.buf.len();
    write_string_payload(&mut builder, string_ids, &strings);
    let code = builder.section(
        0x2001,
        1,
        &code_item(&[0x23, 0x10, 0x03, 0x00, 0x0e, 0x00]),
        4,
    );
    let mut class_data = vec![0, 0, 1, 0, 0, 0x09];
    class_data.extend(uleb(code));
    let class_data_off = builder.section(0x2000, 1, &class_data, 1);
    put_u32(&mut builder.buf, class_defs, 0);
    put_u32(&mut builder.buf, class_defs + 4, 1);
    put_u32(&mut builder.buf, class_defs + 8, 1);
    put_u32(&mut builder.buf, class_defs + 16, 0xffff_ffff);
    put_u32(&mut builder.buf, class_defs + 24, class_data_off as u32);
    builder.finish(
        strings.len(),
        string_ids,
        4,
        type_ids,
        1,
        proto_ids,
        0,
        0,
        1,
        method_ids,
        1,
        class_defs,
        data_off,
    )
}

fn push_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub fn zip_stored_flags(name: &str, data: &[u8], crc: u32, flags: u16) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let descriptor = flags & 0x0008 != 0;
    let mut local = Vec::new();
    push_u32(&mut local, 0x0403_4b50);
    push_u16(&mut local, 20);
    push_u16(&mut local, flags);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u32(&mut local, if descriptor { 0 } else { crc });
    push_u32(&mut local, if descriptor { 0 } else { data.len() as u32 });
    push_u32(&mut local, if descriptor { 0 } else { data.len() as u32 });
    push_u16(&mut local, name_bytes.len() as u16);
    push_u16(&mut local, 0);
    local.extend_from_slice(name_bytes);
    local.extend_from_slice(data);
    if descriptor {
        push_u32(&mut local, 0x0807_4b50);
        push_u32(&mut local, crc);
        push_u32(&mut local, data.len() as u32);
        push_u32(&mut local, data.len() as u32);
    }
    let mut cd = Vec::new();
    push_u32(&mut cd, 0x0201_4b50);
    push_u16(&mut cd, 20);
    push_u16(&mut cd, 20);
    push_u16(&mut cd, flags);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u32(&mut cd, crc);
    push_u32(&mut cd, data.len() as u32);
    push_u32(&mut cd, data.len() as u32);
    push_u16(&mut cd, name_bytes.len() as u16);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u32(&mut cd, 0);
    push_u32(&mut cd, 0);
    cd.extend_from_slice(name_bytes);
    let cd_off = local.len() as u32;
    let cd_size = cd.len() as u32;
    let mut out = local;
    out.extend(cd);
    push_u32(&mut out, 0x0605_4b50);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 1);
    push_u16(&mut out, 1);
    push_u32(&mut out, cd_size);
    push_u32(&mut out, cd_off);
    push_u16(&mut out, 0);
    out
}

pub fn zip64_stored(name: &str, data: &[u8]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let crc = crc32fast::hash(data);
    let mut local = Vec::new();
    push_u32(&mut local, 0x0403_4b50);
    push_u16(&mut local, 20);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u32(&mut local, crc);
    push_u32(&mut local, data.len() as u32);
    push_u32(&mut local, data.len() as u32);
    push_u16(&mut local, name_bytes.len() as u16);
    push_u16(&mut local, 0);
    local.extend_from_slice(name_bytes);
    local.extend_from_slice(data);

    let mut extra = Vec::new();
    push_u16(&mut extra, 0x0001);
    push_u16(&mut extra, 24);
    push_u64(&mut extra, data.len() as u64);
    push_u64(&mut extra, data.len() as u64);
    push_u64(&mut extra, 0);

    let mut cd = Vec::new();
    push_u32(&mut cd, 0x0201_4b50);
    push_u16(&mut cd, 45);
    push_u16(&mut cd, 45);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u32(&mut cd, crc);
    push_u32(&mut cd, 0xffff_ffff);
    push_u32(&mut cd, 0xffff_ffff);
    push_u16(&mut cd, name_bytes.len() as u16);
    push_u16(&mut cd, extra.len() as u16);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u16(&mut cd, 0);
    push_u32(&mut cd, 0);
    push_u32(&mut cd, 0xffff_ffff);
    cd.extend_from_slice(name_bytes);
    cd.extend_from_slice(&extra);

    let cd_off = local.len() as u64;
    let cd_size = cd.len() as u64;
    let mut out = local;
    out.extend_from_slice(&cd);
    let eocd64_off = out.len() as u64;
    push_u32(&mut out, 0x0606_4b50);
    push_u64(&mut out, 44);
    push_u16(&mut out, 45);
    push_u16(&mut out, 45);
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    push_u64(&mut out, 1);
    push_u64(&mut out, 1);
    push_u64(&mut out, cd_size);
    push_u64(&mut out, cd_off);
    push_u32(&mut out, 0x0706_4b50);
    push_u32(&mut out, 0);
    push_u64(&mut out, eocd64_off);
    push_u32(&mut out, 1);
    push_u32(&mut out, 0x0605_4b50);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0xffff);
    push_u16(&mut out, 0xffff);
    push_u32(&mut out, 0xffff_ffff);
    push_u32(&mut out, 0xffff_ffff);
    push_u16(&mut out, 0);
    out
}
