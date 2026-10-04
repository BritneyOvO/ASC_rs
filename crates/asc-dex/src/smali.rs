//! Baksmali-style printer. One class becomes `.class` / `.field` / `.method`
//! text. Instructions keep their Dalvik mnemonics and `v`/`p` registers.

use std::collections::BTreeSet;

use crate::bytes::{read_uleb, u16_at, u32_at};
use crate::dex::{java_quote, ClassDef, CodeItem, Dex, EncodedField, EncodedMethod};
use crate::opcodes::{payload_len, Fmt, IndexKind, OPS};
use crate::Result;

pub fn smali_class(data: &[u8], descriptor: &str) -> Result<String> {
    let dex = Dex::parse(data)?;
    let Some(def) = dex.find_class_def(descriptor)? else {
        bail!("Class {descriptor} not found in DEX.");
    };
    smali_class_def(&dex, &def)
}

pub fn smali_class_def(dex: &Dex<'_>, def: &ClassDef) -> Result<String> {
    let class_desc = dex.type_desc(def.class_idx)?;
    let mut out = String::new();
    out.push_str(".class ");
    out.push_str(&access_words(def.access_flags, Access::Class));
    if !out.ends_with(' ') {
        out.push(' ');
    }
    out.push_str(&class_desc);
    out.push('\n');
    if def.superclass_idx != 0xffff_ffff {
        out.push_str(".super ");
        out.push_str(&dex.type_desc(def.superclass_idx)?);
        out.push('\n');
    }
    if def.source_file_idx != 0xffff_ffff {
        out.push_str(".source ");
        out.push_str(&java_quote(&dex.string(def.source_file_idx)?));
        out.push('\n');
    }
    for iface in dex.interfaces(def.interfaces_off)? {
        out.push_str(".implements ");
        out.push_str(&iface);
        out.push('\n');
    }
    out.push('\n');

    let class_data = if def.class_data_off == 0 {
        None
    } else {
        Some(dex.class_data_at(def.class_data_off)?.0)
    };
    let Some(class_data) = class_data else {
        return Ok(out);
    };
    let literals = dex.static_literals(def.static_values_off)?;
    if !class_data.static_fields.is_empty() {
        out.push_str("# static fields\n");
        for (index, field) in class_data.static_fields.iter().enumerate() {
            out.push_str(&field_line(dex, field, literals.get(index).map(String::as_str))?);
            out.push('\n');
        }
        out.push('\n');
    }
    if !class_data.instance_fields.is_empty() {
        out.push_str("# instance fields\n");
        for field in &class_data.instance_fields {
            out.push_str(&field_line(dex, field, None)?);
            out.push('\n');
        }
        out.push('\n');
    }
    write_methods(dex, &mut out, "# direct methods", &class_data.direct_methods)?;
    write_methods(
        dex,
        &mut out,
        "# virtual methods",
        &class_data.virtual_methods,
    )?;
    Ok(out)
}

fn write_methods(
    dex: &Dex,
    out: &mut String,
    title: &str,
    methods: &[EncodedMethod],
) -> Result<()> {
    if methods.is_empty() {
        return Ok(());
    }
    out.push_str(title);
    out.push('\n');
    for method in methods {
        out.push_str(&method_block(dex, method)?);
        out.push('\n');
    }
    Ok(())
}

fn field_line(dex: &Dex, field: &EncodedField, init: Option<&str>) -> Result<String> {
    let id = dex.field_id(field.field_idx)?;
    let name = dex.string(id.name_idx)?;
    let ty = dex.type_desc(u32::from(id.type_idx))?;
    let mut line = format!(
        ".field {}{name}:{ty}",
        access_words(field.access_flags, Access::Field)
    );
    if let Some(init) = init {
        line.push_str(" = ");
        line.push_str(init);
    }
    Ok(line)
}

fn method_block(dex: &Dex, method: &EncodedMethod) -> Result<String> {
    let id = dex.method_id(method.method_idx)?;
    let name = dex.string(id.name_idx)?;
    let proto = method_proto(dex, u32::from(id.proto_idx))?;
    let mut out = format!(
        ".method {}{name}{proto}\n",
        access_words(method.access_flags, Access::Method)
    );
    if method.code_off != 0 {
        let code = dex.code(method.code_off)?;
        let tries = read_tries(dex, method.code_off)?;
        out.push_str(&format!("    .registers {}\n", code.registers_size));
        out.push('\n');
        out.push_str(&insns(dex, &code, &tries)?);
        for catch in &tries {
            let start = label(catch.start);
            let end = label(catch.end);
            let handler = label(catch.addr);
            if let Some(ty) = &catch.ty {
                out.push_str(&format!("    .catch {ty} {{ {start} .. {end} }} {handler}\n"));
            } else {
                out.push_str(&format!("    .catchall {{ {start} .. {end} }} {handler}\n"));
            }
        }
    }
    out.push_str(".end method\n");
    Ok(out)
}

struct Catch {
    start: u32,
    end: u32,
    addr: u32,
    ty: Option<String>,
}

fn read_tries(dex: &Dex, code_off: u32) -> Result<Vec<Catch>> {
    let at = code_off as usize;
    let tries_size = u16_at(dex.data, at + 6)? as usize;
    if tries_size == 0 {
        return Ok(Vec::new());
    }
    let insns_size = u32_at(dex.data, at + 12)? as usize;
    let mut pos = at + 16 + insns_size * 2;
    if insns_size % 2 == 1 {
        pos += 2;
    }
    let list_at = pos + tries_size * 8;
    let mut catches = Vec::new();
    for index in 0..tries_size {
        let off = pos + index * 8;
        let start = u32_at(dex.data, off)?;
        let count = u16_at(dex.data, off + 4)? as u32;
        let handler = u16_at(dex.data, off + 6)? as usize;
        let mut cursor = list_at + handler;
        let (size, n) = read_sleb(dex.data, cursor)?;
        cursor += n;
        let typed = size.unsigned_abs() as usize;
        for _ in 0..typed {
            let (type_idx, n) = read_uleb(dex.data, cursor)?;
            cursor += n;
            let (addr, n) = read_uleb(dex.data, cursor)?;
            cursor += n;
            catches.push(Catch {
                start,
                end: start.saturating_add(count),
                addr,
                ty: Some(dex.type_desc(type_idx)?),
            });
        }
        if size <= 0 {
            let (addr, _) = read_uleb(dex.data, cursor)?;
            catches.push(Catch {
                start,
                end: start.saturating_add(count),
                addr,
                ty: None,
            });
        }
    }
    Ok(catches)
}

fn insns(dex: &Dex, code: &CodeItem, catches: &[Catch]) -> Result<String> {
    let bytes = code.insns;
    let mut targets = BTreeSet::new();
    let mut pc = 0usize;
    while pc * 2 + 1 < bytes.len() {
        let pos = pc * 2;
        if let Some(nbytes) = payload_len(bytes, pos) {
            pc += nbytes / 2;
            continue;
        }
        let op = bytes[pos];
        let info = OPS[op as usize];
        if info.len == 0 {
            break;
        }
        let units = info.len as usize;
        collect_target(bytes, pos, pc, info.fmt, &mut targets)?;
        pc += units;
    }
    for catch in catches {
        targets.insert(catch.start);
        targets.insert(catch.end);
        targets.insert(catch.addr);
    }

    let mut out = String::new();
    pc = 0;
    let total = bytes.len() / 2;
    while pc < total {
        if targets.contains(&(pc as u32)) {
            out.push_str(&label(pc as u32));
            out.push('\n');
        }
        let pos = pc * 2;
        if pos + 1 >= bytes.len() {
            break;
        }
        if let Some(nbytes) = payload_len(bytes, pos) {
            out.push_str(&payload(bytes, pos, pc, nbytes)?);
            pc += nbytes / 2;
            continue;
        }
        let op = bytes[pos];
        let info = OPS[op as usize];
        if info.len == 0 {
            out.push_str(&format!("    # unknown opcode {op:#04x}\n"));
            break;
        }
        let units = info.len as usize;
        if pos + units * 2 > bytes.len() {
            break;
        }
        out.push_str("    ");
        out.push_str(&format_insn(
            dex,
            bytes,
            pos,
            pc,
            code.registers_size,
            code.ins_size,
        )?);
        out.push('\n');
        pc += units;
    }
    if targets.contains(&(total as u32)) {
        out.push_str(&label(total as u32));
        out.push('\n');
    }
    Ok(out)
}

fn collect_target(
    bytes: &[u8],
    pos: usize,
    pc: usize,
    fmt: Fmt,
    targets: &mut BTreeSet<u32>,
) -> Result<()> {
    let add = |offset: i32, targets: &mut BTreeSet<u32>| {
        targets.insert(pc.wrapping_add(offset as usize) as u32);
    };
    match fmt {
        Fmt::F10t => add(i8::from_le_bytes([bytes[pos + 1]]) as i32, targets),
        Fmt::F20t => add(i16_at(bytes, pos + 2)? as i32, targets),
        Fmt::F21t | Fmt::F22t => add(i16_at(bytes, pos + 2)? as i32, targets),
        Fmt::F30t | Fmt::F31t => add(i32_at(bytes, pos + 2)?, targets),
        _ => {}
    }
    if fmt == Fmt::F31t {
        if let Some(nbytes) = payload_at_target(bytes, pc, i32_at(bytes, pos + 2)?) {
            let payload_pc = pc.wrapping_add(i32_at(bytes, pos + 2)? as usize);
            mark_payload_targets(bytes, payload_pc * 2, nbytes, payload_pc, targets);
        }
    }
    Ok(())
}

fn payload_at_target(bytes: &[u8], pc: usize, offset: i32) -> Option<usize> {
    let at = pc.wrapping_add(offset as usize) * 2;
    payload_len(bytes, at)
}

fn mark_payload_targets(
    bytes: &[u8],
    pos: usize,
    nbytes: usize,
    pc: usize,
    targets: &mut BTreeSet<u32>,
) {
    if pos + 4 > bytes.len() {
        return;
    }
    let ident = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
    if ident == 0x0100 || ident == 0x0200 {
        let size = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        let base = if ident == 0x0100 { pos + 8 } else { pos + 4 + size * 4 };
        for index in 0..size {
            let off = base + index * 4;
            if off + 4 > bytes.len() || off + 4 > pos + nbytes {
                break;
            }
            let rel = i32::from_le_bytes(
                bytes[off..off + 4]
                    .try_into()
                    .expect("switch target is 4 bytes"),
            );
            targets.insert(pc.wrapping_add(rel as usize) as u32);
        }
    }
}

fn format_insn(
    dex: &Dex,
    bytes: &[u8],
    pos: usize,
    pc: usize,
    registers: u16,
    ins: u16,
) -> Result<String> {
    let op = bytes[pos];
    let info = OPS[op as usize];
    let name = info.name;
    let reg = |index: u32| reg_name(index, registers, ins);
    let target = |offset: i32| label(pc.wrapping_add(offset as usize) as u32);
    match info.fmt {
        Fmt::F10x => Ok(name.to_string()),
        Fmt::F12x => {
            let nibbles = bytes[pos + 1];
            Ok(format!(
                "{name} {}, {}",
                reg(u32::from(nibbles & 0x0f)),
                reg(u32::from(nibbles >> 4))
            ))
        }
        Fmt::F11n => {
            let nibbles = bytes[pos + 1];
            let literal = ((nibbles as i8) >> 4) as i32;
            Ok(format!(
                "{name} {}, {}",
                reg(u32::from(nibbles & 0x0f)),
                hex_i32(literal)
            ))
        }
        Fmt::F11x => Ok(format!("{name} {}", reg(u32::from(bytes[pos + 1])))),
        Fmt::F10t => Ok(format!(
            "{name} {}",
            target(i8::from_le_bytes([bytes[pos + 1]]) as i32)
        )),
        Fmt::F20t => Ok(format!("{name} {}", target(i16_at(bytes, pos + 2)? as i32))),
        Fmt::F22x => Ok(format!(
            "{name} {}, {}",
            reg(u32::from(bytes[pos + 1])),
            reg(u32::from(u16_at(bytes, pos + 2)?))
        )),
        Fmt::F21t => Ok(format!(
            "{name} {}, {}",
            reg(u32::from(bytes[pos + 1])),
            target(i16_at(bytes, pos + 2)? as i32)
        )),
        Fmt::F21s => Ok(format!(
            "{name} {}, {}",
            reg(u32::from(bytes[pos + 1])),
            hex_i32(i16_at(bytes, pos + 2)? as i32)
        )),
        Fmt::F21h => {
            let raw = u16_at(bytes, pos + 2)? as u64;
            let literal = if name.contains("wide") {
                raw << 48
            } else {
                raw << 16
            };
            Ok(format!(
                "{name} {}, {}",
                reg(u32::from(bytes[pos + 1])),
                hex_u64(literal)
            ))
        }
        Fmt::F21c => {
            let dest = reg(u32::from(bytes[pos + 1]));
            let idx = u32::from(u16_at(bytes, pos + 2)?);
            Ok(format!("{name} {dest}, {}", reference(dex, info.index, idx)?))
        }
        Fmt::F23x => Ok(format!(
            "{name} {}, {}, {}",
            reg(u32::from(bytes[pos + 1])),
            reg(u32::from(bytes[pos + 2])),
            reg(u32::from(bytes[pos + 3]))
        )),
        Fmt::F22b => Ok(format!(
            "{name} {}, {}, {}",
            reg(u32::from(bytes[pos + 1])),
            reg(u32::from(bytes[pos + 2])),
            hex_i32(bytes[pos + 3] as i8 as i32)
        )),
        Fmt::F22t => {
            let nibbles = bytes[pos + 1];
            Ok(format!(
                "{name} {}, {}, {}",
                reg(u32::from(nibbles & 0x0f)),
                reg(u32::from(nibbles >> 4)),
                target(i16_at(bytes, pos + 2)? as i32)
            ))
        }
        Fmt::F22s => {
            let nibbles = bytes[pos + 1];
            Ok(format!(
                "{name} {}, {}, {}",
                reg(u32::from(nibbles & 0x0f)),
                reg(u32::from(nibbles >> 4)),
                hex_i32(i16_at(bytes, pos + 2)? as i32)
            ))
        }
        Fmt::F22c => {
            let nibbles = bytes[pos + 1];
            let idx = u32::from(u16_at(bytes, pos + 2)?);
            Ok(format!(
                "{name} {}, {}, {}",
                reg(u32::from(nibbles & 0x0f)),
                reg(u32::from(nibbles >> 4)),
                reference(dex, info.index, idx)?
            ))
        }
        Fmt::F32x => Ok(format!(
            "{name} {}, {}",
            reg(u32::from(u16_at(bytes, pos + 2)?)),
            reg(u32::from(u16_at(bytes, pos + 4)?))
        )),
        Fmt::F30t => Ok(format!("{name} {}", target(i32_at(bytes, pos + 2)?))),
        Fmt::F31t => Ok(format!(
            "{name} {}, {}",
            reg(u32::from(bytes[pos + 1])),
            target(i32_at(bytes, pos + 2)?)
        )),
        Fmt::F31i => Ok(format!(
            "{name} {}, {}",
            reg(u32::from(bytes[pos + 1])),
            hex_i32(i32_at(bytes, pos + 2)?)
        )),
        Fmt::F31c => {
            let idx = u32_at(bytes, pos + 2)?;
            Ok(format!(
                "{name} {}, {}",
                reg(u32::from(bytes[pos + 1])),
                reference(dex, info.index, idx)?
            ))
        }
        Fmt::F35c | Fmt::F45cc => {
            let count = (bytes[pos + 1] >> 4) as usize;
            let extra = u32::from(bytes[pos + 1] & 0x0f);
            let idx = u32::from(u16_at(bytes, pos + 2)?);
            let regs = [
                u32::from(bytes[pos + 4] & 0x0f),
                u32::from(bytes[pos + 4] >> 4),
                u32::from(bytes[pos + 5] & 0x0f),
                u32::from(bytes[pos + 5] >> 4),
                extra,
            ];
            let list = reg_list(&regs[..count.min(5)], registers, ins);
            let mut line = format!("{name} {{{list}}}, {}", reference(dex, info.index, idx)?);
            if info.fmt == Fmt::F45cc {
                let proto = u32::from(u16_at(bytes, pos + 6)?);
                line.push_str(", ");
                line.push_str(&method_proto(dex, proto)?);
            }
            Ok(line)
        }
        Fmt::F3rc | Fmt::F4rcc => {
            let count = bytes[pos + 1] as u32;
            let idx = u32::from(u16_at(bytes, pos + 2)?);
            let first = u32::from(u16_at(bytes, pos + 4)?);
            let list = if count == 0 {
                String::new()
            } else {
                format!(
                    "{} .. {}",
                    reg(first),
                    reg(first + count - 1)
                )
            };
            let mut line = format!("{name} {{{list}}}, {}", reference(dex, info.index, idx)?);
            if info.fmt == Fmt::F4rcc {
                let proto = u32::from(u16_at(bytes, pos + 6)?);
                line.push_str(", ");
                line.push_str(&method_proto(dex, proto)?);
            }
            Ok(line)
        }
        Fmt::F51l => {
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&bytes[pos + 2..pos + 10]);
            Ok(format!(
                "{name} {}, {}",
                reg(u32::from(bytes[pos + 1])),
                hex_u64(u64::from_le_bytes(wide))
            ))
        }
    }
}

fn payload(bytes: &[u8], pos: usize, pc: usize, nbytes: usize) -> Result<String> {
    let ident = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
    let size = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
    match ident {
        0x0100 => {
            let first = i32_at(bytes, pos + 4)?;
            let mut out = format!(".packed-switch {}\n", hex_i32(first));
            for index in 0..size {
                let rel = i32_at(bytes, pos + 8 + index * 4)?;
                out.push_str("        ");
                out.push_str(&label(pc.wrapping_add(rel as usize) as u32));
                out.push('\n');
            }
            out.push_str(".end packed-switch\n");
            Ok(out)
        }
        0x0200 => {
            let mut out = String::from(".sparse-switch\n");
            let keys = pos + 4;
            let rels = keys + size * 4;
            for index in 0..size {
                let key = i32_at(bytes, keys + index * 4)?;
                let rel = i32_at(bytes, rels + index * 4)?;
                out.push_str(&format!(
                    "        {} -> {}\n",
                    hex_i32(key),
                    label(pc.wrapping_add(rel as usize) as u32)
                ));
            }
            out.push_str(".end sparse-switch\n");
            Ok(out)
        }
        0x0300 => {
            let width = size;
            let count =
                u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
            let mut out = format!(".array-data {width}\n");
            let mut data = pos + 8;
            let suffix = match width {
                1 => "t",
                2 => "s",
                8 => "L",
                _ => "",
            };
            for _ in 0..count {
                if data + width > pos + nbytes || data + width > bytes.len() {
                    break;
                }
                let mut buf = [0u8; 8];
                buf[..width].copy_from_slice(&bytes[data..data + width]);
                out.push_str(&format!(
                    "        {}{suffix}\n",
                    hex_u64(u64::from_le_bytes(buf))
                ));
                data += width;
            }
            out.push_str(".end array-data\n");
            Ok(out)
        }
        _ => Ok(String::new()),
    }
}

fn reference(dex: &Dex, kind: IndexKind, idx: u32) -> Result<String> {
    match kind {
        IndexKind::None => Ok(format!("@{idx}")),
        IndexKind::String => Ok(java_quote(&dex.string(idx).unwrap_or_else(|_| format!("string@{idx}")))),
        IndexKind::Type => Ok(dex
            .type_desc(idx)
            .unwrap_or_else(|_| format!("type@{idx}"))),
        IndexKind::Field => field_ref(dex, idx),
        IndexKind::Method | IndexKind::MethodProto => method_ref(dex, idx),
        IndexKind::Proto => method_proto(dex, idx),
        IndexKind::CallSite => Ok(format!("call_site@{idx}")),
        IndexKind::MethodHandle => Ok(format!("method_handle@{idx}")),
    }
}

fn field_ref(dex: &Dex, idx: u32) -> Result<String> {
    let id = dex.field_id(idx)?;
    Ok(format!(
        "{}->{}:{}",
        dex.type_desc(u32::from(id.class_idx))?,
        dex.string(id.name_idx)?,
        dex.type_desc(u32::from(id.type_idx))?
    ))
}

fn method_ref(dex: &Dex, idx: u32) -> Result<String> {
    let id = dex.method_id(idx)?;
    Ok(format!(
        "{}->{}{}",
        dex.type_desc(u32::from(id.class_idx))?,
        dex.string(id.name_idx)?,
        method_proto(dex, u32::from(id.proto_idx))?
    ))
}

fn method_proto(dex: &Dex, idx: u32) -> Result<String> {
    let proto = dex.proto(idx)?;
    let mut desc = String::from("(");
    for param in &proto.params {
        desc.push_str(&dex.type_desc(*param)?);
    }
    desc.push(')');
    desc.push_str(&dex.type_desc(proto.return_type_idx)?);
    Ok(desc)
}

fn reg_list(regs: &[u32], registers: u16, ins: u16) -> String {
    regs.iter()
        .map(|index| reg_name(*index, registers, ins))
        .collect::<Vec<_>>()
        .join(", ")
}

fn reg_name(index: u32, registers: u16, ins: u16) -> String {
    let locals = u32::from(registers.saturating_sub(ins));
    if index >= locals {
        format!("p{}", index - locals)
    } else {
        format!("v{index}")
    }
}

fn label(pc: u32) -> String {
    format!(":l_{pc:x}")
}

fn hex_i32(value: i32) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

enum Access {
    Class,
    Field,
    Method,
}

fn access_words(flags: u32, kind: Access) -> String {
    let mut words = Vec::new();
    let mut add = |bit: u32, name: &'static str| {
        if flags & bit != 0 {
            words.push(name);
        }
    };
    add(0x1, "public");
    add(0x2, "private");
    add(0x4, "protected");
    add(0x8, "static");
    add(0x10, "final");
    add(0x20, "synchronized");
    match kind {
        Access::Field => {
            add(0x40, "volatile");
            add(0x80, "transient");
        }
        Access::Method => {
            add(0x40, "bridge");
            add(0x80, "varargs");
            add(0x100, "native");
            add(0x400, "abstract");
        }
        Access::Class => {
            add(0x200, "interface");
            add(0x400, "abstract");
            add(0x2000, "annotation");
            add(0x4000, "enum");
        }
    }
    add(0x1000, "synthetic");
    if matches!(kind, Access::Field | Access::Method) {
        add(0x4000, "enum");
    }
    add(0x2_0000, "declared-synchronized");
    let mut text = words.join(" ");
    if !text.is_empty() {
        text.push(' ');
    }
    text
}

fn read_sleb(data: &[u8], mut pos: usize) -> Result<(i32, usize)> {
    let start = pos;
    let mut result = 0i32;
    let mut shift = 0;
    loop {
        let byte = *data
            .get(pos)
            .ok_or_else(|| crate::Error::new("truncated sleb128"))?;
        pos += 1;
        result |= i32::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 32 && byte & 0x40 != 0 {
                result |= !0 << shift;
            }
            return Ok((result, pos - start));
        }
        if shift >= 32 {
            bail!("sleb128 overflows");
        }
    }
}

fn i16_at(data: &[u8], off: usize) -> Result<i16> {
    Ok(i16::from_le_bytes([
        *data
            .get(off)
            .ok_or_else(|| crate::Error::new("truncated i16"))?,
        *data
            .get(off + 1)
            .ok_or_else(|| crate::Error::new("truncated i16"))?,
    ]))
}

fn i32_at(data: &[u8], off: usize) -> Result<i32> {
    let bytes = data
        .get(off..off + 4)
        .ok_or_else(|| crate::Error::new("truncated i32"))?;
    Ok(i32::from_le_bytes(
        bytes
            .try_into()
            .expect("i32 slice is 4 bytes"),
    ))
}

