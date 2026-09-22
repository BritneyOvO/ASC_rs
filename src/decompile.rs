//! Native class printer. Signatures are Java; method bodies are a direct lift
//! of Dalvik instructions, so they stay readable without a whole-program IR.

use crate::dex::{java_quote, java_type, ClassDef, CodeItem, Dex, EncodedField, EncodedMethod};
use crate::opcodes::{
    OpInfo, FMT_10T, FMT_10X, FMT_11N, FMT_11X, FMT_12X, FMT_20T, FMT_21C, FMT_21H, FMT_21S,
    FMT_21T, FMT_22B, FMT_22C, FMT_22S, FMT_22T, FMT_22X, FMT_23X, FMT_30T, FMT_31C, FMT_31I,
    FMT_31T, FMT_32X, FMT_35C, FMT_3RC, FMT_51L, IDX_FIELD, IDX_METHOD, IDX_STRING, IDX_TYPE, OPS,
};
use crate::Result;

pub fn decompile_class(data: &[u8], descriptor: &str) -> Result<String> {
    let dex = Dex::parse(data)?;
    let Some(def) = dex.find_class_def(descriptor)? else {
        bail!("Class {descriptor} not found in DEX.");
    };
    let class_desc = dex.type_desc(def.class_idx)?;
    let (package, simple) = split_class(&class_desc);
    let mut out = String::new();
    if !package.is_empty() {
        out.push_str("package ");
        out.push_str(&package);
        out.push_str(";\n\n");
    }
    out.push_str(&class_header(&dex, &def, &simple)?);
    out.push_str(" {\n");
    let class_data = if def.class_data_off == 0 {
        None
    } else {
        Some(dex.class_data_at(def.class_data_off)?.0)
    };
    if let Some(class_data) = &class_data {
        let literals = dex.static_literals(def.static_values_off)?;
        for (index, field) in class_data.static_fields.iter().enumerate() {
            let init = literals.get(index).map(String::as_str);
            out.push_str(&field_line(&dex, field, init)?);
            out.push('\n');
        }
        for field in &class_data.instance_fields {
            out.push_str(&field_line(&dex, field, None)?);
            out.push('\n');
        }
        if !class_data.static_fields.is_empty() || !class_data.instance_fields.is_empty() {
            out.push('\n');
        }
        let methods: Vec<&EncodedMethod> = class_data.methods().collect();
        for (index, method) in methods.iter().enumerate() {
            out.push_str(&method_block(&dex, &simple, method)?);
            if index + 1 != methods.len() {
                out.push('\n');
            }
        }
    }
    out.push_str("}\n");
    Ok(out)
}

fn class_header(dex: &Dex, def: &ClassDef, simple: &str) -> Result<String> {
    let flags = def.access_flags;
    let interface = flags & 0x200 != 0;
    let mut shown = flags;
    if interface {
        shown &= !0x400;
    }
    let mut mods = String::new();
    push_flag(&mut mods, shown, 0x1, "public");
    push_flag(&mut mods, shown, 0x2, "private");
    push_flag(&mut mods, shown, 0x4, "protected");
    push_flag(&mut mods, shown, 0x8, "static");
    push_flag(&mut mods, shown, 0x10, "final");
    push_flag(&mut mods, shown, 0x400, "abstract");
    let kind = if flags & 0x2000 != 0 {
        "@interface"
    } else if interface {
        "interface"
    } else if flags & 0x4000 != 0 {
        "enum"
    } else {
        "class"
    };
    let mut header = format!("{mods}{kind} {simple}");
    if def.superclass_idx != 0xffff_ffff {
        let super_desc = dex.type_desc(def.superclass_idx)?;
        if super_desc != "Ljava/lang/Object;" {
            header.push_str(" extends ");
            header.push_str(&java_type(&super_desc));
        }
    }
    let interfaces = dex.interfaces(def.interfaces_off)?;
    if !interfaces.is_empty() {
        let keyword = if interface {
            " extends "
        } else {
            " implements "
        };
        header.push_str(keyword);
        header.push_str(
            &interfaces
                .iter()
                .map(|desc| java_type(desc))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    Ok(header)
}

fn field_line(dex: &Dex, field: &EncodedField, init: Option<&str>) -> Result<String> {
    let id = dex.field_id(field.field_idx)?;
    let ty = java_type(&dex.type_desc(u32::from(id.type_idx))?);
    let name = dex.string(id.name_idx)?;
    let mods = member_mods(field.access_flags, true);
    if let Some(init) = init {
        Ok(format!("    {mods}{ty} {name} = {init};"))
    } else {
        Ok(format!("    {mods}{ty} {name};"))
    }
}

fn method_block(dex: &Dex, simple: &str, method: &EncodedMethod) -> Result<String> {
    let id = dex.method_id(method.method_idx)?;
    let name = dex.string(id.name_idx)?;
    let proto = dex.proto(u32::from(id.proto_idx))?;
    let params = proto
        .params
        .iter()
        .enumerate()
        .map(|(index, type_idx)| {
            dex.type_desc(*type_idx)
                .map(|desc| format!("{} p{index}", java_type(&desc)))
        })
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    let is_init = name == "<init>";
    let is_clinit = name == "<clinit>";
    let mods = if is_clinit {
        String::new()
    } else {
        member_mods(method.access_flags, false)
    };
    let signature = if is_clinit {
        "    static {".to_string()
    } else if is_init {
        format!("    {mods}{simple}({params}) {{")
    } else {
        let ret = java_type(&dex.type_desc(proto.return_type_idx)?);
        if method.code_off == 0 {
            return Ok(format!("    {mods}{ret} {name}({params});\n"));
        }
        format!("    {mods}{ret} {name}({params}) {{")
    };
    if method.code_off == 0 {
        return Ok(format!("{signature}\n"));
    }
    let mut out = signature;
    out.push('\n');
    let code = dex.code(method.code_off)?;
    out.push_str(&lift_code(dex, &code)?);
    out.push_str("    }\n");
    Ok(out)
}

fn lift_code(dex: &Dex, code: &CodeItem) -> Result<String> {
    let insns = code.insns;
    let mut pos = 0;
    let mut out = String::new();
    while pos + 1 < insns.len() {
        if let Some(nbytes) = payload_bytes(insns, pos) {
            if pos + nbytes > insns.len() {
                break;
            }
            out.push_str("        // data payload\n");
            pos += nbytes;
            continue;
        }
        let info = OPS[insns[pos] as usize];
        if info.len == 0 {
            out.push_str(&format!("        // unknown opcode {:#04x}\n", insns[pos]));
            break;
        }
        let nbytes = info.len as usize * 2;
        if pos + nbytes > insns.len() {
            break;
        }
        out.push_str("        ");
        out.push_str(&format_insn(dex, insns, pos, info)?);
        out.push('\n');
        pos += nbytes;
    }
    Ok(out)
}

fn payload_bytes(insns: &[u8], pos: usize) -> Option<usize> {
    if insns[pos] != 0x00 || pos + 4 > insns.len() {
        return None;
    }
    let ident = u16::from_le_bytes([insns[pos], insns[pos + 1]]);
    match ident {
        0x0100 => {
            let size = u16::from_le_bytes([insns[pos + 2], insns[pos + 3]]) as usize;
            Some(8 + size * 4)
        }
        0x0200 => {
            let size = u16::from_le_bytes([insns[pos + 2], insns[pos + 3]]) as usize;
            Some(4 + size * 8)
        }
        0x0300 => {
            if pos + 8 > insns.len() {
                return None;
            }
            let width = u16::from_le_bytes([insns[pos + 2], insns[pos + 3]]) as usize;
            let size = u32::from_le_bytes([
                insns[pos + 4],
                insns[pos + 5],
                insns[pos + 6],
                insns[pos + 7],
            ]) as usize;
            let bytes = 8 + width * size;
            Some((bytes + 1) & !1)
        }
        _ => None,
    }
}

fn format_insn(dex: &Dex, insns: &[u8], pos: usize, info: OpInfo) -> Result<String> {
    let name = info.name;
    if name == "return-void" {
        return Ok("return;".to_string());
    }
    if name == "return" || name == "return-wide" || name == "return-object" {
        return Ok(format!("return {};", reg(insns[pos + 1] as u32)));
    }
    if name == "throw" {
        return Ok(format!("throw {};", reg(insns[pos + 1] as u32)));
    }
    if name == "const-string" || name == "const-string/jumbo" {
        let (dest, idx) = if info.fmt == FMT_31C {
            (insns[pos + 1] as u32, u32_at(insns, pos + 2))
        } else {
            (insns[pos + 1] as u32, u32::from(u16_at(insns, pos + 2)))
        };
        return Ok(format!(
            "{} = {};",
            reg(dest),
            java_quote(&dex.string(idx)?)
        ));
    }
    if let Some(op) = if_op(name) {
        if name.ends_with('z') {
            let dest = insns[pos + 1] as u32;
            let off = i16_at(insns, pos + 2);
            return Ok(format!("if ({} {op}) goto {off:+};", reg(dest)));
        }
        let a = (insns[pos + 1] & 0x0f) as u32;
        let b = (insns[pos + 1] >> 4) as u32;
        let off = i16_at(insns, pos + 2);
        return Ok(format!("if ({} {op} {}) goto {off:+};", reg(a), reg(b)));
    }
    if name == "goto" {
        let off = insns[pos + 1] as i8 as i32;
        return Ok(format!("goto {off:+};"));
    }
    if name == "goto/16" {
        return Ok(format!("goto {:+};", i16_at(insns, pos + 2)));
    }
    if name == "goto/32" {
        return Ok(format!("goto {:+};", i32_at(insns, pos + 2)));
    }
    if name.starts_with("move")
        && !name.starts_with("move-result")
        && !name.starts_with("move-exception")
    {
        let (a, b) = regs_of_move(insns, pos, info.fmt);
        return Ok(format!("{} = {};", reg(a), reg(b)));
    }
    if name.starts_with("move-result") || name == "move-exception" {
        return Ok(format!("{} = result;", reg(insns[pos + 1] as u32)));
    }
    if name.starts_with("const/") || name == "const" || name.starts_with("const-wide") {
        let (dest, value) = const_literal(insns, pos, info.fmt, name);
        return Ok(format!("{} = {value};", reg(dest)));
    }
    if name.starts_with("iget") || name.starts_with("iput") {
        let a = (insns[pos + 1] & 0x0f) as u32;
        let b = (insns[pos + 1] >> 4) as u32;
        let field = dex.format_field(u32::from(u16_at(insns, pos + 2)))?;
        return if name.starts_with("iget") {
            Ok(format!("{} = {}.{field};", reg(a), reg(b)))
        } else {
            Ok(format!("{}.{field} = {};", reg(b), reg(a)))
        };
    }
    if name.starts_with("sget") || name.starts_with("sput") {
        let dest = insns[pos + 1] as u32;
        let field = dex.format_field(u32::from(u16_at(insns, pos + 2)))?;
        return if name.starts_with("sget") {
            Ok(format!("{} = {field};", reg(dest)))
        } else {
            Ok(format!("{field} = {};", reg(dest)))
        };
    }
    if name == "new-instance" {
        let dest = insns[pos + 1] as u32;
        let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)))?);
        return Ok(format!("{} = new {ty}();", reg(dest)));
    }
    if name == "new-array" {
        let a = (insns[pos + 1] & 0x0f) as u32;
        let b = (insns[pos + 1] >> 4) as u32;
        let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)))?);
        let elem = ty.trim_end_matches("[]");
        return Ok(format!("{} = new {elem}[{}];", reg(a), reg(b)));
    }
    if name == "array-length" {
        let a = (insns[pos + 1] & 0x0f) as u32;
        let b = (insns[pos + 1] >> 4) as u32;
        return Ok(format!("{} = {}.length;", reg(a), reg(b)));
    }
    if name == "check-cast" {
        let dest = insns[pos + 1] as u32;
        let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)))?);
        return Ok(format!("{} = ({ty}) {};", reg(dest), reg(dest)));
    }
    if name == "instance-of" {
        let a = (insns[pos + 1] & 0x0f) as u32;
        let b = (insns[pos + 1] >> 4) as u32;
        let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)))?);
        return Ok(format!("{} = {} instanceof {ty};", reg(a), reg(b)));
    }
    if name.starts_with("invoke-") {
        return format_invoke(dex, insns, pos, name);
    }
    if let Some(symbol) = binary_symbol(name) {
        if name.contains("2addr") {
            let a = (insns[pos + 1] & 0x0f) as u32;
            let b = (insns[pos + 1] >> 4) as u32;
            return Ok(format!("{} = {} {symbol} {};", reg(a), reg(a), reg(b)));
        }
        if name.contains("lit") || name.starts_with("rsub") {
            let (a, b, lit) = lit_binop(insns, pos, info.fmt);
            if name.starts_with("rsub") {
                return Ok(format!("{} = {lit} - {};", reg(a), reg(b)));
            }
            return Ok(format!("{} = {} {symbol} {lit};", reg(a), reg(b)));
        }
        let a = insns[pos + 1] as u32;
        let b = insns[pos + 2] as u32;
        let c = insns[pos + 3] as u32;
        return Ok(format!("{} = {} {symbol} {};", reg(a), reg(b), reg(c)));
    }
    Ok(format!(
        "{name} {}",
        fallback_operands(dex, insns, pos, info)?
    ))
}

fn format_invoke(dex: &Dex, insns: &[u8], pos: usize, name: &str) -> Result<String> {
    let (index, regs, _proto) = invoke_operands(insns, pos, name);
    let method = dex.method_id(index)?;
    let method_name = dex.string(method.name_idx)?;
    let owner = java_type(&dex.type_desc(u32::from(method.class_idx))?);
    let rendered: Vec<String> = regs.iter().map(|reg| reg_name(*reg)).collect();
    let call = if name.contains("static") || name.contains("custom") {
        format!("{owner}.{method_name}({})", rendered.join(", "))
    } else if rendered.is_empty() {
        format!("{owner}.{method_name}()")
    } else {
        format!(
            "{}.{method_name}({})",
            rendered[0],
            rendered[1..].join(", ")
        )
    };
    Ok(format!("{call};"))
}

fn invoke_operands(insns: &[u8], pos: usize, name: &str) -> (u32, Vec<u32>, Option<u32>) {
    if name.contains("range") {
        let count = insns[pos + 1] as u32;
        let index = u32::from(u16_at(insns, pos + 2));
        let start = u32::from(u16_at(insns, pos + 4));
        let proto = if name.contains("polymorphic") {
            Some(u32::from(u16_at(insns, pos + 6)))
        } else {
            None
        };
        let regs = (0..count).map(|offset| start + offset).collect();
        (index, regs, proto)
    } else {
        let byte = insns[pos + 1];
        let count = (byte & 0x0f) as usize;
        let g = (byte >> 4) as u32;
        let index = u32::from(u16_at(insns, pos + 2));
        let fedc = u16_at(insns, pos + 4);
        let nibbles = [
            (fedc & 0x0f) as u32,
            ((fedc >> 4) & 0x0f) as u32,
            ((fedc >> 8) & 0x0f) as u32,
            ((fedc >> 12) & 0x0f) as u32,
            g,
        ];
        let proto = if name.contains("polymorphic") {
            Some(u32::from(u16_at(insns, pos + 6)))
        } else {
            None
        };
        (index, nibbles[..count.min(5)].to_vec(), proto)
    }
}

fn fallback_operands(dex: &Dex, insns: &[u8], pos: usize, info: OpInfo) -> Result<String> {
    let text = match info.fmt {
        FMT_10X => String::new(),
        FMT_12X | FMT_11N => {
            let a = (insns[pos + 1] & 0x0f) as u32;
            let b = (insns[pos + 1] >> 4) as u32;
            format!("{}, {}", reg(a), reg(b))
        }
        FMT_11X | FMT_10T => reg(insns[pos + 1] as u32),
        FMT_22X | FMT_21T | FMT_21S | FMT_21H | FMT_21C => {
            let a = insns[pos + 1] as u32;
            let b = u16_at(insns, pos + 2);
            format!("{}, {}", reg(a), ref_or_raw(dex, info.index, u32::from(b))?)
        }
        FMT_23X => format!(
            "{}, {}, {}",
            reg(insns[pos + 1] as u32),
            reg(insns[pos + 2] as u32),
            reg(insns[pos + 3] as u32)
        ),
        FMT_22C | FMT_22T | FMT_22S => {
            let a = (insns[pos + 1] & 0x0f) as u32;
            let b = (insns[pos + 1] >> 4) as u32;
            format!(
                "{}, {}, {}",
                reg(a),
                reg(b),
                ref_or_raw(dex, info.index, u32::from(u16_at(insns, pos + 2)))?
            )
        }
        FMT_35C | FMT_3RC | FMT_31C | FMT_31I | FMT_31T | FMT_32X | FMT_30T | FMT_51L | FMT_20T
        | FMT_22B => name_bytes(insns, pos, info.len),
        _ => name_bytes(insns, pos, info.len),
    };
    Ok(text)
}

fn ref_or_raw(dex: &Dex, index_kind: u8, idx: u32) -> Result<String> {
    match index_kind {
        IDX_STRING => Ok(java_quote(&dex.string(idx)?)),
        IDX_TYPE => Ok(java_type(&dex.type_desc(idx)?)),
        IDX_FIELD => dex.format_field(idx),
        IDX_METHOD => dex.format_method(idx),
        _ => Ok(format!("@{idx}")),
    }
}

fn name_bytes(insns: &[u8], pos: usize, len: u8) -> String {
    insns[pos + 1..pos + len as usize * 2]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn regs_of_move(insns: &[u8], pos: usize, fmt: u8) -> (u32, u32) {
    match fmt {
        FMT_12X => ((insns[pos + 1] & 0x0f) as u32, (insns[pos + 1] >> 4) as u32),
        FMT_22X => (insns[pos + 1] as u32, u32::from(u16_at(insns, pos + 2))),
        FMT_32X => (
            u32::from(u16_at(insns, pos + 2)),
            u32::from(u16_at(insns, pos + 4)),
        ),
        _ => (insns[pos + 1] as u32, 0),
    }
}

fn const_literal(insns: &[u8], pos: usize, fmt: u8, name: &str) -> (u32, String) {
    match fmt {
        FMT_11N => {
            let a = (insns[pos + 1] & 0x0f) as u32;
            let nibble = (insns[pos + 1] >> 4) as i32;
            let value = if nibble & 0x8 != 0 {
                nibble - 16
            } else {
                nibble
            };
            (a, value.to_string())
        }
        FMT_21S => (insns[pos + 1] as u32, i16_at(insns, pos + 2).to_string()),
        FMT_21H => {
            let dest = insns[pos + 1] as u32;
            let high = u32::from(u16_at(insns, pos + 2));
            if name.contains("wide") {
                (dest, format!("{}", (high as i64) << 48))
            } else {
                (dest, format!("{}", (high as i32) << 16))
            }
        }
        FMT_31I => (insns[pos + 1] as u32, i32_at(insns, pos + 2).to_string()),
        FMT_51L => (insns[pos + 1] as u32, i64_at(insns, pos + 2).to_string()),
        _ => (insns[pos + 1] as u32, "0".to_string()),
    }
}

fn lit_binop(insns: &[u8], pos: usize, fmt: u8) -> (u32, u32, i32) {
    if fmt == FMT_22B {
        let a = insns[pos + 1] as u32;
        let b = insns[pos + 2] as u32;
        let lit = insns[pos + 3] as i8 as i32;
        (a, b, lit)
    } else {
        let a = (insns[pos + 1] & 0x0f) as u32;
        let b = (insns[pos + 1] >> 4) as u32;
        (a, b, i32::from(i16_at(insns, pos + 2)))
    }
}

fn if_op(name: &str) -> Option<&'static str> {
    Some(match name {
        "if-eq" => "==",
        "if-ne" => "!=",
        "if-lt" => "<",
        "if-ge" => ">=",
        "if-gt" => ">",
        "if-le" => "<=",
        "if-eqz" => "== 0",
        "if-nez" => "!= 0",
        "if-ltz" => "< 0",
        "if-gez" => ">= 0",
        "if-gtz" => "> 0",
        "if-lez" => "<= 0",
        _ => return None,
    })
}

fn binary_symbol(name: &str) -> Option<&'static str> {
    let base = name.split('/').next().unwrap_or(name);
    let base = base.strip_prefix("rsub").map(|_| "rsub").unwrap_or(base);
    Some(match base {
        "add-int" | "add-long" | "add-float" | "add-double" => "+",
        "sub-int" | "sub-long" | "sub-float" | "sub-double" | "rsub" => "-",
        "mul-int" | "mul-long" | "mul-float" | "mul-double" => "*",
        "div-int" | "div-long" | "div-float" | "div-double" => "/",
        "rem-int" | "rem-long" | "rem-float" | "rem-double" => "%",
        "and-int" | "and-long" => "&",
        "or-int" | "or-long" => "|",
        "xor-int" | "xor-long" => "^",
        "shl-int" | "shl-long" => "<<",
        "shr-int" | "shr-long" => ">>",
        "ushr-int" | "ushr-long" => ">>>",
        _ => return None,
    })
}

fn member_mods(flags: u32, field: bool) -> String {
    let mut mods = String::new();
    push_flag(&mut mods, flags, 0x1, "public");
    push_flag(&mut mods, flags, 0x2, "private");
    push_flag(&mut mods, flags, 0x4, "protected");
    push_flag(&mut mods, flags, 0x8, "static");
    push_flag(&mut mods, flags, 0x10, "final");
    push_flag(&mut mods, flags, 0x20, "synchronized");
    if field {
        push_flag(&mut mods, flags, 0x40, "volatile");
        push_flag(&mut mods, flags, 0x80, "transient");
    } else {
        push_flag(&mut mods, flags, 0x100, "native");
        push_flag(&mut mods, flags, 0x400, "abstract");
    }
    mods
}

fn push_flag(out: &mut String, flags: u32, bit: u32, name: &str) {
    if flags & bit != 0 {
        out.push_str(name);
        out.push(' ');
    }
}

fn split_class(desc: &str) -> (String, String) {
    let inner = desc.trim_start_matches('L').trim_end_matches(';');
    if let Some((package, name)) = inner.rsplit_once('/') {
        (package.replace('/', "."), name.to_string())
    } else {
        (String::new(), inner.to_string())
    }
}

fn reg(index: u32) -> String {
    reg_name(index)
}

fn reg_name(index: u32) -> String {
    format!("v{index}")
}

fn u16_at(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn i16_at(data: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([data[off], data[off + 1]])
}

fn i32_at(data: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn i64_at(data: &[u8], off: usize) -> i64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[off..off + 8]);
    i64::from_le_bytes(buf)
}
