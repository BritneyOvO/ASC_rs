//! Native class printer. Signatures are Java; method bodies are a direct lift
//! of Dalvik instructions, so they stay readable without a whole-program IR.

use crate::bytes::{u16_at, u32_at};
use crate::dex::{java_quote, java_type, ClassDef, CodeItem, Dex, EncodedField, EncodedMethod};
use crate::opcodes::{
    payload_len, Arith, BinShape, Fmt, IfKind, IndexKind, InvokeShape, InvokeTarget, OpInfo,
    OpKind, OPS,
};
use crate::Result;

const ACC_PUBLIC: u32 = 0x0001;
const ACC_PRIVATE: u32 = 0x0002;
const ACC_PROTECTED: u32 = 0x0004;
const ACC_STATIC: u32 = 0x0008;
const ACC_FINAL: u32 = 0x0010;
const ACC_SYNCHRONIZED: u32 = 0x0020;
const ACC_VOLATILE: u32 = 0x0040;
const ACC_TRANSIENT: u32 = 0x0080;
const ACC_NATIVE: u32 = 0x0100;
const ACC_INTERFACE: u32 = 0x0200;
const ACC_ABSTRACT: u32 = 0x0400;
const ACC_ANNOTATION: u32 = 0x2000;
const ACC_ENUM: u32 = 0x4000;

enum Member {
    Field,
    Method,
}

pub fn decompile_class(data: &[u8], descriptor: &str) -> Result<String> {
    let dex = Dex::parse(data)?;
    let Some(def) = dex.find_class_def(descriptor)? else {
        bail!("Class {descriptor} not found in DEX.");
    };
    decompile_class_def(&dex, &def)
}

pub fn decompile_class_def(dex: &Dex<'_>, def: &ClassDef) -> Result<String> {
    let class_desc = dex.type_desc(def.class_idx)?;
    let (package, simple) = split_class(&class_desc);
    let mut out = String::new();
    if !package.is_empty() {
        out.push_str("package ");
        out.push_str(&package);
        out.push_str(";\n\n");
    }
    out.push_str(&class_header(dex, def, &simple)?);
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
            out.push_str(&field_line(dex, field, init)?);
            out.push('\n');
        }
        for field in &class_data.instance_fields {
            out.push_str(&field_line(dex, field, None)?);
            out.push('\n');
        }
        if !class_data.static_fields.is_empty() || !class_data.instance_fields.is_empty() {
            out.push('\n');
        }
        let methods: Vec<&EncodedMethod> = class_data.methods().collect();
        for (index, method) in methods.iter().enumerate() {
            out.push_str(&method_block(dex, &simple, method)?);
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
    let interface = flags & ACC_INTERFACE != 0;
    let mut shown = flags;
    if interface {
        shown &= !ACC_ABSTRACT;
    }
    let mut mods = String::new();
    push_flag(&mut mods, shown, ACC_PUBLIC, "public");
    push_flag(&mut mods, shown, ACC_PRIVATE, "private");
    push_flag(&mut mods, shown, ACC_PROTECTED, "protected");
    push_flag(&mut mods, shown, ACC_STATIC, "static");
    push_flag(&mut mods, shown, ACC_FINAL, "final");
    push_flag(&mut mods, shown, ACC_ABSTRACT, "abstract");
    let kind = if flags & ACC_ANNOTATION != 0 {
        "@interface"
    } else if interface {
        "interface"
    } else if flags & ACC_ENUM != 0 {
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
    let mods = member_mods(field.access_flags, Member::Field);
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
        member_mods(method.access_flags, Member::Method)
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
        if let Some(nbytes) = payload_len(insns, pos) {
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

fn format_insn(dex: &Dex, insns: &[u8], pos: usize, info: OpInfo) -> Result<String> {
    match info.kind {
        OpKind::ReturnVoid => Ok("return;".to_string()),
        OpKind::Return => Ok(format!("return {};", reg(u32::from(insns[pos + 1])))),
        OpKind::Throw => Ok(format!("throw {};", reg(u32::from(insns[pos + 1])))),
        OpKind::ConstString => {
            let (dest, idx) = match info.fmt {
                Fmt::F31c => (u32::from(insns[pos + 1]), u32_at(insns, pos + 2)?),
                Fmt::F21c => (
                    u32::from(insns[pos + 1]),
                    u32::from(u16_at(insns, pos + 2)?),
                ),
                Fmt::F10x
                | Fmt::F12x
                | Fmt::F11n
                | Fmt::F11x
                | Fmt::F10t
                | Fmt::F20t
                | Fmt::F22x
                | Fmt::F21t
                | Fmt::F21s
                | Fmt::F21h
                | Fmt::F23x
                | Fmt::F22b
                | Fmt::F22t
                | Fmt::F22s
                | Fmt::F22c
                | Fmt::F32x
                | Fmt::F30t
                | Fmt::F31t
                | Fmt::F31i
                | Fmt::F35c
                | Fmt::F3rc
                | Fmt::F51l
                | Fmt::F45cc
                | Fmt::F4rcc => (
                    u32::from(insns[pos + 1]),
                    u32::from(u16_at(insns, pos + 2)?),
                ),
            };
            Ok(format!(
                "{} = {};",
                reg(dest),
                java_quote(&dex.string(idx)?)
            ))
        }
        OpKind::If(kind) => format_if(insns, pos, kind),
        OpKind::Goto => {
            let off = i32::from(insns[pos + 1] as i8);
            Ok(format!("goto {off:+};"))
        }
        OpKind::Goto16 => Ok(format!("goto {:+};", i16_at(insns, pos + 2)?)),
        OpKind::Goto32 => Ok(format!("goto {:+};", i32_at(insns, pos + 2)?)),
        OpKind::Move => {
            let (a, b) = regs_of_move(insns, pos, info.fmt)?;
            Ok(format!("{} = {};", reg(a), reg(b)))
        }
        OpKind::MoveResult => Ok(format!("{} = result;", reg(u32::from(insns[pos + 1])))),
        OpKind::Const { wide } => {
            let (dest, value) = const_literal(insns, pos, info.fmt, wide)?;
            Ok(format!("{} = {value};", reg(dest)))
        }
        OpKind::Iget | OpKind::Iput => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            let field = dex.format_field(u32::from(u16_at(insns, pos + 2)?))?;
            if matches!(info.kind, OpKind::Iget) {
                Ok(format!("{} = {}.{field};", reg(a), reg(b)))
            } else {
                Ok(format!("{}.{field} = {};", reg(b), reg(a)))
            }
        }
        OpKind::Sget | OpKind::Sput => {
            let dest = u32::from(insns[pos + 1]);
            let field = dex.format_field(u32::from(u16_at(insns, pos + 2)?))?;
            if matches!(info.kind, OpKind::Sget) {
                Ok(format!("{} = {field};", reg(dest)))
            } else {
                Ok(format!("{field} = {};", reg(dest)))
            }
        }
        OpKind::NewInstance => {
            let dest = u32::from(insns[pos + 1]);
            let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)?))?);
            Ok(format!("{} = new {ty}();", reg(dest)))
        }
        OpKind::NewArray => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)?))?);
            let elem = ty.strip_suffix("[]").unwrap_or(&ty);
            Ok(format!("{} = new {elem}[{}];", reg(a), reg(b)))
        }
        OpKind::ArrayLength => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            Ok(format!("{} = {}.length;", reg(a), reg(b)))
        }
        OpKind::CheckCast => {
            let dest = u32::from(insns[pos + 1]);
            let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)?))?);
            Ok(format!("{} = ({ty}) {};", reg(dest), reg(dest)))
        }
        OpKind::InstanceOf => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            let ty = java_type(&dex.type_desc(u32::from(u16_at(insns, pos + 2)?))?);
            Ok(format!("{} = {} instanceof {ty};", reg(a), reg(b)))
        }
        OpKind::Invoke { target, shape } => format_invoke(dex, insns, pos, target, shape),
        OpKind::Binop { arith, shape } => format_binop(insns, pos, info.fmt, arith, shape),
        OpKind::Plain => Ok(format!(
            "{} {}",
            info.name,
            fallback_operands(dex, insns, pos, info)?
        )),
    }
}

fn format_if(insns: &[u8], pos: usize, kind: IfKind) -> Result<String> {
    let off = i16_at(insns, pos + 2)?;
    match kind {
        IfKind::Zero(cmp) => {
            let dest = u32::from(insns[pos + 1]);
            Ok(format!(
                "if ({} {} 0) goto {off:+};",
                reg(dest),
                cmp.symbol()
            ))
        }
        IfKind::Cmp(cmp) => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            Ok(format!(
                "if ({} {} {}) goto {off:+};",
                reg(a),
                cmp.symbol(),
                reg(b)
            ))
        }
    }
}

fn format_binop(
    insns: &[u8],
    pos: usize,
    fmt: Fmt,
    arith: Arith,
    shape: BinShape,
) -> Result<String> {
    let symbol = arith.symbol();
    match shape {
        BinShape::TwoAddr => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            Ok(format!("{} = {} {symbol} {};", reg(a), reg(a), reg(b)))
        }
        BinShape::Rsub => {
            let (a, b, lit) = lit_binop(insns, pos, fmt)?;
            Ok(format!("{} = {lit} - {};", reg(a), reg(b)))
        }
        BinShape::Lit => {
            let (a, b, lit) = lit_binop(insns, pos, fmt)?;
            Ok(format!("{} = {} {symbol} {lit};", reg(a), reg(b)))
        }
        BinShape::Regs => {
            let a = u32::from(insns[pos + 1]);
            let b = u32::from(insns[pos + 2]);
            let c = u32::from(insns[pos + 3]);
            Ok(format!("{} = {} {symbol} {};", reg(a), reg(b), reg(c)))
        }
    }
}

fn format_invoke(
    dex: &Dex,
    insns: &[u8],
    pos: usize,
    target: InvokeTarget,
    shape: InvokeShape,
) -> Result<String> {
    let (index, regs, _proto) = invoke_operands(insns, pos, target, shape)?;
    let method = dex.method_id(index)?;
    let method_name = dex.string(method.name_idx)?;
    let owner = java_type(&dex.type_desc(u32::from(method.class_idx))?);
    let rendered: Vec<String> = regs.iter().map(|reg| reg_name(*reg)).collect();
    let call = if target.skips_receiver() {
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

fn invoke_operands(
    insns: &[u8],
    pos: usize,
    target: InvokeTarget,
    shape: InvokeShape,
) -> Result<(u32, Vec<u32>, Option<u32>)> {
    match shape {
        InvokeShape::Range => {
            let count = u32::from(insns[pos + 1]);
            let index = u32::from(u16_at(insns, pos + 2)?);
            let start = u32::from(u16_at(insns, pos + 4)?);
            let proto = if target.carries_proto() {
                Some(u32::from(u16_at(insns, pos + 6)?))
            } else {
                None
            };
            let regs = (0..count).map(|offset| start + offset).collect();
            Ok((index, regs, proto))
        }
        InvokeShape::List => {
            let byte = insns[pos + 1];
            let count = usize::from(byte & 0x0f);
            let g = u32::from(byte >> 4);
            let index = u32::from(u16_at(insns, pos + 2)?);
            let fedc = u16_at(insns, pos + 4)?;
            let nibbles = [
                u32::from(fedc & 0x0f),
                u32::from((fedc >> 4) & 0x0f),
                u32::from((fedc >> 8) & 0x0f),
                u32::from((fedc >> 12) & 0x0f),
                g,
            ];
            let proto = if target.carries_proto() {
                Some(u32::from(u16_at(insns, pos + 6)?))
            } else {
                None
            };
            Ok((index, nibbles[..count.min(5)].to_vec(), proto))
        }
    }
}

fn fallback_operands(dex: &Dex, insns: &[u8], pos: usize, info: OpInfo) -> Result<String> {
    let text = match info.fmt {
        Fmt::F10x => String::new(),
        Fmt::F12x | Fmt::F11n => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            format!("{}, {}", reg(a), reg(b))
        }
        Fmt::F11x | Fmt::F10t => reg(u32::from(insns[pos + 1])),
        Fmt::F22x | Fmt::F21t | Fmt::F21s | Fmt::F21h | Fmt::F21c => {
            let a = u32::from(insns[pos + 1]);
            let b = u16_at(insns, pos + 2)?;
            format!("{}, {}", reg(a), ref_or_raw(dex, info.index, u32::from(b))?)
        }
        Fmt::F23x => format!(
            "{}, {}, {}",
            reg(u32::from(insns[pos + 1])),
            reg(u32::from(insns[pos + 2])),
            reg(u32::from(insns[pos + 3]))
        ),
        Fmt::F22c | Fmt::F22t | Fmt::F22s => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let b = u32::from(insns[pos + 1] >> 4);
            format!(
                "{}, {}, {}",
                reg(a),
                reg(b),
                ref_or_raw(dex, info.index, u32::from(u16_at(insns, pos + 2)?))?
            )
        }
        Fmt::F35c
        | Fmt::F3rc
        | Fmt::F31c
        | Fmt::F31i
        | Fmt::F31t
        | Fmt::F32x
        | Fmt::F30t
        | Fmt::F51l
        | Fmt::F20t
        | Fmt::F22b
        | Fmt::F45cc
        | Fmt::F4rcc => name_bytes(insns, pos, info.len),
    };
    Ok(text)
}

fn ref_or_raw(dex: &Dex, index_kind: IndexKind, idx: u32) -> Result<String> {
    match index_kind {
        IndexKind::String => Ok(java_quote(&dex.string(idx)?)),
        IndexKind::Type => Ok(java_type(&dex.type_desc(idx)?)),
        IndexKind::Field => dex.format_field(idx),
        IndexKind::Method => dex.format_method(idx),
        IndexKind::None
        | IndexKind::MethodProto
        | IndexKind::CallSite
        | IndexKind::MethodHandle
        | IndexKind::Proto => Ok(format!("@{idx}")),
    }
}

fn name_bytes(insns: &[u8], pos: usize, len: u8) -> String {
    insns[pos + 1..pos + usize::from(len) * 2]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn regs_of_move(insns: &[u8], pos: usize, fmt: Fmt) -> Result<(u32, u32)> {
    match fmt {
        Fmt::F12x => Ok((
            u32::from(insns[pos + 1] & 0x0f),
            u32::from(insns[pos + 1] >> 4),
        )),
        Fmt::F22x => Ok((
            u32::from(insns[pos + 1]),
            u32::from(u16_at(insns, pos + 2)?),
        )),
        Fmt::F32x => Ok((
            u32::from(u16_at(insns, pos + 2)?),
            u32::from(u16_at(insns, pos + 4)?),
        )),
        Fmt::F10x
        | Fmt::F11n
        | Fmt::F11x
        | Fmt::F10t
        | Fmt::F20t
        | Fmt::F21t
        | Fmt::F21s
        | Fmt::F21h
        | Fmt::F21c
        | Fmt::F23x
        | Fmt::F22b
        | Fmt::F22t
        | Fmt::F22s
        | Fmt::F22c
        | Fmt::F30t
        | Fmt::F31t
        | Fmt::F31i
        | Fmt::F31c
        | Fmt::F35c
        | Fmt::F3rc
        | Fmt::F51l
        | Fmt::F45cc
        | Fmt::F4rcc => Ok((u32::from(insns[pos + 1]), 0)),
    }
}

fn const_literal(insns: &[u8], pos: usize, fmt: Fmt, wide: bool) -> Result<(u32, String)> {
    match fmt {
        Fmt::F11n => {
            let a = u32::from(insns[pos + 1] & 0x0f);
            let nibble = i32::from(insns[pos + 1] >> 4);
            let value = if nibble & 0x8 != 0 {
                nibble - 16
            } else {
                nibble
            };
            Ok((a, value.to_string()))
        }
        Fmt::F21s => Ok((
            u32::from(insns[pos + 1]),
            i16_at(insns, pos + 2)?.to_string(),
        )),
        Fmt::F21h => {
            let dest = u32::from(insns[pos + 1]);
            let high = u16_at(insns, pos + 2)?;
            if wide {
                Ok((dest, format!("{}", i64::from(high) << 48)))
            } else {
                Ok((dest, format!("{}", i32::from(high) << 16)))
            }
        }
        Fmt::F31i => Ok((
            u32::from(insns[pos + 1]),
            i32_at(insns, pos + 2)?.to_string(),
        )),
        Fmt::F51l => Ok((
            u32::from(insns[pos + 1]),
            i64_at(insns, pos + 2)?.to_string(),
        )),
        Fmt::F10x
        | Fmt::F12x
        | Fmt::F11x
        | Fmt::F10t
        | Fmt::F20t
        | Fmt::F22x
        | Fmt::F21t
        | Fmt::F21c
        | Fmt::F23x
        | Fmt::F22b
        | Fmt::F22t
        | Fmt::F22s
        | Fmt::F22c
        | Fmt::F32x
        | Fmt::F30t
        | Fmt::F31t
        | Fmt::F31c
        | Fmt::F35c
        | Fmt::F3rc
        | Fmt::F45cc
        | Fmt::F4rcc => Ok((u32::from(insns[pos + 1]), "0".to_string())),
    }
}

fn lit_binop(insns: &[u8], pos: usize, fmt: Fmt) -> Result<(u32, u32, i32)> {
    if let Fmt::F22b = fmt {
        let a = u32::from(insns[pos + 1]);
        let b = u32::from(insns[pos + 2]);
        let lit = i32::from(insns[pos + 3] as i8);
        return Ok((a, b, lit));
    }
    let a = u32::from(insns[pos + 1] & 0x0f);
    let b = u32::from(insns[pos + 1] >> 4);
    Ok((a, b, i32::from(i16_at(insns, pos + 2)?)))
}

fn member_mods(flags: u32, member: Member) -> String {
    let mut mods = String::new();
    push_flag(&mut mods, flags, ACC_PUBLIC, "public");
    push_flag(&mut mods, flags, ACC_PRIVATE, "private");
    push_flag(&mut mods, flags, ACC_PROTECTED, "protected");
    push_flag(&mut mods, flags, ACC_STATIC, "static");
    push_flag(&mut mods, flags, ACC_FINAL, "final");
    push_flag(&mut mods, flags, ACC_SYNCHRONIZED, "synchronized");
    match member {
        Member::Field => {
            push_flag(&mut mods, flags, ACC_VOLATILE, "volatile");
            push_flag(&mut mods, flags, ACC_TRANSIENT, "transient");
        }
        Member::Method => {
            push_flag(&mut mods, flags, ACC_NATIVE, "native");
            push_flag(&mut mods, flags, ACC_ABSTRACT, "abstract");
        }
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

fn i16_at(data: &[u8], off: usize) -> Result<i16> {
    Ok(i16::from_le_bytes(u16_at(data, off)?.to_le_bytes()))
}

fn i32_at(data: &[u8], off: usize) -> Result<i32> {
    Ok(i32::from_le_bytes(u32_at(data, off)?.to_le_bytes()))
}

fn i64_at(data: &[u8], off: usize) -> Result<i64> {
    let bytes = data
        .get(off..off + 8)
        .ok_or_else(|| crate::Error::new(format!("truncated read at {off:#x}")))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(i64::from_le_bytes(buf))
}
