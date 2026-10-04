//! Dalvik opcode lengths, formats, and names for the smali printer.
//!
//! The table below is the only mapping from opcode byte to name, width, and
//! format. Adding an opcode means adding one row.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fmt {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F32x,
    F30t,
    F31t,
    F31i,
    F31c,
    F35c,
    F3rc,
    F51l,
    F45cc,
    F4rcc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexKind {
    None,
    String,
    Type,
    Field,
    Method,
    MethodProto,
    CallSite,
    MethodHandle,
    Proto,
}

#[derive(Clone, Copy)]
pub struct OpInfo {
    pub name: &'static str,
    pub len: u8,
    pub fmt: Fmt,
    pub index: IndexKind,
}

macro_rules! opcodes {
    ($(($name:literal, $len:expr, $fmt:ident, $index:ident),)*) => {
        pub static OPS: [OpInfo; 256] = [$(
            OpInfo {
                name: $name,
                len: $len,
                fmt: Fmt::$fmt,
                index: IndexKind::$index,
            },
        )*];
    };
}

opcodes! {
    ("nop", 1, F10x, None),
    ("move", 1, F12x, None),
    ("move/from16", 2, F22x, None),
    ("move/16", 3, F32x, None),
    ("move-wide", 1, F12x, None),
    ("move-wide/from16", 2, F22x, None),
    ("move-wide/16", 3, F32x, None),
    ("move-object", 1, F12x, None),
    ("move-object/from16", 2, F22x, None),
    ("move-object/16", 3, F32x, None),
    ("move-result", 1, F11x, None),
    ("move-result-wide", 1, F11x, None),
    ("move-result-object", 1, F11x, None),
    ("move-exception", 1, F11x, None),
    ("return-void", 1, F10x, None),
    ("return", 1, F11x, None),
    ("return-wide", 1, F11x, None),
    ("return-object", 1, F11x, None),
    ("const/4", 1, F11n, None),
    ("const/16", 2, F21s, None),
    ("const", 3, F31i, None),
    ("const/high16", 2, F21h, None),
    ("const-wide/16", 2, F21s, None),
    ("const-wide/32", 3, F31i, None),
    ("const-wide", 5, F51l, None),
    ("const-wide/high16", 2, F21h, None),
    ("const-string", 2, F21c, String),
    ("const-string/jumbo", 3, F31c, String),
    ("const-class", 2, F21c, Type),
    ("monitor-enter", 1, F11x, None),
    ("monitor-exit", 1, F11x, None),
    ("check-cast", 2, F21c, Type),
    ("instance-of", 2, F22c, Type),
    ("array-length", 1, F12x, None),
    ("new-instance", 2, F21c, Type),
    ("new-array", 2, F22c, Type),
    ("filled-new-array", 3, F35c, Type),
    ("filled-new-array/range", 3, F3rc, Type),
    ("fill-array-data", 3, F31t, None),
    ("throw", 1, F11x, None),
    ("goto", 1, F10t, None),
    ("goto/16", 2, F20t, None),
    ("goto/32", 3, F30t, None),
    ("packed-switch", 3, F31t, None),
    ("sparse-switch", 3, F31t, None),
    ("cmpl-float", 2, F23x, None),
    ("cmpg-float", 2, F23x, None),
    ("cmpl-double", 2, F23x, None),
    ("cmpg-double", 2, F23x, None),
    ("cmp-long", 2, F23x, None),
    ("if-eq", 2, F22t, None),
    ("if-ne", 2, F22t, None),
    ("if-lt", 2, F22t, None),
    ("if-ge", 2, F22t, None),
    ("if-gt", 2, F22t, None),
    ("if-le", 2, F22t, None),
    ("if-eqz", 2, F21t, None),
    ("if-nez", 2, F21t, None),
    ("if-ltz", 2, F21t, None),
    ("if-gez", 2, F21t, None),
    ("if-gtz", 2, F21t, None),
    ("if-lez", 2, F21t, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("aget", 2, F23x, None),
    ("aget-wide", 2, F23x, None),
    ("aget-object", 2, F23x, None),
    ("aget-boolean", 2, F23x, None),
    ("aget-byte", 2, F23x, None),
    ("aget-char", 2, F23x, None),
    ("aget-short", 2, F23x, None),
    ("aput", 2, F23x, None),
    ("aput-wide", 2, F23x, None),
    ("aput-object", 2, F23x, None),
    ("aput-boolean", 2, F23x, None),
    ("aput-byte", 2, F23x, None),
    ("aput-char", 2, F23x, None),
    ("aput-short", 2, F23x, None),
    ("iget", 2, F22c, Field),
    ("iget-wide", 2, F22c, Field),
    ("iget-object", 2, F22c, Field),
    ("iget-boolean", 2, F22c, Field),
    ("iget-byte", 2, F22c, Field),
    ("iget-char", 2, F22c, Field),
    ("iget-short", 2, F22c, Field),
    ("iput", 2, F22c, Field),
    ("iput-wide", 2, F22c, Field),
    ("iput-object", 2, F22c, Field),
    ("iput-boolean", 2, F22c, Field),
    ("iput-byte", 2, F22c, Field),
    ("iput-char", 2, F22c, Field),
    ("iput-short", 2, F22c, Field),
    ("sget", 2, F21c, Field),
    ("sget-wide", 2, F21c, Field),
    ("sget-object", 2, F21c, Field),
    ("sget-boolean", 2, F21c, Field),
    ("sget-byte", 2, F21c, Field),
    ("sget-char", 2, F21c, Field),
    ("sget-short", 2, F21c, Field),
    ("sput", 2, F21c, Field),
    ("sput-wide", 2, F21c, Field),
    ("sput-object", 2, F21c, Field),
    ("sput-boolean", 2, F21c, Field),
    ("sput-byte", 2, F21c, Field),
    ("sput-char", 2, F21c, Field),
    ("sput-short", 2, F21c, Field),
    ("invoke-virtual", 3, F35c, Method),
    ("invoke-super", 3, F35c, Method),
    ("invoke-direct", 3, F35c, Method),
    ("invoke-static", 3, F35c, Method),
    ("invoke-interface", 3, F35c, Method),
    ("unused", 0, F10x, None),
    ("invoke-virtual/range", 3, F3rc, Method),
    ("invoke-super/range", 3, F3rc, Method),
    ("invoke-direct/range", 3, F3rc, Method),
    ("invoke-static/range", 3, F3rc, Method),
    ("invoke-interface/range", 3, F3rc, Method),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("neg-int", 1, F12x, None),
    ("not-int", 1, F12x, None),
    ("neg-long", 1, F12x, None),
    ("not-long", 1, F12x, None),
    ("neg-float", 1, F12x, None),
    ("neg-double", 1, F12x, None),
    ("int-to-long", 1, F12x, None),
    ("int-to-float", 1, F12x, None),
    ("int-to-double", 1, F12x, None),
    ("long-to-int", 1, F12x, None),
    ("long-to-float", 1, F12x, None),
    ("long-to-double", 1, F12x, None),
    ("float-to-int", 1, F12x, None),
    ("float-to-long", 1, F12x, None),
    ("float-to-double", 1, F12x, None),
    ("double-to-int", 1, F12x, None),
    ("double-to-long", 1, F12x, None),
    ("double-to-float", 1, F12x, None),
    ("int-to-byte", 1, F12x, None),
    ("int-to-char", 1, F12x, None),
    ("int-to-short", 1, F12x, None),
    ("add-int", 2, F23x, None),
    ("sub-int", 2, F23x, None),
    ("mul-int", 2, F23x, None),
    ("div-int", 2, F23x, None),
    ("rem-int", 2, F23x, None),
    ("and-int", 2, F23x, None),
    ("or-int", 2, F23x, None),
    ("xor-int", 2, F23x, None),
    ("shl-int", 2, F23x, None),
    ("shr-int", 2, F23x, None),
    ("ushr-int", 2, F23x, None),
    ("add-long", 2, F23x, None),
    ("sub-long", 2, F23x, None),
    ("mul-long", 2, F23x, None),
    ("div-long", 2, F23x, None),
    ("rem-long", 2, F23x, None),
    ("and-long", 2, F23x, None),
    ("or-long", 2, F23x, None),
    ("xor-long", 2, F23x, None),
    ("shl-long", 2, F23x, None),
    ("shr-long", 2, F23x, None),
    ("ushr-long", 2, F23x, None),
    ("add-float", 2, F23x, None),
    ("sub-float", 2, F23x, None),
    ("mul-float", 2, F23x, None),
    ("div-float", 2, F23x, None),
    ("rem-float", 2, F23x, None),
    ("add-double", 2, F23x, None),
    ("sub-double", 2, F23x, None),
    ("mul-double", 2, F23x, None),
    ("div-double", 2, F23x, None),
    ("rem-double", 2, F23x, None),
    ("add-int/2addr", 1, F12x, None),
    ("sub-int/2addr", 1, F12x, None),
    ("mul-int/2addr", 1, F12x, None),
    ("div-int/2addr", 1, F12x, None),
    ("rem-int/2addr", 1, F12x, None),
    ("and-int/2addr", 1, F12x, None),
    ("or-int/2addr", 1, F12x, None),
    ("xor-int/2addr", 1, F12x, None),
    ("shl-int/2addr", 1, F12x, None),
    ("shr-int/2addr", 1, F12x, None),
    ("ushr-int/2addr", 1, F12x, None),
    ("add-long/2addr", 1, F12x, None),
    ("sub-long/2addr", 1, F12x, None),
    ("mul-long/2addr", 1, F12x, None),
    ("div-long/2addr", 1, F12x, None),
    ("rem-long/2addr", 1, F12x, None),
    ("and-long/2addr", 1, F12x, None),
    ("or-long/2addr", 1, F12x, None),
    ("xor-long/2addr", 1, F12x, None),
    ("shl-long/2addr", 1, F12x, None),
    ("shr-long/2addr", 1, F12x, None),
    ("ushr-long/2addr", 1, F12x, None),
    ("add-float/2addr", 1, F12x, None),
    ("sub-float/2addr", 1, F12x, None),
    ("mul-float/2addr", 1, F12x, None),
    ("div-float/2addr", 1, F12x, None),
    ("rem-float/2addr", 1, F12x, None),
    ("add-double/2addr", 1, F12x, None),
    ("sub-double/2addr", 1, F12x, None),
    ("mul-double/2addr", 1, F12x, None),
    ("div-double/2addr", 1, F12x, None),
    ("rem-double/2addr", 1, F12x, None),
    ("add-int/lit16", 2, F22s, None),
    ("rsub-int", 2, F22s, None),
    ("mul-int/lit16", 2, F22s, None),
    ("div-int/lit16", 2, F22s, None),
    ("rem-int/lit16", 2, F22s, None),
    ("and-int/lit16", 2, F22s, None),
    ("or-int/lit16", 2, F22s, None),
    ("xor-int/lit16", 2, F22s, None),
    ("add-int/lit8", 2, F22b, None),
    ("rsub-int/lit8", 2, F22b, None),
    ("mul-int/lit8", 2, F22b, None),
    ("div-int/lit8", 2, F22b, None),
    ("rem-int/lit8", 2, F22b, None),
    ("and-int/lit8", 2, F22b, None),
    ("or-int/lit8", 2, F22b, None),
    ("xor-int/lit8", 2, F22b, None),
    ("shl-int/lit8", 2, F22b, None),
    ("shr-int/lit8", 2, F22b, None),
    ("ushr-int/lit8", 2, F22b, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("unused", 0, F10x, None),
    ("invoke-polymorphic", 4, F45cc, MethodProto),
    ("invoke-polymorphic/range", 4, F4rcc, MethodProto),
    ("invoke-custom", 3, F35c, CallSite),
    ("invoke-custom/range", 3, F3rc, CallSite),
    ("const-method-handle", 2, F21c, MethodHandle),
    ("const-method-type", 2, F21c, Proto),

}

pub fn op_len(opcode: u8) -> usize {
    OPS[opcode as usize].len as usize
}

/// Byte length of a packed-switch, sparse-switch, or fill-array-data payload.
///
/// These payloads sit in the instruction stream and start with opcode `nop`.
/// `None` means `pos` is an ordinary instruction.
pub fn payload_len(data: &[u8], pos: usize) -> Option<usize> {
    if data.get(pos).copied()? != 0x00 || pos.checked_add(4)? > data.len() {
        return None;
    }
    let ident = u16::from_le_bytes([data[pos], data[pos + 1]]);
    match ident {
        0x0100 => {
            let size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            size.checked_mul(4)?.checked_add(8)
        }
        0x0200 => {
            let size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            size.checked_mul(8)?.checked_add(4)
        }
        0x0300 => {
            if pos.checked_add(8)? > data.len() {
                return None;
            }
            let width = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let size =
                u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                    as usize;
            let raw = width.checked_mul(size)?.checked_add(8)?;
            raw.checked_add(1).map(|value| value & !1)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{payload_len, OPS};

    #[test]
    fn nop_is_not_a_payload() {
        assert_eq!(payload_len(&[0x00, 0x00, 0x00, 0x00], 0), None);
    }

    #[test]
    fn payload_lengths_cover_switch_and_fill_array() {
        let packed = [0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let sparse = [0x00, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let fill = [0x00, 0x03, 0x04, 0x00, 0x01, 0, 0, 0, 1, 2, 3, 4];
        assert_eq!(payload_len(&packed, 0), Some(12));
        assert_eq!(payload_len(&sparse, 0), Some(12));
        assert_eq!(payload_len(&fill, 0), Some(12));
    }

    #[test]
    fn const_string_opcode_is_named() {
        assert_eq!(OPS[0x1a].name, "const-string");
        assert_eq!(OPS[0x1a].len, 2);
    }
}
