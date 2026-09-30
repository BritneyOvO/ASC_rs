//! Dalvik opcode lengths, formats, and how each opcode is lifted.
//!
//! The table below is the only mapping from opcode byte to name, width, and
//! lift kind. Adding an opcode means adding one row; `match` on the enums
//! then points at every printer that must learn about it.

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

impl Cmp {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Ge => ">=",
            Self::Gt => ">",
            Self::Le => "<=",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfKind {
    Cmp(Cmp),
    Zero(Cmp),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvokeTarget {
    Virtual,
    Super,
    Direct,
    Static,
    Interface,
    Polymorphic,
    Custom,
}

impl InvokeTarget {
    pub fn skips_receiver(self) -> bool {
        match self {
            Self::Static | Self::Custom => true,
            Self::Virtual | Self::Super | Self::Direct | Self::Interface | Self::Polymorphic => {
                false
            }
        }
    }

    pub fn carries_proto(self) -> bool {
        match self {
            Self::Polymorphic => true,
            Self::Virtual
            | Self::Super
            | Self::Direct
            | Self::Static
            | Self::Interface
            | Self::Custom => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvokeShape {
    List,
    Range,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arith {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
    Rsub,
}

impl Arith {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub | Self::Rsub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Ushr => ">>>",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinShape {
    Regs,
    TwoAddr,
    Lit,
    Rsub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Plain,
    ReturnVoid,
    Return,
    Throw,
    ConstString,
    If(IfKind),
    Goto,
    Goto16,
    Goto32,
    Move,
    MoveResult,
    Const {
        wide: bool,
    },
    Iget,
    Iput,
    Sget,
    Sput,
    NewInstance,
    NewArray,
    ArrayLength,
    CheckCast,
    InstanceOf,
    Invoke {
        target: InvokeTarget,
        shape: InvokeShape,
    },
    Binop {
        arith: Arith,
        shape: BinShape,
    },
}

#[derive(Clone, Copy)]
pub struct OpInfo {
    pub name: &'static str,
    pub len: u8,
    pub fmt: Fmt,
    pub index: IndexKind,
    pub kind: OpKind,
}

macro_rules! opcodes {
    ($(($name:literal, $len:expr, $fmt:ident, $index:ident, $kind:expr),)*) => {
        pub static OPS: [OpInfo; 256] = [$(
            OpInfo {
                name: $name,
                len: $len,
                fmt: Fmt::$fmt,
                index: IndexKind::$index,
                kind: $kind,
            },
        )*];
    };
}

opcodes! {
    ("nop", 1, F10x, None, OpKind::Plain),
    ("move", 1, F12x, None, OpKind::Move),
    ("move/from16", 2, F22x, None, OpKind::Move),
    ("move/16", 3, F32x, None, OpKind::Move),
    ("move-wide", 1, F12x, None, OpKind::Move),
    ("move-wide/from16", 2, F22x, None, OpKind::Move),
    ("move-wide/16", 3, F32x, None, OpKind::Move),
    ("move-object", 1, F12x, None, OpKind::Move),
    ("move-object/from16", 2, F22x, None, OpKind::Move),
    ("move-object/16", 3, F32x, None, OpKind::Move),
    ("move-result", 1, F11x, None, OpKind::MoveResult),
    ("move-result-wide", 1, F11x, None, OpKind::MoveResult),
    ("move-result-object", 1, F11x, None, OpKind::MoveResult),
    ("move-exception", 1, F11x, None, OpKind::MoveResult),
    ("return-void", 1, F10x, None, OpKind::ReturnVoid),
    ("return", 1, F11x, None, OpKind::Return),
    ("return-wide", 1, F11x, None, OpKind::Return),
    ("return-object", 1, F11x, None, OpKind::Return),
    ("const/4", 1, F11n, None, OpKind::Const { wide: false }),
    ("const/16", 2, F21s, None, OpKind::Const { wide: false }),
    ("const", 3, F31i, None, OpKind::Const { wide: false }),
    ("const/high16", 2, F21h, None, OpKind::Const { wide: false }),
    ("const-wide/16", 2, F21s, None, OpKind::Const { wide: true }),
    ("const-wide/32", 3, F31i, None, OpKind::Const { wide: true }),
    ("const-wide", 5, F51l, None, OpKind::Const { wide: true }),
    ("const-wide/high16", 2, F21h, None, OpKind::Const { wide: true }),
    ("const-string", 2, F21c, String, OpKind::ConstString),
    ("const-string/jumbo", 3, F31c, String, OpKind::ConstString),
    ("const-class", 2, F21c, Type, OpKind::Plain),
    ("monitor-enter", 1, F11x, None, OpKind::Plain),
    ("monitor-exit", 1, F11x, None, OpKind::Plain),
    ("check-cast", 2, F21c, Type, OpKind::CheckCast),
    ("instance-of", 2, F22c, Type, OpKind::InstanceOf),
    ("array-length", 1, F12x, None, OpKind::ArrayLength),
    ("new-instance", 2, F21c, Type, OpKind::NewInstance),
    ("new-array", 2, F22c, Type, OpKind::NewArray),
    ("filled-new-array", 3, F35c, Type, OpKind::Plain),
    ("filled-new-array/range", 3, F3rc, Type, OpKind::Plain),
    ("fill-array-data", 3, F31t, None, OpKind::Plain),
    ("throw", 1, F11x, None, OpKind::Throw),
    ("goto", 1, F10t, None, OpKind::Goto),
    ("goto/16", 2, F20t, None, OpKind::Goto16),
    ("goto/32", 3, F30t, None, OpKind::Goto32),
    ("packed-switch", 3, F31t, None, OpKind::Plain),
    ("sparse-switch", 3, F31t, None, OpKind::Plain),
    ("cmpl-float", 2, F23x, None, OpKind::Plain),
    ("cmpg-float", 2, F23x, None, OpKind::Plain),
    ("cmpl-double", 2, F23x, None, OpKind::Plain),
    ("cmpg-double", 2, F23x, None, OpKind::Plain),
    ("cmp-long", 2, F23x, None, OpKind::Plain),
    ("if-eq", 2, F22t, None, OpKind::If(IfKind::Cmp(Cmp::Eq))),
    ("if-ne", 2, F22t, None, OpKind::If(IfKind::Cmp(Cmp::Ne))),
    ("if-lt", 2, F22t, None, OpKind::If(IfKind::Cmp(Cmp::Lt))),
    ("if-ge", 2, F22t, None, OpKind::If(IfKind::Cmp(Cmp::Ge))),
    ("if-gt", 2, F22t, None, OpKind::If(IfKind::Cmp(Cmp::Gt))),
    ("if-le", 2, F22t, None, OpKind::If(IfKind::Cmp(Cmp::Le))),
    ("if-eqz", 2, F21t, None, OpKind::If(IfKind::Zero(Cmp::Eq))),
    ("if-nez", 2, F21t, None, OpKind::If(IfKind::Zero(Cmp::Ne))),
    ("if-ltz", 2, F21t, None, OpKind::If(IfKind::Zero(Cmp::Lt))),
    ("if-gez", 2, F21t, None, OpKind::If(IfKind::Zero(Cmp::Ge))),
    ("if-gtz", 2, F21t, None, OpKind::If(IfKind::Zero(Cmp::Gt))),
    ("if-lez", 2, F21t, None, OpKind::If(IfKind::Zero(Cmp::Le))),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("aget", 2, F23x, None, OpKind::Plain),
    ("aget-wide", 2, F23x, None, OpKind::Plain),
    ("aget-object", 2, F23x, None, OpKind::Plain),
    ("aget-boolean", 2, F23x, None, OpKind::Plain),
    ("aget-byte", 2, F23x, None, OpKind::Plain),
    ("aget-char", 2, F23x, None, OpKind::Plain),
    ("aget-short", 2, F23x, None, OpKind::Plain),
    ("aput", 2, F23x, None, OpKind::Plain),
    ("aput-wide", 2, F23x, None, OpKind::Plain),
    ("aput-object", 2, F23x, None, OpKind::Plain),
    ("aput-boolean", 2, F23x, None, OpKind::Plain),
    ("aput-byte", 2, F23x, None, OpKind::Plain),
    ("aput-char", 2, F23x, None, OpKind::Plain),
    ("aput-short", 2, F23x, None, OpKind::Plain),
    ("iget", 2, F22c, Field, OpKind::Iget),
    ("iget-wide", 2, F22c, Field, OpKind::Iget),
    ("iget-object", 2, F22c, Field, OpKind::Iget),
    ("iget-boolean", 2, F22c, Field, OpKind::Iget),
    ("iget-byte", 2, F22c, Field, OpKind::Iget),
    ("iget-char", 2, F22c, Field, OpKind::Iget),
    ("iget-short", 2, F22c, Field, OpKind::Iget),
    ("iput", 2, F22c, Field, OpKind::Iput),
    ("iput-wide", 2, F22c, Field, OpKind::Iput),
    ("iput-object", 2, F22c, Field, OpKind::Iput),
    ("iput-boolean", 2, F22c, Field, OpKind::Iput),
    ("iput-byte", 2, F22c, Field, OpKind::Iput),
    ("iput-char", 2, F22c, Field, OpKind::Iput),
    ("iput-short", 2, F22c, Field, OpKind::Iput),
    ("sget", 2, F21c, Field, OpKind::Sget),
    ("sget-wide", 2, F21c, Field, OpKind::Sget),
    ("sget-object", 2, F21c, Field, OpKind::Sget),
    ("sget-boolean", 2, F21c, Field, OpKind::Sget),
    ("sget-byte", 2, F21c, Field, OpKind::Sget),
    ("sget-char", 2, F21c, Field, OpKind::Sget),
    ("sget-short", 2, F21c, Field, OpKind::Sget),
    ("sput", 2, F21c, Field, OpKind::Sput),
    ("sput-wide", 2, F21c, Field, OpKind::Sput),
    ("sput-object", 2, F21c, Field, OpKind::Sput),
    ("sput-boolean", 2, F21c, Field, OpKind::Sput),
    ("sput-byte", 2, F21c, Field, OpKind::Sput),
    ("sput-char", 2, F21c, Field, OpKind::Sput),
    ("sput-short", 2, F21c, Field, OpKind::Sput),
    ("invoke-virtual", 3, F35c, Method, OpKind::Invoke { target: InvokeTarget::Virtual, shape: InvokeShape::List }),
    ("invoke-super", 3, F35c, Method, OpKind::Invoke { target: InvokeTarget::Super, shape: InvokeShape::List }),
    ("invoke-direct", 3, F35c, Method, OpKind::Invoke { target: InvokeTarget::Direct, shape: InvokeShape::List }),
    ("invoke-static", 3, F35c, Method, OpKind::Invoke { target: InvokeTarget::Static, shape: InvokeShape::List }),
    ("invoke-interface", 3, F35c, Method, OpKind::Invoke { target: InvokeTarget::Interface, shape: InvokeShape::List }),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("invoke-virtual/range", 3, F3rc, Method, OpKind::Invoke { target: InvokeTarget::Virtual, shape: InvokeShape::Range }),
    ("invoke-super/range", 3, F3rc, Method, OpKind::Invoke { target: InvokeTarget::Super, shape: InvokeShape::Range }),
    ("invoke-direct/range", 3, F3rc, Method, OpKind::Invoke { target: InvokeTarget::Direct, shape: InvokeShape::Range }),
    ("invoke-static/range", 3, F3rc, Method, OpKind::Invoke { target: InvokeTarget::Static, shape: InvokeShape::Range }),
    ("invoke-interface/range", 3, F3rc, Method, OpKind::Invoke { target: InvokeTarget::Interface, shape: InvokeShape::Range }),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("neg-int", 1, F12x, None, OpKind::Plain),
    ("not-int", 1, F12x, None, OpKind::Plain),
    ("neg-long", 1, F12x, None, OpKind::Plain),
    ("not-long", 1, F12x, None, OpKind::Plain),
    ("neg-float", 1, F12x, None, OpKind::Plain),
    ("neg-double", 1, F12x, None, OpKind::Plain),
    ("int-to-long", 1, F12x, None, OpKind::Plain),
    ("int-to-float", 1, F12x, None, OpKind::Plain),
    ("int-to-double", 1, F12x, None, OpKind::Plain),
    ("long-to-int", 1, F12x, None, OpKind::Plain),
    ("long-to-float", 1, F12x, None, OpKind::Plain),
    ("long-to-double", 1, F12x, None, OpKind::Plain),
    ("float-to-int", 1, F12x, None, OpKind::Plain),
    ("float-to-long", 1, F12x, None, OpKind::Plain),
    ("float-to-double", 1, F12x, None, OpKind::Plain),
    ("double-to-int", 1, F12x, None, OpKind::Plain),
    ("double-to-long", 1, F12x, None, OpKind::Plain),
    ("double-to-float", 1, F12x, None, OpKind::Plain),
    ("int-to-byte", 1, F12x, None, OpKind::Plain),
    ("int-to-char", 1, F12x, None, OpKind::Plain),
    ("int-to-short", 1, F12x, None, OpKind::Plain),
    ("add-int", 2, F23x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::Regs }),
    ("sub-int", 2, F23x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::Regs }),
    ("mul-int", 2, F23x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::Regs }),
    ("div-int", 2, F23x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::Regs }),
    ("rem-int", 2, F23x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::Regs }),
    ("and-int", 2, F23x, None, OpKind::Binop { arith: Arith::And, shape: BinShape::Regs }),
    ("or-int", 2, F23x, None, OpKind::Binop { arith: Arith::Or, shape: BinShape::Regs }),
    ("xor-int", 2, F23x, None, OpKind::Binop { arith: Arith::Xor, shape: BinShape::Regs }),
    ("shl-int", 2, F23x, None, OpKind::Binop { arith: Arith::Shl, shape: BinShape::Regs }),
    ("shr-int", 2, F23x, None, OpKind::Binop { arith: Arith::Shr, shape: BinShape::Regs }),
    ("ushr-int", 2, F23x, None, OpKind::Binop { arith: Arith::Ushr, shape: BinShape::Regs }),
    ("add-long", 2, F23x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::Regs }),
    ("sub-long", 2, F23x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::Regs }),
    ("mul-long", 2, F23x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::Regs }),
    ("div-long", 2, F23x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::Regs }),
    ("rem-long", 2, F23x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::Regs }),
    ("and-long", 2, F23x, None, OpKind::Binop { arith: Arith::And, shape: BinShape::Regs }),
    ("or-long", 2, F23x, None, OpKind::Binop { arith: Arith::Or, shape: BinShape::Regs }),
    ("xor-long", 2, F23x, None, OpKind::Binop { arith: Arith::Xor, shape: BinShape::Regs }),
    ("shl-long", 2, F23x, None, OpKind::Binop { arith: Arith::Shl, shape: BinShape::Regs }),
    ("shr-long", 2, F23x, None, OpKind::Binop { arith: Arith::Shr, shape: BinShape::Regs }),
    ("ushr-long", 2, F23x, None, OpKind::Binop { arith: Arith::Ushr, shape: BinShape::Regs }),
    ("add-float", 2, F23x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::Regs }),
    ("sub-float", 2, F23x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::Regs }),
    ("mul-float", 2, F23x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::Regs }),
    ("div-float", 2, F23x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::Regs }),
    ("rem-float", 2, F23x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::Regs }),
    ("add-double", 2, F23x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::Regs }),
    ("sub-double", 2, F23x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::Regs }),
    ("mul-double", 2, F23x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::Regs }),
    ("div-double", 2, F23x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::Regs }),
    ("rem-double", 2, F23x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::Regs }),
    ("add-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::TwoAddr }),
    ("sub-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::TwoAddr }),
    ("mul-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::TwoAddr }),
    ("div-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::TwoAddr }),
    ("rem-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::TwoAddr }),
    ("and-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::And, shape: BinShape::TwoAddr }),
    ("or-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Or, shape: BinShape::TwoAddr }),
    ("xor-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Xor, shape: BinShape::TwoAddr }),
    ("shl-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Shl, shape: BinShape::TwoAddr }),
    ("shr-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Shr, shape: BinShape::TwoAddr }),
    ("ushr-int/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Ushr, shape: BinShape::TwoAddr }),
    ("add-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::TwoAddr }),
    ("sub-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::TwoAddr }),
    ("mul-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::TwoAddr }),
    ("div-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::TwoAddr }),
    ("rem-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::TwoAddr }),
    ("and-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::And, shape: BinShape::TwoAddr }),
    ("or-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Or, shape: BinShape::TwoAddr }),
    ("xor-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Xor, shape: BinShape::TwoAddr }),
    ("shl-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Shl, shape: BinShape::TwoAddr }),
    ("shr-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Shr, shape: BinShape::TwoAddr }),
    ("ushr-long/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Ushr, shape: BinShape::TwoAddr }),
    ("add-float/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::TwoAddr }),
    ("sub-float/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::TwoAddr }),
    ("mul-float/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::TwoAddr }),
    ("div-float/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::TwoAddr }),
    ("rem-float/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::TwoAddr }),
    ("add-double/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::TwoAddr }),
    ("sub-double/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Sub, shape: BinShape::TwoAddr }),
    ("mul-double/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::TwoAddr }),
    ("div-double/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::TwoAddr }),
    ("rem-double/2addr", 1, F12x, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::TwoAddr }),
    ("add-int/lit16", 2, F22s, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::Lit }),
    ("rsub-int", 2, F22s, None, OpKind::Binop { arith: Arith::Rsub, shape: BinShape::Rsub }),
    ("mul-int/lit16", 2, F22s, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::Lit }),
    ("div-int/lit16", 2, F22s, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::Lit }),
    ("rem-int/lit16", 2, F22s, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::Lit }),
    ("and-int/lit16", 2, F22s, None, OpKind::Binop { arith: Arith::And, shape: BinShape::Lit }),
    ("or-int/lit16", 2, F22s, None, OpKind::Binop { arith: Arith::Or, shape: BinShape::Lit }),
    ("xor-int/lit16", 2, F22s, None, OpKind::Binop { arith: Arith::Xor, shape: BinShape::Lit }),
    ("add-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Add, shape: BinShape::Lit }),
    ("rsub-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Rsub, shape: BinShape::Rsub }),
    ("mul-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Mul, shape: BinShape::Lit }),
    ("div-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Div, shape: BinShape::Lit }),
    ("rem-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Rem, shape: BinShape::Lit }),
    ("and-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::And, shape: BinShape::Lit }),
    ("or-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Or, shape: BinShape::Lit }),
    ("xor-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Xor, shape: BinShape::Lit }),
    ("shl-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Shl, shape: BinShape::Lit }),
    ("shr-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Shr, shape: BinShape::Lit }),
    ("ushr-int/lit8", 2, F22b, None, OpKind::Binop { arith: Arith::Ushr, shape: BinShape::Lit }),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("unused", 0, F10x, None, OpKind::Plain),
    ("invoke-polymorphic", 4, F45cc, MethodProto, OpKind::Invoke { target: InvokeTarget::Polymorphic, shape: InvokeShape::List }),
    ("invoke-polymorphic/range", 4, F4rcc, MethodProto, OpKind::Invoke { target: InvokeTarget::Polymorphic, shape: InvokeShape::Range }),
    ("invoke-custom", 3, F35c, CallSite, OpKind::Invoke { target: InvokeTarget::Custom, shape: InvokeShape::List }),
    ("invoke-custom/range", 3, F3rc, CallSite, OpKind::Invoke { target: InvokeTarget::Custom, shape: InvokeShape::Range }),
    ("const-method-handle", 2, F21c, MethodHandle, OpKind::Plain),
    ("const-method-type", 2, F21c, Proto, OpKind::Plain),

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
    use super::{payload_len, OpKind, OPS};

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
    fn const_string_keeps_its_lift_kind() {
        assert!(matches!(OPS[0x1a].kind, OpKind::ConstString));
        assert_eq!(OPS[0x1a].name, "const-string");
    }
}
