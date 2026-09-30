//! ASC is an on-demand Android decompiler front-end.
//!
//! APK entries are inflated only when a command asks for them. Reference
//! searches resolve string, type, method, and field ids, then map raw
//! instruction offsets back to methods without building a persistent index.

#[macro_use]
mod error;

pub mod apk;
pub mod axml;
mod bytes;
mod decompile;
pub mod dex;
pub mod findrefs;
mod opcodes;

pub use apk::{
    dump_apk, find_refs, get_class_source, list_classes, manifest_xml, DumpStats, Options,
};
pub use decompile::{decompile_class, decompile_class_def};
pub use error::{Error, Result};
pub use findrefs::{MemberSel, RefQuery};

pub mod cli;
