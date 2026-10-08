//! DEX parser, smali printer, and reference search.
//!
//! The input is a DEX byte slice. ZIP containers and manifests live in other crates.

#[macro_use]
mod error;

pub mod bytes;
pub mod dex;
pub mod findrefs;
pub mod quick;
mod opcodes;
mod smali;

pub use smali::{smali_class, smali_class_def};
pub use dex::{normalize_dalvik_class, normalize_prefix, Dex};
pub use error::{Error, Result};
pub use findrefs::{find_in_dex, find_in_dex_resolved, MemberSel, RefQuery};
