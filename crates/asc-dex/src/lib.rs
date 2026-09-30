//! DEX parser, instruction lifter, and reference search.
//!
//! The input is a DEX byte slice. ZIP containers and manifests live in other crates.

#[macro_use]
mod error;

pub mod bytes;
mod decompile;
pub mod dex;
pub mod findrefs;
mod opcodes;

pub use decompile::{decompile_class, decompile_class_def};
pub use dex::{normalize_dalvik_class, normalize_prefix, Dex};
pub use error::{Error, Result};
pub use findrefs::{find_in_dex, MemberSel, RefQuery};
