//! Read an ELF shared object and compare two of them.
//!
//! The reader covers the ELF header, `DT_SONAME`, `DT_NEEDED`, and the dynamic
//! symbol table. Imports are named undefined symbols. Exports are named global
//! or weak defined symbols. Section headers and program headers are both read.
//! If they disagree, the program headers are kept.

#[macro_use]
mod error;

mod disasm;
mod elf;

pub use disasm::{disassemble_changes, DisasmBlock};
pub use elf::{Class, ElfDiff, ElfInfo, Endian, ObjectKind, Symbol};
pub use error::{Error, Result};
