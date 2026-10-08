//! On-demand Ark bytecode reader.
//!
//! The header is the only structure read up front. Class names, members, and
//! literal strings are decoded from the original buffer when a query needs them.

#[macro_use]
mod error;
mod file;

pub use error::{Error, Result};
pub use file::{
    class_names, class_text, class_text_optional, find_members, find_strings,
    find_strings_resolved, find_types, Abc, MemberKind,
};

/// `PANDA\0\0\0`, the magic at the start of an `.abc` file.
pub fn is_abc(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == b"PANDA\0\0\0"
}
