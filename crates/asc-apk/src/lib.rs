//! APK and Android App Bundle access.
//!
//! DEX members are discovered from the ZIP central directory and inflated only
//! when a command needs them.

#[macro_use]
mod error;

mod apk;

pub use apk::{
    dump_apk, find_refs, get_class_source, list_classes, manifest_xml, DumpStats, Options,
};
pub use asc_dex::{MemberSel, RefQuery};
pub use error::{Error, Result};
