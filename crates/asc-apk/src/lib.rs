//! APK and Android App Bundle access.
//!
//! DEX members are discovered from the ZIP central directory and inflated only
//! when a command needs them.

#[macro_use]
mod error;

mod apk;
mod arsc;
mod cache;
mod ddc_engine;

pub use apk::{
    dump_apk, find_refs, get_class_source, is_dex, list_classes, manifest_xml, packaged_resources,
    DumpStats, Engine, Options, RefReport,
};
pub use arsc::resource_paths;
pub use asc_dex::{MemberSel, RefQuery};
pub use cache::DiskCache;
pub use error::{Error, Result};
