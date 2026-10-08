//! HarmonyOS HAP access.
//!
//! `.abc` members are discovered from the ZIP central directory and inflated
//! only when a command needs them.

#[macro_use]
mod error;
mod hap;
mod resources;

pub use error::{Error, Result};
pub use hap::{
    dump_abc, dump_hap, find_refs, get_class_source, is_hap, list_classes, load_resources,
    module_json, DumpStats, Options, Query,
};
pub use resources::HapResources;
