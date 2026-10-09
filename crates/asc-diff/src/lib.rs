//! Compare two APK, HAP, or other ZIP archives by central-directory entry.
//!
//! The comparison uses each entry's path and CRC. `META-INF` files themselves
//! are not compared. Signature blocks there are read only to extract X.509
//! certificates. Shortened `r/` paths are restored from `resources.arsc`
//! before entries are matched. `res` XML is decoded to text before its bytes
//! are compared. `ArchiveDiff::export` writes changed files, with XML as text.
//! DEX files are not decoded.

#[macro_use]
mod error;

mod archive;
mod cert;
mod diff;

pub use archive::{Archive, FileEntry};
pub use cert::Certificate;
pub use diff::{
    ArchiveDiff, CertificateDiff, ContentChange, FileChange, Group, GroupDiff, XmlDiff, XmlLine,
    XmlSide,
};
pub use error::{Error, Result};
