use std::path::PathBuf;

use thiserror::Error;

/// A recoverable archive or diff failure.
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("EOCD not found")]
    NoEocd,
    #[error("{0}")]
    Message(String),
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::Error::new(format!($($arg)*)))
    };
}
