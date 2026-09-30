use thiserror::Error;

/// Recoverable archive, manifest, or DEX failure surfaced by the commands.
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to {action} {path}: {source}")]
    IoPath {
        action: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Dex(#[from] asc_dex::Error),
    #[error(transparent)]
    Manifest(#[from] asc_axml::Error),
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
