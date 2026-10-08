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
    /// The file has no ZIP end-of-central-directory record.
    #[error("EOCD not found")]
    NoEocd,
    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(transparent)]
    External(Box<dyn std::error::Error + Send + Sync>),
    #[error("{0}")]
    Message(String),
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }

    pub fn context(
        context: impl Into<String>,
        err: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(err),
        }
    }

    pub fn external(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::External(Box::new(err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::Error::new(format!($($arg)*)))
    };
}
