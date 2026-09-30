use thiserror::Error;

/// Recoverable analysis or I/O failure. The CLI prints this as `Error: ...`.
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
    #[error("invalid pattern: {0}")]
    Pattern(#[from] regex::Error),
    #[error("{0}")]
    Message(String),
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::Error::new(format!($($arg)*)))
    };
}
