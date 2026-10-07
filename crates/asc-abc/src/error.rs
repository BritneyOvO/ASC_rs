use thiserror::Error;

/// Recoverable ABC parse or query failure.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid pattern: {0}")]
    Pattern(#[from] regex::Error),
    #[error("{0}")]
    Message(String),
    /// Data this reader recognizes but cannot answer from yet. Callers that
    /// search several files can warn and keep the files they can read.
    #[error("{0}")]
    Unsupported(String),
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
