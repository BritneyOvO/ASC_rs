use thiserror::Error;

/// A shared object that is not a readable ELF file.
#[derive(Debug, Error)]
pub enum Error {
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
