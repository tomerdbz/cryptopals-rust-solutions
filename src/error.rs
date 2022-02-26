use openssl::error::ErrorStack;
use std::str;
pub type Res<T> = Result<T, Error>;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    InvalidArgument,
    EncryptionError,
    EncodingError,
    IOError,
}

impl From<str::Utf8Error> for Error {
    fn from(_: str::Utf8Error) -> Self {
        Error::EncodingError
    }
}

impl From<ErrorStack> for Error {
    fn from(_: ErrorStack) -> Self {
        Error::EncryptionError
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::IOError
    }
}

use std::fmt;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::EncodingError => write!(f, "Encoding error has occurred"),
            Error::EncryptionError => write!(f, "Encryption error has occurred"),
            Error::InvalidArgument => write!(f, "Invalid argument supplied.."),
            Error::IOError => write!(f, "IO Error has occurred"),
        }
    }
}

impl std::error::Error for Error {}
