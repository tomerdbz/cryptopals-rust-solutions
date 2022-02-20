pub type Res<T> = Result<T, Error>;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    InvalidArgument,
}

use std::fmt;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid argument supplied..")
    }
}

impl std::error::Error for Error {}
