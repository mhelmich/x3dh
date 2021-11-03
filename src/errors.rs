use base64;
use std::fmt;

#[derive(Debug)]
pub enum X3dhError {
    Base64EncodingError(base64::DecodeError),
    StringError(String),
}

impl std::error::Error for X3dhError {}

impl fmt::Display for X3dhError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            X3dhError::Base64EncodingError(e) => write!(f, "Base64EncodingError {{ {} }}", e),
            X3dhError::StringError(e) => write!(f, "Error {{ {} }}", e),
        }
    }
}

impl From<base64::DecodeError> for X3dhError {
    fn from(value: base64::DecodeError) -> Self {
        X3dhError::Base64EncodingError(value)
    }
}

impl From<String> for X3dhError {
    fn from(value: String) -> Self {
        X3dhError::StringError(value)
    }
}
