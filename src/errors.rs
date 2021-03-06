use std::fmt;

#[derive(Debug)]
pub enum X3dhError {
    Base64EncodingError(base64::DecodeError),
    HkdfInvalidLengthError(hkdf::InvalidLength),
    AesGcmError(aes_gcm::Error),
    StringError(String),
}

impl std::error::Error for X3dhError {}

impl fmt::Display for X3dhError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            X3dhError::Base64EncodingError(e) => write!(f, "Base64EncodingError {{ {} }}", e),
            X3dhError::HkdfInvalidLengthError(e) => write!(f, "HkdfInvalidLengthError {{ {} }}", e),
            X3dhError::AesGcmError(e) => write!(f, "AesGcmError {{ {} }}", e),
            X3dhError::StringError(e) => write!(f, "Error {{ {} }}", e),
        }
    }
}

impl From<base64::DecodeError> for X3dhError {
    fn from(value: base64::DecodeError) -> Self {
        X3dhError::Base64EncodingError(value)
    }
}

impl From<hkdf::InvalidLength> for X3dhError {
    fn from(value: hkdf::InvalidLength) -> Self {
        X3dhError::HkdfInvalidLengthError(value)
    }
}

impl From<aes_gcm::Error> for X3dhError {
    fn from(value: aes_gcm::Error) -> Self {
        X3dhError::AesGcmError(value)
    }
}

impl From<String> for X3dhError {
    fn from(value: String) -> Self {
        X3dhError::StringError(value)
    }
}

impl From<&str> for X3dhError {
    fn from(value: &str) -> Self {
        X3dhError::StringError(String::from(value))
    }
}
