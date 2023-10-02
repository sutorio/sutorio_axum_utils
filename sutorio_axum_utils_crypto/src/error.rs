pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, serde::Serialize)]
pub enum Error {
    // Format errors
    B64DecodingFailure,
    UTCParsingFailure(String),
    // Key-related errors
    HmacKeyFailure,
    // Password-related errors
    PasswordMismatch,
    // Token-related errors
    TokenFormatInvalid,
    TokenIdentifierDecodeFailure,
    TokenExpirationDecodeFailure,
    TokenSignatureMismatch,
    TokenExpirationNotIso,
    TokenExpired,
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}

