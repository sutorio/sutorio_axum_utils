//! Base64 encoding/decoding
//!
//! NOTE: url-safe base64 encoding is used for portability.
//! REVIEW: should the *un*padded b64u encoding be used? Currently the *padded* version is used.
use crate::{Error, Result};
use base64ct::{Base64Url, Encoding};

/// This accepts a byte slice, not a string slice. The input will likely be in the form
/// of a string slice, so use of `into_bytes()` will be required.
pub fn encode(content: &[u8]) -> String {
    Base64Url::encode_string(content)
}

pub fn decode(content: &str) -> Result<String> {
    match Base64Url::decode_vec(content) {
        Ok(byte_vec) => String::from_utf8(byte_vec)
            .map(|s| s.to_string())
            .map_err(|_| Error::B64DecodingFailure),
        Err(_) => Err(Error::B64DecodingFailure),
    }
}