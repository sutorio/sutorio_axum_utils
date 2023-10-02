//! Security related functionality.
//!
//! Password hashing, validation etc. This tries to rely on the [RustCrypto](https://github.com/RustCrypto)
//! organisation's crates as much as possible. I have absolutely no wish to
//! roll my own crypto/auth, so I am following the instructions laid out in the
//! respective RustCrypto repositories as closely as possible.
//!
//! It is extremely important that the documentation is read and understood
//! before any changes are made to this code: for quick reference, see:
//!
//! - [hmac](https://docs.rs/hmac/latest/hmac/)
//! - [sha2](https://docs.rs/sha2/latest/sha2/)
//! - [base64ct](https://docs.rs/base64ct/latest/base64ct/)
mod encypted_envelope;
mod error;
mod url_safe_base64;
mod utc_fixed;

pub use encypted_envelope::EncryptedEnvelope;
pub use error::{Error, Result};
use std::{fmt::Display, str::FromStr};

// -----------------------------------------------------------------------------
// Passwords
// -----------------------------------------------------------------------------

pub fn encrypt_password(
    encrypted_content: &EncryptedEnvelope,
    password_key: &[u8],
) -> Result<String> {
    let result = encrypted_content.into_b64u(password_key)?;

    Ok(format!("#01#{result}"))
}

pub fn validate_password(
    encrypted_content: &EncryptedEnvelope,
    password_reference: &str,
    password_key: &[u8],
) -> Result<()> {
    let password = encrypt_password(encrypted_content, password_key)?;

    if password == password_reference {
        Ok(())
    } else {
        Err(Error::PasswordMismatch)
    }
}

// -----------------------------------------------------------------------------
// Tokens
//
// TODO: run benchmarks and optimise. This is not afaics blazingly fast: the process
//       of simply checking takes milliseconds. This means that if the expiry time
//       is within milliseconds of the current time, by the time the check is complete
//       the token will have expired. This may not be a huge issue but may lead to bugs.
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct Token {
    pub identifier: String,
    pub expiration: String,
    pub signature: String,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            url_safe_base64::encode(&self.identifier.as_bytes()),
            url_safe_base64::encode(&self.expiration.as_bytes()),
            self.signature,
        )
    }
}

impl FromStr for Token {
    type Err = Error;

    fn from_str(token_string: &str) -> std::result::Result<Self, Self::Err> {
        let chunks: Vec<&str> = token_string.split(".").collect();

        if chunks.len() != 3 {
            return Err(Error::TokenFormatInvalid);
        }

        let identifier =
            url_safe_base64::decode(chunks[0]).map_err(|_| Error::TokenIdentifierDecodeFailure)?;
        let expiration =
            url_safe_base64::decode(chunks[1]).map_err(|_| Error::TokenExpirationDecodeFailure)?;
        let signature = chunks[2].to_string();

        Ok(Token {
            identifier,
            expiration,
            signature,
        })
    }
}

pub fn generate_token(
    identifier: &str,
    duration_in_seconds: f64,
    salt: &str,
    key: &[u8],
) -> Result<Token> {
    let identifier = identifier.to_string();
    let expiration = utc_fixed::add_seconds_and_format(duration_in_seconds);
    let signature = token_sign_into_b64u(&identifier, &expiration, salt, key)?;

    Ok(Token {
        identifier,
        expiration,
        signature,
    })
}

pub fn validate_token_signature_and_expiration(
    original_token: &Token,
    salt: &str,
    key: &[u8],
) -> Result<()> {
    let new_signature = token_sign_into_b64u(
        &original_token.identifier,
        &original_token.expiration,
        salt,
        key,
    )?;

    // Validate the signature.
    if new_signature != original_token.signature {
        return Err(Error::TokenSignatureMismatch);
    }

    // Validate the expiration.
    let expiration_datetime =
        utc_fixed::parse(&original_token.expiration).map_err(|_| Error::TokenExpirationNotIso)?;
    let current_datetime = utc_fixed::now();

    if expiration_datetime < current_datetime {
        return Err(Error::TokenExpired);
    }

    Ok(())
}

/// Create token signature from token parts + salt
fn token_sign_into_b64u(
    identifier: &str,
    expiration: &str,
    salt: &str,
    key: &[u8],
) -> Result<String> {
    let content = format!(
        "{}.{}",
        url_safe_base64::encode(identifier.as_bytes()),
        url_safe_base64::encode(expiration.as_bytes())
    );
    let signature = EncryptedEnvelope {
        content,
        salt: salt.to_string(),
    }
    .into_b64u(key)?;

    Ok(signature)
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;
    use anyhow::Result;

    const IDENTIFIER: &str = "user";
    const KEY: &[u8] = b"key";
    const SALT: &str = "salt";

    #[test]
    fn test_token_display_impl() -> Result<()> {
        let stringified_input_token = Token {
            identifier: IDENTIFIER.to_string(),
            expiration: "expiration".to_string(),
            signature: "signature".to_string(),
        }
        .to_string();

        let expected_output_string = "dXNlcg==.ZXhwaXJhdGlvbg==.signature";

        assert_eq!(stringified_input_token, expected_output_string);

        Ok(())
    }

    #[test]
    fn test_token_from_string_impl() -> Result<()> {
        let parsed_input_string: Token = "dXNlcg==.ZXhwaXJhdGlvbg==.signature".parse()?;

        let expected_output_token = Token {
            identifier: IDENTIFIER.to_string(),
            expiration: "expiration".to_string(),
            signature: "signature".to_string(),
        };

        // NOTE: `Token` does not implement `PartialEq` by design -- it would be implemented for testing
        //       purposes only, so deriving that would be confusing. It _does_ implement `Debug`, so
        //       we can use the `:?` format specifier to compare the two instances.
        assert_eq!(
            format!("{parsed_input_string:?}"),
            format!("{expected_output_token:?}")
        );

        Ok(())
    }

    #[test]
    fn test_validate_web_token() -> Result<()> {
        // Input token expires in 4 seconds
        let seconds_in_future = 4.0;
        let input_token = generate_token(IDENTIFIER, seconds_in_future, SALT, KEY)?;

        // Sleep for ten milliseconds, input token should still be valid
        thread::sleep(Duration::from_millis(10));

        let expected_result = validate_token_signature_and_expiration(&input_token, SALT, KEY);

        expected_result?;

        Ok(())
    }

    #[test]
    fn test_validate_web_token_expired() -> Result<()> {
        // Input token expires in 4 milliseconds.
        let seconds_in_future = 0.004;
        let input_token = generate_token(IDENTIFIER, seconds_in_future, SALT, KEY)?;

        // Sleep for ten milliseconds, input token should be invalid.
        thread::sleep(Duration::from_millis(10));

        let expected_result = validate_token_signature_and_expiration(&input_token, SALT, KEY);

        assert!(matches!(expected_result, Err(Error::TokenExpired)));

        Ok(())
    }
}
