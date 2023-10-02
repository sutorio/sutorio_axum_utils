use crate::{Error, Result};
use crate::url_safe_base64;
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub struct EncryptedEnvelope {
    pub content: String, // Clear content.
    pub salt: String,    // Clear salt.
}

type HmacSha512 = Hmac<Sha512>;

impl EncryptedEnvelope {
    pub fn into_b64u(&self, key: &[u8]) -> Result<String> {
        let mut mac = HmacSha512::new_from_slice(key).map_err(|_| Error::HmacKeyFailure)?;
        // Add the content to be encrypted.
        mac.update(self.content.as_bytes());
        mac.update(self.salt.as_bytes());
        // Finalise the HMAC-SHA-512 instance
        let mac_result = mac.finalize();

        Ok(url_safe_base64::encode(&mac_result.into_bytes()))
    }
}
