# Security related functionality.

Password hashing, validation etc. This tries to rely on the [RustCrypto](https://github.com/RustCrypto)
organisation's crates as much as possible. I have absolutely no wish to
roll my own crypto/auth, so I am following the instructions laid out in the
respective RustCrypto repositories as closely as possible.
It is extremely important that the documentation is read and understood
before any changes are made to this code: for quick reference, see:

- [hmac](https://docs.rs/hmac/latest/hmac/)
- [sha2](https://docs.rs/sha2/latest/sha2/)
- [base64ct](https://docs.rs/base64ct/latest/base64ct/)

