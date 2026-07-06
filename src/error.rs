// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

pub type Result<T> = core::result::Result<T, LithiumError>;

#[derive(Debug)]
pub struct LithiumError {
    pub kind: ErrorKind,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LithiumError {
    #[inline]
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }

    #[inline]
    pub fn with_source<E>(mut self, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(err));
        self
    }

    #[inline]
    pub fn is_verbose() -> bool {
        cfg!(debug_assertions)
    }

    #[inline]
    pub fn invalid_len(expected: usize, got: usize) -> Self {
        Self::new(ErrorKind::InvalidLength { expected, got })
    }

    #[inline]
    pub fn invalid_hex_len(expected: usize, got: usize) -> Self {
        Self::new(ErrorKind::InvalidHexLength { expected, got })
    }

    #[inline]
    pub fn invalid_hex<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::InvalidHex).with_source(err)
    }

    #[inline]
    pub fn hex_prefix_disallowed() -> Self {
        Self::new(ErrorKind::HexDisallowedPrefix)
    }

    #[inline]
    pub fn hex_must_be_lowercase() -> Self {
        Self::new(ErrorKind::HexMustBeLowercase)
    }

    #[inline]
    pub fn string_policy() -> Self {
        Self::new(ErrorKind::StringPolicy)
    }

    #[inline]
    pub fn missing_header(name: &'static str) -> Self {
        Self::new(ErrorKind::MissingHeader { name })
    }

    #[inline]
    pub fn invalid_utf8_header<E>(name: &'static str, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::InvalidUtf8Header { name }).with_source(err)
    }

    #[inline]
    pub fn json_parse<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::JsonParse).with_source(err)
    }

    #[inline]
    pub fn json_not_object() -> Self {
        Self::new(ErrorKind::JsonNotObject)
    }

    #[inline]
    pub fn json_missing_field(key: &'static str) -> Self {
        Self::new(ErrorKind::JsonMissingField { key })
    }

    #[inline]
    pub fn json_type_mismatch(key: &'static str, expected: &'static str) -> Self {
        Self::new(ErrorKind::JsonTypeMismatch { key, expected })
    }

    #[inline]
    pub fn aead_failed() -> Self {
        Self::new(ErrorKind::AeadFailed)
    }

    #[inline]
    pub fn kdf_failed() -> Self {
        Self::new(ErrorKind::KdfFailed)
    }

    #[inline]
    pub fn kem_invalid_ciphertext() -> Self {
        Self::new(ErrorKind::KemInvalidCiphertext)
    }

    #[inline]
    pub fn invalid_public_key(key: &'static str, reason: &'static str) -> Self {
        Self::new(ErrorKind::InvalidPublicKey { key, reason })
    }

    #[inline]
    pub fn key_import_failed(reason: &'static str) -> Self {
        Self::new(ErrorKind::KeyImportFailed { reason })
    }

    #[inline]
    pub fn invalid_context(reason: &'static str) -> Self {
        Self::new(ErrorKind::InvalidContext { reason })
    }

    #[inline]
    pub fn random_failed() -> Self {
        Self::new(ErrorKind::RandomFailed)
    }

    #[inline]
    pub fn io<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Io).with_source(err)
    }

    #[inline]
    pub fn internal(reason: &'static str) -> Self {
        Self::new(ErrorKind::Internal { reason })
    }

    #[inline]
    pub fn coarse(&self) -> LithiumError {
        LithiumError::new(ErrorKind::Opaque)
    }

    #[inline]
    pub fn opaque_protocol(reason: &'static str) -> Self {
        Self::new(ErrorKind::OpaqueProtocol { reason })
    }

    #[inline]
    pub fn malformed_keyfile() -> Self {
        Self::new(ErrorKind::MalformedKeyfile)
    }

    #[inline]
    pub fn malformed_input(reason: &'static str) -> Self {
        Self::new(ErrorKind::MalformedInput { reason })
    }

    #[inline]
    pub fn keystore_locked() -> Self {
        Self::new(ErrorKind::KeystoreLocked)
    }

    #[inline]
    pub fn ttl_too_large() -> Self {
        Self::new(ErrorKind::TtlTooLarge)
    }

    #[inline]
    pub fn invalid_credentials(msg: &'static str) -> Self {
        Self::new(ErrorKind::InvalidCredentials { msg })
    }

    #[inline]
    pub fn invalid_perms(msg: &'static str) -> Self {
        Self::new(ErrorKind::InvalidPermissions { msg })
    }

    #[inline]
    pub fn invalid_utf(msg: &'static str) -> Self {
        Self::new(ErrorKind::InvalidUtf { msg })
    }

    #[inline]
    pub fn env_missing(name: &'static str) -> Self {
        Self::new(ErrorKind::EnvMissing { name })
    }

    #[inline]
    pub fn env_invalid(name: &'static str) -> Self {
        Self::new(ErrorKind::EnvInvalid { name })
    }

    #[inline]
    pub fn state_missing(name: &'static str) -> Self {
        Self::new(ErrorKind::StateMissing { name })
    }

    #[inline]
    pub fn timeout<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Timeout).with_source(err)
    }

    #[inline]
    pub fn transport<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Transport).with_source(err)
    }

    #[inline]
    pub fn http_status(code: u16) -> Self {
        Self::new(ErrorKind::HttpStatus { code })
    }

    #[inline]
    pub fn is_not_found(&self) -> bool {
        self.io_kind() == Some(std::io::ErrorKind::NotFound)
    }

    #[inline]
    pub fn is_already_exists(&self) -> bool {
        self.io_kind() == Some(std::io::ErrorKind::AlreadyExists)
    }

    #[inline]
    fn io_kind(&self) -> Option<std::io::ErrorKind> {
        if self.kind != ErrorKind::Io {
            return None;
        }
        self.source
            .as_deref()?
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidLength {
        expected: usize,
        got: usize,
    },
    InvalidHexLength {
        expected: usize,
        got: usize,
    },
    InvalidHex,
    HexDisallowedPrefix,
    HexMustBeLowercase,
    StringPolicy,
    InvalidUtf {
        msg: &'static str,
    },
    MissingHeader {
        name: &'static str,
    },
    InvalidUtf8Header {
        name: &'static str,
    },
    JsonParse,
    JsonNotObject,
    JsonMissingField {
        key: &'static str,
    },
    JsonTypeMismatch {
        key: &'static str,
        expected: &'static str,
    },
    AeadFailed,
    KdfFailed,
    KemInvalidCiphertext,
    InvalidPublicKey {
        key: &'static str,
        reason: &'static str,
    },
    KeyImportFailed {
        reason: &'static str,
    },
    InvalidContext {
        reason: &'static str,
    },
    RandomFailed,
    InvalidCredentials {
        msg: &'static str,
    },
    InvalidPermissions {
        msg: &'static str,
    },
    MalformedKeyfile,
    MalformedInput {
        reason: &'static str,
    },
    KeystoreLocked,
    TtlTooLarge,
    EnvMissing {
        name: &'static str,
    },
    EnvInvalid {
        name: &'static str,
    },
    StateMissing {
        name: &'static str,
    },
    Io,
    Timeout,
    Transport,
    HttpStatus {
        code: u16,
    },
    OpaqueProtocol {
        reason: &'static str,
    },
    Internal {
        reason: &'static str,
    },
    Opaque,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::InvalidLength { expected, got } => {
                write!(f, "invalid length: expected {expected}, got {got}")
            }
            ErrorKind::InvalidHexLength { expected, got } => {
                write!(f, "invalid hex length: expected {expected}, got {got}")
            }
            ErrorKind::InvalidHex => write!(f, "invalid hex"),
            ErrorKind::HexDisallowedPrefix => write!(f, "hex prefix disallowed"),
            ErrorKind::HexMustBeLowercase => write!(f, "hex must be lowercase"),
            ErrorKind::StringPolicy => write!(f, "input rejected by policy"),
            ErrorKind::InvalidUtf { msg } => write!(f, "invalid utf-8: {msg}"),
            ErrorKind::MissingHeader { name } => write!(f, "missing header: {name}"),
            ErrorKind::InvalidUtf8Header { name } => write!(f, "invalid utf-8 in header: {name}"),
            ErrorKind::JsonParse => write!(f, "invalid json"),
            ErrorKind::JsonNotObject => write!(f, "json is not an object"),
            ErrorKind::JsonMissingField { key } => write!(f, "json missing field: {key}"),
            ErrorKind::JsonTypeMismatch { key, expected } => {
                write!(f, "json type mismatch at {key}: expected {expected}")
            }
            ErrorKind::AeadFailed => write!(f, "aead operation failed"),
            ErrorKind::KdfFailed => write!(f, "key derivation failed"),
            ErrorKind::KemInvalidCiphertext => write!(f, "invalid kem ciphertext"),
            ErrorKind::InvalidPublicKey { key, reason } => {
                write!(f, "invalid public key [{key}]: {reason}")
            }
            ErrorKind::KeyImportFailed { reason } => write!(f, "key import failed: {reason}"),
            ErrorKind::InvalidContext { reason } => write!(f, "invalid context: {reason}"),
            ErrorKind::RandomFailed => write!(f, "random number generation failed"),
            ErrorKind::InvalidCredentials { msg } => write!(f, "invalid credentials: {msg}"),
            ErrorKind::InvalidPermissions { msg } => write!(f, "permission denied: {msg}"),
            ErrorKind::MalformedKeyfile => write!(f, "malformed keyfile"),
            ErrorKind::MalformedInput { reason } => write!(f, "malformed input: {reason}"),
            ErrorKind::KeystoreLocked => {
                write!(f, "keystore already locked by another instance")
            }
            ErrorKind::TtlTooLarge => write!(f, "ttl too large"),
            ErrorKind::EnvMissing { name } => write!(f, "missing environment variable: {name}"),
            ErrorKind::EnvInvalid { name } => write!(f, "invalid environment variable: {name}"),
            ErrorKind::StateMissing { name } => write!(f, "missing state: {name}"),
            ErrorKind::Io => write!(f, "i/o error"),
            ErrorKind::Timeout => write!(f, "timeout"),
            ErrorKind::Transport => write!(f, "transport error"),
            ErrorKind::HttpStatus { code } => write!(f, "http status {code}"),
            ErrorKind::OpaqueProtocol { reason } => write!(f, "opaque protocol error: {reason}"),
            ErrorKind::Internal { reason } => write!(f, "internal error: {reason}"),
            ErrorKind::Opaque => write!(f, "operation failed"),
        }
    }
}

impl fmt::Display for LithiumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let (true, Some(src)) = (Self::is_verbose(), &self.source) {
            write!(f, " | source: {src}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LithiumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<std::io::Error> for LithiumError {
    fn from(value: std::io::Error) -> Self {
        LithiumError::io(value)
    }
}
impl From<hex::FromHexError> for LithiumError {
    fn from(value: hex::FromHexError) -> Self {
        LithiumError::invalid_hex(value)
    }
}
impl From<serde_json::Error> for LithiumError {
    fn from(value: serde_json::Error) -> Self {
        LithiumError::json_parse(value)
    }
}
impl From<hkdf::InvalidLength> for LithiumError {
    fn from(_: hkdf::InvalidLength) -> Self {
        LithiumError::kdf_failed()
    }
}
impl From<aes_gcm_siv::aead::Error> for LithiumError {
    fn from(_: aes_gcm_siv::aead::Error) -> Self {
        LithiumError::aead_failed()
    }
}
impl From<rand::rngs::SysError> for LithiumError {
    fn from(err: rand::rngs::SysError) -> Self {
        LithiumError::random_failed().with_source(err)
    }
}

pub trait CoarseResult {
    fn coarse_err(self) -> Self;
}

impl<T> CoarseResult for Result<T> {
    #[inline]
    fn coarse_err(self) -> Self {
        self.map_err(|e| e.coarse())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_collapses_distinct_errors_identically() {
        let errs = [
            LithiumError::aead_failed(),
            LithiumError::malformed_keyfile(),
            LithiumError::io(std::io::Error::other("boom")),
        ];
        for e in errs {
            let c = e.coarse();
            assert_eq!(c.kind, ErrorKind::Opaque);
            assert_eq!(c.to_string(), "operation failed");
            assert!(c.source.is_none());
        }
    }

    #[test]
    fn coarse_err_maps_err_and_passes_ok() {
        let ok: Result<u8> = Ok(7);
        assert_eq!(ok.coarse_err().unwrap(), 7);

        let err: Result<u8> = Err(LithiumError::aead_failed());
        assert_eq!(err.coarse_err().unwrap_err().kind, ErrorKind::Opaque);
    }
}
