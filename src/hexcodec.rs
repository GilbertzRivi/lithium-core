// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{ErrorKind, LithiumError, Result};

#[inline]
fn reject_prefix(s: &str) -> Result<()> {
    if s.starts_with("0x") || s.starts_with("0X") {
        return Err(LithiumError::hex_prefix_disallowed());
    }
    Ok(())
}

#[inline]
fn validate_charset(s: &str) -> Result<()> {
    for &b in s.as_bytes() {
        match b {
            b'0'..=b'9' | b'a'..=b'f' => {}
            b'A'..=b'F' => return Err(LithiumError::hex_must_be_lowercase()),
            _ => return Err(LithiumError::new(ErrorKind::InvalidHex)),
        }
    }
    Ok(())
}

#[inline]
pub(crate) fn decode_into(s: &str, dst: &mut [u8]) -> Result<()> {
    reject_prefix(s)?;
    let expected = 2 * dst.len();
    if s.len() != expected {
        return Err(LithiumError::new(ErrorKind::InvalidHexLength {
            expected,
            got: s.len(),
        }));
    }
    validate_charset(s)?;
    hex::decode_to_slice(s, dst).map_err(LithiumError::from)
}

#[inline]
pub(crate) fn decode_vec(s: &str) -> Result<Vec<u8>> {
    reject_prefix(s)?;
    if !s.len().is_multiple_of(2) {
        return Err(LithiumError::new(ErrorKind::InvalidHexLength {
            expected: s.len() + 1,
            got: s.len(),
        }));
    }
    validate_charset(s)?;
    let mut out = vec![0u8; s.len() / 2];
    hex::decode_to_slice(s, &mut out).map_err(LithiumError::from)?;
    Ok(out)
}
