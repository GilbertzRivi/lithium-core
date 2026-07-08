// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{LithiumError, Result};
use crate::hexcodec;

pub struct PublicFixedBytes<const N: usize>([u8; N]);

impl<const N: usize> PublicFixedBytes<N> {
    pub const LEN: usize = N;

    #[inline]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(LithiumError::invalid_len(N, slice.len()));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(Self(out))
    }

    #[inline]
    pub fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        let mut out = [0u8; N];
        hexcodec::decode_into(s, &mut out)?;
        Ok(Self(out))
    }
}

impl<const N: usize> Copy for PublicFixedBytes<N> {}

impl<const N: usize> Clone for PublicFixedBytes<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<const N: usize> PartialEq for PublicFixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const N: usize> Eq for PublicFixedBytes<N> {}

impl<const N: usize> fmt::Debug for PublicFixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicFixed<{N}>({})", hex::encode(self.0))
    }
}

impl<const N: usize> AsRef<[u8]> for PublicFixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for PublicFixedBytes<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> TryFrom<&[u8]> for PublicFixedBytes<N> {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_slice(value)
    }
}

pub type PubByte32 = PublicFixedBytes<32>;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBytes(Vec<u8>);

impl PublicBytes {
    #[inline]
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
    #[inline]
    pub fn from_slice(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[inline]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(Self(hexcodec::decode_vec(s)?))
    }
}

impl fmt::Debug for PublicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicBytes({})", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for PublicBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PublicBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for PublicBytes {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}
