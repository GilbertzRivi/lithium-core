// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;
use std::io;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

use crate::error::{LithiumError, Result};
use crate::hexcodec;
use crate::secrets::SecretString;

pub struct SecretFixedBytes<const N: usize>(SecretBox<[u8; N]>);

impl<const N: usize> SecretFixedBytes<N> {
    pub const LEN: usize = N;

    #[inline]
    pub fn new(mut bytes: [u8; N]) -> Self {
        let out = Self(SecretBox::new(Box::new(bytes)));
        bytes.zeroize();
        out
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(LithiumError::invalid_len(N, slice.len()));
        }
        let mut out = Self::new_zeroed();
        out.expose_as_mut_slice().copy_from_slice(slice);
        Ok(out)
    }

    #[inline]
    pub fn from_wiped<T: AsMut<[u8]>>(mut src: T) -> Result<Self> {
        let s = src.as_mut();
        if s.len() != N {
            let got = s.len();
            s.zeroize();
            return Err(LithiumError::invalid_len(N, got));
        }
        let mut out = Self::new_zeroed();
        out.expose_as_mut_slice().copy_from_slice(s);
        s.zeroize();
        Ok(out)
    }

    #[inline]
    pub fn from_wiped_array(src: &mut [u8; N]) -> Self {
        let out = Self(SecretBox::new(Box::new(*src)));
        src.zeroize();
        out
    }

    #[inline]
    pub fn expose_into_array(&self) -> Zeroizing<[u8; N]> {
        Zeroizing::new(*self.expose_as_array())
    }

    #[inline]
    pub fn expose_as_array(&self) -> &[u8; N] {
        self.0.expose_secret()
    }

    #[inline]
    pub fn expose_as_slice(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }

    #[inline]
    pub fn to_hex(&self) -> SecretString {
        SecretString::new(hex::encode(self.expose_as_slice()))
    }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        let mut out = Self::new_zeroed();
        hexcodec::decode_into(s, out.expose_as_mut_slice())?;
        Ok(out)
    }

    #[inline]
    pub fn new_zeroed() -> Self {
        Self(SecretBox::new(Box::new([0u8; N])))
    }

    #[inline]
    pub fn expose_as_mut_array(&mut self) -> &mut [u8; N] {
        self.0.expose_secret_mut()
    }

    #[inline]
    pub fn expose_as_mut_slice(&mut self) -> &mut [u8] {
        self.0.expose_secret_mut().as_mut_slice()
    }
}

impl<const N: usize> Clone for SecretFixedBytes<N> {
    fn clone(&self) -> Self {
        let mut out = Self::new_zeroed();
        out.expose_as_mut_slice()
            .copy_from_slice(self.expose_as_slice());
        out
    }
}

impl<const N: usize> PartialEq for SecretFixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.expose_as_slice().ct_eq(other.expose_as_slice()).into()
    }
}

impl<const N: usize> Eq for SecretFixedBytes<N> {}

impl<const N: usize> fmt::Debug for SecretFixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretFixedBytes<{}>(..)", N)
    }
}

impl<const N: usize> AsRef<[u8]> for SecretFixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.expose_as_slice()
    }
}

impl<const N: usize> TryFrom<&[u8]> for SecretFixedBytes<N> {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_slice(value)
    }
}

pub type SecByte12 = SecretFixedBytes<12>;
pub type SecByte32 = SecretFixedBytes<32>;
pub type SecByte64 = SecretFixedBytes<64>;

pub type MasterKey32 = SecByte32;
pub type Nonce12 = SecByte12;
pub type SessionId32 = SecByte32;

pub struct SecretBytes(SecretBox<Vec<u8>>);

impl SecretBytes {
    #[inline]
    pub fn new(mut v: Vec<u8>) -> Self {
        if v.capacity() == v.len() {
            Self(SecretBox::new(Box::new(v)))
        } else {
            let exact = v.as_slice().to_vec();
            v.zeroize();
            Self(SecretBox::new(Box::new(exact)))
        }
    }
    #[inline]
    pub fn from_slice(v: &[u8]) -> Self {
        Self::new(v.to_vec())
    }
    #[inline]
    pub fn from_wiped<T: AsMut<[u8]>>(mut src: T) -> Self {
        let out = Self::new(src.as_mut().to_vec());
        src.as_mut().zeroize();
        out
    }
    #[inline]
    pub fn expose_as_slice(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }
    #[inline]
    pub fn expose_as_mut_vec(&mut self) -> &mut Vec<u8> {
        self.0.expose_secret_mut()
    }
    #[inline]
    pub fn expose_into_vec(self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.expose_secret().clone())
    }
    #[inline]
    pub fn expose_into_array<const N: usize>(&self) -> Result<Zeroizing<[u8; N]>> {
        let s = self.expose_as_slice();
        if s.len() != N {
            return Err(LithiumError::invalid_len(N, s.len()));
        }
        let mut out = Zeroizing::new([0u8; N]);
        out.copy_from_slice(s);
        Ok(out)
    }
    #[inline]
    pub fn to_hex(&self) -> SecretString {
        SecretString::new(hex::encode(self.expose_as_slice()))
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.expose_as_slice().len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.expose_as_slice().is_empty()
    }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(Self::new(hexcodec::decode_vec(s)?))
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(self.expose_as_slice())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(..)")
    }
}

impl ExposeSecret<Vec<u8>> for SecretBytes {
    fn expose_secret(&self) -> &Vec<u8> {
        self.0.expose_secret()
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.expose_as_slice()
    }
}

pub struct ZeroizingWriter {
    buf: Zeroizing<Vec<u8>>,
}

impl ZeroizingWriter {
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
        }
    }

    #[inline]
    pub fn into_secret(self) -> SecretBytes {
        SecretBytes::from_slice(&self.buf)
    }
}

impl Default for ZeroizingWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl io::Write for ZeroizingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let needed = self
            .buf
            .len()
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("zeroizing writer length overflow"))?;

        if needed > self.buf.capacity() {
            let new_cap = self.buf.capacity().saturating_mul(2).max(needed).max(64);

            let mut next = Vec::with_capacity(new_cap);
            next.extend_from_slice(&self.buf);
            self.buf.zeroize();
            *self.buf = next;
        }

        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
