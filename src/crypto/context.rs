// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;

use crate::error::{LithiumError, Result};
use crate::public::PublicBytes;

const VERSION: &str = "v1";
const MAX_CONTEXT_LEN: usize = 255;

fn validate_segment(seg: &str) -> Result<()> {
    if seg.is_empty() {
        return Err(LithiumError::invalid_context("empty_segment"));
    }
    if !seg.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'/') {
        return Err(LithiumError::invalid_context("segment_charset"));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Context<'a>(Cow<'a, str>);

impl<'a> Context<'a> {
    pub fn base(root: &'a str) -> Result<Self> {
        validate_segment(root)?;
        if root.len() > MAX_CONTEXT_LEN {
            return Err(LithiumError::invalid_context("too_long"));
        }
        Ok(Self(Cow::Borrowed(root)))
    }

    pub fn add(&self, segment: &str) -> Result<Context<'static>> {
        validate_segment(segment)?;
        let joined = format!("{}/{}", self.0, segment);
        if joined.len() > MAX_CONTEXT_LEN {
            return Err(LithiumError::invalid_context("too_long"));
        }
        Ok(Context(Cow::Owned(joined)))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn label(&self) -> PublicBytes {
        PublicBytes::from_slice(format!("{}/{}", self.0, VERSION).as_bytes())
    }
}
