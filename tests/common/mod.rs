// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use lithium_core::keys::MkProvider;
use lithium_core::secrets::SecByte32;
use lithium_core::{LithiumError, Result};

/// Cleartext file provider for tests only; keeps the suite off the
/// `insecure-plaintext-mk` feature.
pub struct FileMk {
    pub path: PathBuf,
}

impl MkProvider for FileMk {
    fn load_mk(&self) -> Result<SecByte32> {
        let bytes = std::fs::read(&self.path).map_err(LithiumError::io)?;
        SecByte32::from_slice(&bytes)
    }

    fn store_mk(&self, mk: &SecByte32) -> Result<()> {
        std::fs::write(&self.path, mk.expose_as_slice()).map_err(LithiumError::io)
    }
}
