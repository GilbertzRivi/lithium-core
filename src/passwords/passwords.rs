// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{crypto::keys, error::Result, secrets::SecByte32};

pub fn generate_dek() -> Result<SecByte32> {
    keys::random_32()
}
