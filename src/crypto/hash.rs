// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use sha2::{Digest, Sha256};

use crate::secrets::SecByte32;

pub fn sha256(data: &[u8]) -> SecByte32 {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SecByte32::new(out)
}
