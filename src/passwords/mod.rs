// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#[allow(clippy::module_inception)]
mod passwords;

pub use passwords::generate_dek;
