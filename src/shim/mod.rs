// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

pub mod address;
pub mod clock;
pub mod crypto;
pub mod econ;
pub mod sector;
pub mod version;

pub mod fvm_shared_latest {
    // If `#[doc(inline)]`, we steal these docs from an external crate.
    // But they contain dead links, which means our dead link checker (lychee)
    // will complain.
    #[doc(no_inline)]
    pub use fvm_shared4::*;
}
