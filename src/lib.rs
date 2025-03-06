// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

#![recursion_limit = "1024"]
#![cfg_attr(
    not(test),
    deny(
        clippy::todo,
        clippy::dbg_macro,
        clippy::indexing_slicing,
        clippy::get_unwrap
    )
)]
#![cfg_attr(
    doc,
    deny(rustdoc::all),
    allow(
        // We build with `--document-private-items` on both docs.rs and our
        // vendored docs.
        rustdoc::private_intra_doc_links,
        // See module `doctest_private` below.
        rustdoc::private_doc_tests,
        rustdoc::missing_crate_level_docs
    )
)]

mod beacon;
mod blocks;
mod chain;
mod cid_collections;
mod db;
mod ipld;
mod shim;
mod utils;

pub mod export_snapshot {
    pub use crate::chain::export;
}
