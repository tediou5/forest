// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT
use std::num::NonZeroUsize;

use super::NonMaximalU64;
use cid::Cid;

/// Summarize a [`Cid`]'s internal hash as a `u64`-sized hash.
pub fn summary(cid: &Cid) -> NonMaximalU64 {
    NonMaximalU64::fit(
        cid.hash()
            .digest()
            .chunks_exact(8)
            .map(<[u8; 8]>::try_from)
            .filter_map(Result::ok)
            .fold(cid.codec() ^ cid.hash().code(), |hash, chunk| {
                hash ^ u64::from_le_bytes(chunk)
            }),
    )
}

/// Desired slot for a hash with a given table length
///
/// See: <https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/>
pub fn ideal_slot_ix(hash: NonMaximalU64, num_buckets: NonZeroUsize) -> usize {
    // One could simply write `self.0 as usize % buckets` but that involves
    // a relatively slow division.
    // Splitting the hash into chunks and mapping them linearly to buckets is much faster.
    // On modern computers, this mapping can be done with a single multiplication
    // (the right shift is optimized away).

    // break 0..=u64::MAX into 'buckets' chunks and map each chunk to 0..len.
    // if buckets=2, 0..(u64::MAX/2) maps to 0, and (u64::MAX/2)..=u64::MAX maps to 1.
    usize::try_from((hash.get() as u128 * num_buckets.get() as u128) >> 64).unwrap()
}
