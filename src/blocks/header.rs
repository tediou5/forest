// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use super::{ElectionProof, Ticket, TipsetKey};
use crate::beacon::BeaconEntry;
use crate::shim::clock::ChainEpoch;
use crate::shim::{address::Address, crypto::Signature, econ::TokenAmount, sector::PoStProof};
use crate::utils::{cid::CidCborExt as _, encoding::blake2b_256};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::CborStore as _;
use num::BigInt;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

// See <https://github.com/filecoin-project/lotus/blob/d3ca54d617f4783a1a492993f06e737ea87a5834/chain/gen/genesis/genesis.go#L627>
// and <https://github.com/filecoin-project/lotus/commit/13e5b72cdbbe4a02f3863c04f9ecb69c21c3f80f#diff-fda2789d966ea533e74741c076f163070cbc7eb265b5513cd0c0f3bdee87245cR437>
#[cfg(test)]
static FILECOIN_GENESIS_CID: once_cell::sync::Lazy<Cid> = once_cell::sync::Lazy::new(|| {
    "bafyreiaqpwbbyjo4a42saasj36kkrpv4tsherf2e7bvezkert2a7dhonoi"
        .parse()
        .expect("Infallible")
});

#[cfg(test)]
pub static GENESIS_BLOCK_PARENTS: once_cell::sync::Lazy<TipsetKey> =
    once_cell::sync::Lazy::new(|| nunny::vec![*FILECOIN_GENESIS_CID].into());

#[derive(Deserialize_tuple, Serialize_tuple, Clone, Hash, Eq, PartialEq, Debug)]
pub struct RawBlockHeader {
    /// The address of the miner actor that mined this block
    pub miner_address: Address,
    pub ticket: Option<Ticket>,
    pub election_proof: Option<ElectionProof>,
    /// The verifiable oracle randomness used to elect this block's author leader
    pub beacon_entries: Vec<BeaconEntry>,
    pub winning_post_proof: Vec<PoStProof>,
    /// The set of parents this block was based on.
    /// Typically one, but can be several in the case where there were multiple
    /// winning ticket-holders for an epoch
    pub parents: TipsetKey,
    /// The aggregate chain weight of the parent set
    #[serde(with = "crate::shim::fvm_shared_latest::bigint::bigint_ser")]
    pub weight: BigInt,
    /// The period in which a new block is generated.
    /// There may be multiple rounds in an epoch.
    pub epoch: ChainEpoch,
    /// The CID of the parent state root after calculating parent tipset.
    pub state_root: Cid,
    /// The CID of the root of an array of `MessageReceipts`
    pub message_receipts: Cid,
    /// The CID of the Merkle links for `bls_messages` and `secp_messages`
    pub messages: Cid,
    /// Aggregate signature of miner in block
    pub bls_aggregate: Option<Signature>,
    /// Block creation time, in seconds since the Unix epoch
    pub timestamp: u64,
    pub signature: Option<Signature>,
    pub fork_signal: u64,
    /// The base fee of the parent block
    pub parent_base_fee: TokenAmount,
}

#[cfg(test)]
impl Default for RawBlockHeader {
    fn default() -> Self {
        Self {
            parents: GENESIS_BLOCK_PARENTS.clone(),
            miner_address: Default::default(),
            ticket: Default::default(),
            election_proof: Default::default(),
            beacon_entries: Default::default(),
            winning_post_proof: Default::default(),
            weight: Default::default(),
            epoch: Default::default(),
            state_root: Default::default(),
            message_receipts: Default::default(),
            messages: Default::default(),
            bls_aggregate: Default::default(),
            timestamp: Default::default(),
            signature: Default::default(),
            fork_signal: Default::default(),
            parent_base_fee: Default::default(),
        }
    }
}

impl RawBlockHeader {
    pub fn cid(&self) -> Cid {
        Cid::from_cbor_blake2b256(self).unwrap()
    }

    pub(super) fn tipset_sort_key(&self) -> Option<([u8; 32], Vec<u8>)> {
        let ticket_hash = blake2b_256(self.ticket.as_ref()?.vrfproof.as_bytes());
        Some((ticket_hash, self.cid().to_bytes()))
    }
}

/// A [`RawBlockHeader`] which caches calls to [`RawBlockHeader::cid`] and [`RawBlockHeader::verify_signature_against`]
#[cfg_attr(test, derive(Default))]
#[derive(Debug)]
pub struct CachingBlockHeader {
    uncached: RawBlockHeader,
    cid: OnceCell<Cid>,
    has_ever_been_verified_against_any_signature: AtomicBool,
}

impl PartialEq for CachingBlockHeader {
    fn eq(&self, other: &Self) -> bool {
        // Epoch check is redundant but cheap.
        self.uncached.epoch == other.uncached.epoch && self.cid() == other.cid()
    }
}

impl Clone for CachingBlockHeader {
    fn clone(&self) -> Self {
        Self {
            uncached: self.uncached.clone(),
            cid: self.cid.clone(),
            has_ever_been_verified_against_any_signature: AtomicBool::new(
                self.has_ever_been_verified_against_any_signature
                    .load(Ordering::Acquire),
            ),
        }
    }
}

impl Deref for CachingBlockHeader {
    type Target = RawBlockHeader;

    fn deref(&self) -> &Self::Target {
        &self.uncached
    }
}

impl CachingBlockHeader {
    pub fn new(uncached: RawBlockHeader) -> Self {
        Self {
            uncached,
            cid: OnceCell::new(),
            has_ever_been_verified_against_any_signature: AtomicBool::new(false),
        }
    }

    /// Returns [`None`] if the blockstore doesn't contain the CID.
    pub fn load(store: &impl Blockstore, cid: Cid) -> anyhow::Result<Option<Self>> {
        if let Some(uncached) = store.get_cbor::<RawBlockHeader>(&cid)? {
            Ok(Some(Self {
                uncached,
                cid: OnceCell::with_value(cid),
                has_ever_been_verified_against_any_signature: AtomicBool::new(false),
            }))
        } else {
            Ok(None)
        }
    }
    pub fn cid(&self) -> &Cid {
        self.cid.get_or_init(|| self.uncached.cid())
    }
}

impl Serialize for CachingBlockHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.uncached.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CachingBlockHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawBlockHeader::deserialize(deserializer).map(Self::new)
    }
}
