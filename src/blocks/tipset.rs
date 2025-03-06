// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::cid_collections::SmallCidNonEmptyVec;
use crate::shim::clock::ChainEpoch;
use crate::utils::cid::CidCborExt;
use anyhow::Context as _;
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use itertools::Itertools as _;
use nunny::{vec as nonempty, Vec as NonEmpty};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

use super::CachingBlockHeader;

/// A set of `CIDs` forming a unique key for a Tipset.
/// Equal keys will have equivalent iteration order, but note that the `CIDs`
/// are *not* maintained in the same order as the canonical iteration order of
/// blocks in a tipset (which is by ticket)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct TipsetKey(SmallCidNonEmptyVec);

impl TipsetKey {
    // Special encoding to match Lotus.
    pub fn cid(&self) -> anyhow::Result<Cid> {
        use fvm_ipld_encoding::RawBytes;

        let mut bytes = Vec::new();
        for cid in self.to_cids() {
            bytes.append(&mut cid.to_bytes())
        }
        Ok(Cid::from_cbor_blake2b256(&RawBytes::new(bytes))?)
    }

    /// Returns `true` if the tipset key contains the given CID.
    pub fn contains(&self, cid: Cid) -> bool {
        self.0.contains(cid)
    }

    /// Returns a non-empty collection of `CID`
    pub fn into_cids(self) -> NonEmpty<Cid> {
        self.0.into_cids()
    }

    /// Returns a non-empty collection of `CID`
    pub fn to_cids(&self) -> NonEmpty<Cid> {
        self.0.clone().into_cids()
    }

    /// Returns an iterator of `CID`s.
    pub fn iter(&self) -> impl Iterator<Item = Cid> + '_ {
        self.0.iter()
    }

    /// Returns the number of `CID`s
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<NonEmpty<Cid>> for TipsetKey {
    fn from(value: NonEmpty<Cid>) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for TipsetKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self
            .to_cids()
            .into_iter()
            .map(|cid| cid.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "[{}]", s)
    }
}

impl<'a> IntoIterator for &'a TipsetKey {
    type Item = <&'a SmallCidNonEmptyVec as IntoIterator>::Item;

    type IntoIter = <&'a SmallCidNonEmptyVec as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

impl IntoIterator for TipsetKey {
    type Item = <SmallCidNonEmptyVec as IntoIterator>::Item;

    type IntoIter = <SmallCidNonEmptyVec as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// An immutable set of blocks at the same height with the same parent set.
/// Blocks in a tipset are canonically ordered by ticket size.
///
/// Represents non-null tipsets, see the documentation on [`crate::state_manager::apply_block_messages`]
/// for more.
#[derive(Clone, Debug)]
pub struct Tipset {
    /// Sorted
    headers: NonEmpty<CachingBlockHeader>,
    // key is lazily initialized via `fn key()`.
    key: OnceCell<TipsetKey>,
}

impl From<CachingBlockHeader> for Tipset {
    fn from(value: CachingBlockHeader) -> Self {
        Self {
            headers: nonempty![value],
            key: OnceCell::new(),
        }
    }
}

impl PartialEq for Tipset {
    fn eq(&self, other: &Self) -> bool {
        self.headers.eq(&other.headers)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum CreateTipsetError {
    #[error("tipsets must not be empty")]
    Empty,
    #[error("parent CID is inconsistent. All block headers in a tipset must agree on their parent tipset")]
    BadParents,
    #[error("state root is inconsistent. All block headers in a tipset must agree on their parent state root")]
    BadStateRoot,
    #[error("epoch is inconsistent. All block headers in a tipset must agree on their epoch")]
    BadEpoch,
    #[error("duplicate miner address. All miners in a tipset must be unique.")]
    DuplicateMiner,
}

#[allow(clippy::len_without_is_empty)]
impl Tipset {
    /// Builds a new Tipset from a collection of blocks.
    /// A valid tipset contains a non-empty collection of blocks that have
    /// distinct miners and all specify identical epoch, parents, weight,
    /// height, state root, receipt root; content-id for headers are
    /// supposed to be distinct but until encoding is added will be equal.
    pub fn new<H: Into<CachingBlockHeader>>(
        headers: impl IntoIterator<Item = H>,
    ) -> Result<Self, CreateTipsetError> {
        let headers = NonEmpty::new(
            headers
                .into_iter()
                .map(Into::<CachingBlockHeader>::into)
                .sorted_by_cached_key(|it| it.tipset_sort_key())
                .collect(),
        )
        .map_err(|_| CreateTipsetError::Empty)?;

        verify_block_headers(&headers)?;

        Ok(Self {
            headers,
            key: OnceCell::new(),
        })
    }

    /// Fetch a tipset from the blockstore. This call fails if the tipset is
    /// present but invalid. If the tipset is missing, None is returned.
    pub fn load(store: &impl Blockstore, tsk: &TipsetKey) -> anyhow::Result<Option<Tipset>> {
        Ok(tsk
            .to_cids()
            .into_iter()
            .map(|key| CachingBlockHeader::load(store, key))
            .collect::<anyhow::Result<Option<Vec<_>>>>()?
            .map(Tipset::new)
            .transpose()?)
    }

    /// Fetch a tipset from the blockstore. This calls fails if the tipset is
    /// missing or invalid.
    pub fn load_required(store: &impl Blockstore, tsk: &TipsetKey) -> anyhow::Result<Tipset> {
        Tipset::load(store, tsk)?.context("Required tipset missing from database")
    }

    /// Returns epoch of the tipset.
    pub fn epoch(&self) -> ChainEpoch {
        self.min_ticket_block().epoch
    }

    pub fn block_headers(&self) -> &NonEmpty<CachingBlockHeader> {
        &self.headers
    }

    pub fn into_block_headers(self) -> NonEmpty<CachingBlockHeader> {
        self.headers
    }

    /// Returns the block with the smallest ticket of all blocks in the tipset
    pub fn min_ticket_block(&self) -> &CachingBlockHeader {
        self.headers.first()
    }

    /// Returns a key for the tipset.
    pub fn key(&self) -> &TipsetKey {
        self.key
            .get_or_init(|| TipsetKey::from(self.headers.iter_ne().map(|h| *h.cid()).collect_vec()))
    }

    /// Returns the keys of the parents of the blocks in the tipset.
    pub fn parents(&self) -> &TipsetKey {
        &self.min_ticket_block().parents
    }

    /// Returns an iterator of all tipsets, taking an owned [`Blockstore`]
    pub fn chain_owned(self, store: impl Blockstore) -> impl Iterator<Item = Tipset> {
        let mut tipset = Some(self);
        std::iter::from_fn(move || {
            let child = tipset.take()?;
            tipset = Tipset::load_required(&store, child.parents()).ok();
            Some(child)
        })
    }

    /// Returns an iterator of all tipsets
    pub fn chain(self, store: &impl Blockstore) -> impl Iterator<Item = Tipset> + '_ {
        let mut tipset = Some(self);
        std::iter::from_fn(move || {
            let child = tipset.take()?;
            tipset = Tipset::load_required(store, child.parents()).ok();
            Some(child)
        })
    }

    /// Returns an iterator of all tipsets
    pub fn chain_arc(
        self: Arc<Self>,
        store: &impl Blockstore,
    ) -> impl Iterator<Item = Arc<Tipset>> + '_ {
        let mut tipset = Some(self);
        std::iter::from_fn(move || {
            let child = tipset.take()?;
            tipset = Tipset::load_required(store, child.parents())
                .ok()
                .map(Arc::new);
            Some(child)
        })
    }
}

fn verify_block_headers<'a>(
    headers: impl IntoIterator<Item = &'a CachingBlockHeader>,
) -> Result<(), CreateTipsetError> {
    use itertools::all;

    let headers =
        NonEmpty::new(headers.into_iter().collect()).map_err(|_| CreateTipsetError::Empty)?;
    if !all(&headers, |it| it.parents == headers.first().parents) {
        return Err(CreateTipsetError::BadParents);
    }
    if !all(&headers, |it| it.state_root == headers.first().state_root) {
        return Err(CreateTipsetError::BadStateRoot);
    }
    if !all(&headers, |it| it.epoch == headers.first().epoch) {
        return Err(CreateTipsetError::BadEpoch);
    }

    if !headers.iter().map(|it| it.miner_address).all_unique() {
        return Err(CreateTipsetError::DuplicateMiner);
    }

    Ok(())
}
