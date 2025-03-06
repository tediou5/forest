// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use super::{CidV1DagCborBlake2b256, MaybeCompactedCid, Uncompactable};
use cid::Cid;
use std::collections::hash_map::IntoIter as StdIntoIter;
#[cfg(doc)]
use std::collections::HashMap;

/// A space-optimised hash map of [`Cid`]s, matching the API for [`std::collections::HashMap`].
///
/// We accept the implementation complexity of per-compaction-method `HashMap`s for
/// the space savings, which are constant per-variant, rather than constant per-item.
///
/// This is dramatic for large maps!
/// Using, e.g [`SmallCidNonEmptyVec`](super::SmallCidNonEmptyVec) will cost
/// 25% more per-CID in the median case (32 B vs 40 B)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidHashMap<V> {
    compact: ahash::HashMap<CidV1DagCborBlake2b256, V>,
    uncompact: ahash::HashMap<Uncompactable, V>,
}

impl<V> CidHashMap<V> {
    /// Creates an empty `HashMap`.
    ///
    /// See also [`HashMap::new`].
    pub fn new() -> Self {
        Self::default()
    }

    /// How many values this map is guaranteed to hold without reallocating.
    #[allow(dead_code)] // mirror of `total_capacity`, below
    pub fn capacity_min(&self) -> usize {
        let Self { compact, uncompact } = self;
        std::cmp::min(compact.capacity(), uncompact.capacity())
    }

    /// Returns `true` if the map contains a value for the specified key.
    ///
    /// See also [`HashMap::contains_key`].
    pub fn contains_key(&self, key: &Cid) -> bool {
        match MaybeCompactedCid::from(*key) {
            MaybeCompactedCid::Compact(c) => self.compact.contains_key(&c),
            MaybeCompactedCid::Uncompactable(u) => self.uncompact.contains_key(&u),
        }
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, [`None`] is returned.
    ///
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned.
    ///
    /// See also [`HashMap::insert`].
    pub fn insert(&mut self, key: Cid, value: V) -> Option<V> {
        match MaybeCompactedCid::from(key) {
            MaybeCompactedCid::Compact(c) => self.compact.insert(c, value),
            MaybeCompactedCid::Uncompactable(u) => self.uncompact.insert(u, value),
        }
    }
}

////////////////////
// Collection Ops //
////////////////////

impl<V> Default for CidHashMap<V> {
    fn default() -> Self {
        Self {
            compact: Default::default(),
            uncompact: Default::default(),
        }
    }
}

impl<V> Extend<(Cid, V)> for CidHashMap<V> {
    fn extend<T: IntoIterator<Item = (Cid, V)>>(&mut self, iter: T) {
        for (cid, v) in iter {
            match MaybeCompactedCid::from(cid) {
                MaybeCompactedCid::Compact(compact) => {
                    self.compact.insert(compact, v);
                }
                MaybeCompactedCid::Uncompactable(uncompact) => {
                    self.uncompact.insert(uncompact, v);
                }
            };
        }
    }
}

impl<V> FromIterator<(Cid, V)> for CidHashMap<V> {
    fn from_iter<T: IntoIterator<Item = (Cid, V)>>(iter: T) -> Self {
        let mut this = Self::new();
        this.extend(iter);
        this
    }
}

pub struct IntoIter<V> {
    compact: StdIntoIter<CidV1DagCborBlake2b256, V>,
    uncompact: StdIntoIter<Uncompactable, V>,
}

impl<V> Iterator for IntoIter<V> {
    type Item = (Cid, V);

    fn next(&mut self) -> Option<Self::Item> {
        self.compact
            .next()
            .map(|(k, v)| (MaybeCompactedCid::Compact(k).into(), v))
            .or_else(|| {
                self.uncompact
                    .next()
                    .map(|(k, v)| (MaybeCompactedCid::Uncompactable(k).into(), v))
            })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        join_size_hints(self.compact.size_hint(), self.uncompact.size_hint())
    }
}

fn join_size_hints(
    left: (usize, Option<usize>),
    right: (usize, Option<usize>),
) -> (usize, Option<usize>) {
    let (l_lower, l_upper) = left;
    let (r_lower, r_upper) = right;
    let lower = l_lower.saturating_add(r_lower);
    let upper = match (l_upper, r_upper) {
        (Some(l), Some(r)) => l.checked_add(r),
        _ => None,
    };
    (lower, upper)
}

impl<V> IntoIterator for CidHashMap<V> {
    type Item = (Cid, V);

    type IntoIter = IntoIter<V>;

    fn into_iter(self) -> Self::IntoIter {
        let Self { compact, uncompact } = self;
        IntoIter {
            compact: compact.into_iter(),
            uncompact: uncompact.into_iter(),
        }
    }
}

//////////
// Keys //
//////////

#[cfg(test)]
use std::collections::hash_map::Keys as StdKeys;

/// An iterator over the keys of a `HashMap`.
///
/// See [`CidHashMap::keys`].
#[cfg(test)]
pub struct Keys<'a, V> {
    compact: StdKeys<'a, CidV1DagCborBlake2b256, V>,
    uncompact: StdKeys<'a, Uncompactable, V>,
}

#[cfg(test)]
impl<V> Iterator for Keys<'_, V> {
    type Item = Cid;

    fn next(&mut self) -> Option<Self::Item> {
        self.compact
            .next()
            .copied()
            .map(MaybeCompactedCid::Compact)
            .map(Into::into)
            .or_else(|| {
                self.uncompact
                    .next()
                    .copied()
                    .map(MaybeCompactedCid::Uncompactable)
                    .map(Into::into)
            })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        join_size_hints(self.compact.size_hint(), self.uncompact.size_hint())
    }
}
