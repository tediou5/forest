// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use blake2b_simd::Params;
use fvm_ipld_encoding::strict_bytes::{Deserialize, Serialize};
use serde::{de, ser, Deserializer, Serializer};

mod fallback_de_ipld_dagcbor;

/// This method will attempt to de-serialize given bytes using the regular
/// `serde_ipld_dagcbor::from_slice`. Due to a historical issue in Lotus (see more in
/// [FIP-0027](https://github.com/filecoin-project/FIPs/blob/master/FIPS/fip-0027.md), we must still
/// support strings with invalid UTF-8 bytes. On a failure, it
/// will retry the operation using the fallback that will de-serialize
/// strings with invalid UTF-8 bytes as bytes.
pub fn from_slice_with_fallback<'a, T: serde::de::Deserialize<'a>>(
    bytes: &'a [u8],
) -> anyhow::Result<T> {
    match serde_ipld_dagcbor::from_slice(bytes) {
        Ok(v) => Ok(v),
        Err(err) => fallback_de_ipld_dagcbor::from_slice(bytes).map_err(|fallback_err| {
            anyhow::anyhow!(
                "Fallback deserialization failed: {fallback_err}. Original error: {err}"
            )
        }),
    }
}

mod cid_de_cbor;
pub use cid_de_cbor::extract_cids;

/// `serde_bytes` with max length check
pub mod serde_byte_array {
    use super::*;
    /// lotus use cbor-gen for generating codec for types, it has a length limit
    /// for byte array as `2 << 20`
    ///
    /// <https://github.com/whyrusleeping/cbor-gen/blob/f57984553008dd4285df16d4ec2760f97977d713/gen.go#L16>
    pub const BYTE_ARRAY_MAX_LEN: usize = 2 << 20;

    /// checked if `input > crate::utils::BYTE_ARRAY_MAX_LEN`
    pub fn serialize<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: ?Sized + Serialize + AsRef<[u8]>,
        S: Serializer,
    {
        let len = bytes.as_ref().len();
        if len > BYTE_ARRAY_MAX_LEN {
            return Err(ser::Error::custom::<String>(
                "Array exceed max length".into(),
            ));
        }

        Serialize::serialize(bytes, serializer)
    }

    /// checked if `output > crate::utils::ByteArrayMaxLen`
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: Deserialize<'de> + AsRef<[u8]>,
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).and_then(|bytes: T| {
            if bytes.as_ref().len() > BYTE_ARRAY_MAX_LEN {
                Err(de::Error::custom::<String>(
                    "Array exceed max length".into(),
                ))
            } else {
                Ok(bytes)
            }
        })
    }
}

/// Generates BLAKE2b hash of fixed 32 bytes size.
///
/// # Example
/// ```
/// # use forest::doctest_private::blake2b_256;
///
/// let ingest: Vec<u8> = vec![];
/// let hash = blake2b_256(&ingest);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn blake2b_256(ingest: &[u8]) -> [u8; 32] {
    let digest = Params::new()
        .hash_length(32)
        .to_state()
        .update(ingest)
        .finalize();

    let mut ret = [0u8; 32];
    ret.clone_from_slice(digest.as_bytes());
    ret
}

/// Generates Keccak-256 hash of fixed 32 bytes size.
///
/// # Example
/// ```
/// # use forest::doctest_private::keccak_256;
/// let ingest: Vec<u8> = vec![];
/// let hash = keccak_256(&ingest);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn keccak_256(ingest: &[u8]) -> [u8; 32] {
    let mut ret: [u8; 32] = Default::default();
    keccak_hash::keccak_256(ingest, &mut ret);
    ret
}
