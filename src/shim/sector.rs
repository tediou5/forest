// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

pub use fvm_shared4::sector::PoStProof as PoStProofV4;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Debug,
    PartialEq,
    derive_more::From,
    derive_more::Into,
    Eq,
)]
pub struct PoStProof(PoStProofV4);

impl Hash for PoStProof {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let PoStProofV4 {
            post_proof,
            proof_bytes,
        } = &self.0;
        post_proof.hash(state);
        proof_bytes.hash(state);
    }
}

impl Deref for PoStProof {
    type Target = PoStProofV4;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
