// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use cid::Cid;
use integer_encoding::VarInt;
use nunny::Vec as NonEmpty;
use serde::{Deserialize, Serialize};
use std::io::{self};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarV1Header {
    // The roots array must contain one or more CIDs,
    // each of which should be present somewhere in the remainder of the CAR.
    // See <https://ipld.io/specs/transport/car/carv1/#constraints>
    pub roots: NonEmpty<Cid>,
    pub version: u64,
}

/// <https://ipld.io/specs/transport/car/carv2/#header>
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarV2Header {
    pub characteristics: [u8; 16],
    pub data_offset: i64,
    pub data_size: i64,
    pub index_offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CarBlock {
    pub cid: Cid,
    pub data: Vec<u8>,
}

impl CarBlock {
    // Write a varint frame containing the cid and the data
    pub fn write(&self, mut writer: &mut impl io::Write) -> io::Result<()> {
        let frame_length = self.cid.encoded_len() + self.data.len();
        writer.write_all(&frame_length.encode_var_vec())?;
        #[allow(clippy::needless_borrows_for_generic_args)]
        self.cid
            .write_bytes(&mut writer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}
