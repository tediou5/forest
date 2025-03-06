// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! # Varint frames
//!
//! CARs are made of concatenations of _varint frames_. Each varint frame is a concatenation of the
//! _body length_ as an
//! [varint](https://docs.rs/integer-encoding/4.0.0/integer_encoding/trait.VarInt.html), and the
//! _frame body_ itself. [`unsigned_varint::codec::UviBytes`] can be used to read frames
//! piecewise into memory.
//!
//! ```text
//!        varint frame
//! │◄───────────────────────►│
//! │                         │
//! ├───────────┬─────────────┤
//! │varint:    │             │
//! │body length│frame body   │
//! └───────────┼─────────────┤
//!             │             │
//! frame body ►│◄───────────►│
//!     offset     =body length
//! ```
//!
//! # CARv1 layout and seeking
//!
//! The first varint frame is a _header frame_, where the frame body is a [`CarHeader`] encoded
//! using [`ipld_dagcbor`](serde_ipld_dagcbor).
//!
//! Subsequent varint frames are _block frames_, where the frame body is a concatenation of a
//! [`Cid`] and the _block data_ addressed by that CID.
//!
//! ```text
//! block frame ►│
//! body offset  │
//!              │  =body length
//!              │◄────────────►│
//!  ┌───────────┼───┬──────────┤
//!  │body length│cid│block data│
//!  └───────────┴───┼──────────┤
//!                  │◄────────►│
//!                  │  =block data length
//!      block data  │
//!          offset ►│
//! ```
//!
//! ## Block ordering
//! > _... a filecoin-deterministic car-file is currently implementation-defined as containing all
//! > DAG-forming blocks in first-seen order, as a result of a depth-first DAG traversal starting
//! > from a single root._
//! - [CAR documentation](https://ipld.io/specs/transport/car/carv1/#determinism)
//!
//! # Future work
//! - [`fadvise`](https://linux.die.net/man/2/posix_fadvise)-based APIs to pre-fetch parts of the
//!   file, to improve random access performance.
//! - Use an inner [`Blockstore`] for writes.
//! - Use safe arithmetic for all operations - a malicious frame shouldn't cause a crash.
//! - Theoretically, file-backed blockstores should be clonable (or even [`Sync`]) with very low
//!   overhead, so that multiple threads could perform operations concurrently.
//! - CARv2 support
//! - A wrapper that abstracts over car formats for reading.

use tokio::io::{AsyncWrite, AsyncWriteExt};

pub async fn write_skip_frame_header_async(
    mut writer: impl AsyncWrite + Unpin,
    data_len: u32,
) -> std::io::Result<()> {
    writer.write_all(&[0x50, 0x2A, 0x4D, 0x18]).await?;
    writer.write_all(&data_len.to_le_bytes()).await?;
    Ok(())
}
