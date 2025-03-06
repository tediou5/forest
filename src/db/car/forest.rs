// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! # Forest CAR format
//!
//! See [`crate::db::car::plain`] for details on the CAR format.
//!
//! The `forest.car.zst` format wraps multiple CAR blocks in small (usually 8 KiB)
//! zstd frames, and has an index in a skippable zstd frame. At the end of the
//! data, there has to be a fixed-size skippable frame containing magic numbers
//! and meta information about the archive. CAR blocks may not span multiple
//! z-frames and the CAR header is kept it a separate z-frame.
//!
//! Imagine a `forest.car.zst` archive with 5 blocks. They could be arranged in
//! z-frames as drawn below:
//!
//! ```text
//!  Z-Frame 1   Z-Frame 2   Z-Frame 3   Skip Frame    Skip Frame
//! ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ ┌────────────┐
//! │┌──────┐ │ │┌───────┐│ │┌───────┐│ │Offsets    │ │Index offset│
//! ││Header│ │ ││Block 1││ ││Block 4││ │ Z-Frame 2 │ │Magic number│
//! │└──────┘ │ │└───────┘│ │└───────┘│ │ Z-Frame 2 │ │Version info|
//! └─────────┘ │┌───────┐│ │┌───────┐│ │ Z-Frame 2 │ └────────────┘
//!             ││Block 2││ ││Block 5││ │ Z-Frame 3 │
//!             │└───────┘│ │└───────┘│ │ Z-Frame 3 │
//!             │┌───────┐│ └─────────┘ └───────────┘
//!             ││Block 3││
//!             │└───────┘│
//!             └─────────┘
//! ```
//!
//! Looking up a block uses an [`index::Reader`] to find
//! the right z-frame. The frame is then decoded and each block is linearly
//! scanned until a match is found. Decoded (and scanned) z-frames are stored in
//! a lru-cache for faster repeat retrievals.
//!
//! `forest.car.zst` files are backward compatible with Lotus (and all other
//! tools that consume compressed CAR files). All Forest-specifc information is
//! encoded as skippable frames that are (as the name suggests) skipped by tools
//! that don't understand them.
//!
//! # Additional reading
//!
//! `zstd` frame format: <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md>
//!
//! CARv1 specification: <https://ipld.io/specs/transport/car/carv1/>
//!

use crate::db::car::plain::write_skip_frame_header_async;
use crate::utils::db::car_stream::{CarBlock, CarV1Header};
use bytes::{buf::Writer, BufMut as _, Bytes, BytesMut};
use cid::Cid;
use futures::{Stream, TryStream, TryStreamExt as _};
use fvm_ipld_encoding::to_vec;
use nunny::Vec as NonEmpty;
use std::task::Poll;
use std::{io, io::Write};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::codec::Encoder as _;
use unsigned_varint::codec::UviBytes;

#[cfg(feature = "benchmark-private")]
pub mod index;
#[cfg(not(feature = "benchmark-private"))]
mod index;

pub const DEFAULT_FOREST_CAR_FRAME_SIZE: usize = 8000_usize.next_power_of_two();
pub const DEFAULT_FOREST_CAR_COMPRESSION_LEVEL: u16 = zstd::DEFAULT_COMPRESSION_LEVEL as _;
const ZSTD_SKIP_FRAME_LEN: u64 = 8;
pub struct Encoder {}

impl Encoder {
    pub async fn write(
        mut sink: impl AsyncWrite + Unpin,
        roots: NonEmpty<Cid>,
        mut stream: impl TryStream<Ok = (Vec<Cid>, Bytes), Error = anyhow::Error> + Unpin,
    ) -> anyhow::Result<()> {
        let mut offset = 0;

        // Write CARv1 header
        let mut header_encoder = new_encoder(3)?;

        let header = CarV1Header { roots, version: 1 };
        let mut header_uvi_frame = BytesMut::new();
        UviBytes::default().encode(Bytes::from(to_vec(&header)?), &mut header_uvi_frame)?;
        header_encoder.write_all(&header_uvi_frame)?;
        let header_bytes = header_encoder.finish()?.into_inner().freeze();

        sink.write_all(&header_bytes).await?;
        let header_len = header_bytes.len();

        offset += header_len;

        // Write seekable zstd and collect a mapping of CIDs to frame_offset+data_offset.
        let mut builder = index::Builder::new();
        while let Some((cids, zstd_frame)) = stream.try_next().await? {
            builder.extend(cids.into_iter().map(|cid| (cid, offset as u64)));
            sink.write_all(&zstd_frame).await?;
            offset += zstd_frame.len()
        }

        // Create index
        let writer = builder.into_writer();
        write_skip_frame_header_async(&mut sink, writer.written_len().try_into().unwrap()).await?;
        writer.write_into(&mut sink).await?;

        // Write ForestCAR.zst footer, it's a valid ZSTD skip-frame
        let footer = ForestCarFooter {
            index: offset as u64 + ZSTD_SKIP_FRAME_LEN,
        };
        sink.write_all(&footer.to_le_bytes()).await?;
        Ok(())
    }

    /// `compress_stream` with [`DEFAULT_FOREST_CAR_FRAME_SIZE`] as default frame size and [`DEFAULT_FOREST_CAR_COMPRESSION_LEVEL`] as default compression level.
    pub fn compress_stream_default(
        stream: impl TryStream<Ok = CarBlock, Error = anyhow::Error>,
    ) -> impl TryStream<Ok = (Vec<Cid>, Bytes), Error = anyhow::Error> {
        Self::compress_stream(
            DEFAULT_FOREST_CAR_FRAME_SIZE,
            DEFAULT_FOREST_CAR_COMPRESSION_LEVEL,
            stream,
        )
    }

    /// Consume stream of blocks, emit a new position of each block and a stream
    /// of zstd frames.
    pub fn compress_stream(
        zstd_frame_size_tripwire: usize,
        zstd_compression_level: u16,
        stream: impl TryStream<Ok = CarBlock, Error = anyhow::Error>,
    ) -> impl TryStream<Ok = (Vec<Cid>, Bytes), Error = anyhow::Error> {
        let mut encoder_store = new_encoder(zstd_compression_level);
        let mut frame_cids = vec![];

        let mut stream = Box::pin(stream.into_stream());
        futures::stream::poll_fn(move |cx| {
            let encoder = match encoder_store.as_mut() {
                Err(e) => {
                    let dummy_error = io::Error::other("Error already consumed.");
                    return Poll::Ready(Some(Err(anyhow::Error::from(std::mem::replace(
                        e,
                        dummy_error,
                    )))));
                }
                Ok(encoder) => encoder,
            };
            loop {
                // Emit frame if compressed_len > zstd_frame_size_tripwire
                if compressed_len(encoder) > zstd_frame_size_tripwire {
                    let cids = std::mem::take(&mut frame_cids);
                    let frame = finalize_frame(zstd_compression_level, encoder)?;
                    return Poll::Ready(Some(Ok((cids, frame))));
                }
                // No frame to emit, let's get another block
                let ret = futures::ready!(stream.as_mut().poll_next(cx));
                match ret {
                    // End-of-stream
                    None => {
                        // If there's anything in the zstd buffer, emit it.
                        if compressed_len(encoder) > 0 {
                            let cids = std::mem::take(&mut frame_cids);
                            let frame = finalize_frame(zstd_compression_level, encoder)?;
                            return Poll::Ready(Some(Ok((cids, frame))));
                        } else {
                            // Otherwise we're all done.
                            return Poll::Ready(None);
                        }
                    }
                    // Pass errors through
                    Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                    // Got element, add to encoder and emit block position
                    Some(Ok(block)) => {
                        frame_cids.push(block.cid);
                        block.write(encoder)?;
                        encoder.flush()?;
                    }
                }
            }
        })
    }
}

fn compressed_len(encoder: &zstd::Encoder<'static, Writer<BytesMut>>) -> usize {
    encoder.get_ref().get_ref().len()
}

fn finalize_frame(
    zstd_compression_level: u16,
    encoder: &mut zstd::Encoder<'static, Writer<BytesMut>>,
) -> io::Result<Bytes> {
    let prev_encoder = std::mem::replace(encoder, new_encoder(zstd_compression_level)?);
    Ok(prev_encoder.finish()?.into_inner().freeze())
}

fn new_encoder(
    zstd_compression_level: u16,
) -> io::Result<zstd::Encoder<'static, Writer<BytesMut>>> {
    zstd::Encoder::new(BytesMut::new().writer(), i32::from(zstd_compression_level))
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ForestCarFooter {
    index: u64,
}

impl ForestCarFooter {
    pub const SIZE: usize = 16;

    pub fn to_le_bytes(&self) -> [u8; Self::SIZE] {
        let footer_data_len: u32 = 8;

        let mut buffer = [0; 16];
        // Skippable frames start with 50 2A 4D 18
        buffer[0..4].copy_from_slice(&[0x50, 0x2A, 0x4D, 0x18]);
        // Then a u32 containing the length of the data in the frame
        buffer[4..8].copy_from_slice(&footer_data_len.to_le_bytes());
        // And finally the metadata we want to store
        buffer[8..16].copy_from_slice(&self.index.to_le_bytes());
        buffer
    }
}
