//! # Chunked Serialization Module
//!
//! This module provides utilities for splitting large messages or payloads into smaller `Chunk`s,
//! transmitting them, and reconstructing them. It is designed for scenarios where fixed-size
//! fragments are preferred, such as network transport, storage, or messaging systems.
//!
//! Chunks are grouped by a `group_id` representing a logical message. The `ChunkProducer` and
//! `ChunkReader` abstractions handle serialization and deserialization seamlessly across
//! multiple fragments. Randomized group processing is supported via `GroupChunkQueue`.

use std::collections::{HashMap, VecDeque};

use bincode::{Decode, Encode, encode_into_writer, decode_from_reader};
use bincode::error::{EncodeError, DecodeError};
use bincode::de::read::Reader;
use bincode::enc::write::Writer;
use bytes::{Bytes, BytesMut};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use mirrord_protocol::payload::Payload;

/// Represents a single chunk of a larger message or data payload.
///
/// A `Chunk` is used to split large messages into smaller pieces for transmission
/// over a network or storage where fixed and smaller size frames are preferable. Each chunk
/// contains metadata that allows the receiver to reassemble the original
/// data correctly.
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct Chunk {
    /// Identifier for the group of chunks that belong to the same message.
    pub group_id: u8,

    /// Index of this chunk within the group.
    pub index: u64,

    /// Total number of chunks in the group.
    pub total: u64,

    /// Data payload contained in this chunk.
    pub payload: Payload,
}

impl Chunk {
    pub fn new(group_id: u8, index: u64, total: u64, payload: Payload) -> Self {
        Self {
            group_id,
            index,
            total,
            payload,
        }
    }
}

/// A writer that splits encoded data into fixed-size fragments.
///
/// `FragmentWriter` implements the `bincode::enc::write::Writer` trait,
/// allowing it to be used with `bincode::encode_into_writer` to serialize
/// arbitrary Rust values. The serialized data is collected into `Bytes`
/// fragments of size `FRAGMENT_SIZE`.
///
/// This is useful for sending large messages over the network in fixed-size
/// chunks.
pub struct FragmentWriter<const FRAGMENT_SIZE: usize> {
    /// Queue of fully encoded fragments
    fragments: VecDeque<Bytes>,

    /// Temporary storage for data being accumulated
    pending_fragment: BytesMut,
}

impl<const FRAGMENT_SIZE: usize> FragmentWriter<FRAGMENT_SIZE> {
    pub fn new() -> Self {
        Self {
            fragments: VecDeque::new(),
            pending_fragment: BytesMut::with_capacity(FRAGMENT_SIZE),
        }
    }

    /// Encode a value using this writer and bincode standard config
    pub fn encode<T: Encode>(&mut self, value: &T) -> Result<(), EncodeError> {
        encode_into_writer(value, self, bincode::config::standard())
    }

    /// Consume this writer and return all completed fragments
    pub fn finalize(mut self) -> VecDeque<Bytes> {
        self.flush_pending();
        self.fragments
    }

    /// Flush the current pending fragment into the completed fragments queue
    fn flush_pending(&mut self) {
        if self.pending_fragment.is_empty() {
            return;
        }
        let bytes = self.pending_fragment.split().freeze();
        self.fragments.push_back(bytes);
    }
}

impl<const FRAGMENT_SIZE: usize> Default for FragmentWriter<FRAGMENT_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const FRAGMENT_SIZE: usize> Writer for FragmentWriter<FRAGMENT_SIZE> {
    /// Write bytes into the queue, splitting into fragments as needed
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let mut remaining_data = bytes;

        while !remaining_data.is_empty() {
            let space_left_in_pending = FRAGMENT_SIZE - self.pending_fragment.len();

            if remaining_data.len() >= space_left_in_pending {
                // Fill pending fragment to full capacity
                self.pending_fragment
                    .extend_from_slice(&remaining_data[..space_left_in_pending]);
                self.flush_pending();

                // Move the slice forward
                remaining_data = &remaining_data[space_left_in_pending..];
            } else {
                // All remaining data fits in the pending fragment
                self.pending_fragment.extend_from_slice(remaining_data);
                break;
            }
        }

        Ok(())
    }
}

/// An iterator that produces `Chunk`s from a serializable value.
///
/// This iterator takes a value that implements `bincode::Encode`, serializes it into
/// fixed-size fragments using `FragmentWriter` and then yields each fragment as `Chunk`
///
/// # Type Parameters
/// - `FRAGMENT_SIZE`: The maximum size of each fragment in bytes.
pub struct ChunkProducer<const FRAGMENT_SIZE: usize> {
    fragments: VecDeque<Bytes>,
    group_id: u8,
    total: u64,
}

impl<const FRAGMENT_SIZE: usize> ChunkProducer<FRAGMENT_SIZE> {
    /// Create a new `ChunkProducer` from a serializable value.
    ///
    /// This method serializes the given value using `bincode` and splits it into
    /// fragments of size `FRAGMENT_SIZE`. The first byte of the first fragment is
    /// used as the `group_id`.
    pub fn new<T: Encode>(value: &T) -> Result<Self, EncodeError> {
        let mut writer = FragmentWriter::<FRAGMENT_SIZE>::new();
        writer.encode(value)?;

        let fragments = writer.finalize();

        // Extract the first byte as group ID safely.
        // `bincode` always encodes enums with a leading byte.
        let group_id = fragments
            .front()
            .and_then(|b| b.first())
            .copied()
            .ok_or_else(|| {
                EncodeError::OtherString("No data encoded into fragments".to_string())
            })?;

        let total = fragments.len() as u64;

        Ok(Self {
            fragments,
            group_id,
            total,
        })
    }
}

impl<const FRAGMENT_SIZE: usize> Iterator for ChunkProducer<FRAGMENT_SIZE> {
    type Item = Chunk;

    /// Return the next chunk.
    ///
    /// Each call to `next` yields the next chunk, along with its index and the
    /// total number of chunks. When all chunks have been consumed, it returns `None`.
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.total - self.fragments.len() as u64;
        let bytes = self.fragments.pop_front()?;
        let chunk = Chunk::new(self.group_id, index, self.total, Payload::from(bytes));
        Some(chunk)
    }
}

/// Reads bytes sequentially from a series of `Chunk`s for bincode decoding.
///
/// `ChunkReader` implements `bincode::de::read::Reader`, allowing `bincode` to
/// decode data that is split across multiple `Chunk`s.
pub struct ChunkReader {
    /// Chunks to be read.
    chunks: Vec<Chunk>,

    /// Index of the chunk currently being read.
    chunk_index: usize,

    /// Offset within the current chunk.
    offset: usize,
}

impl ChunkReader {
    /// Creates a new `ChunkReader` from a vector of `Chunk`s.
    ///
    /// # Parameters
    /// - `chunks`: A vector of `Chunk`s to read from. The order should match the
    ///   intended byte sequence for decoding. Sorting will not be performed.
    pub fn new(chunks: Vec<Chunk>) -> Self {
        Self {
            chunks,
            chunk_index: 0,
            offset: 0,
        }
    }

    /// Decode a value from the chunks using bincode standard config.
    pub fn decode<T: Decode<()>>(&mut self) -> Result<T, DecodeError> {
        decode_from_reader(self, bincode::config::standard())
    }

    /// Returns the current chunk's payload as a byte slice.
    #[inline]
    fn payload(&self) -> Option<&Bytes> {
        self.chunks.get(self.chunk_index).map(|c| &c.payload.0)
    }

    /// Advances to the next chunk if the current one is fully consumed.
    #[inline]
    fn next_chunk(&mut self) {
        if let Some(payload) = self.payload()
            && self.offset >= payload.len()
        {
            self.chunk_index += 1;
            self.offset = 0;
        }
    }
}

impl Reader for ChunkReader {
    /// Fills the provided buffer with sequential bytes from the chunks.
    fn read(&mut self, mut buf: &mut [u8]) -> Result<(), DecodeError> {
        // Keep copying bytes until the entire buffer is filled
        while !buf.is_empty() {
            self.next_chunk();

            // Get the payload of the current chunk or exit if no more chunks
            let payload = self.payload().ok_or(DecodeError::UnexpectedEnd {
                additional: buf.len(),
            })?;

            // Remaining bytes in the current chunk
            let remaining = &payload[self.offset..];

            // Copy the smaller of remaining chunk bytes or remaining buffer space
            let to_copy = remaining.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&remaining[..to_copy]);

            // Move offset forward in the current chunk
            self.offset += to_copy;

            // Reduce buf to the remaining part that still needs to be filled
            buf = &mut buf[to_copy..];
        }

        Ok(())
    }
}

/// A queue that holds chunks grouped by `group_id` and allows random selection when popping.
///
/// This structure is useful for sending chunked messages with a randomized group order
/// while maintaining the order of chunks within a group.
pub struct GroupChunkQueue {
    // Maps group_id to its queued chunks
    groups: HashMap<u8, VecDeque<Chunk>>,

    // Active group IDs for random selection synced with `groups` keys
    group_ids: Vec<u8>,

    // Non-cryptographic RNG for quick random rotation
    rng: SmallRng,
}

impl GroupChunkQueue {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            group_ids: Vec::new(),
            rng: SmallRng::from_seed([0; 32]),
        }
    }

    /// Pushes a single chunk into the queue.
    pub fn push_chunk(&mut self, chunk: Chunk) {
        let group_id = chunk.group_id;

        // Get or create the queue for this group
        let queue = self.groups.entry(group_id).or_default();

        // Sync the group_id if it is newly added
        if queue.is_empty() {
            self.group_ids.push(group_id);
        }

        queue.push_back(chunk);
    }

    /// Pops the front chunk from a randomly selected active group
    pub fn pop_random_chunk(&mut self) -> Option<Chunk> {
        if self.group_ids.is_empty() {
            return None;
        }

        // Pick a random group index
        let idx = self.rng.random_range(0..self.group_ids.len());
        let group_id = self.group_ids[idx];

        // Pop the first chunk from the selected group queue
        let queue = self.groups.get_mut(&group_id)?;
        let chunk = queue.pop_front();

        // Remove the group if it becomes empty
        if queue.is_empty() {
            self.groups.remove(&group_id);
            self.group_ids.swap_remove(idx); // O(1) removal
        }

        chunk
    }

    /// Returns true if there are no chunks in any group
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// Collector for partially received chunks within groups.
///
/// This ensures that chunks are stored in order and can be assembled into a complete message.
pub struct GroupChunkCollector {
    // Maps group_id to its received chunks
    groups: HashMap<u8, Vec<Chunk>>,
}

impl GroupChunkCollector {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Adds a chunk to the corresponding group.
    ///
    /// If this chunk completes its group, the function returns all collected chunks for that group.
    ///
    /// If a chunk with `index == 0` arrives, any previously collected chunks for that group are
    /// discarded.
    pub fn push(&mut self, chunk: Chunk) -> Option<Vec<Chunk>> {
        // If a chunk with index 0 arrives, drop any previously collected chunks
        if chunk.index == 0 && self.groups.contains_key(&chunk.group_id) {
            // TODO: Handle or log discarded chunks
            self.groups.remove(&chunk.group_id);
        }

        let entry = self.groups.entry(chunk.group_id).or_default();
        entry.push(chunk.clone());

        // Check if this is the last chunk of the group
        if chunk.index + 1 == chunk.total {
            // Take the completed group
            let complete_chunks = self.groups.remove(&chunk.group_id).unwrap();
            Some(complete_chunks)
        } else {
            None
        }
    }
}
