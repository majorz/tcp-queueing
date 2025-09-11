//! # Chunked Serialization Module
//!
//! This module provides utilities for splitting large messages or payloads into smaller `Chunk`s
//! for transmission and for reconstructing them on the receiving end. It is designed for scenarios
//! where fixed-size fragments are preferred, such as network transport or storage.
//!
//! `ChunkProducer` and `ChunkReader` handle serialization and deserialization across multiple
//! chunk fragments. `GroupChunkQueue` enables randomized message group-based processing.
//! `GroupChunkCollector` manages chunk assembly into complete messages.

use std::collections::{HashMap, VecDeque};

use bincode::de::read::Reader;
use bincode::enc::write::Writer;
use bincode::error::{DecodeError, EncodeError};
use bincode::{Decode, Encode, decode_from_reader, encode_into_writer};
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
pub enum Chunk {
    Start {
        /// Message ID for grouping related chunks
        message_id: u16,

        /// Total length of the original message in bytes
        total_length: u64,

        /// The actual data payload of this chunk
        data: Payload,
    },
    Data {
        /// Message ID for grouping related chunks
        message_id: u16,

        /// The actual data payload of this chunk
        data: Payload,
    },
}

impl Chunk {
    pub fn message_id(&self) -> u16 {
        match self {
            Chunk::Start { message_id, .. } => *message_id,
            Chunk::Data { message_id, .. } => *message_id,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Chunk::Start { data, .. } => data.len(),
            Chunk::Data { data, .. } => data.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Chunk::Start { data, .. } => data.is_empty(),
            Chunk::Data { data, .. } => data.is_empty(),
        }
    }

    pub fn data(&self) -> &[u8] {
        match self {
            Chunk::Start { data, .. } => data,
            Chunk::Data { data, .. } => data,
        }
    }

    pub fn bytes(&self) -> &Bytes {
        match self {
            Chunk::Start { data, .. } => data,
            Chunk::Data { data, .. } => data,
        }
    }

    pub fn is_start(&self) -> bool {
        matches!(self, Chunk::Start { .. })
    }
}

/// Writer that appends encoded data into a `BytesMut`
pub struct BytesMutWriter<'a> {
    bytes: &'a mut BytesMut,
}

impl<'a> Writer for BytesMutWriter<'a> {
    fn write(&mut self, data: &[u8]) -> Result<(), EncodeError> {
        self.bytes.extend_from_slice(data);
        Ok(())
    }
}

impl<'a> BytesMutWriter<'a> {
    pub fn new(bytes: &'a mut BytesMut) -> Self {
        Self { bytes }
    }
}

/// Encodes a value into a `BytesMut`, similar to `bincode::encode_to_vec`.
pub fn encode_to_bytes_mut<T: Encode>(value: &T) -> Result<BytesMut, EncodeError> {
    let mut bytes = BytesMut::new();

    let mut writer = BytesMutWriter::new(&mut bytes);
    encode_into_writer(value, &mut writer, bincode::config::standard())?;

    Ok(bytes)
}

/// An iterator that produces `Chunk`s from a serializable value.
pub struct ChunkProducer<const FRAGMENT_SIZE: usize> {
    // The serialized message
    buffer: BytesMut,

    // Derived from the first byte of the serialized message
    message_id: u16,

    // Total length of the original serialized message
    total_length: usize,

    // Should Chunk::Start be produced
    is_start_chunk: bool,
}

impl<const FRAGMENT_SIZE: usize> ChunkProducer<FRAGMENT_SIZE> {
    /// Serialize a value into a `BytesMut` and prepare for chunking
    pub fn new<T: Encode>(value: &T) -> Result<Self, EncodeError> {
        let buffer = encode_to_bytes_mut(value)?;
        let total_length = buffer.len();

        let message_id = buffer
            .first()
            .copied()
            .ok_or_else(|| EncodeError::OtherString("No data encoded".to_string()))?
            as u16;

        Ok(Self {
            buffer,
            message_id,
            total_length,
            is_start_chunk: true,
        })
    }
}

impl<const FRAGMENT_SIZE: usize> Iterator for ChunkProducer<FRAGMENT_SIZE> {
    type Item = Chunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }

        // Determine size of this chunk
        let chunk_size = FRAGMENT_SIZE.min(self.buffer.len());

        // Split the chunk and freeze without extra allocation
        let bytes = self.buffer.split_to(chunk_size).freeze();
        let data = Payload(bytes);

        let chunk = if self.is_start_chunk {
            self.is_start_chunk = false;
            Chunk::Start {
                message_id: self.message_id,
                total_length: self.total_length as u64,
                data,
            }
        } else {
            Chunk::Data {
                message_id: self.message_id,
                data,
            }
        };

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
    fn payload(&self) -> Option<&[u8]> {
        self.chunks.get(self.chunk_index).map(|c| c.data())
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

/// A queue that holds chunks grouped by `message_id` and allows random selection when popping.
///
/// This structure is useful for sending chunked messages with a randomized group order
/// while maintaining the order of chunks within a message group.
pub struct GroupChunkQueue {
    // Maps message_id to its queued chunks
    messages: HashMap<u16, VecDeque<Chunk>>,

    // Active message IDs for random selection synced with `messages` keys
    message_ids: Vec<u16>,

    // Non-cryptographic RNG for quick random rotation
    rng: SmallRng,
}

impl GroupChunkQueue {
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
            message_ids: Vec::new(),
            rng: SmallRng::from_seed([0; 32]),
        }
    }

    /// Pushes a single chunk into the queue.
    pub fn push_chunk(&mut self, chunk: Chunk) {
        let message_id = chunk.message_id();

        // Get or create the queue for this message_id
        let queue = self.messages.entry(message_id).or_default();

        // Sync the message_id if it is newly added
        if queue.is_empty() {
            self.message_ids.push(message_id);
        }

        queue.push_back(chunk);
    }

    /// Pops the front chunk from a randomly selected active message group
    pub fn pop_random_chunk(&mut self) -> Option<Chunk> {
        if self.message_ids.is_empty() {
            return None;
        }

        // Pick a random message group index
        let idx = self.rng.random_range(0..self.message_ids.len());
        let message_id = self.message_ids[idx];

        // Pop the first chunk from the selected group queue
        let queue = self.messages.get_mut(&message_id)?;
        let chunk = queue.pop_front();

        // Remove the message group if it becomes empty
        if queue.is_empty() {
            self.messages.remove(&message_id);
            self.message_ids.swap_remove(idx); // O(1) removal
        }

        chunk
    }

    /// Returns true if there are no chunks in any group
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Collector for partially received chunks within message groups.
///
/// This ensures that chunks are stored in order and can be assembled into a complete message.
pub struct GroupChunkCollector {
    // Maps message_id to its received chunks
    messages: HashMap<u16, Vec<Chunk>>,

    // Tracks total bytes received per message
    bytes_received: HashMap<u16, usize>,
}

impl GroupChunkCollector {
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
            bytes_received: HashMap::new(),
        }
    }

    /// Adds a chunk to the corresponding message group.
    ///
    /// If this chunk completes its group, the function returns all collected chunks for
    /// that message group.
    ///
    /// If a start chunk arrives, any previously collected chunks for that message group are
    /// discarded.
    pub fn push(&mut self, chunk: Chunk) -> Option<Vec<Chunk>> {
        let message_id = chunk.message_id();

        // If first chunk is Start, reset previous state
        if chunk.is_start() {
            self.messages.remove(&message_id);
            self.bytes_received.insert(message_id, 0);
            self.messages.insert(message_id, Vec::new());
        }

        let chunk_length = chunk.len();

        let entry = self.messages.entry(message_id).or_default();
        entry.push(chunk);

        let bytes_received = self.bytes_received.entry(message_id).or_default();
        *bytes_received += chunk_length;

        // Check if this is the last chunk of the message
        if let Some(Chunk::Start { total_length, .. }) = entry.first()
            && *bytes_received >= *total_length as usize
        {
            // Message complete
            self.bytes_received.remove(&message_id);
            return self.messages.remove(&message_id);
        }

        None
    }
}
