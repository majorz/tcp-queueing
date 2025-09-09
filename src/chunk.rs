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
use std::borrow::Cow;

use bincode::{Decode, Encode, encode_into_writer, decode_from_reader};
use bincode::error::{EncodeError, DecodeError};
use bincode::de::read::Reader;
use bincode::enc::write::Writer;
//use bytes::{Bytes, BytesMut};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

/// Represents a single chunk of a larger message or data payload.
///
/// A `Chunk` is used to split large messages into smaller pieces for transmission
/// over a network or storage where fixed and smaller size frames are preferable. Each chunk
/// contains metadata that allows the receiver to reassemble the original
/// data correctly.
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum Chunk<'a> {
    Start {
        message_id: u16,
        total_length: u64,
        data: Cow<'a, [u8]>,
    },
    Data {
        message_id: u16,
        data: Cow<'a, [u8]>,
    },
}

impl<'a> Chunk<'a> {
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

    pub fn is_start(&self) -> bool {
        matches!(self, Chunk::Start { .. })
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
pub struct FragmentWriter<'a, const FRAGMENT_SIZE: usize> {
    /// Queue of fully encoded fragments
    fragments: VecDeque<Cow<'a, [u8]>>,

    /// Temporary storage for data being accumulated
    pending_fragment: Vec<u8>,

    /// Total length of data written
    total_length: u64,
}

impl<'a, const FRAGMENT_SIZE: usize> FragmentWriter<'a, FRAGMENT_SIZE> {
    pub fn new() -> Self {
        Self {
            fragments: VecDeque::new(),
            pending_fragment: Vec::with_capacity(FRAGMENT_SIZE),
            total_length: 0,
        }
    }

    /// Encode a value using this writer and bincode standard config
    pub fn encode<T: Encode>(&mut self, value: &T) -> Result<(), EncodeError> {
        encode_into_writer(value, self, bincode::config::standard())
    }

    /// Consume this writer and return all completed fragments
    pub fn finalize(mut self) -> (VecDeque<Cow<'a, [u8]>>, u64) {
        self.flush_pending();
        (self.fragments, self.total_length)
    }

    /// Flush the current pending fragment into the completed fragments queue
    fn flush_pending(&mut self) {
        if self.pending_fragment.is_empty() {
            return;
        }
        self.total_length += self.pending_fragment.len() as u64;
        let data = Cow::Owned(std::mem::take(&mut self.pending_fragment));
        self.fragments.push_back(data);
    }
}

impl<'a, const FRAGMENT_SIZE: usize> Default for FragmentWriter<'a, FRAGMENT_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, const FRAGMENT_SIZE: usize> Writer for FragmentWriter<'a, FRAGMENT_SIZE> {
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
pub struct ChunkProducer<'a, const FRAGMENT_SIZE: usize> {
    fragments: VecDeque<Cow<'a, [u8]>>,
    message_id: u16,
    total_length: u64,
    chunk_count: usize,
}

impl<'a, const FRAGMENT_SIZE: usize> ChunkProducer<'a, FRAGMENT_SIZE> {
    /// Create a new `ChunkProducer` from a serializable value.
    ///
    /// This method serializes the given value using `bincode` and splits it into
    /// fragments of size `FRAGMENT_SIZE`. The first byte of the first fragment is
    /// used as the `message_id`.
    pub fn new<T: Encode>(value: &T) -> Result<Self, EncodeError> {
        let mut writer = FragmentWriter::<FRAGMENT_SIZE>::new();
        writer.encode(value)?;

        let (fragments, total_length) = writer.finalize();

        // Extract the first byte as message ID safely.
        // `bincode` always encodes enums with a leading byte.
        let message_id = fragments
            .front()
            .and_then(|b| b.first())
            .copied()
            .ok_or_else(|| {
                EncodeError::OtherString("No data encoded into fragments".to_string())
            })? as u16;

        let chunk_count = fragments.len();

        Ok(Self {
            fragments,
            message_id,
            total_length,
            chunk_count,
        })
    }
}

impl<'a, const FRAGMENT_SIZE: usize> Iterator for ChunkProducer<'a, FRAGMENT_SIZE> {
    type Item = Chunk<'a>;

    /// Return the next chunk.
    ///
    /// Each call to `next` yields the next chunk, along with its index and the
    /// total number of chunks. When all chunks have been consumed, it returns `None`.
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.chunk_count - self.fragments.len();
        let data = self.fragments.pop_front()?;
        if index == 0 {
            Some(Chunk::Start {
                message_id: self.message_id,
                total_length: self.total_length,
                data,
            })
        } else {
            Some(Chunk::Data {
                message_id: self.message_id,
                data,
            })
        }
    }
}

/// Reads bytes sequentially from a series of `Chunk`s for bincode decoding.
///
/// `ChunkReader` implements `bincode::de::read::Reader`, allowing `bincode` to
/// decode data that is split across multiple `Chunk`s.
pub struct ChunkReader<'a> {
    /// Chunks to be read.
    chunks: Vec<Chunk<'a>>,

    /// Index of the chunk currently being read.
    chunk_index: usize,

    /// Offset within the current chunk.
    offset: usize,
}

impl<'a> ChunkReader<'a> {
    /// Creates a new `ChunkReader` from a vector of `Chunk`s.
    ///
    /// # Parameters
    /// - `chunks`: A vector of `Chunk`s to read from. The order should match the
    ///   intended byte sequence for decoding. Sorting will not be performed.
    pub fn new(chunks: Vec<Chunk<'a>>) -> Self {
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

impl<'a> Reader for ChunkReader<'a>{
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
pub struct GroupChunkQueue<'a> {
    // Maps message_id to its queued chunks
    messages: HashMap<u16, VecDeque<Chunk<'a>>>,

    // Active message IDs for random selection synced with `messages` keys
    message_ids: Vec<u16>,

    // Non-cryptographic RNG for quick random rotation
    rng: SmallRng,
}

impl<'a> GroupChunkQueue<'a> {
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
            message_ids: Vec::new(),
            rng: SmallRng::from_seed([0; 32]),
        }
    }

    /// Pushes a single chunk into the queue.
    pub fn push_chunk(&mut self, chunk: Chunk<'a>) {
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
    pub fn pop_random_chunk(&mut self) -> Option<Chunk<'_>> {
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

    /// Returns true if there are no chunks in any message group
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Collector for partially received chunks within message groups.
///
/// This ensures that chunks are stored in order and can be assembled into a complete message.
pub struct GroupChunkCollector<'a> {
    // Maps message_id to its received chunks
    messages: HashMap<u16, Vec<Chunk<'a>>>,

    // Tracks total bytes received per message
    bytes_received: HashMap<u16, usize>,
}

impl<'a> GroupChunkCollector<'a> {
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
    pub fn push(&mut self, chunk: Chunk<'a>) -> Option<Vec<Chunk<'_>>> {
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
            && *bytes_received >= *total_length as usize {
            // Message complete
            self.bytes_received.remove(&message_id);
            return self.messages.remove(&message_id);                
        }

        None
    }
}
