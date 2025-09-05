use std::collections::VecDeque;

use bincode::de::read::Reader;
use bincode::enc::write::Writer;
use bincode::encode_into_writer;
use bincode::error::{DecodeError, EncodeError};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};

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
    pub index: usize,

    /// Total number of chunks in the group.
    pub total: usize,

    /// Data payload contained in this chunk.
    pub payload: Payload,
}

impl Chunk {
    pub fn new(group_id: u8, index: usize, total: usize, payload: Payload) -> Self {
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

/// A trait for types that can be constructed from multiple `Chunk`s.
///
/// This is useful when a type can be split into multiple chunks for serialization
/// or transmission, but can also hold just a single chunk.
pub trait ChunkWrapper {
    fn wrap_chunk(chunk: Chunk) -> Self;
}

/// An iterator that produces `ChunkWrapper` instances from a serializable value.
///
/// This iterator takes a value that implements `bincode::Encode`, serializes it into
/// fixed-size fragments using `FragmentWriter` and then yields each fragment as a
/// `Chunk` wrapped in a `ChunkWrapper` instance.
///
/// # Type Parameters
/// - `FRAGMENT_SIZE`: The maximum size of each fragment in bytes.
/// - `C`: The type that implements `ChunkWrapper` and can be constructed from series of `Chunk`s.
pub struct ChunkIterator<const FRAGMENT_SIZE: usize, C: ChunkWrapper> {
    fragments: VecDeque<Bytes>,
    group_id: u8,
    total: usize,
    _phantom: std::marker::PhantomData<C>,
}

impl<const FRAGMENT_SIZE: usize, C: ChunkWrapper> ChunkIterator<FRAGMENT_SIZE, C> {
    /// Create a new `ChunkIterator` from a serializable value.
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

        let total = fragments.len();

        Ok(Self {
            fragments,
            group_id,
            total,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<const FRAGMENT_SIZE: usize, C: ChunkWrapper> Iterator for ChunkIterator<FRAGMENT_SIZE, C> {
    type Item = C;

    /// Return the next chunk wrapped in the `ChunkWrapper`.
    ///
    /// Each call to `next` yields the next chunk, along with its index and the
    /// total number of chunks. When all chunks have been consumed, it returns `None`.
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.total - self.fragments.len();
        let bytes = self.fragments.pop_front()?;
        let chunk = Chunk::new(self.group_id, index, self.total, Payload::from(bytes));
        Some(C::wrap_chunk(chunk))
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

    /// Returns the current chunk's payload as a byte slice.
    fn payload(&self) -> Option<&Bytes> {
        self.chunks.get(self.chunk_index).map(|c| &c.payload.0)
    }

    /// Advances to the next chunk if the current one is fully consumed.
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
