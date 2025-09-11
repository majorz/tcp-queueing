mod chunk;

use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};

use actix_codec::{Decoder, Encoder};
use anyhow::Result;
use bincode::error::DecodeError;
use bincode::{Decode, Encode};
use bytes::{Buf, BufMut, BytesMut};
use futures::{SinkExt, StreamExt, stream::SplitSink};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio::time::timeout;
use tokio_util::codec::Framed;

use mirrord_macros::protocol_break;

use mirrord_protocol::{
    FileRequest, FileResponse, GetEnvVarsRequest, LogMessage, RemoteResult,
    dns::{GetAddrInfoRequest, GetAddrInfoRequestV2, GetAddrInfoResponse},
    outgoing::{
        DaemonRead, LayerWrite,
        tcp::{DaemonTcpOutgoing, LayerTcpOutgoing},
        udp::{DaemonUdpOutgoing, LayerUdpOutgoing},
    },
    tcp::{DaemonTcp, LayerTcp, LayerTcpSteal},
    vpn::{ClientVpn, ServerVpn},
};

#[allow(deprecated)]
use mirrord_protocol::pause::DaemonPauseTarget;

use crate::chunk::{Chunk, ChunkProducer, ChunkReader, GroupChunkCollector, GroupChunkQueue};

const SERVER_ADDRESS: &str = "127.0.0.1:3333";

const MESSAGE_COUNT: usize = 10;
const MESSAGE_SIZE: usize = 1000; //1_000_000;

const CHANNEL_CAPACITY: usize = 1000;

const PING_TIMEOUT_MS: u64 = 200;

const CHUNK_SIZE: usize = 32 * 1024; // 32 KB

// const TCP_DELAY_MS: u64 = 10;

////////////////////////////////////////////////////////////////////
// codec.rs
//

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum ProtocolFlavor {
    Standard,
    Chunked,
}

/// `-layer` --> `-agent` messages.
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum ClientMessage {
    Close,
    /// TCP sniffer message.
    ///
    /// These are the messages used by the `mirror` feature, and handled by the
    /// `TcpSnifferApi` in the agent.
    Tcp(LayerTcp),

    /// TCP stealer message.
    ///
    /// These are the messages used by the `steal` feature, and handled by the `TcpStealerApi` in
    /// the agent.
    TcpSteal(LayerTcpSteal),
    /// TCP outgoing message.
    ///
    /// These are the messages used by the `outgoing` feature (tcp), and handled by the
    /// `TcpOutgoingApi` in the agent.
    TcpOutgoing(LayerTcpOutgoing),

    /// UDP outgoing message.
    ///
    /// These are the messages used by the `outgoing` feature (udp), and handled by the
    /// `UdpOutgoingApi` in the agent.
    UdpOutgoing(LayerUdpOutgoing),
    FileRequest(FileRequest),
    GetEnvVarsRequest(GetEnvVarsRequest),
    Ping,
    GetAddrInfoRequest(GetAddrInfoRequest),
    /// Whether to pause or unpause the target container.
    PauseTargetRequest(bool),
    SwitchProtocolVersion(#[bincode(with_serde)] semver::Version),
    ReadyForLogs,
    Vpn(ClientVpn),
    GetAddrInfoRequestV2(GetAddrInfoRequestV2),
    /// Pong message that replies to [`DaemonMessage::OperatorPing`].
    ///
    /// Has the same ID that we got from the [`DaemonMessage::OperatorPing`].
    OperatorPong(u128),
    Chunk(Chunk),
    /// Client demands switching the protocol.
    /// After receiving [`DaemonMessage::ProtocolSwitched`] the client can recover the raw IO stream and apply the protocol-specific codec.
    /// After sending this message, the client must suspend sending messages until [`DaemonMessage::ProtocolSwitched`] is received.
    SwitchProtocol(ProtocolFlavor),
}

/// `-agent` --> `-layer` messages.
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
#[protocol_break(2)]
#[allow(deprecated)] // We can't remove deprecated variants without breaking the protocol
pub enum DaemonMessage {
    /// Kills the intproxy, no guarantee that messages that were sent before a `Close` will be
    /// handled by the intproxy and forwarded to the layer before the intproxy exits.
    Close(String),
    Tcp(DaemonTcp),
    TcpSteal(DaemonTcp),
    TcpOutgoing(DaemonTcpOutgoing),
    UdpOutgoing(DaemonUdpOutgoing),
    LogMessage(LogMessage),
    File(FileResponse),
    Pong,
    /// NOTE: can remove `RemoteResult` when we break protocol compatibility.
    GetEnvVarsResponse(RemoteResult<HashMap<String, String>>),
    GetAddrInfoResponse(GetAddrInfoResponse),
    /// Pause is deprecated but we don't want to break protocol
    PauseTarget(DaemonPauseTarget),
    SwitchProtocolVersionResponse(#[bincode(with_serde)] semver::Version),
    Vpn(ServerVpn),
    /// Ping message that comes from the operator to mirrord.
    ///
    /// - Unlike other `DaemonMessage`s, this should never come from the agent!
    ///
    /// Holds the unique id of this ping.
    OperatorPing(u128),
    Chunk(Chunk),
    /// Informs the client that the protocol has been switched according to the [`ClientMessage::SwitchProtocol`] request.
    /// After sending this message, the daemon can recover the raw IO stream and apply the protocol-specific codec.
    ProtocolSwitched,
}

pub struct ProtocolCodec<I, O> {
    config: bincode::config::Configuration,
    /// Phantom fields to make this struct generic over message types.
    _phantom_incoming_message: PhantomData<I>,
    _phantom_outgoing_message: PhantomData<O>,
}

// Codec to be used by the client side to receive `DaemonMessage`s from the agent and send
// `ClientMessage`s to the agent.
pub type ClientCodec = ProtocolCodec<DaemonMessage, ClientMessage>;
// Codec to be used by the agent side to receive `ClientMessage`s from the client and send
// `DaemonMessage`s to the client.
pub type DaemonCodec = ProtocolCodec<ClientMessage, DaemonMessage>;

impl<I, O> Default for ProtocolCodec<I, O> {
    fn default() -> Self {
        Self {
            config: bincode::config::standard(),
            _phantom_incoming_message: Default::default(),
            _phantom_outgoing_message: Default::default(),
        }
    }
}

impl<I: bincode::Decode<()>, O> Decoder for ProtocolCodec<I, O> {
    type Item = I;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        match bincode::decode_from_slice(&src[..], self.config) {
            Ok((message, read)) => {
                src.advance(read);
                Ok(Some(message))
            }
            Err(DecodeError::UnexpectedEnd { .. }) => Ok(None),
            Err(err) => Err(io::Error::other(err.to_string())),
        }
    }
}

impl<I, O: bincode::Encode> Encoder<O> for ProtocolCodec<I, O> {
    type Error = io::Error;

    fn encode(&mut self, msg: O, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded = match bincode::encode_to_vec(msg, self.config) {
            Ok(encoded) => encoded,
            Err(err) => {
                return Err(io::Error::other(err.to_string()));
            }
        };
        dst.reserve(encoded.len());
        dst.put(&encoded[..]);

        Ok(())
    }
}

pub type ChunkCodec = ProtocolCodec<Chunk, Chunk>;

//////////////////////////////////////////////////////////////////////

pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    async fn run(mut self) -> Result<()> {
        let socket = TcpStream::connect(SERVER_ADDRESS).await?;
        let mut framed = Framed::new(socket, ClientCodec::default());

        self.send_heavy_messages(&mut framed).await?;
        self.measure_ping(&mut framed).await?;
        println!("Client finished.");
        Ok(())
    }

    async fn send_heavy_messages(
        &mut self,
        framed: &mut Framed<TcpStream, ClientCodec>,
    ) -> Result<()> {
        for i in 0..MESSAGE_COUNT {
            let write = LayerWrite {
                connection_id: i as u64,
                bytes: vec![0u8; MESSAGE_SIZE].into(),
            };
            framed
                .send(ClientMessage::TcpOutgoing(LayerTcpOutgoing::Write(write)))
                .await?;
        }
        Ok(())
    }

    /// Sends a Ping and waits for a Pong with a timeout, printing latency
    async fn measure_ping(&mut self, framed: &mut Framed<TcpStream, ClientCodec>) -> Result<()> {
        let start = Instant::now();
        framed.send(ClientMessage::Ping).await?;

        let mut collector = GroupChunkCollector::new();

        let result = timeout(Duration::from_millis(PING_TIMEOUT_MS), async {
            while let Some(msg) = framed.next().await {
                match msg? {
                    DaemonMessage::Pong => return Ok::<(), anyhow::Error>(()),
                    DaemonMessage::Chunk(chunk) => {
                        if let Some(chunks) = collector.push(chunk) {
                            // We now have a complete group of chunks
                            let mut reader = ChunkReader::new(chunks);

                            let decoded_msg = reader.decode().unwrap();

                            if let DaemonMessage::Pong = decoded_msg {
                                println!("Received Pong!");
                                return Ok(());
                            } else {
                                println!("Received unexpected message: {:?}", decoded_msg);
                            }
                        }
                    }
                    _ => continue,
                }
            }
            Ok(())
        })
        .await;

        match result {
            Ok(_) => println!("Ping responded in {:?}", start.elapsed()),
            Err(_) => println!("Ping timed out after {:?}", start.elapsed()),
        }

        Ok(())
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Server {}

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    /// Runs the server loop: handles incoming messages and sends responses
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(SERVER_ADDRESS).await?;
        println!("Server listening on {}", SERVER_ADDRESS);

        let (stream, _) = listener.accept().await?;

        let framed = Framed::new(stream, DaemonCodec::default());

        // Split the framed stream into sink & stream
        let (sink, mut stream) = framed.split();

        let (tx_out, rx_out) = mpsc::channel::<DaemonMessage>(CHANNEL_CAPACITY);

        tokio::spawn(sender_task(rx_out, sink));

        while let Some(msg) = stream.next().await {
            match msg {
                Ok(client_msg) => {
                    if let Err(e) = self.handle_client_message(client_msg, &tx_out).await {
                        eprintln!("Error handling message: {:?}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from client: {:?}", e);
                    break;
                }
            }
        }

        println!("Server shutting down.");
        Ok(())
    }

    /// Handles individual client messages
    async fn handle_client_message(
        &self,
        msg: ClientMessage,
        tx_out: &mpsc::Sender<DaemonMessage>,
    ) -> Result<()> {
        match msg {
            ClientMessage::TcpOutgoing(LayerTcpOutgoing::Write(tcp)) => {
                let read = DaemonRead {
                    connection_id: tcp.connection_id,
                    bytes: tcp.bytes,
                };
                let response = DaemonMessage::TcpOutgoing(DaemonTcpOutgoing::Read(Ok(read)));
                tx_out.send(response).await?;
            }
            ClientMessage::Ping => {
                tx_out.send(DaemonMessage::Pong).await?;
            }
            _ => {} // ignore others for now
        }
        Ok(())
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let server = Server::new();
    let client = Client::new();
    // Run server and client concurrently
    tokio::try_join!(server.run(), client.run())?;
    Ok(())
}

/// Continuously receives `DaemonMessage`s, splits into chunks, and sends them randomly
async fn sender_task(
    mut rx: mpsc::Receiver<DaemonMessage>,
    mut sink: SplitSink<Framed<TcpStream, DaemonCodec>, DaemonMessage>,
) {
    let notify = Arc::new(Notify::new());
    let mut group_queue = GroupChunkQueue::new();

    loop {
        tokio::select! {
            // Prioritize receiving new messages
            msg = rx.recv() => {
                match msg {
                    Some(msg) => {
                        let chunk_producer = ChunkProducer::<CHUNK_SIZE>::new(&msg).unwrap();

                        drop(msg); // Drop early the original message to free memory

                        for chunk in chunk_producer {
                            group_queue.push_chunk(chunk);
                        }

                        notify.notify_one();
                    }
                    None => break,
                }
            }

            // Wait for a chunk to be ready and send it
            _ = notify.notified(), if !group_queue.is_empty() => {
                if let Some(chunk) = group_queue.pop_random_chunk()
                    && let Err(e) = sink.send(DaemonMessage::Chunk(chunk)).await {
                    eprintln!("Error sending chunk: {:?}", e);
                    break;
                }
            }
        }
    }
}
