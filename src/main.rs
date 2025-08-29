use std::time::Duration;

use anyhow::Result;
use futures::{SinkExt, StreamExt, stream::SplitSink};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};
use tokio_util::codec::Framed;

use mirrord_protocol::outgoing::tcp::{DaemonTcpOutgoing, LayerTcpOutgoing};
use mirrord_protocol::outgoing::{DaemonRead, LayerWrite};
use mirrord_protocol::{ClientCodec, ClientMessage, DaemonCodec, DaemonMessage};

const SERVER_ADDRESS: &str = "127.0.0.1:3333";

const MESSAGE_COUNT: usize = 100;
const MESSAGE_SIZE: usize = 1_000_000;

const CHANNEL_CAPACITY: usize = 1000;

const PING_TIMEOUT_MS: u64 = 200;

const TCP_DELAY_MS: u64 = 10;

#[tokio::main]
async fn main() -> Result<()> {
    // Run server and client concurrently
    tokio::try_join!(run_server(), run_client())?;
    Ok(())
}

/// Runs the server, accepts a single client and processes incoming messages.
/// TcpOutgoing messages are handled with artificial delay to simulate heavy traffic.
async fn run_server() -> Result<()> {
    let listener = TcpListener::bind(SERVER_ADDRESS).await?;
    println!("Server listening on {}", SERVER_ADDRESS);

    let (socket, _) = listener.accept().await?;
    let framed = Framed::new(socket, DaemonCodec::default());
    let (sink, mut stream) = framed.split();

    let (tx_out, rx_out) = mpsc::channel::<DaemonMessage>(CHANNEL_CAPACITY);

    tokio::spawn(sender_task(rx_out, sink));

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(client_msg) => {
                if let Err(e) = handle_client_message(client_msg, &tx_out).await {
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

/// Processes ClientMessage sending a response via the channel
async fn handle_client_message(
    msg: ClientMessage,
    tx_out: &mpsc::Sender<DaemonMessage>,
) -> Result<()> {
    match msg {
        ClientMessage::TcpOutgoing(LayerTcpOutgoing::Write(tcp)) => {
            // Simulate heavy processing
            tokio::time::sleep(Duration::from_millis(TCP_DELAY_MS)).await;
            let read = DaemonRead {
                connection_id: tcp.connection_id,
                bytes: tcp.bytes,
            };
            let msg = DaemonMessage::TcpOutgoing(DaemonTcpOutgoing::Read(Ok(read)));
            tx_out.send(msg).await?;
        }
        ClientMessage::Ping => {
            tx_out.send(DaemonMessage::Pong).await?;
        }
        _ => {} // Ignore other messages for now
    }
    Ok(())
}

/// Continuously receives DaemonMessages and sends them to the client
async fn sender_task(
    mut rx: mpsc::Receiver<DaemonMessage>,
    mut sink: SplitSink<Framed<TcpStream, DaemonCodec>, DaemonMessage>,
) {
    while let Some(msg) = rx.recv().await {
        if let Err(e) = sink.send(msg).await {
            eprintln!("Error sending message to client: {:?}", e);
            break;
        }
    }
}

/// Runs the client sending heavy messages and measuring ping latency
async fn run_client() -> Result<()> {
    let socket = TcpStream::connect(SERVER_ADDRESS).await?;
    let mut framed = Framed::new(socket, ClientCodec::default());

    send_heavy_messages(&mut framed).await?;

    measure_ping(&mut framed).await?;

    println!("Client finished.");
    Ok(())
}

/// Sends a sequence of large TCPOutgoing messages to the server
async fn send_heavy_messages(framed: &mut Framed<TcpStream, ClientCodec>) -> Result<()> {
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
async fn measure_ping(framed: &mut Framed<TcpStream, ClientCodec>) -> Result<()> {
    let start = Instant::now();
    framed.send(ClientMessage::Ping).await?;

    let result = timeout(Duration::from_millis(PING_TIMEOUT_MS), async {
        while let Some(msg) = framed.next().await {
            match msg? {
                DaemonMessage::Pong => return Ok::<(), anyhow::Error>(()),
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
