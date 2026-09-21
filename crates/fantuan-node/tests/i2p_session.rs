//! Real I2P integration test: two nodes connect over SAM and exchange a
//! signed message.
//!
//! Requires a local i2pd with SAM enabled. Run with:
//!
//! ```text
//! cargo test -p fantuan-node --features i2p-integration -- --ignored
//! ```

#![cfg(feature = "i2p-integration")]

use fantuan_core::config::NodeConfig;
use fantuan_identity::Identity;
use fantuan_msg::{Message, Object};
use fantuan_node::peer;
use fantuan_transport::sam::{SamConfig, SamSession, generate_destination};
use std::time::Duration;

fn sam() -> SamConfig {
    SamConfig::from_addr(&NodeConfig::default().sam_addr).expect("sam config")
}

#[tokio::test]
#[ignore = "requires a local i2pd router with SAM enabled"]
async fn two_nodes_exchange_a_signed_message_over_i2p() {
    let pid = std::process::id();
    let base = sam();

    // Server destination + identity.
    let init = SamConfig {
        nickname: format!("fantuan-it-init-{pid}"),
        ..base.clone()
    };
    let (server_destination, server_key) = generate_destination(&init)
        .await
        .expect("generate destination");
    let (server_identity, _) = identity("i2p-server", &server_destination);

    // Server session accepts one connection.
    let server_config = SamConfig {
        nickname: format!("fantuan-it-server-{pid}"),
        publish: true,
        ..base.clone()
    };
    let server_task = tokio::spawn(async move {
        let mut session = SamSession::open(&server_config, Some(&server_key))
            .await
            .expect("server session");
        let mut stream = session.accept().await.expect("accept");
        let mut peer =
            peer::handshake_server(&mut stream, &server_identity, Duration::from_secs(180))
                .await
                .expect("server handshake");
        let bytes = peer.session.recv(&mut stream).await.expect("receive");
        match Object::from_canonical_bytes(&bytes).expect("decode") {
            Object::Message(message) => {
                message.verify(&peer.cert).expect("verify");
                String::from_utf8_lossy(&message.payload).to_string()
            }
            other => panic!("unexpected object: {other:?}"),
        }
    });

    // Client session connects out, retrying while the server's lease set
    // propagates and its tunnels are built.
    let (client_identity, _) = identity("i2p-client", "unused");
    let client_config = SamConfig {
        nickname: format!("fantuan-it-client-{pid}"),
        publish: false,
        ..base
    };
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut session = SamSession::open(&client_config, None)
        .await
        .expect("client session");
    let mut stream = connect_with_retry(&mut session, &server_destination).await;
    let mut peer = peer::handshake_client(&mut stream, &client_identity, Duration::from_secs(180))
        .await
        .expect("client handshake");

    let message = Message::create(&client_identity, b"hello over real i2p").expect("message");
    let bytes = Object::Message(message)
        .to_canonical_bytes()
        .expect("encode");
    peer.session.send(&mut stream, &bytes).await.expect("send");

    let received = tokio::time::timeout(Duration::from_secs(60), server_task)
        .await
        .expect("server task timeout")
        .expect("server task");
    assert_eq!(received, "hello over real i2p");
}

fn identity(uid: &str, destination: &str) -> (Identity, String) {
    let identity = Identity::generate(uid, destination).expect("identity");
    let fingerprint = identity.fingerprint_hex();
    (identity, fingerprint)
}

/// Retry `STREAM CONNECT` until the server becomes reachable.
async fn connect_with_retry(session: &mut SamSession, destination: &str) -> yosemite::Stream {
    let deadline = std::time::Instant::now() + Duration::from_secs(240);
    let mut last_error = None;
    loop {
        match session.connect(destination).await {
            Ok(stream) => return stream,
            Err(error) => {
                tracing::warn!("connect attempt failed: {error}");
                last_error = Some(error);
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("i2p connect never succeeded: {last_error:?}");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
