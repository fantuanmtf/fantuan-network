//! Live connection loop.
//!
//! Each established session runs one task that owns the stream and Noise
//! state. It multiplexes inbound objects with outbound frames queued in the
//! connection pool, so other tasks (gossip, relaying) can send without
//! touching the session.

use crate::peer::BoundPeer;
use crate::state::{NodeEvent, NodeState};
use anyhow::{Result, anyhow};
use fantuan_msg::{HistoryRequest, Object};
use fantuan_transport::DEFAULT_WRITER_QUEUE;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Drive one authenticated connection until it closes or goes idle.
pub async fn run<S>(state: Arc<NodeState>, mut stream: S, mut peer: BoundPeer) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let idle = Duration::from_secs(state.config.idle_timeout_secs);
    let (handle, mut outbound) = state
        .pool
        .register(peer.fingerprint(), DEFAULT_WRITER_QUEUE)?;
    state.record_route(peer.fingerprint(), peer.fingerprint());

    // Offer our gossip right after the handshake.
    let gossip = crate::gossip::build(&state);
    if !gossip.is_empty() {
        let bytes = Object::Gossip(gossip).to_canonical_bytes()?;
        peer.session.send(&mut stream, &bytes).await?;
    }

    // Ask for anything we missed while this peer was disconnected.
    let requests: Vec<Object> = {
        let subscriptions = state.subscription_list();
        let store = state
            .messages
            .lock()
            .map_err(|_| anyhow!("message store poisoned"))?;
        let mut requests = Vec::new();
        for (topic, is_board) in subscriptions {
            let since = if is_board {
                store.latest_forum_timestamp(&topic)?
            } else {
                store.latest_channel_timestamp(&topic)?
            };
            requests.push(Object::HistoryRequest(HistoryRequest::new(
                &topic, is_board, since,
            )));
        }
        requests
    };
    for request in requests {
        peer.session
            .send(&mut stream, &request.to_canonical_bytes()?)
            .await?;
    }

    let result = loop {
        tokio::select! {
            incoming = tokio::time::timeout(idle, peer.session.recv(&mut stream)) => match incoming {
                Ok(Ok(bytes)) => match fantuan_traffic::parse(&bytes) {
                    fantuan_traffic::Frame::Data(payload)
                    | fantuan_traffic::Frame::Raw(payload) => {
                        if let Err(error) = handle_object(&state, &mut peer, &mut stream, payload).await {
                            break Err(error);
                        }
                    }
                    fantuan_traffic::Frame::Cover => {
                        tracing::trace!("cover frame discarded");
                    }
                    fantuan_traffic::Frame::Invalid => {
                        tracing::debug!("invalid shaped frame dropped");
                    }
                },
                Ok(Err(error)) => break Err(error.into()),
                Err(_) => break Err(anyhow!("peer idle timeout")),
            },
            outgoing = outbound.recv() => match outgoing {
                Some(payload) => {
                    let frame = shape_payload(&state, payload);
                    if let Err(error) = peer.session.send(&mut stream, &frame).await {
                        break Err(error.into());
                    }
                }
                None => break Ok(()),
            },
        }
    };

    state.pool.remove(peer.fingerprint(), handle.connection_id);
    result
}

/// Pad outgoing frames into fixed buckets (cover frames pass through).
fn shape_payload(state: &NodeState, payload: Vec<u8>) -> Vec<u8> {
    if fantuan_traffic::is_cover(&payload) || !state.config.traffic_shaping {
        return payload;
    }
    fantuan_traffic::pad(&payload).unwrap_or(payload)
}

async fn handle_object<S>(
    state: &Arc<NodeState>,
    peer: &mut BoundPeer,
    stream: &mut S,
    bytes: &[u8],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match Object::from_canonical_bytes(bytes)? {
        Object::Message(message) => {
            message.verify(&peer.cert)?;
            let text = String::from_utf8_lossy(&message.payload).to_string();
            tracing::info!(from = peer.descriptor.uid, "message received: {text}");
            state.emit(NodeEvent::Message {
                from: message.sender.clone(),
                text,
            });
        }
        Object::Ping { timestamp, .. } => {
            let pong = Object::Pong { timestamp }.to_canonical_bytes()?;
            peer.session.send(stream, &pong).await?;
        }
        Object::Pong { .. } => {
            tracing::debug!(peer = peer.descriptor.uid, "pong received");
        }
        Object::Gossip(gossip) => {
            let accepted = crate::gossip::handle(state, peer.fingerprint(), &gossip)?;
            tracing::info!(peer = peer.descriptor.uid, accepted, "gossip received");
            if accepted > 0 {
                // We learned something new: reply with our updated list and
                // push it to other peers so knowledge propagates.
                let reply = crate::gossip::build(state);
                if !reply.is_empty() {
                    let bytes = Object::Gossip(reply).to_canonical_bytes()?;
                    peer.session.send(stream, &bytes).await?;
                }
                crate::gossip::broadcast(state, peer.fingerprint());
            }
        }
        Object::Relay(relay) => {
            crate::relay::handle(state, peer, relay)?;
        }
        Object::ChannelMessage(message) => {
            crate::social::handle_channel(
                state,
                peer.fingerprint(),
                &peer.descriptor.openpgp_cert,
                message,
            )?;
        }
        Object::ForumPost(post) => {
            crate::social::handle_forum(
                state,
                peer.fingerprint(),
                &peer.descriptor.openpgp_cert,
                post,
            )?;
        }
        Object::HistoryRequest(request) => {
            if let Some(response) = crate::social::handle_history_request(state, &request)? {
                peer.session
                    .send(stream, &response.to_canonical_bytes()?)
                    .await?;
            }
        }
        Object::HistoryResponse(response) => {
            let accepted = crate::social::handle_history_response(state, &response)?;
            tracing::debug!(accepted, "history received");
        }
        Object::DeleteRequest(delete) => {
            crate::social::handle_delete(
                state,
                peer.fingerprint(),
                &peer.descriptor.openpgp_cert,
                delete,
            )?;
        }
        Object::FileChunk(chunk) => {
            crate::files::handle_file_chunk(
                state,
                peer.fingerprint(),
                &peer.descriptor.openpgp_cert,
                chunk,
            )?;
        }
        Object::ChunkRequest(request) => {
            crate::files::handle_chunk_request(state, peer.fingerprint(), request)?;
        }
        Object::FileManifest(_) => {
            // Manifests contain the file key and are only accepted inside
            // relay envelopes (see relay::handle).
            tracing::warn!(
                peer = peer.descriptor.uid,
                "ignoring manifest outside a relay envelope"
            );
        }
        object @ (Object::DcRoundStart(_) | Object::DcRoundShare(_)) => {
            crate::anon::handle_round(state, &object)?;
        }
    }
    Ok(())
}
