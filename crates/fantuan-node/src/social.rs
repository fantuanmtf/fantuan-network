//! Channel, forum, history and delete handling.
//!
//! All incoming objects are signature-verified before they are stored or
//! forwarded. Subscribed topics are persisted, deduplicated by object id and
//! flooded to other peers; history requests are answered from the local
//! store so peers can catch up after being offline.

use crate::state::{NodeEvent, NodeState};
use anyhow::{Result, anyhow};
use fantuan_msg::{
    ChannelMessage, DeleteRequest, ForumPost, HistoryRequest, HistoryResponse,
    MAX_HISTORY_MESSAGES, MAX_HISTORY_POSTS, Object,
};
use std::sync::Arc;

/// Resolve the certificate for a claimed sender: the direct peer's own
/// certificate, or the stored certificate for a known third party.
fn resolve_cert(
    state: &Arc<NodeState>,
    peer_fingerprint: &str,
    peer_cert: &[u8],
    sender: &str,
) -> Result<Vec<u8>> {
    if sender == peer_fingerprint {
        return Ok(peer_cert.to_vec());
    }
    let store = state
        .trust
        .lock()
        .map_err(|_| anyhow!("trust store poisoned"))?;
    let peer = store
        .get_peer(sender)?
        .ok_or_else(|| anyhow!("unknown sender {sender}"))?;
    hex::decode(&peer.public_key_hex).map_err(|error| anyhow!("stored key is not hex: {error}"))
}

fn known_cert(state: &Arc<NodeState>, sender: &str) -> Option<Vec<u8>> {
    let store = state.trust.lock().ok()?;
    let peer = store.get_peer(sender).ok()??;
    hex::decode(&peer.public_key_hex).ok()
}

/// Create, store and flood a channel message from this node.
pub fn publish_channel(
    state: &Arc<NodeState>,
    channel: &str,
    text: &str,
) -> Result<ChannelMessage> {
    state.subscribe_channel(channel);
    let message = ChannelMessage::create(&state.identity, channel, text)?;
    let object = Object::ChannelMessage(message.clone()).to_canonical_bytes()?;
    let inserted = state
        .messages
        .lock()
        .map_err(|_| anyhow!("message store poisoned"))?
        .insert_channel_message(
            &message.channel,
            &message.sender,
            message.timestamp,
            &message.text,
            &object,
        )?;
    if inserted {
        state.emit(NodeEvent::Channel {
            channel: message.channel.clone(),
            from: message.sender.clone(),
            text: String::from_utf8_lossy(&message.text).to_string(),
            timestamp: message.timestamp,
        });
        state.flood(None, object);
    }
    Ok(message)
}

/// Create, store and flood a forum post from this node.
pub fn publish_forum(
    state: &Arc<NodeState>,
    board: &str,
    title: &str,
    body: &str,
) -> Result<ForumPost> {
    state.subscribe_board(board);
    let post = ForumPost::create(&state.identity, board, title, body)?;
    let object = Object::ForumPost(post.clone()).to_canonical_bytes()?;
    let inserted = state
        .messages
        .lock()
        .map_err(|_| anyhow!("message store poisoned"))?
        .insert_forum_post(
            &post.board,
            &post.sender,
            post.timestamp,
            &post.title,
            &post.body,
            &object,
        )?;
    if inserted {
        state.emit(NodeEvent::Forum {
            board: post.board.clone(),
            from: post.sender.clone(),
            title: post.title.clone(),
            body: String::from_utf8_lossy(&post.body).to_string(),
            timestamp: post.timestamp,
        });
        state.flood(None, object);
    }
    Ok(post)
}

/// Verify and store one incoming channel message.
pub fn handle_channel(
    state: &Arc<NodeState>,
    peer_fingerprint: &str,
    peer_cert: &[u8],
    message: ChannelMessage,
) -> Result<bool> {
    let cert_bytes = resolve_cert(state, peer_fingerprint, peer_cert, &message.sender)?;
    message.verify_cert_bytes(&cert_bytes)?;
    if !state.is_subscribed_channel(&message.channel) {
        return Ok(false);
    }

    let object = Object::ChannelMessage(message.clone()).to_canonical_bytes()?;
    let inserted = state
        .messages
        .lock()
        .map_err(|_| anyhow!("message store poisoned"))?
        .insert_channel_message(
            &message.channel,
            &message.sender,
            message.timestamp,
            &message.text,
            &object,
        )?;
    if inserted {
        state.emit(NodeEvent::Channel {
            channel: message.channel.clone(),
            from: message.sender.clone(),
            text: String::from_utf8_lossy(&message.text).to_string(),
            timestamp: message.timestamp,
        });
        state.flood(Some(peer_fingerprint), object);
    }
    Ok(inserted)
}

/// Verify and store one incoming forum post.
pub fn handle_forum(
    state: &Arc<NodeState>,
    peer_fingerprint: &str,
    peer_cert: &[u8],
    post: ForumPost,
) -> Result<bool> {
    let cert_bytes = resolve_cert(state, peer_fingerprint, peer_cert, &post.sender)?;
    post.verify_cert_bytes(&cert_bytes)?;
    if !state.is_subscribed_board(&post.board) {
        return Ok(false);
    }

    let object = Object::ForumPost(post.clone()).to_canonical_bytes()?;
    let inserted = state
        .messages
        .lock()
        .map_err(|_| anyhow!("message store poisoned"))?
        .insert_forum_post(
            &post.board,
            &post.sender,
            post.timestamp,
            &post.title,
            &post.body,
            &object,
        )?;
    if inserted {
        state.emit(NodeEvent::Forum {
            board: post.board.clone(),
            from: post.sender.clone(),
            title: post.title.clone(),
            body: String::from_utf8_lossy(&post.body).to_string(),
            timestamp: post.timestamp,
        });
        state.flood(Some(peer_fingerprint), object);
    }
    Ok(inserted)
}

/// Answer a history request from the local store, when subscribed.
pub fn handle_history_request(
    state: &Arc<NodeState>,
    request: &HistoryRequest,
) -> Result<Option<Object>> {
    request.validate()?;
    let store = state
        .messages
        .lock()
        .map_err(|_| anyhow!("message store poisoned"))?;

    if request.is_board {
        if !state.is_subscribed_board(&request.topic) {
            return Ok(None);
        }
        let posts: Vec<ForumPost> = store
            .forum_posts(&request.topic, request.since, MAX_HISTORY_POSTS)?
            .into_iter()
            .filter_map(
                |stored| match Object::from_canonical_bytes(&stored.object) {
                    Ok(Object::ForumPost(post)) => Some(post),
                    _ => None,
                },
            )
            .collect();
        return Ok(Some(Object::HistoryResponse(HistoryResponse::new(
            &request.topic,
            true,
            Vec::new(),
            posts,
        ))));
    }

    if !state.is_subscribed_channel(&request.topic) {
        return Ok(None);
    }
    let messages: Vec<ChannelMessage> = store
        .channel_messages(&request.topic, request.since, MAX_HISTORY_MESSAGES)?
        .into_iter()
        .filter_map(
            |stored| match Object::from_canonical_bytes(&stored.object) {
                Ok(Object::ChannelMessage(message)) => Some(message),
                _ => None,
            },
        )
        .collect();
    Ok(Some(Object::HistoryResponse(HistoryResponse::new(
        &request.topic,
        false,
        messages,
        Vec::new(),
    ))))
}

/// Verify and store messages and posts from a history response.
///
/// Returns the number of newly stored objects.
pub fn handle_history_response(
    state: &Arc<NodeState>,
    response: &HistoryResponse,
) -> Result<usize> {
    response.validate()?;
    let mut accepted = 0usize;

    for message in &response.messages {
        let Some(cert_bytes) = known_cert(state, &message.sender) else {
            continue;
        };
        if message.verify_cert_bytes(&cert_bytes).is_err() {
            continue;
        }
        if !state.is_subscribed_channel(&message.channel) {
            continue;
        }
        let object = Object::ChannelMessage(message.clone()).to_canonical_bytes()?;
        let inserted = state
            .messages
            .lock()
            .map_err(|_| anyhow!("message store poisoned"))?
            .insert_channel_message(
                &message.channel,
                &message.sender,
                message.timestamp,
                &message.text,
                &object,
            )?;
        if inserted {
            state.emit(NodeEvent::Channel {
                channel: message.channel.clone(),
                from: message.sender.clone(),
                text: String::from_utf8_lossy(&message.text).to_string(),
                timestamp: message.timestamp,
            });
            accepted += 1;
        }
    }

    for post in &response.posts {
        let Some(cert_bytes) = known_cert(state, &post.sender) else {
            continue;
        };
        if post.verify_cert_bytes(&cert_bytes).is_err() {
            continue;
        }
        if !state.is_subscribed_board(&post.board) {
            continue;
        }
        let object = Object::ForumPost(post.clone()).to_canonical_bytes()?;
        let inserted = state
            .messages
            .lock()
            .map_err(|_| anyhow!("message store poisoned"))?
            .insert_forum_post(
                &post.board,
                &post.sender,
                post.timestamp,
                &post.title,
                &post.body,
                &object,
            )?;
        if inserted {
            state.emit(NodeEvent::Forum {
                board: post.board.clone(),
                from: post.sender.clone(),
                title: post.title.clone(),
                body: String::from_utf8_lossy(&post.body).to_string(),
                timestamp: post.timestamp,
            });
            accepted += 1;
        }
    }

    Ok(accepted)
}

/// Verify and apply a delete request; floods it when something was removed.
pub fn handle_delete(
    state: &Arc<NodeState>,
    peer_fingerprint: &str,
    peer_cert: &[u8],
    delete: DeleteRequest,
) -> Result<bool> {
    let cert_bytes = resolve_cert(state, peer_fingerprint, peer_cert, &delete.sender)?;
    delete.verify_cert_bytes(&cert_bytes)?;
    let removed = state
        .messages
        .lock()
        .map_err(|_| anyhow!("message store poisoned"))?
        .delete_object(&delete.target[..])?;
    if removed {
        let bytes = Object::DeleteRequest(delete).to_canonical_bytes()?;
        state.flood(Some(peer_fingerprint), bytes);
    }
    Ok(removed)
}
