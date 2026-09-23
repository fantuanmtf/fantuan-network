//! Adversarial reproductions for the clock-derived round-id acceptance path.
//!
//! Findings R1/R2 of `docs/ROUND_SYNC_REVIEW.md`. These tests assert that the
//! attacks **succeed** against the current implementation, exactly like the
//! N−1 collusion test in `fantuan-anon`: they document a known weakness rather
//! than desired behaviour. When R1/R2 are fixed they must be inverted to
//! assert the fixed behaviour, not deleted.
//!
//! Topology: mallory <-> bob (attack path), plus a triangle alice <-> bob <->>
//! carol <-> alice. The triangle matters: participants must be able to reach
//! each other directly (shares are never relayed), so a non-clique participant
//! set makes the round fail for everyone — see R12 in the review. Mallory is a
//! stranger to alice, so the attacker is never in the rounds that penalise its
//! victim.

use fantuan_core::config::NodeConfig;
use fantuan_core::time;
use fantuan_identity::{Identity, TrustStore};
use fantuan_msg::{DcRoundStart, Object};
use fantuan_node::state::{NodeEvent, NodeState};
use fantuan_node::store::MessageStore;
use fantuan_node::{anon, connection, peer};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

struct TestNode {
    state: Arc<NodeState>,
    events: mpsc::UnboundedReceiver<NodeEvent>,
    fingerprint: String,
    _dir: TempDir,
}

impl TestNode {
    fn new(uid: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = Arc::new(Identity::generate(uid, &format!("dest-{uid}")).expect("identity"));
        let fingerprint = identity.fingerprint_hex();
        let trust = TrustStore::open(&dir.path().join("trust.sqlite")).expect("trust");
        let messages = MessageStore::in_memory().expect("messages");
        let chunks = fantuan_storage::ChunkCache::in_memory(1 << 20).expect("chunks");
        let (events_tx, events) = mpsc::unbounded_channel();
        let config = NodeConfig {
            handshake_timeout_secs: 5,
            idle_timeout_secs: 30,
            ..NodeConfig::default()
        };
        let state = NodeState::new(identity, config, trust, messages, chunks, events_tx, None);
        Self {
            state,
            events,
            fingerprint,
            _dir: dir,
        }
    }

    fn active_rounds(&self) -> usize {
        self.state
            .rounds
            .lock()
            .expect("round driver")
            .active_rounds()
    }

    fn current_round_id(&self) -> u64 {
        self.state
            .rounds
            .lock()
            .expect("round driver")
            .current_round_id()
    }

    fn is_evicted(&self, uid: &str) -> bool {
        self.state
            .reputation
            .lock()
            .expect("reputation")
            .is_evicted(uid)
    }
}

fn connect_pair(left: &TestNode, right: &TestNode) -> Vec<JoinHandle<()>> {
    let (left_side, right_side) = tokio::io::duplex(1 << 20);
    let left_state = left.state.clone();
    let right_state = right.state.clone();
    vec![
        tokio::spawn(async move {
            let mut stream = left_side;
            let peer =
                peer::handshake_client(&mut stream, &left_state.identity, Duration::from_secs(5))
                    .await
                    .expect("client handshake");
            let _ = connection::run(left_state, stream, peer).await;
        }),
        tokio::spawn(async move {
            let mut stream = right_side;
            let peer =
                peer::handshake_server(&mut stream, &right_state.identity, Duration::from_secs(5))
                    .await
                    .expect("server handshake");
            let _ = connection::run(right_state, stream, peer).await;
        }),
    ]
}

async fn wait_for_route(node: &TestNode, destination: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.state.next_hop(destination).is_none() {
        assert!(
            Instant::now() < deadline,
            "node never learned a route to {destination}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Three-node fixture: the attacker's path to the victim, the honest
/// initiator, and an unpoisoned control participant.
struct Fixture {
    mallory: TestNode,
    bob: TestNode,
    alice: TestNode,
    carol: TestNode,
    tasks: Vec<JoinHandle<()>>,
}

async fn fixture() -> Fixture {
    let mallory = TestNode::new("mallory");
    let bob = TestNode::new("bob");
    let alice = TestNode::new("alice");
    let carol = TestNode::new("carol");

    let mut tasks = Vec::new();
    tasks.extend(connect_pair(&mallory, &bob));
    tasks.extend(connect_pair(&alice, &bob));
    tasks.extend(connect_pair(&bob, &carol));
    tasks.extend(connect_pair(&alice, &carol));
    for (node, other) in [
        (&mallory, &bob),
        (&alice, &bob),
        (&bob, &carol),
        (&alice, &carol),
    ] {
        wait_for_route(node, &other.fingerprint).await;
    }
    Fixture {
        mallory,
        bob,
        alice,
        carol,
        tasks,
    }
}

/// Send the forged start an attacker would inject: unsigned, naming no peer it
/// controls, and dated 25 s into the victim's future. Returns the id, and waits
/// until the victim's tracker has actually absorbed it — without that wait the
/// honest round below could race ahead of the poison and the test would pass
/// for the wrong reason.
async fn poison(fixture: &Fixture) -> u64 {
    let future = time::now_unix_millis() as u64 + 25_000;
    let participants = vec!["SOMEONE".to_string(), "OTHER".to_string()];
    let forged = DcRoundStart::new("#anon", future, "SOMEONE", &participants, 15, 256)
        .expect("forged start validates");
    let bytes = Object::DcRoundStart(forged)
        .to_canonical_bytes()
        .expect("bytes");
    fixture
        .mallory
        .state
        .pool
        .try_send(&fixture.bob.fingerprint, bytes)
        .expect("send forged start");

    let deadline = Instant::now() + Duration::from_secs(10);
    while fixture.bob.current_round_id() < future {
        assert!(
            Instant::now() < deadline,
            "the victim never absorbed the forged round id"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    future
}

#[tokio::test]
async fn a_future_dated_start_poisons_the_round_tracker() {
    let mut fixture = fixture().await;

    // Control phase: before any poison, every node extracts alice's message.
    anon::queue(&fixture.alice.state, "#anon", "honest round one").expect("queue");
    anon::tick(&fixture.alice.state).expect("tick");
    assert_eq!(
        recv_anonymous(&mut fixture.bob, 10).await,
        "honest round one"
    );
    assert_eq!(
        recv_anonymous(&mut fixture.carol, 10).await,
        "honest round one"
    );

    // A different initiator for the second round, so the effect cannot be
    // mistaken for something initiator-specific.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let poisoned_until = poison(&fixture).await;
    assert!(fixture.bob.current_round_id() >= poisoned_until);

    // Carol's round reaches the same participant set. Alice absorbs the start
    // and creates a collector; the poisoned bob does not.
    anon::queue(&fixture.carol.state, "#anon", "honest round two").expect("queue");
    anon::tick(&fixture.carol.state).expect("tick");
    let deadline = Instant::now() + Duration::from_secs(10);
    while fixture.alice.active_rounds() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        fixture.alice.active_rounds() >= 1,
        "the unpoisoned peer absorbs the honest start"
    );
    assert_eq!(
        fixture.bob.active_rounds(),
        0,
        "the poisoned peer rejects the same start: its tracker is ahead of every honest id"
    );

    for task in fixture.tasks {
        task.abort();
    }
}

#[tokio::test]
async fn poisoning_escalates_to_eviction_by_honest_rounds() {
    let fixture = fixture().await;
    assert!(
        anon::participants(&fixture.alice.state).contains(&fixture.bob.fingerprint),
        "bob starts as a participant of alice's rounds"
    );
    poison(&fixture).await;

    // Short deadline so the test does not wait 15 s per round.
    fixture
        .alice
        .state
        .rounds
        .lock()
        .expect("round driver")
        .set_deadline_secs(1);

    // One honest round per message. Note this deliberately does *not* rely on
    // retries: the driver's retry objects are queued into `pending_outgoing`,
    // which the scheduler tick never drains (finding R11), so retries only
    // leave the node when other traffic arrives. A quiet network therefore
    // costs the poisoned peer one strike per honest round, not three.
    for round in 1..=3u32 {
        anon::queue(
            &fixture.alice.state,
            "#anon",
            &format!("honest round {round}"),
        )
        .expect("queue");
        let before = strikes(&fixture.alice, &fixture.bob.fingerprint);
        let deadline = Instant::now() + Duration::from_secs(10);
        while strikes(&fixture.alice, &fixture.bob.fingerprint) == before
            && Instant::now() < deadline
        {
            anon::tick(&fixture.alice.state).expect("tick");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            strikes(&fixture.alice, &fixture.bob.fingerprint),
            before + 1,
            "round {round} expires with the poisoned peer missing"
        );
    }

    assert!(
        fixture.alice.is_evicted(&fixture.bob.fingerprint),
        "three honest rounds evict the poisoned peer"
    );
    assert!(
        !anon::participants(&fixture.alice.state).contains(&fixture.bob.fingerprint),
        "the victim is removed from future rounds"
    );
    assert!(
        anon::participants(&fixture.alice.state).contains(&fixture.carol.fingerprint),
        "the participant that answered keeps its standing"
    );

    for task in fixture.tasks {
        task.abort();
    }
}

fn strikes(node: &TestNode, uid: &str) -> u32 {
    node.state
        .reputation
        .lock()
        .expect("reputation")
        .strikes(uid)
}

/// Wait for the next extraction event.
async fn recv_anonymous(node: &mut TestNode, timeout_secs: u64) -> String {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match node.events.try_recv() {
            Ok(NodeEvent::Anonymous { text, .. }) => return text,
            Ok(_) => continue,
            Err(mpsc::error::TryRecvError::Empty) => {
                assert!(Instant::now() < deadline, "no extraction arrived");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(mpsc::error::TryRecvError::Disconnected) => panic!("event channel closed"),
        }
    }
}
