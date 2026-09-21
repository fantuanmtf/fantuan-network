//! Virtual clock and discrete-event queue.
//!
//! Simulation time is logical milliseconds; scenarios can cover hours of
//! traffic in a few milliseconds of wall clock. Event ordering is
//! deterministic: earliest time first, ties broken by scheduling sequence.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Logical time in milliseconds since simulation start.
pub type LogicalTime = u64;

/// Virtual clock.
#[derive(Debug, Default)]
pub struct VirtualClock {
    now_ms: LogicalTime,
}

impl VirtualClock {
    /// Create a clock at time zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current logical time.
    pub fn now_ms(&self) -> LogicalTime {
        self.now_ms
    }

    /// Advance the clock; going backwards is a programming error and is
    /// ignored rather than panicking in release builds.
    pub fn advance_to(&mut self, time_ms: LogicalTime) {
        if time_ms > self.now_ms {
            self.now_ms = time_ms;
        }
    }
}

struct Scheduled<T> {
    at_ms: LogicalTime,
    sequence: u64,
    payload: T,
}

impl<T> PartialEq for Scheduled<T> {
    fn eq(&self, other: &Self) -> bool {
        self.at_ms == other.at_ms && self.sequence == other.sequence
    }
}

impl<T> Eq for Scheduled<T> {}

impl<T> PartialOrd for Scheduled<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Scheduled<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed so BinaryHeap (a max-heap) yields the earliest event.
        other
            .at_ms
            .cmp(&self.at_ms)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// Priority queue ordered by (time, sequence).
pub struct EventQueue<T> {
    heap: BinaryHeap<Scheduled<T>>,
    next_sequence: u64,
}

impl<T> Default for EventQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> EventQueue<T> {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_sequence: 0,
        }
    }

    /// Schedule an event at `at_ms`.
    pub fn schedule(&mut self, at_ms: LogicalTime, payload: T) {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.heap.push(Scheduled {
            at_ms,
            sequence,
            payload,
        });
    }

    /// Pop the next event, if any.
    pub fn pop(&mut self) -> Option<(LogicalTime, T)> {
        self.heap
            .pop()
            .map(|scheduled| (scheduled.at_ms, scheduled.payload))
    }

    /// Time of the next event without removing it.
    pub fn peek_time(&self) -> Option<LogicalTime> {
        self.heap.peek().map(|scheduled| scheduled.at_ms)
    }

    /// Number of queued events.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// True when no events are queued.
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_never_goes_backwards() {
        let mut clock = VirtualClock::new();
        clock.advance_to(100);
        clock.advance_to(50);
        assert_eq!(clock.now_ms(), 100);
    }

    #[test]
    fn events_pop_in_time_order() {
        let mut queue = EventQueue::new();
        queue.schedule(30, "c");
        queue.schedule(10, "a");
        queue.schedule(20, "b");
        assert_eq!(queue.pop(), Some((10, "a")));
        assert_eq!(queue.pop(), Some((20, "b")));
        assert_eq!(queue.pop(), Some((30, "c")));
        assert!(queue.is_empty());
    }

    #[test]
    fn ties_break_by_scheduling_order() {
        let mut queue = EventQueue::new();
        queue.schedule(5, "first");
        queue.schedule(5, "second");
        assert_eq!(queue.pop(), Some((5, "first")));
        assert_eq!(queue.pop(), Some((5, "second")));
    }

    #[test]
    fn peek_does_not_remove() {
        let mut queue = EventQueue::new();
        queue.schedule(1, 1);
        assert_eq!(queue.peek_time(), Some(1));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop(), Some((1, 1)));
        assert_eq!(queue.peek_time(), None);
    }
}
