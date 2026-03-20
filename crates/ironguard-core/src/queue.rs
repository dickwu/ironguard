use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

/// A multi-producer multi-consumer bounded queue for dispatching handshake
/// jobs to async worker tasks. Uses round-robin dispatch across N
/// per-worker channels. Closing the queue causes all receivers to return
/// `None`, stopping the workers.
pub struct ParallelQueue<T: Send + 'static> {
    senders: Mutex<Option<Vec<mpsc::Sender<T>>>>,
    next: AtomicUsize,
}

impl<T: Send + 'static> ParallelQueue<T> {
    /// Create a new ParallelQueue with `num_workers` receivers.
    /// Each worker gets its own channel; the sender side round-robins
    /// across them.
    pub fn new(num_workers: usize, capacity: usize) -> (Self, Vec<mpsc::Receiver<T>>) {
        let mut senders = Vec::with_capacity(num_workers);
        let mut receivers = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let (tx, rx) = mpsc::channel(capacity);
            senders.push(tx);
            receivers.push(rx);
        }

        (
            ParallelQueue {
                senders: Mutex::new(Some(senders)),
                next: AtomicUsize::new(0),
            },
            receivers,
        )
    }

    /// Send a job into the queue. Silently drops if the queue is closed.
    pub fn send(&self, v: T) {
        let guard = self.senders.lock().unwrap();
        if let Some(senders) = guard.as_ref() {
            if senders.is_empty() {
                return;
            }
            let idx = self.next.fetch_add(1, Ordering::Relaxed) % senders.len();
            let _ = senders[idx].try_send(v);
        }
    }

    /// Close the queue, causing all workers to eventually stop.
    pub fn close(&self) {
        *self.senders.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parallel_queue_send_recv() {
        let (pq, mut receivers) = ParallelQueue::new(2, 16);
        pq.send(42u32);
        // Round-robin starts at 0, so first message goes to receiver 0
        let val = receivers[0].recv().await.unwrap();
        assert_eq!(val, 42);
    }

    #[tokio::test]
    async fn test_parallel_queue_close() {
        let (pq, mut receivers) = ParallelQueue::<u32>::new(1, 16);
        pq.close();
        assert!(receivers[0].recv().await.is_none());
    }
}
