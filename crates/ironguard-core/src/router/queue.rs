use arraydeque::ArrayDeque;
use spin::Mutex;

use core::mem;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::constants::INORDER_QUEUE_SIZE;

use crossbeam_channel::{Receiver, Sender, bounded};

/// A job whose sequential_work must be called in insertion order.
pub trait SequentialJob {
    fn is_ready(&self) -> bool;
    fn sequential_work(self);
}

/// A job that can be executed in parallel, but whose sequential portion
/// must be drained in insertion order.
pub trait ParallelJob: Sized + SequentialJob {
    fn queue(&self) -> &Queue<Self>;
    fn parallel_work(&self);
}

/// In-order sequential queue. Multiple threads call `parallel_work()` concurrently,
/// but `sequential_work()` is guaranteed to execute in insertion order via `consume()`.
pub struct Queue<J: SequentialJob> {
    contenders: AtomicUsize,
    queue: Mutex<ArrayDeque<J, INORDER_QUEUE_SIZE>>,
}

impl<J: SequentialJob> Default for Queue<J> {
    fn default() -> Self {
        Self::new()
    }
}

impl<J: SequentialJob> Queue<J> {
    pub fn new() -> Queue<J> {
        Queue {
            contenders: AtomicUsize::new(0),
            queue: Mutex::new(ArrayDeque::new()),
        }
    }

    /// Push a job onto the back of the queue. Returns true if successful.
    pub fn push(&self, job: J) -> bool {
        self.queue.lock().push_back(job).is_ok()
    }

    /// Drain ready jobs from the front of the queue, executing them in order.
    /// Uses an atomic contenders counter so only one thread runs the drain loop
    /// at a time, while still allowing new contenders to extend the drain.
    pub fn consume(&self) {
        // check if we are the first contender
        let pos = self.contenders.fetch_add(1, Ordering::SeqCst);
        if pos > 0 {
            assert!(usize::MAX > pos, "contenders overflow");
            return;
        }

        // enter the critical section
        let mut contenders = 1; // myself
        while contenders > 0 {
            // handle every ready element
            loop {
                let mut queue = self.queue.lock();

                // check if front job is ready
                match queue.front() {
                    None => break,
                    Some(job) => {
                        if !job.is_ready() {
                            break;
                        }
                    }
                }

                // take the job out of the queue
                let job = queue.pop_front().unwrap();
                debug_assert!(job.is_ready());
                mem::drop(queue);

                // process element
                job.sequential_work();
            }

            // decrease contenders
            contenders = self.contenders.fetch_sub(contenders, Ordering::SeqCst) - contenders;
        }
    }
}

/// A multi-producer work queue for dispatching jobs to worker threads.
pub struct ParallelQueue<T> {
    queue: std::sync::Mutex<Option<Sender<T>>>,
}

impl<T> ParallelQueue<T> {
    /// Create a new ParallelQueue with the given number of consumer receivers.
    pub fn new(num_workers: usize, capacity: usize) -> (Self, Vec<Receiver<T>>) {
        let (tx, rx) = bounded(capacity);
        let mut receivers = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            receivers.push(rx.clone());
        }
        (
            ParallelQueue {
                queue: std::sync::Mutex::new(Some(tx)),
            },
            receivers,
        )
    }

    /// Send a job to the work queue.
    pub fn send(&self, v: T) {
        if let Some(s) = self.queue.lock().unwrap().as_ref() {
            let _ = s.send(v);
        }
    }

    /// Close the queue, causing all workers to eventually stop.
    pub fn close(&self) {
        *self.queue.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    #[test]
    fn test_queue_ordering() {
        // Track which jobs were executed and in what order
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));

        struct OrderedJob {
            id: usize,
            order: Arc<std::sync::Mutex<Vec<usize>>>,
        }

        impl SequentialJob for OrderedJob {
            fn is_ready(&self) -> bool {
                true
            }
            fn sequential_work(self) {
                self.order.lock().unwrap().push(self.id);
            }
        }

        let queue: Queue<OrderedJob> = Queue::new();

        // Push jobs in order
        for i in 0..10 {
            queue.push(OrderedJob {
                id: i,
                order: order.clone(),
            });
        }

        // Consume all jobs
        queue.consume();

        let executed = order.lock().unwrap();
        assert_eq!(*executed, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn test_queue_not_ready_blocks() {
        use std::sync::atomic::AtomicBool;

        struct DelayedJob {
            ready: Arc<AtomicBool>,
            id: usize,
            order: Arc<std::sync::Mutex<Vec<usize>>>,
        }

        impl SequentialJob for DelayedJob {
            fn is_ready(&self) -> bool {
                self.ready.load(Ordering::Acquire)
            }
            fn sequential_work(self) {
                self.order.lock().unwrap().push(self.id);
            }
        }

        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let queue: Queue<DelayedJob> = Queue::new();

        let ready0 = Arc::new(AtomicBool::new(false));
        let ready1 = Arc::new(AtomicBool::new(true));

        queue.push(DelayedJob {
            ready: ready0.clone(),
            id: 0,
            order: order.clone(),
        });
        queue.push(DelayedJob {
            ready: ready1.clone(),
            id: 1,
            order: order.clone(),
        });

        // Consume - job 0 is not ready, so nothing should run
        queue.consume();
        assert!(order.lock().unwrap().is_empty());

        // Mark job 0 as ready
        ready0.store(true, Ordering::Release);

        // Now both should drain in order
        queue.consume();
        let executed = order.lock().unwrap();
        assert_eq!(*executed, vec![0, 1]);
    }

    #[test]
    fn test_queue_concurrent() {
        struct TestJob {
            cnt: Arc<AtomicUsize>,
        }

        impl SequentialJob for TestJob {
            fn is_ready(&self) -> bool {
                true
            }
            fn sequential_work(self) {
                self.cnt.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn hammer(queue: &Arc<Queue<TestJob>>, cnt: Arc<AtomicUsize>) -> usize {
            let mut jobs = 0;
            for i in 0..10_000 {
                if i % 2 == 0 {
                    if queue.push(TestJob { cnt: cnt.clone() }) {
                        jobs += 1;
                    }
                } else {
                    queue.consume();
                }
            }
            queue.consume();
            jobs
        }

        let queue = Arc::new(Queue::new());
        let counter = Arc::new(AtomicUsize::new(0));

        let other = {
            let queue = queue.clone();
            let counter = counter.clone();
            thread::spawn(move || hammer(&queue, counter))
        };
        let mut jobs = hammer(&queue, counter.clone());

        jobs += other.join().unwrap();
        queue.consume();
        assert_eq!(queue.queue.lock().len(), 0, "elements left in queue");
        assert_eq!(
            jobs,
            counter.load(Ordering::Acquire),
            "did not consume every job"
        );
    }

    #[test]
    fn test_parallel_queue_basic() {
        let (pq, receivers) = ParallelQueue::new(2, 16);
        assert_eq!(receivers.len(), 2);

        pq.send(42u32);
        let val = receivers[0].recv().unwrap();
        assert_eq!(val, 42);

        pq.close();
        assert!(receivers[0].recv().is_err());
    }
}
