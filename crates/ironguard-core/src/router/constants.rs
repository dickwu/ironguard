/// Maximum number of packets that can be staged awaiting a key.
pub const MAX_QUEUED_PACKETS: usize = 1024;

/// Capacity of the parallel work queue (jobs dispatched to worker threads).
pub const PARALLEL_QUEUE_SIZE: usize = 4 * MAX_QUEUED_PACKETS;

/// Capacity of each peer's in-order sequential queue.
pub const INORDER_QUEUE_SIZE: usize = MAX_QUEUED_PACKETS;
