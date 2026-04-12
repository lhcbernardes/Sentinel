use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QueueMetrics {
    pub depth: usize,
    pub high_water_mark: usize,
    pub is_overloaded: bool,
}

pub struct BackpressureController {
    queue_depth: Arc<AtomicUsize>,
    high_water_mark: usize,
    current_batch_size: Arc<AtomicUsize>,
    drop_counter: Arc<AtomicUsize>,
}

impl BackpressureController {
    pub fn new(high_water_mark: usize, initial_batch_size: usize) -> Self {
        Self {
            queue_depth: Arc::new(AtomicUsize::new(0)),
            high_water_mark,
            current_batch_size: Arc::new(AtomicUsize::new(initial_batch_size)),
            drop_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn increment(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self, count: usize) {
        self.queue_depth.fetch_sub(count, Ordering::Relaxed);
    }

    pub fn get_depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }

    pub fn record_drop(&self) {
        self.drop_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_drops(&self) -> usize {
        self.drop_counter.load(Ordering::Relaxed)
    }

    pub fn get_batch_size(&self) -> usize {
        self.current_batch_size.load(Ordering::Relaxed)
    }

    pub fn update_adaptive_batch_size(&self) {
        let depth = self.get_depth();

        let new_batch_size = if depth > self.high_water_mark * 9 / 10 {
            // Very high load: reduce batch size to process faster
            self.current_batch_size.load(Ordering::Relaxed).max(32) / 2
        } else if depth > self.high_water_mark * 7 / 10 {
            // High load: slightly reduce batch size
            self.current_batch_size
                .load(Ordering::Relaxed)
                .saturating_sub(16)
        } else if depth < self.high_water_mark * 3 / 10 {
            // Low load: can increase batch size
            (self.current_batch_size.load(Ordering::Relaxed) + 8).min(512)
        } else {
            self.current_batch_size.load(Ordering::Relaxed)
        };

        self.current_batch_size
            .store(new_batch_size.max(32), Ordering::Relaxed);
    }

    pub fn should_drop(&self) -> bool {
        self.get_depth() > self.high_water_mark * 95 / 100
    }

    pub fn metrics(&self) -> QueueMetrics {
        let depth = self.get_depth();
        QueueMetrics {
            depth,
            high_water_mark: self.high_water_mark,
            is_overloaded: depth > self.high_water_mark,
        }
    }
}

impl Default for BackpressureController {
    fn default() -> Self {
        Self::new(10_000, 128)
    }
}
