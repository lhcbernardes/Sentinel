use crossbeam_deque::{Steal, Stealer, Worker};

pub struct WorkStealingQueue<T> {
    stealers: Vec<Stealer<T>>,
}

impl<T: Send + 'static> WorkStealingQueue<T> {
    pub fn new(num_workers: usize) -> (Vec<Worker<T>>, Self) {
        let mut workers = Vec::with_capacity(num_workers);
        let mut stealers = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let worker = Worker::new_fifo();
            let stealer = worker.stealer();
            workers.push(worker);
            stealers.push(stealer);
        }

        (workers, Self { stealers })
    }

    pub fn steal_from(&self, worker_id: usize) -> Option<T> {
        if worker_id < self.stealers.len() {
            match self.stealers[worker_id].steal() {
                Steal::Success(item) => Some(item),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn steal_batch_from(&self, worker_id: usize, batch_size: usize) -> Vec<T> {
        let mut batch = Vec::with_capacity(batch_size);

        if worker_id < self.stealers.len() {
            for _ in 0..batch_size {
                match self.stealers[worker_id].steal() {
                    Steal::Success(item) => batch.push(item),
                    _ => break,
                }
            }
        }

        batch
    }

    pub fn num_workers(&self) -> usize {
        self.stealers.len()
    }

    pub fn stealer(&self, id: usize) -> Option<&Stealer<T>> {
        self.stealers.get(id)
    }
}

impl<T> Default for WorkStealingQueue<T> {
    fn default() -> Self {
        Self {
            stealers: Vec::new(),
        }
    }
}
