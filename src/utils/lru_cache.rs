use indexmap::IndexMap;
use std::hash::Hash;

pub struct LruCache<K: Hash + Eq, V: Clone> {
    capacity: usize,
    map: IndexMap<K, V>,
}

impl<K: Hash + Eq + Clone, V: Clone> LruCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: IndexMap::with_capacity(capacity),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.map.get(key).cloned()
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            self.map.shift_remove(&key);
        } else if self.map.len() >= self.capacity {
            self.map.pop();
        }
        self.map.insert(key, value);
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.map.shift_remove(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        self.map.retain(|k, v| f(k, v));
    }
}

impl<K: Hash + Eq + Clone, V: Clone> Default for LruCache<K, V> {
    fn default() -> Self {
        Self::new(1000)
    }
}
