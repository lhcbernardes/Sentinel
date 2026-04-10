use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum DeviceGroup {
    #[default]
    Trusted,
    Kids,
    Guests,
    IoT,
    Default,
}

pub struct ClientManager;

impl Default for ClientManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientManager {
    pub fn new() -> Self {
        Self
    }
}
