use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum DeviceGroup {
    #[default]
    Trusted,
    Kids,
    Guests,
    IoT,
    Default,
}

impl DeviceGroup {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Kids => "kids",
            Self::Guests => "guests",
            Self::IoT => "iot",
            Self::Default => "default",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "trusted" => Some(Self::Trusted),
            "kids" => Some(Self::Kids),
            "guests" => Some(Self::Guests),
            "iot" => Some(Self::IoT),
            "default" => Some(Self::Default),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicies {
    pub block_trackers: bool,
    pub block_malware: bool,
    pub block_adult: bool,
    pub allow_internet: bool,
}

impl Default for GroupPolicies {
    fn default() -> Self {
        Self {
            block_trackers: true,
            block_malware: true,
            block_adult: false,
            allow_internet: true,
        }
    }
}

pub struct ClientManager {
    memberships: RwLock<HashMap<String, DeviceGroup>>, // MAC -> Group
    policies: RwLock<HashMap<DeviceGroup, GroupPolicies>>,
}

impl ClientManager {
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(DeviceGroup::Trusted, GroupPolicies {
            block_trackers: false,
            block_malware: true,
            block_adult: false,
            allow_internet: true,
        });
        policies.insert(DeviceGroup::Kids, GroupPolicies {
            block_trackers: true,
            block_malware: true,
            block_adult: true,
            allow_internet: true,
        });
        policies.insert(DeviceGroup::Guests, GroupPolicies {
            block_trackers: true,
            block_malware: true,
            block_adult: false,
            allow_internet: true,
        });
        policies.insert(DeviceGroup::IoT, GroupPolicies {
            block_trackers: true,
            block_malware: true,
            block_adult: false,
            allow_internet: true,
        });
        policies.insert(DeviceGroup::Default, GroupPolicies::default());

        Self {
            memberships: RwLock::new(HashMap::new()),
            policies: RwLock::new(policies),
        }
    }

    pub fn assign_device(&self, mac: String, group_id: &str) -> bool {
        if let Some(group) = DeviceGroup::from_id(group_id) {
            self.memberships.write().insert(mac, group);
            true
        } else {
            false
        }
    }

    pub fn remove_device(&self, mac: &str) {
        self.memberships.write().remove(mac);
    }

    pub fn get_device_group(&self, mac: &str) -> DeviceGroup {
        self.memberships.read().get(mac).cloned().unwrap_or(DeviceGroup::Default)
    }

    pub fn update_policies(&self, group_id: &str, new_policies: GroupPolicies) -> bool {
        if let Some(group) = DeviceGroup::from_id(group_id) {
            self.policies.write().insert(group, new_policies);
            true
        } else {
            false
        }
    }

    pub fn get_policies(&self, group: DeviceGroup) -> GroupPolicies {
        self.policies.read().get(&group).cloned().unwrap_or_default()
    }

    pub fn get_all_group_ids(&self) -> Vec<&'static str> {
        vec!["trusted", "kids", "guests", "iot", "default"]
    }

    pub fn get_members_for_group(&self, group: DeviceGroup) -> Vec<String> {
        self.memberships.read()
            .iter()
            .filter(|(_, &g)| g == group)
            .map(|(mac, _)| mac.clone())
            .collect()
    }
}

impl Default for ClientManager {
    fn default() -> Self {
        Self::new()
    }
}
