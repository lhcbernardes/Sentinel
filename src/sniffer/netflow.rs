use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetFlowV5 {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetFlowRecord {
    pub src_addr: String,
    pub dst_addr: String,
    pub next_hop: String,
    pub input: u16,
    pub output: u16,
    pub packets: u32,
    pub bytes: u64,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub protocol: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowStats {
    pub total_flows: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub protocols: HashMap<String, u64>,
    pub top_talkers: HashMap<String, u64>,
    pub top_destinations: HashMap<String, u64>,
}

pub struct NetFlowProcessor {
    flows: std::sync::RwLock<HashMap<String, NetFlowRecord>>,
    stats: std::sync::RwLock<FlowStats>,
}

impl NetFlowProcessor {
    pub fn new() -> Self {
        Self {
            flows: std::sync::RwLock::new(HashMap::new()),
            stats: std::sync::RwLock::new(FlowStats::default()),
        }
    }

    pub fn parse_netflow_v5(&self, data: &[u8]) -> Result<Vec<NetFlowRecord>, String> {
        if data.len() < 24 {
            return Err("NetFlow packet too short".to_string());
        }

        let mut records = Vec::new();
        let header = NetFlowV5 {
            version: u16::from_be_bytes([data[0], data[1]]),
            count: u16::from_be_bytes([data[2], data[3]]),
            sys_uptime: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            unix_secs: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            unix_nsecs: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            flow_sequence: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            engine_type: data[20],
            engine_id: data[21],
            sampling_interval: u16::from_be_bytes([data[22], data[23]]),
        };

        if header.version != 5 {
            return Err(format!("Unsupported NetFlow version: {}", header.version));
        }

        let record_size = 48;
        let expected_len = 24 + (header.count as usize * record_size);

        if data.len() < expected_len {
            return Err(format!(
                "Incomplete NetFlow data: expected {} bytes, got {}",
                expected_len,
                data.len()
            ));
        }

        for i in 0..header.count as usize {
            let offset = 24 + (i * record_size);
            let record = NetFlowRecord {
                src_addr: format_ip(&data[offset..offset + 4]),
                dst_addr: format_ip(&data[offset + 4..offset + 8]),
                next_hop: format_ip(&data[offset + 8..offset + 12]),
                input: u16::from_be_bytes([data[offset + 12], data[offset + 13]]),
                output: u16::from_be_bytes([data[offset + 14], data[offset + 15]]),
                packets: u32::from_be_bytes([
                    data[offset + 16],
                    data[offset + 17],
                    data[offset + 18],
                    data[offset + 19],
                ]),
                bytes: u64::from_be_bytes([
                    data[offset + 20],
                    data[offset + 21],
                    data[offset + 22],
                    data[offset + 23],
                    data[offset + 24],
                    data[offset + 25],
                    data[offset + 26],
                    data[offset + 27],
                ]),
                src_port: u16::from_be_bytes([data[offset + 28], data[offset + 29]]),
                dst_port: u16::from_be_bytes([data[offset + 30], data[offset + 31]]),
                tcp_flags: data[offset + 32],
                protocol: data[offset + 33],
                tos: data[offset + 34],
                src_as: u16::from_be_bytes([data[offset + 35], data[offset + 36]]),
                dst_as: u16::from_be_bytes([data[offset + 37], data[offset + 38]]),
                src_mask: data[offset + 39],
                dst_mask: data[offset + 40],
            };
            records.push(record);
        }

        // Update stats
        self.update_stats(&records);

        Ok(records)
    }

    fn update_stats(&self, records: &[NetFlowRecord]) {
        let mut stats = self.stats.write().unwrap();

        stats.total_flows += records.len() as u64;

        for record in records {
            stats.total_packets += record.packets as u64;
            stats.total_bytes += record.bytes;

            let proto = match record.protocol {
                1 => "ICMP".to_string(),
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                _ => format!("Protocol {}", record.protocol),
            };
            *stats.protocols.entry(proto).or_insert(0) += record.bytes;

            let key = record.src_addr.clone();
            *stats.top_talkers.entry(key).or_insert(0) += record.bytes;

            let key = record.dst_addr.clone();
            *stats.top_destinations.entry(key).or_insert(0) += record.bytes;
        }
    }

    pub fn get_stats(&self) -> FlowStats {
        self.stats.read().unwrap().clone()
    }

    pub fn get_top_talkers(&self) -> Vec<(String, u64)> {
        let stats = self.stats.read().unwrap();
        let mut talkers: Vec<_> = stats
            .top_talkers
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        talkers.sort_by(|a, b| b.1.cmp(&a.1));
        talkers.truncate(10);
        talkers
    }

    pub fn get_top_destinations(&self) -> Vec<(String, u64)> {
        let stats = self.stats.read().unwrap();
        let mut dests: Vec<_> = stats
            .top_destinations
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        dests.sort_by(|a, b| b.1.cmp(&a.1));
        dests.truncate(10);
        dests
    }

    pub fn get_flows(&self) -> Vec<NetFlowRecord> {
        self.flows.read().unwrap().values().cloned().collect()
    }

    pub fn clear(&self) {
        self.flows.write().unwrap().clear();
        *self.stats.write().unwrap() = FlowStats::default();
    }
}

fn format_ip(data: &[u8]) -> String {
    format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])
}

impl Default for NetFlowProcessor {
    fn default() -> Self {
        Self::new()
    }
}
