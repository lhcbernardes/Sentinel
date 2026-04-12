use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

#[derive(Debug)]
pub struct PacketInfoReusable {
    pub timestamp: i64,
    pub src_ip: [u8; 16],
    pub src_ip_len: u8,
    pub dst_ip: [u8; 16],
    pub dst_ip_len: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8,
    pub size: u32,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub has_src_mac: bool,
    pub has_dst_mac: bool,
}

pub struct PacketPool {
    inner: Mutex<VecDeque<PacketInfoReusable>>,
}

impl PacketPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    pub fn acquire(&self) -> Option<PacketInfoReusable> {
        self.inner.lock().pop_front()
    }

    pub fn release(&self, packet: PacketInfoReusable) {
        let mut queue = self.inner.lock();
        if queue.len() < 10000 {
            queue.push_front(packet);
        }
    }
}

impl PacketInfoReusable {
    pub fn populate(&mut self, timestamp: i64, size: u32, protocol: u8) {
        self.timestamp = timestamp;
        self.size = size;
        self.protocol = protocol;
    }

    pub fn set_ipv4_src(&mut self, addr: [u8; 4]) {
        self.src_ip[0..4].copy_from_slice(&addr);
        self.src_ip_len = 4;
    }

    pub fn set_ipv4_dst(&mut self, addr: [u8; 4]) {
        self.dst_ip[0..4].copy_from_slice(&addr);
        self.dst_ip_len = 4;
    }

    pub fn set_ipv6_src(&mut self, addr: [u8; 16]) {
        self.src_ip.copy_from_slice(&addr);
        self.src_ip_len = 16;
    }

    pub fn set_ipv6_dst(&mut self, addr: [u8; 16]) {
        self.dst_ip.copy_from_slice(&addr);
        self.dst_ip_len = 16;
    }

    pub fn set_mac_src(&mut self, addr: [u8; 6]) {
        self.src_mac.copy_from_slice(&addr);
        self.has_src_mac = true;
    }

    pub fn set_mac_dst(&mut self, addr: [u8; 6]) {
        self.dst_mac.copy_from_slice(&addr);
        self.has_dst_mac = true;
    }
}

pub struct PooledPacketInfo {
    pool: Arc<PacketPool>,
    inner: PacketInfoReusable,
}

impl PooledPacketInfo {
    pub fn new(pool: Arc<PacketPool>) -> Self {
        let inner = pool.acquire().unwrap_or_else(|| PacketInfoReusable {
            timestamp: 0,
            src_ip: [0; 16],
            src_ip_len: 0,
            dst_ip: [0; 16],
            dst_ip_len: 0,
            src_port: None,
            dst_port: None,
            protocol: 0,
            size: 0,
            src_mac: [0; 6],
            dst_mac: [0; 6],
            has_src_mac: false,
            has_dst_mac: false,
        });

        Self { pool, inner }
    }

    pub fn populate(&mut self, timestamp: i64, size: u32, protocol: u8) {
        self.inner.populate(timestamp, size, protocol);
    }

    pub fn set_ipv4_src(&mut self, addr: [u8; 4]) {
        self.inner.set_ipv4_src(addr);
    }

    pub fn set_ipv4_dst(&mut self, addr: [u8; 4]) {
        self.inner.set_ipv4_dst(addr);
    }

    pub fn set_ipv6_src(&mut self, addr: [u8; 16]) {
        self.inner.set_ipv6_src(addr);
    }

    pub fn set_ipv6_dst(&mut self, addr: [u8; 16]) {
        self.inner.set_ipv6_dst(addr);
    }

    pub fn set_mac_src(&mut self, addr: [u8; 6]) {
        self.inner.set_mac_src(addr);
    }

    pub fn set_mac_dst(&mut self, addr: [u8; 6]) {
        self.inner.set_mac_dst(addr);
    }

    pub fn set_ports(&mut self, src: Option<u16>, dst: Option<u16>) {
        self.inner.src_port = src;
        self.inner.dst_port = dst;
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.inner.protocol = protocol;
    }

    pub fn into_owned(self) -> crate::sniffer::PacketInfo {
        use crate::sniffer::packet::Protocol;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let src_ip = if self.inner.src_ip_len == 4 {
            let octets: [u8; 4] = [
                self.inner.src_ip[0],
                self.inner.src_ip[1],
                self.inner.src_ip[2],
                self.inner.src_ip[3],
            ];
            IpAddr::V4(Ipv4Addr::from(octets))
        } else if self.inner.src_ip_len == 16 {
            IpAddr::V6(Ipv6Addr::from(self.inner.src_ip))
        } else {
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        };

        let dst_ip = if self.inner.dst_ip_len == 4 {
            let octets: [u8; 4] = [
                self.inner.dst_ip[0],
                self.inner.dst_ip[1],
                self.inner.dst_ip[2],
                self.inner.dst_ip[3],
            ];
            IpAddr::V4(Ipv4Addr::from(octets))
        } else if self.inner.dst_ip_len == 16 {
            IpAddr::V6(Ipv6Addr::from(self.inner.dst_ip))
        } else {
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        };

        let protocol = match self.inner.protocol {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Unknown,
        };

        let src_mac = if self.inner.has_src_mac {
            Some(std::borrow::Cow::Owned(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.inner.src_mac[0],
                self.inner.src_mac[1],
                self.inner.src_mac[2],
                self.inner.src_mac[3],
                self.inner.src_mac[4],
                self.inner.src_mac[5]
            )))
        } else {
            None
        };

        let dst_mac = if self.inner.has_dst_mac {
            Some(std::borrow::Cow::Owned(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.inner.dst_mac[0],
                self.inner.dst_mac[1],
                self.inner.dst_mac[2],
                self.inner.dst_mac[3],
                self.inner.dst_mac[4],
                self.inner.dst_mac[5]
            )))
        } else {
            None
        };

        crate::sniffer::PacketInfo {
            timestamp: self.inner.timestamp,
            src_ip,
            dst_ip,
            src_port: self.inner.src_port,
            dst_port: self.inner.dst_port,
            protocol,
            size: self.inner.size,
            src_mac,
            dst_mac,
        }
    }
}

impl Drop for PooledPacketInfo {
    fn drop(&mut self) {
        self.pool.release(std::mem::replace(
            &mut self.inner,
            PacketInfoReusable {
                timestamp: 0,
                src_ip: [0; 16],
                src_ip_len: 0,
                dst_ip: [0; 16],
                dst_ip_len: 0,
                src_port: None,
                dst_port: None,
                protocol: 0,
                size: 0,
                src_mac: [0; 6],
                dst_mac: [0; 6],
                has_src_mac: false,
                has_dst_mac: false,
            },
        ));
    }
}
