use maxminddb::geoip2;
use std::net::IpAddr;
use std::path::Path;
use parking_lot::RwLock;
use tracing::{info, warn};

pub struct GeoIPService {
    reader: RwLock<Option<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoIPService {
    pub fn new() -> Self {
        Self {
            reader: RwLock::new(None),
        }
    }

    pub fn load_database<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        match maxminddb::Reader::open_readfile(path.as_ref()) {
            Ok(reader) => {
                let mut guard = self.reader.write();
                *guard = Some(reader);
                info!("GeoIP database loaded from {:?}", path.as_ref());
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("Failed to load GeoIP database: {}", e);
                warn!("{}", err_msg);
                Err(err_msg)
            }
        }
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader_guard = self.reader.read();
        let reader = reader_guard.as_ref()?;
        
        match reader.lookup::<geoip2::Country>(ip) {
            Ok(country) => {
                country.country?
                    .iso_code
                    .map(|s| s.to_string())
            }
            Err(_) => None,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.reader.read().is_some()
    }
}

impl Default for GeoIPService {
    fn default() -> Self {
        Self::new()
    }
}
