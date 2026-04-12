use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;
use std::sync::LazyLock;
use tracing::info;

static OUI_DATABASE: LazyLock<RwLock<HashMap<String, String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

static OUI_MEMORY_MAPPED: LazyLock<RwLock<Option<MappedOuiDatabase>>> =
    LazyLock::new(|| RwLock::new(None));

struct MappedOuiDatabase {
    data: memmap2::Mmap,
}

impl MappedOuiDatabase {
    fn from_file(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open OUI file: {}", e))?;
        let mmap = unsafe {
            memmap2::Mmap::map(&file)
                .map_err(|e| format!("Failed to memory-map OUI file: {}", e))?
        };
        Ok(Self { data: mmap })
    }

    fn lookup(&self, prefix: &str) -> Option<String> {
        let data = std::str::from_utf8(&self.data).ok()?;

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((oui, manufacturer)) = line.split_once(',') {
                let oui = oui.trim().to_uppercase().replace('-', ":");
                if oui.len() >= 8 && &oui[..8] == prefix {
                    return Some(manufacturer.trim().to_string());
                }
            }
        }
        None
    }
}

pub fn load_oui_database(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("OUI file not found: {:?}", path));
    }

    // Try memory-mapped loading first (faster for large files)
    match MappedOuiDatabase::from_file(path) {
        Ok(mapped) => {
            *OUI_MEMORY_MAPPED.write() = Some(mapped);
            info!("OUI database loaded with memory-mapping");
        }
        Err(e) => {
            // Fallback to regular loading
            info!("Memory-mapping failed ({}), using regular loading", e);
            load_regular(path)?;
        }
    }

    Ok(())
}

fn load_regular(path: &Path) -> Result<(), String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read OUI file: {}", e))?;

    let mut database = OUI_DATABASE.write();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((oui, manufacturer)) = line.split_once(',') {
            let oui = oui.trim().to_uppercase().replace('-', ":");
            if oui.len() >= 8 {
                let prefix = &oui[..8];
                database.insert(prefix.to_string(), manufacturer.trim().to_string());
            }
        }
    }

    info!("Loaded {} OUI entries", database.len());
    Ok(())
}

pub fn lookup_manufacturer(mac: &str) -> Option<String> {
    let mac_clean = mac.to_uppercase().replace('-', ":");

    if mac_clean.len() < 8 {
        return None;
    }

    let prefix = &mac_clean[..8];

    // Try memory-mapped lookup first
    if let Some(mapped) = OUI_MEMORY_MAPPED.read().as_ref() {
        if let Some(result) = mapped.lookup(prefix) {
            return Some(result);
        }
    }

    // Fallback to regular lookup
    let db = OUI_DATABASE.read();
    db.get(prefix).cloned()
}

pub fn is_loaded() -> bool {
    OUI_MEMORY_MAPPED.read().is_some() || !OUI_DATABASE.read().is_empty()
}

pub fn count() -> usize {
    OUI_MEMORY_MAPPED.read().as_ref().map_or_else(
        || OUI_DATABASE.read().len(),
        |_| {
            // Estimate count from memory-mapped file
            let data = OUI_MEMORY_MAPPED.read();
            if let Some(mapped) = data.as_ref() {
                std::str::from_utf8(&mapped.data)
                    .map(|s| {
                        s.lines()
                            .filter(|l| !l.is_empty() && !l.starts_with('#'))
                            .count()
                    })
                    .unwrap_or(0)
            } else {
                0
            }
        },
    )
}
