use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;

static OUI_DATABASE: Lazy<RwLock<HashMap<String, String>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub fn load_oui_database(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("OUI file not found: {:?}", path));
    }

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
    let db = OUI_DATABASE.read();
    db.get(prefix).cloned()
}

pub fn is_loaded() -> bool {
    !OUI_DATABASE.read().is_empty()
}

pub fn count() -> usize {
    OUI_DATABASE.read().len()
}
