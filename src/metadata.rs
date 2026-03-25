use crate::error::Result;
use crate::model::WalletProfileMetadata;
use std::fs;
use std::path::{Path, PathBuf};

pub trait WalletMetadataStore {
    fn load(&self) -> Result<Option<WalletProfileMetadata>>;
    fn save(&self, metadata: &WalletProfileMetadata) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct FileWalletMetadataStore {
    path: PathBuf,
}

impl FileWalletMetadataStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl WalletMetadataStore for FileWalletMetadataStore {
    fn load(&self) -> Result<Option<WalletProfileMetadata>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let json = fs::read_to_string(&self.path)?;
        Ok(Some(serde_json::from_str(&json)?))
    }

    fn save(&self, metadata: &WalletProfileMetadata) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec_pretty(metadata)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn file_store_round_trips_metadata() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let path = std::env::temp_dir().join(format!("watt-wallet-metadata-{unique}.json"));
        let store = FileWalletMetadataStore::new(&path);
        let metadata = WalletProfileMetadata::new("default", 1);
        store.save(&metadata).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.profile_id, "default");
        let _ = fs::remove_file(path);
    }
}
