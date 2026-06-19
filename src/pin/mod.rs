use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::domain::{ServerId, ToolDefinitionHash, ToolName};

pub struct PinStore {
    path: PathBuf,
    pins: HashMap<String, String>,
}

impl PinStore {
    pub fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let pins = if path.exists() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice(&bytes)?
        } else {
            HashMap::new()
        };
        Ok(Self { path, pins })
    }

    fn key(server: &ServerId, name: &ToolName) -> String {
        format!("{}/{}", server.as_ref(), name.as_ref())
    }

    pub fn get(&self, server: &ServerId, name: &ToolName) -> Option<ToolDefinitionHash> {
        self.pins
            .get(&Self::key(server, name))
            .map(|h| ToolDefinitionHash::from_hex(h.clone()))
    }

    /// Record a batch of pins and persist in a single write. The store has no
    /// other mutator, so "mutated but unsaved" can't be left lying around.
    pub fn apply(
        &mut self,
        server: &ServerId,
        updates: impl IntoIterator<Item = (ToolName, ToolDefinitionHash)>,
    ) -> anyhow::Result<()> {
        let mut changed = false;
        for (name, hash) in updates {
            self.pins
                .insert(Self::key(server, &name), hash.as_ref().to_owned());
            changed = true;
        }
        if changed {
            self.write_to_disk()
        } else {
            Ok(())
        }
    }

    fn write_to_disk(&self) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.pins)?;
        if let Some(parent) = Path::new(&self.path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ServerId, ToolDefinitionHash, ToolName};

    fn server() -> ServerId {
        ServerId::parse("test-server".to_owned()).unwrap()
    }

    fn tool(name: &str) -> ToolName {
        ToolName::parse(name.to_owned()).unwrap()
    }

    fn hash(s: &str) -> ToolDefinitionHash {
        ToolDefinitionHash::from_hex(s.to_owned())
    }

    #[test]
    fn empty_store_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = PinStore::load(dir.path().join("pins.json")).unwrap();
        assert!(store.get(&server(), &tool("my_tool")).is_none());
    }

    #[test]
    fn apply_then_get_returns_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PinStore::load(dir.path().join("pins.json")).unwrap();
        store
            .apply(&server(), [(tool("my_tool"), hash("abc123"))])
            .unwrap();
        assert_eq!(
            store.get(&server(), &tool("my_tool")).unwrap().as_ref(),
            "abc123"
        );
    }

    #[test]
    fn apply_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let pin_path = dir.path().join("pins.json");

        let mut store = PinStore::load(&pin_path).unwrap();
        store
            .apply(&server(), [(tool("my_tool"), hash("deadbeef"))])
            .unwrap();

        let reloaded = PinStore::load(&pin_path).unwrap();
        assert_eq!(
            reloaded.get(&server(), &tool("my_tool")).unwrap().as_ref(),
            "deadbeef"
        );
    }

    #[test]
    fn apply_with_no_updates_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let pin_path = dir.path().join("pins.json");
        let mut store = PinStore::load(&pin_path).unwrap();
        store.apply(&server(), []).unwrap();
        assert!(!pin_path.exists());
    }
}
