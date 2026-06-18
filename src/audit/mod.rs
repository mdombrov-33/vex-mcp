use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

use anyhow::Context;

pub const CHAIN_SENTINEL: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub timestamp: u64,
    pub direction: Direction,
    pub message_class: String,
    pub server_id: String,
    pub tool_name: Option<String>,
    pub verdict: String,
    pub findings_count: usize,
    pub param_shape: Option<serde_json::Value>,
    pub chain_hash: String,
}

pub struct AuditLog {
    writer: BufWriter<File>,
    prev_hash: String,
}

impl AuditLog {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let prev_hash = Self::last_line_hash(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("could not open audit log at `{path}`"))?;
        Ok(Self {
            writer: BufWriter::new(file),
            prev_hash,
        })
    }

    fn last_line_hash(path: &str) -> anyhow::Result<String> {
        if !std::path::Path::new(path).exists() {
            return Ok(CHAIN_SENTINEL.to_owned());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("could not read existing audit log at `{path}`"))?;
        Ok(match content.lines().last() {
            Some(last) => sha256_hex(last.as_bytes()),
            None => CHAIN_SENTINEL.to_owned(),
        })
    }

    pub fn append(&mut self, mut record: AuditRecord) -> anyhow::Result<()> {
        record.chain_hash = self.prev_hash.clone();
        let json = serde_json::to_string(&record).context("failed to serialize audit record")?;
        self.writer
            .write_all(json.as_bytes())
            .context("failed to write audit record")?;
        self.writer
            .write_all(b"\n")
            .context("failed to write audit record newline")?;
        self.writer.flush().context("failed to flush audit log")?;
        self.prev_hash = sha256_hex(json.as_bytes());
        Ok(())
    }
}

pub fn parameter_shape(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let shaped = map
                .keys()
                .map(|k| {
                    (
                        k.clone(),
                        serde_json::Value::String("<redacted>".to_owned()),
                    )
                })
                .collect();
            serde_json::Value::Object(shaped)
        }
        serde_json::Value::Array(items) => {
            serde_json::json!({ "type": "array", "len": items.len() })
        }
        serde_json::Value::String(_) => serde_json::Value::String("<redacted-string>".to_owned()),
        serde_json::Value::Number(_) => serde_json::Value::String("<number>".to_owned()),
        serde_json::Value::Bool(_) => serde_json::Value::String("<bool>".to_owned()),
        serde_json::Value::Null => serde_json::Value::Null,
    }
}

pub fn verify_chain(path: &str) -> anyhow::Result<usize> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("could not read audit log at `{path}`"))?;

    let mut expected = CHAIN_SENTINEL.to_owned();
    let mut count = 0usize;

    for (i, line) in content.lines().enumerate() {
        let record: AuditRecord =
            serde_json::from_str(line).with_context(|| format!("line {}: invalid JSON", i + 1))?;

        if record.chain_hash != expected {
            anyhow::bail!(
                "chain broken at line {}: expected chain_hash `{}`, found `{}`",
                i + 1,
                expected,
                record.chain_hash
            );
        }

        expected = sha256_hex(line.as_bytes());
        count += 1;
    }

    Ok(count)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_record() -> AuditRecord {
        AuditRecord {
            timestamp: 0,
            direction: Direction::ClientToServer,
            message_class: "tool_call_request".to_owned(),
            server_id: "test-server".to_owned(),
            tool_name: Some("test.tool".to_owned()),
            verdict: "allow".to_owned(),
            findings_count: 0,
            param_shape: None,
            chain_hash: String::new(), // overwritten by AuditLog::append
        }
    }

    #[test]
    fn first_record_carries_sentinel() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();

        let mut log = AuditLog::open(&path).unwrap();
        log.append(make_record()).unwrap();
        drop(log);

        let content = std::fs::read_to_string(&path).unwrap();
        let first: AuditRecord = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(first.chain_hash, CHAIN_SENTINEL);
    }

    #[test]
    fn chain_integrity() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();

        let mut log = AuditLog::open(&path).unwrap();
        log.append(make_record()).unwrap();
        log.append(make_record()).unwrap();
        drop(log);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let second: AuditRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second.chain_hash, sha256_hex(lines[0].as_bytes()));
    }

    #[test]
    fn tamper_detection() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();

        let mut log = AuditLog::open(&path).unwrap();
        log.append(make_record()).unwrap();
        log.append(make_record()).unwrap();
        drop(log);

        // Corrupt the first record's verdict field.
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"allow\"", "\"block\"", 1);
        std::fs::write(&path, tampered).unwrap();

        assert!(verify_chain(&path).is_err());
    }

    #[test]
    fn verify_chain_passes_on_valid_log() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();

        let mut log = AuditLog::open(&path).unwrap();
        for _ in 0..5 {
            log.append(make_record()).unwrap();
        }
        drop(log);

        verify_chain(&path).unwrap();
    }

    #[test]
    fn open_resumes_chain_across_sessions() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();

        let mut log = AuditLog::open(&path).unwrap();
        log.append(make_record()).unwrap();
        log.append(make_record()).unwrap();
        drop(log);

        let mut log2 = AuditLog::open(&path).unwrap();
        log2.append(make_record()).unwrap();
        drop(log2);

        verify_chain(&path).unwrap();
    }

    #[test]
    fn redaction_no_raw_values() {
        let params = serde_json::json!({
            "cmd": "rm -rf /",
            "password": "supersecret",
            "count": 42,
            "flag": true,
        });
        let shape = parameter_shape(&params);
        let serialized = serde_json::to_string(&shape).unwrap();

        assert!(!serialized.contains("rm -rf /"), "string value leaked");
        assert!(!serialized.contains("supersecret"), "secret value leaked");
        assert!(
            !serialized.contains("42"),
            "numeric value leaked: {serialized}"
        );
        assert!(
            serialized.contains("<redacted>"),
            "keys should be preserved with redacted values"
        );
    }

    #[test]
    fn redaction_preserves_keys() {
        let params = serde_json::json!({ "cmd": "secret", "args": ["a", "b"] });
        let shape = parameter_shape(&params);
        let obj = shape.as_object().unwrap();
        assert!(obj.contains_key("cmd"));
        assert!(obj.contains_key("args"));
        assert_eq!(
            obj["cmd"],
            serde_json::Value::String("<redacted>".to_owned())
        );
    }
}
