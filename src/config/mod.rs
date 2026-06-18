use crate::domain::ToolName;
use crate::policy::{DefaultAction, Policy};

#[derive(Debug, serde::Deserialize)]
pub struct RawConfig {
    pub server: RawServerConfig,
    pub policy: RawPolicyConfig,
}

#[derive(Debug, serde::Deserialize)]
pub struct RawServerConfig {
    pub id: String,
    pub pin_store: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct RawPolicyConfig {
    pub default_action: String,
    #[serde(default)]
    pub blocked_tools: Vec<String>,
    #[serde(default)]
    pub confirmation_required: Vec<String>,
}

impl TryFrom<RawPolicyConfig> for Policy {
    type Error = String;

    fn try_from(raw: RawPolicyConfig) -> Result<Self, Self::Error> {
        let default_action = match raw.default_action.as_str() {
            "allow" => DefaultAction::Allow,
            "deny" => DefaultAction::Deny,
            other => {
                return Err(format!(
                    "unknown default_action `{other}`; expected `allow` or `deny`"
                ));
            }
        };
        let blocked_tools = raw
            .blocked_tools
            .into_iter()
            .map(ToolName::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let confirmation_required = raw
            .confirmation_required
            .into_iter()
            .map(ToolName::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Policy {
            default_action,
            blocked_tools,
            confirmation_required,
        })
    }
}

pub struct LoadedConfig {
    pub server_id: String,
    pub pin_store_path: String,
    pub policy: Policy,
}

pub fn load(path: &str) -> anyhow::Result<LoadedConfig> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not read config file `{path}`: {e}"))?;
    let config: RawConfig =
        toml::from_str(&raw).map_err(|e| anyhow::anyhow!("config parse error in `{path}`: {e}"))?;
    let policy = Policy::try_from(config.policy)
        .map_err(|e| anyhow::anyhow!("invalid policy in `{path}`: {e}"))?;
    Ok(LoadedConfig {
        pin_store_path: config
            .server
            .pin_store
            .unwrap_or_else(|| "pins.json".to_owned()),
        server_id: config.server.id,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_policy(toml_str: &str) -> Result<Policy, String> {
        let raw: RawPolicyConfig = toml::from_str(toml_str).map_err(|e| e.to_string())?;
        Policy::try_from(raw)
    }

    #[test]
    fn parses_default_deny_with_blocked_tools() {
        let policy = parse_policy(
            r#"
            default_action = "deny"
            blocked_tools = ["shell.exec", "fs.delete"]
            "#,
        )
        .unwrap();
        assert!(matches!(policy.default_action, DefaultAction::Deny));
        assert_eq!(policy.blocked_tools.len(), 2);
    }

    #[test]
    fn parses_default_allow_with_no_lists() {
        let policy = parse_policy(r#"default_action = "allow""#).unwrap();
        assert!(matches!(policy.default_action, DefaultAction::Allow));
        assert!(policy.blocked_tools.is_empty());
        assert!(policy.confirmation_required.is_empty());
    }

    #[test]
    fn rejects_unknown_default_action() {
        let err = parse_policy(r#"default_action = "maybe""#).unwrap_err();
        assert!(err.contains("unknown default_action"), "got: {err}");
    }

    #[test]
    fn parses_confirmation_required_list() {
        let policy = parse_policy(
            r#"
            default_action = "allow"
            confirmation_required = ["email.send", "github.create_pr"]
            "#,
        )
        .unwrap();
        assert_eq!(policy.confirmation_required.len(), 2);
    }
}
