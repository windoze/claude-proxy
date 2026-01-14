use serde::{Deserialize, Deserializer};
use std::env;

/// Deserialize a string that may contain environment variable references.
/// Supports both `${VAR_NAME}` and `$VAR_NAME` syntax.
fn deserialize_env_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(expand_env_vars(&s))
}

/// Expand environment variables in a string.
/// Supports both `${VAR_NAME}` and `$VAR_NAME` syntax.
fn expand_env_vars(s: &str) -> String {
    let mut result = s.to_string();

    // Handle ${VAR_NAME} syntax
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let end = start + end;
            let var_name = &result[start + 2..end];
            let value = env::var(var_name).unwrap_or_default();
            result = format!("{}{}{}", &result[..start], value, &result[end + 1..]);
        } else {
            break;
        }
    }

    // Handle $VAR_NAME syntax (only if not already handled by ${})
    // Match $VAR where VAR is alphanumeric or underscore, not followed by {
    let mut i = 0;
    let chars: Vec<char> = result.chars().collect();
    let mut new_result = String::new();

    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] != '{' {
            // Found a $ not followed by {
            let var_start = i + 1;
            let mut var_end = var_start;

            // Collect alphanumeric and underscore characters
            while var_end < chars.len()
                && (chars[var_end].is_alphanumeric() || chars[var_end] == '_')
            {
                var_end += 1;
            }

            if var_end > var_start {
                let var_name: String = chars[var_start..var_end].iter().collect();
                let value = env::var(&var_name).unwrap_or_default();
                new_result.push_str(&value);
                i = var_end;
                continue;
            }
        }
        new_result.push(chars[i]);
        i += 1;
    }

    new_result
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// The address to bind the proxy server to
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// The port to listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// The upstream Claude API URL
    #[serde(default = "default_upstream_url")]
    pub upstream_url: String,

    /// API key that clients must provide to access this proxy
    #[serde(deserialize_with = "deserialize_env_string")]
    pub client_api_key: String,

    /// Upstream authentication configuration
    pub upstream_auth: UpstreamAuthConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamAuthConfig {
    /// Direct API key authentication to Claude
    ApiKey {
        /// The Anthropic API key
        #[serde(deserialize_with = "deserialize_env_string")]
        api_key: String,
    },
    /// Azure AD (Entra ID) authentication with client secret
    AzureAd {
        /// Azure AD tenant ID (supports env var expansion: `${VAR}` or `$VAR`)
        #[serde(deserialize_with = "deserialize_env_string")]
        tenant_id: String,
        /// Azure AD client ID (application ID) (supports env var expansion: `${VAR}` or `$VAR`)
        #[serde(deserialize_with = "deserialize_env_string")]
        client_id: String,
        /// Azure AD client secret (supports env var expansion: `${VAR}` or `$VAR`)
        #[serde(deserialize_with = "deserialize_env_string")]
        client_secret: String,
        /// The scope to request (defaults to "https://ai.azure.com/.default")
        #[serde(default = "default_azure_scope")]
        scope: String,
    },
    /// Azure CLI credential authentication (uses `az login` credentials)
    AzureCli {
        /// The scope to request (defaults to "https://ai.azure.com/.default")
        #[serde(default = "default_azure_scope")]
        scope: String,
    },
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_upstream_url() -> String {
    "https://api.anthropic.com".to_string()
}

fn default_azure_scope() -> String {
    "https://ai.azure.com/.default".to_string()
}

impl ProxyConfig {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(
                config::Environment::default()
                    .prefix("CLAUDE_PROXY")
                    .separator("__"),
            )
            .build()?;

        config.try_deserialize()
    }

    pub fn from_file(path: &str) -> Result<Self, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(
                config::Environment::default()
                    .prefix("CLAUDE_PROXY")
                    .separator("__"),
            )
            .build()?;

        config.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_expand_env_vars_braced_syntax() {
        env::set_var("TEST_VAR_BRACED", "hello_world");
        assert_eq!(expand_env_vars("${TEST_VAR_BRACED}"), "hello_world");
        assert_eq!(
            expand_env_vars("prefix_${TEST_VAR_BRACED}_suffix"),
            "prefix_hello_world_suffix"
        );
        env::remove_var("TEST_VAR_BRACED");
    }

    #[test]
    fn test_expand_env_vars_unbraced_syntax() {
        env::set_var("TEST_VAR_UNBRACED", "test_value");
        assert_eq!(expand_env_vars("$TEST_VAR_UNBRACED"), "test_value");
        assert_eq!(
            expand_env_vars("prefix_$TEST_VAR_UNBRACED/suffix"),
            "prefix_test_value/suffix"
        );
        env::remove_var("TEST_VAR_UNBRACED");
    }

    #[test]
    fn test_expand_env_vars_missing_var() {
        env::remove_var("NONEXISTENT_VAR_12345");
        assert_eq!(expand_env_vars("${NONEXISTENT_VAR_12345}"), "");
        assert_eq!(expand_env_vars("$NONEXISTENT_VAR_12345"), "");
        assert_eq!(
            expand_env_vars("prefix_${NONEXISTENT_VAR_12345}_suffix"),
            "prefix__suffix"
        );
    }

    #[test]
    fn test_expand_env_vars_multiple_vars() {
        env::set_var("TEST_MULTI_A", "aaa");
        env::set_var("TEST_MULTI_B", "bbb");
        assert_eq!(
            expand_env_vars("${TEST_MULTI_A}-${TEST_MULTI_B}"),
            "aaa-bbb"
        );
        assert_eq!(expand_env_vars("$TEST_MULTI_A/$TEST_MULTI_B"), "aaa/bbb");
        env::remove_var("TEST_MULTI_A");
        env::remove_var("TEST_MULTI_B");
    }

    #[test]
    fn test_expand_env_vars_no_expansion() {
        assert_eq!(expand_env_vars("plain_string"), "plain_string");
        assert_eq!(expand_env_vars(""), "");
        assert_eq!(expand_env_vars("no $ here"), "no $ here");
    }

    #[test]
    fn test_expand_env_vars_unclosed_brace() {
        assert_eq!(expand_env_vars("${UNCLOSED"), "${UNCLOSED");
    }

    #[test]
    fn test_expand_env_vars_dollar_at_end() {
        assert_eq!(expand_env_vars("end$"), "end$");
    }

    #[test]
    fn test_deserialize_azure_ad_with_env_vars() {
        env::set_var("TEST_TENANT_ID", "my-tenant-123");
        env::set_var("TEST_CLIENT_ID", "my-client-456");
        env::set_var("TEST_CLIENT_SECRET", "super-secret");

        let toml_str = r#"
            client_api_key = "proxy-key"
            [upstream_auth]
            type = "azure_ad"
            tenant_id = "${TEST_TENANT_ID}"
            client_id = "${TEST_CLIENT_ID}"
            client_secret = "${TEST_CLIENT_SECRET}"
        "#;

        let config: ProxyConfig = toml::from_str(toml_str).unwrap();

        match config.upstream_auth {
            UpstreamAuthConfig::AzureAd {
                tenant_id,
                client_id,
                client_secret,
                scope,
            } => {
                assert_eq!(tenant_id, "my-tenant-123");
                assert_eq!(client_id, "my-client-456");
                assert_eq!(client_secret, "super-secret");
                assert_eq!(scope, "https://ai.azure.com/.default");
            }
            _ => panic!("Expected AzureAd config"),
        }

        env::remove_var("TEST_TENANT_ID");
        env::remove_var("TEST_CLIENT_ID");
        env::remove_var("TEST_CLIENT_SECRET");
    }

    #[test]
    fn test_deserialize_api_key_with_env_var() {
        env::set_var("TEST_API_KEY", "sk-ant-test-key");

        let toml_str = r#"
            client_api_key = "proxy-key"
            [upstream_auth]
            type = "api_key"
            api_key = "${TEST_API_KEY}"
        "#;

        let config: ProxyConfig = toml::from_str(toml_str).unwrap();

        match config.upstream_auth {
            UpstreamAuthConfig::ApiKey { api_key } => {
                assert_eq!(api_key, "sk-ant-test-key");
            }
            _ => panic!("Expected ApiKey config"),
        }

        env::remove_var("TEST_API_KEY");
    }

    #[test]
    fn test_deserialize_client_api_key_with_env_var() {
        env::set_var("TEST_PROXY_KEY", "my-proxy-key");

        let toml_str = r#"
            client_api_key = "${TEST_PROXY_KEY}"
            [upstream_auth]
            type = "api_key"
            api_key = "direct-key"
        "#;

        let config: ProxyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_api_key, "my-proxy-key");

        env::remove_var("TEST_PROXY_KEY");
    }

    #[test]
    fn test_deserialize_with_literal_values() {
        let toml_str = r#"
            client_api_key = "literal-proxy-key"
            [upstream_auth]
            type = "azure_ad"
            tenant_id = "literal-tenant"
            client_id = "literal-client"
            client_secret = "literal-secret"
            scope = "https://custom.scope/.default"
        "#;

        let config: ProxyConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.client_api_key, "literal-proxy-key");
        match config.upstream_auth {
            UpstreamAuthConfig::AzureAd {
                tenant_id,
                client_id,
                client_secret,
                scope,
            } => {
                assert_eq!(tenant_id, "literal-tenant");
                assert_eq!(client_id, "literal-client");
                assert_eq!(client_secret, "literal-secret");
                assert_eq!(scope, "https://custom.scope/.default");
            }
            _ => panic!("Expected AzureAd config"),
        }
    }

    #[test]
    fn test_deserialize_azure_cli() {
        let toml_str = r#"
            client_api_key = "proxy-key"
            [upstream_auth]
            type = "azure_cli"
        "#;

        let config: ProxyConfig = toml::from_str(toml_str).unwrap();

        match config.upstream_auth {
            UpstreamAuthConfig::AzureCli { scope } => {
                assert_eq!(scope, "https://ai.azure.com/.default");
            }
            _ => panic!("Expected AzureCli config"),
        }
    }

    #[test]
    fn test_default_values() {
        let toml_str = r#"
            client_api_key = "proxy-key"
            [upstream_auth]
            type = "api_key"
            api_key = "test-key"
        "#;

        let config: ProxyConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.upstream_url, "https://api.anthropic.com");
    }
}
