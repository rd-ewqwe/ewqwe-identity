use crate::{AttError, AttResult, parameters::TlsParams};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const LOCAL_CONFIG_FILE_NAME: &str = "credential-server.toml";
const PLATFORM_CONFIG_FILE_NAME: &str = "config.toml";
const EDITOR_CONFIG_DIR: &str = "ewQwe";
const APP_CONFIG_DIR: &str = "Credential Server";

#[derive(Clone, Debug, Deserialize, Serialize)]
/// The Forward Proxy Parameters
pub struct ServerParams {
    pub host_name: String,
    pub host_port: u16,
    pub tls_params: TlsParams,
    pub default_username: Option<String>,
    pub openid4vp_config: ewqwe_openid4vp::OpenID4VPServiceConfig,
    /// Directory containing trusted credential-issuer CA certificates (PEM files).
    /// All `*.pem` files in this directory are loaded as trusted CA certificates.
    /// Credentials whose issuer JWT `x5c` chain or mDoc `issuerAuth` chain
    /// terminates at a CA in this directory are considered trustworthy.
    /// Defaults to `issuer_certificates/` in the same directory as the config file.
    #[serde(default)]
    pub trusted_issuer_certs_dir: Option<String>,
}

impl ServerParams {
    pub fn load_from_default_locations() -> AttResult<(Self, PathBuf)> {
        let search_paths = Self::default_config_search_paths()?;

        let config_path = search_paths
            .iter()
            .find(|path| path.is_file())
            .cloned()
            .ok_or_else(|| {
                AttError::Config(format!(
                    "No configuration file found. Searched: {}",
                    search_paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;

        let params = Self::load_from_file(&config_path)?;
        Ok((params, config_path))
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> AttResult<Self> {
        let path = path.as_ref();
        let config = fs::read_to_string(path).map_err(|error| {
            AttError::Config(format!(
                "Failed to read configuration file {}: {error}",
                path.display()
            ))
        })?;

        let mut params: Self = toml::from_str(&config).map_err(|error| {
            AttError::Config(format!(
                "Failed to parse configuration file {}: {error}",
                path.display()
            ))
        })?;

        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        params.resolve_relative_paths(base_dir);
        Ok(params)
    }

    fn default_config_search_paths() -> AttResult<Vec<PathBuf>> {
        Ok(vec![
            env::current_dir()
                .map_err(|error| {
                    AttError::Config(format!("Failed to determine current directory: {error}"))
                })?
                .join(LOCAL_CONFIG_FILE_NAME),
            Self::platform_config_dir()?.join(PLATFORM_CONFIG_FILE_NAME),
        ])
    }

    fn platform_config_dir() -> AttResult<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            env::var_os("APPDATA")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    AttError::Config("APPDATA is not set; cannot resolve config directory".into())
                })
                .map(|base| base.join(EDITOR_CONFIG_DIR).join(APP_CONFIG_DIR))
        }

        #[cfg(target_os = "macos")]
        {
            env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    AttError::Config("HOME is not set; cannot resolve config directory".into())
                })
                .map(|home| {
                    home.join("Library")
                        .join("Application Support")
                        .join(EDITOR_CONFIG_DIR)
                        .join(APP_CONFIG_DIR)
                })
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let base = env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
                .ok_or_else(|| {
                    AttError::Config(
                        "Neither XDG_CONFIG_HOME nor HOME is set; cannot resolve config directory"
                            .into(),
                    )
                })?;

            Ok(base.join(EDITOR_CONFIG_DIR).join(APP_CONFIG_DIR))
        }
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.tls_params.server_private_key =
            resolve_path(base_dir, &self.tls_params.server_private_key);
        self.tls_params.server_certificate =
            resolve_path(base_dir, &self.tls_params.server_certificate);
        self.tls_params.server_ca_chain = resolve_path(base_dir, &self.tls_params.server_ca_chain);

        if let Some(client_ca_cert_chain) = &mut self.tls_params.client_ca_cert_chain {
            *client_ca_cert_chain = resolve_path(base_dir, client_ca_cert_chain);
        }

        if let Some(haip_config) = &mut self.openid4vp_config.haip_config {
            haip_config.x509_cert_path = resolve_path(base_dir, &haip_config.x509_cert_path);
            haip_config.x509_key_path = resolve_path(base_dir, &haip_config.x509_key_path);
        }

        // Resolve trusted issuer certificates directory (default: issuer_certificates/)
        let default_dir = "issuer_certificates";
        let dir = self
            .trusted_issuer_certs_dir
            .as_deref()
            .unwrap_or(default_dir);
        self.trusted_issuer_certs_dir = Some(resolve_path(base_dir, dir));
    }
}

impl ServerParams {
    pub fn trusted_issuer_certs_dir(&self) -> &str {
        self.trusted_issuer_certs_dir
            .as_deref()
            .unwrap_or("issuer_certificates")
    }
}

fn resolve_path(base_dir: &Path, value: &str) -> String {
    let path = Path::new(value);
    if path.is_absolute() {
        value.to_string()
    } else {
        base_dir.join(path).display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::ServerParams;
    use std::{fs, path::PathBuf};
    use uuid::Uuid;

    #[test]
    fn loads_toml_and_resolves_relative_paths_from_config_directory() {
        let temp_dir =
            std::env::temp_dir().join(format!("credential-server-config-test-{}", Uuid::new_v4()));

        fs::create_dir_all(&temp_dir).expect("failed to create temp config directory");

        let config_path = temp_dir.join("credential-server.toml");
        fs::write(
            &config_path,
            r#"
host_name = "127.0.0.1"
host_port = 9443
default_username = "demo-user"

[tls_params]
server_private_key = "certs/server.key.pem"
server_certificate = "certs/server.cert.pem"
server_ca_chain = "certs/ca.chain.pem"
client_ca_cert_chain = "certs/client-ca.pem"

[openid4vp_config]
transaction_ttl_secs = 300
trusted_issuer_certs_dir = "issuers"

[openid4vp_config.haip_config]
x509_cert_path = "certs/server.fullchain.pem"
x509_key_path = "certs/server.key.pem"
"#,
        )
        .expect("failed to write config file");

        let params = ServerParams::load_from_file(&config_path).expect("failed to load config");

        assert_eq!(params.host_name, "127.0.0.1");
        assert_eq!(params.host_port, 9443);
        assert_eq!(
            PathBuf::from(&params.tls_params.server_private_key),
            temp_dir.join("certs/server.key.pem")
        );
        assert_eq!(
            PathBuf::from(&params.tls_params.server_certificate),
            temp_dir.join("certs/server.cert.pem")
        );
        assert_eq!(
            PathBuf::from(
                params
                    .openid4vp_config
                    .haip_config
                    .as_ref()
                    .expect("missing haip config")
                    .x509_cert_path
                    .as_str(),
            ),
            temp_dir.join("certs/server.fullchain.pem")
        );
        assert_eq!(
            params.trusted_issuer_certs_dir(),
            temp_dir.join("issuers").display().to_string()
        );

        fs::remove_dir_all(&temp_dir).expect("failed to remove temp config directory");
    }
}
