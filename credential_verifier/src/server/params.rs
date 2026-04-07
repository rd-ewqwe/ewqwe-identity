use crate::parameters::TlsParams;

#[derive(Clone, Debug)]
/// The Forward Proxy Parameters
pub struct AttServerParams {
    pub host_name: String,
    pub host_port: u16,
    pub tls_params: TlsParams,
    pub default_username: Option<String>,
    /// Optional OpenID4VP configuration.
    /// If set, the server will serve OpenID4VP endpoints.
    pub openid4vp_config: Option<ewqwe_openid4vp::OpenID4VPServiceConfig>,
}
