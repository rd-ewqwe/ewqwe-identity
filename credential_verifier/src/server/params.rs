use crate::parameters::TlsParams;

#[derive(Clone, Debug)]
/// The Forward Proxy Parameters
pub struct AttServerParams {
    pub host_name: String,
    pub host_port: u16,
    pub tls_params: TlsParams,
    pub default_username: Option<String>,
}
