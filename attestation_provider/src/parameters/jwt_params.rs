use crate::parameters::ProxyParams;

/// Parameters of an Identity Provider
#[derive(Debug, Clone)]
pub struct IdpParams {
    /// The JWT issuer URI
    pub jwt_issuer_uri: String,

    /// The JWKS URI
    pub jwks_uri: String,

    /// The expected audience (optional)
    pub jwt_audience: Option<String>,
}

/// JWT Middleware Parameters
#[derive(Clone, Debug)]
pub struct JwtParams {
    /// The Identity Providers (IdP) parameters
    pub idp_params: Vec<IdpParams>,

    /// Smallest interval between two JWKS fetches (in seconds)
    pub smallest_refresh_interval_seconds: Option<i64>,

    /// Forward proxy parameters to use when fetching JWKS (optional)
    pub proxy_params: Option<ProxyParams>,
}
