use crate::{AuthResult, auth_error, server::AttServerParams, tests::TestClient};
use actix_web::dev::ServerHandle;
use std::thread::JoinHandle;

#[derive(Debug)]
pub struct TestsContext {
    pub server_params: AttServerParams,
    pub server_handle: ServerHandle,
    pub thread_handle: JoinHandle<AuthResult<()>>,
}

impl TestsContext {
    pub async fn stop_server(self) -> AuthResult<()> {
        self.server_handle.stop(false).await;
        self.thread_handle
            .join()
            .map_err(|_e| auth_error!("failed joining the stop thread"))?
    }

    pub fn get_client_url(&self) -> String {
        let host = if self.server_params.host_name == "localhost" {
            // failure to switch to IP will fail server CA verification on the client
            "127.0.0.1"
        } else {
            &self.server_params.host_name
        };
        format!("https://{}:{}", host, self.server_params.host_port)
    }
}
