use cookie_store::{CookieStore, RawCookie, RawCookieParseError};
use reqwest::header::HeaderValue;
use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};
use tracing::error;

#[derive(Debug)]
pub struct TestCookieStore(Mutex<CookieStore>);

impl Default for TestCookieStore {
    /// Create a new, empty [`TestCookieStore`]
    fn default() -> Self {
        TestCookieStore::new()
    }
}

impl TestCookieStore {
    /// Create a new [`TestCookieStore`] from a default empty [`cookie_store::CookieStore`].
    pub fn new() -> TestCookieStore {
        TestCookieStore(Mutex::new(CookieStore::new()))
    }

    /// Lock and get a handle to the contained [`cookie_store::CookieStore`].
    pub fn lock(
        &self,
    ) -> Result<MutexGuard<'_, CookieStore>, PoisonError<MutexGuard<'_, CookieStore>>> {
        self.0.lock()
    }

    /// Consumes this [`TestCookieStore`], returning the underlying [`cookie_store::CookieStore`]
    pub fn into_inner(self) -> LockResult<CookieStore> {
        self.0.into_inner()
    }
}

impl reqwest::cookie::CookieStore for TestCookieStore {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url) {
        let mut store = self.0.lock().unwrap();
        let cookies = cookie_headers.filter_map(|val| {
            std::str::from_utf8(val.as_bytes())
                .map_err(|e| {
                    error!("Failed to parse cookie header as UTF-8: {}", e);
                    RawCookieParseError::from(e)
                })
                .and_then(RawCookie::parse)
                .inspect_err(|e| error!("Invalid cookie: {e}"))
                .map(|c| c.into_owned())
                .ok()
        });
        store.store_response_cookies(cookies, url);
    }

    fn cookies(&self, url: &url::Url) -> Option<HeaderValue> {
        let store = self.0.lock().unwrap();
        let s = store
            .get_request_values(url)
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join("; ");

        if s.is_empty() {
            return None;
        }

        HeaderValue::from_bytes(s.as_bytes()).ok()
    }
}
