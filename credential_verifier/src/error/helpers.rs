use crate::AttError;

pub type AttResult<R> = Result<R, AttError>;

/// A helper trait for `AuthResult` that provides additional methods for error handling.
pub trait AttResultHelper<T> {
    /// Sets the context for the error.
    ///
    /// # Errors
    ///
    /// Returns a `AuthResult` with the specified context if the original result is an error.
    fn context(self, context: &str) -> AttResult<T>;

    /// Sets the context for the error using a closure.
    ///
    /// # Errors
    ///
    /// Returns a `AuthResult` with the context returned by the closure if the original result is an error.
    fn with_context<O>(self, op: O) -> AttResult<T>
    where
        O: FnOnce() -> String;
}

impl<T, E> AttResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> AttResult<T> {
        self.map_err(|e| AttError::Generic(format!("{context}: {e}")))
    }

    fn with_context<O>(self, op: O) -> AttResult<T>
    where
        O: FnOnce() -> String,
    {
        self.map_err(|e| AttError::Generic(format!("{}: {e}", op())))
    }
}

impl<T> AttResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> AttResult<T> {
        self.ok_or_else(|| AttError::Generic(context.to_owned()))
    }

    fn with_context<O>(self, op: O) -> AttResult<T>
    where
        O: FnOnce() -> String,
    {
        self.ok_or_else(|| AttError::Generic(op()))
    }
}
