mod auth_error;
mod helpers;
#[cfg(test)]
mod tests;

pub use auth_error::AuthError;
pub use helpers::{AuthResult, AuthResultHelper};

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! auth_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::auth_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::auth_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! auth_error {
    ($msg:literal) => {
        $crate::AuthError::Generic(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::AuthError::Generic($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::AuthError::Generic(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! auth_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::auth_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::auth_error!($fmt, $($arg)*))
    };
}
