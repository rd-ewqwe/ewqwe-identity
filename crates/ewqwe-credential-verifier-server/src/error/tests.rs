use crate::{AttError, AttResultHelper, auth_bail, auth_ensure, auth_error};

#[test]
fn test_auth_error_interpolation() {
    let var = 42;
    let err = auth_error!("interpolate {var}");
    assert_eq!("error: interpolate 42", err.to_string());
}

#[test]
fn test_result_helper_context() {
    let result: Result<(), AttError> = Err(AttError::Generic("original error".to_owned()));
    let err = result.context("additional context").unwrap_err();
    assert_eq!(
        "error: additional context: error: original error",
        err.to_string()
    );

    let var = "test";
    let result: Result<(), AttError> = Err(AttError::Generic("original error".to_owned()));
    let err = result.context(&format!("context with {var}")).unwrap_err();
    assert_eq!(
        "error: context with test: error: original error",
        err.to_string()
    );
}

#[test]
fn test_result_helper_with_context() {
    let result: Result<(), AttError> = Err(AttError::Generic("original error".to_owned()));
    let err = result
        .with_context(|| "dynamic context".to_string())
        .unwrap_err();
    assert_eq!(
        "error: dynamic context: error: original error",
        err.to_string()
    );
}

#[test]
fn test_option_helper_context() {
    let option: Option<i32> = None;
    let err = option.context("option was none").unwrap_err();
    assert_eq!("error: option was none", err.to_string());

    let var = "test";
    let option: Option<i32> = None;
    let err = option.context(&format!("context with {var}")).unwrap_err();
    assert_eq!("error: context with test", err.to_string());
}

#[test]
fn test_option_helper_with_context() {
    let option: Option<i32> = None;
    let err = option
        .with_context(|| "dynamic context".to_string())
        .unwrap_err();
    assert_eq!("error: dynamic context", err.to_string());
}

#[test]
fn test_option_helper_some_value() {
    let option: Option<i32> = Some(42);
    let value = option.context("should not be used").unwrap();
    assert_eq!(42, value);
}

#[test]
fn test_result_helper_ok_value() {
    let result: Result<i32, AttError> = Ok(42);
    let value = result.context("should not be used").unwrap();
    assert_eq!(42, value);
}

#[test]
fn test_auth_ensure_true_condition() {
    let result = ensure_true();
    assert!(result.is_ok());
}

fn ensure_true() -> Result<(), AttError> {
    auth_ensure!(true, "this should not trigger");
    Ok(())
}

#[test]
fn test_auth_bail_immediately_returns() {
    let result = bail_early();
    assert!(result.is_err());
    assert_eq!("error: bailed early", result.unwrap_err().to_string());
}

fn bail_early() -> Result<String, AttError> {
    auth_bail!("bailed early");
    #[expect(unreachable_code)]
    Ok("should not reach".to_string())
}
