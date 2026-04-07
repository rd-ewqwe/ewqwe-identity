use ewqwe_logging::{TracingConfig, tracing_init};

pub fn log_test(rust_log: Option<&str>) {
    let config = TracingConfig {
        service_name: String::new(),
        no_log_to_stdout: false,
        log_to_file: None,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: false,
        rust_log: rust_log
            .or(option_env!("RUST_LOG"))
            .map(std::borrow::ToOwned::to_owned),
        with_ansi_colors: true,
        otlp: None,
    };
    tracing_init(&config);
}
