use log::*;

#[test]
fn test_default_files_dir() {
    let handle = flexi_logger::Logger::with_str("info")
        .log_to_file()
        .directory("log_files")
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message - you must not see it!");
    trace!("This is a trace message - you must not see it!");
    handle.validate_logs(&[
        ("ERROR", "test_default_files_dir", "error"),
        ("WARN", "test_default_files_dir", "warning"),
        ("INFO", "test_default_files_dir", "info"),
    ]);
}
