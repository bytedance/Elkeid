use flexi_logger::{Logger, ReconfigurationHandle};
use log::*;

#[test]
fn test_reconfigure_methods() {
    let mut log_handle = Logger::with_str("info")
        .log_to_file()
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    test_parse_new_spec(&mut log_handle);
    test_push_new_spec(&mut log_handle);
    validate_logs(&mut log_handle);
}

fn test_parse_new_spec(log_handle: &mut ReconfigurationHandle) {
    error!("1-error message");
    warn!("1-warning");
    info!("1-info message");
    debug!("1-debug message - you must not see it!");
    trace!("1-trace message - you must not see it!");

    log_handle.parse_new_spec("error");
    error!("1-error message");
    warn!("1-warning - you must not see it!");
    info!("1-info message - you must not see it!");
    debug!("1-debug message - you must not see it!");
    trace!("1-trace message - you must not see it!");

    log_handle.parse_new_spec("trace");
    error!("1-error message");
    warn!("1-warning");
    info!("1-info message");
    debug!("1-debug message");
    trace!("1-trace message");

    log_handle.parse_new_spec("info");
}

#[allow(clippy::cognitive_complexity)]
fn test_push_new_spec(log_handle: &mut ReconfigurationHandle) {
    error!("2-error message");
    warn!("2-warning");
    info!("2-info message");
    debug!("2-debug message - you must not see it!");
    trace!("2-trace message - you must not see it!");

    log_handle.parse_and_push_temp_spec("error");
    error!("2-error message");
    warn!("2-warning - you must not see it!");
    info!("2-info message - you must not see it!");
    debug!("2-debug message - you must not see it!");
    trace!("2-trace message - you must not see it!");

    log_handle.parse_and_push_temp_spec("trace");
    error!("2-error message");
    warn!("2-warning");
    info!("2-info message");
    debug!("2-debug message");
    trace!("2-trace message");

    log_handle.pop_temp_spec(); // we should be back on error
    error!("2-error message");
    warn!("2-warning - you must not see it!");
    info!("2-info message - you must not see it!");
    debug!("2-debug message - you must not see it!");
    trace!("2-trace message - you must not see it!");

    log_handle.pop_temp_spec(); // we should be back on info

    error!("2-error message");
    warn!("2-warning");
    info!("2-info message");
    debug!("2-debug message - you must not see it!");
    trace!("2-trace message - you must not see it!");

    log_handle.pop_temp_spec(); // should be a no-op
}

#[allow(clippy::cognitive_complexity)]
fn validate_logs(log_handle: &mut ReconfigurationHandle) {
    log_handle.validate_logs(&[
        ("ERROR", "test_reconfigure_methods", "1-error"),
        ("WARN", "test_reconfigure_methods", "1-warning"),
        ("INFO", "test_reconfigure_methods", "1-info"),
        //
        ("ERROR", "test_reconfigure_methods", "1-error"),
        //
        ("ERROR", "test_reconfigure_methods", "1-error"),
        ("WARN", "test_reconfigure_methods", "1-warning"),
        ("INFO", "test_reconfigure_methods", "1-info"),
        ("DEBUG", "test_reconfigure_methods", "1-debug"),
        ("TRACE", "test_reconfigure_methods", "1-trace"),
        // -----
        ("ERROR", "test_reconfigure_methods", "2-error"),
        ("WARN", "test_reconfigure_methods", "2-warning"),
        ("INFO", "test_reconfigure_methods", "2-info"),
        //
        ("ERROR", "test_reconfigure_methods", "2-error"),
        //
        ("ERROR", "test_reconfigure_methods", "2-error"),
        ("WARN", "test_reconfigure_methods", "2-warning"),
        ("INFO", "test_reconfigure_methods", "2-info"),
        ("DEBUG", "test_reconfigure_methods", "2-debug"),
        ("TRACE", "test_reconfigure_methods", "2-trace"),
        //
        ("ERROR", "test_reconfigure_methods", "2-error"),
        //
        ("ERROR", "test_reconfigure_methods", "2-error"),
        ("WARN", "test_reconfigure_methods", "2-warning"),
        ("INFO", "test_reconfigure_methods", "2-info"),
    ]);
}
