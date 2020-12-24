use flexi_logger::{detailed_format, Logger, ReconfigurationHandle};
use log::*;

#[test]
fn test_mods() {
    let handle: ReconfigurationHandle = Logger::with_env_or_str(
        "info, test_windows_line_ending::mymod1=debug, test_windows_line_ending::mymod2=error",
    )
    .format(detailed_format)
    .log_to_file()
    .use_windows_line_ending()
    .start()
    .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message - you must not see it!");
    trace!("This is a trace message - you must not see it!");

    mymod1::test_traces();
    mymod2::test_traces();

    handle.validate_logs(&[
        ("ERROR", "test_windows_line_ending", "error"),
        ("WARN", "test_windows_line_ending", "warning"),
        ("INFO", "test_windows_line_ending", "info"),
        ("ERROR", "test_windows_line_ending", "error"),
        ("WARN", "test_windows_line_ending", "warning"),
        ("INFO", "test_windows_line_ending", "info"),
        ("DEBUG", "test_windows_line_ending", "debug"),
        ("ERROR", "test_windows_line_ending", "error"),
    ]);
}

mod mymod1 {
    use log::*;
    pub fn test_traces() {
        error!("This is an error message");
        warn!("This is a warning");
        info!("This is an info message");
        debug!("This is a debug message");
        trace!("This is a trace message - you must not see it!");
    }
}
mod mymod2 {
    use log::*;
    pub fn test_traces() {
        error!("This is an error message");
        warn!("This is a warning - you must not see it!");
        info!("This is an info message - you must not see it!");
        debug!("This is a debug message - you must not see it!");
        trace!("This is a trace message - you must not see it!");
    }
}
