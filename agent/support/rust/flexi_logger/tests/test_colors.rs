use flexi_logger::{LogTarget, Logger};
use log::*;

#[test]
fn test_mods() {
    Logger::with_str("trace")
        .log_target(LogTarget::StdOut)
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message");
    trace!("This is a trace message");
}
