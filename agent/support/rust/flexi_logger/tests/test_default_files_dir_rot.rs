use flexi_logger::*;
use log::*;
#[test]
fn test_default_files_dir_rot() {
    Logger::with_str("info")
        .log_target(LogTarget::File)
        .directory("log_files")
        .rotate(Criterion::Size(2000), Naming::Numbers, Cleanup::Never)
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message - you must not see it!");
    trace!("This is a trace message - you must not see it!");
}
