use flexi_logger::writers::{FileLogWriter, LogWriter};
use flexi_logger::{detailed_format, LogTarget, Logger};
use log::*;

#[test]
fn test_default_file_and_writer() {
    let w = FileLogWriter::builder()
        .format(detailed_format)
        .discriminant("bar")
        .try_build()
        .unwrap();

    let handle = Logger::with_str("info")
        .log_target(LogTarget::FileAndWriter(Box::new(w)))
        .format(detailed_format)
        .discriminant("foo")
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message - you must not see it!");
    trace!("This is a trace message - you must not see it!");

    handle.validate_logs(&[
        ("ERROR", "test_default_file_and_writer", "error"),
        ("WARN", "test_default_file_and_writer", "warning"),
        ("INFO", "test_default_file_and_writer", "info"),
    ]);

    let w = FileLogWriter::builder()
        .format(detailed_format)
        .discriminant("bar")
        .append()
        .try_build()
        .unwrap();
    w.validate_logs(&[
        ("ERROR", "test_default_file_and_writer", "error"),
        ("WARN", "test_default_file_and_writer", "warning"),
        ("INFO", "test_default_file_and_writer", "info"),
    ]);
}
