use std::sync::Mutex;

use flexi_logger::writers::LogWriter;
use flexi_logger::{default_format, DeferredNow, LogTarget, Logger};
use log::*;

pub struct CustomWriter {
    data: Mutex<Vec<u8>>,
}

impl LogWriter for CustomWriter {
    fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
        let mut data = self.data.lock().unwrap();
        default_format(&mut *data, now, record)
    }

    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn max_log_level(&self) -> log::LevelFilter {
        log::LevelFilter::Trace
    }

    fn validate_logs(&self, expected: &[(&'static str, &'static str, &'static str)]) {
        let data = self.data.lock().unwrap();
        let expected_data =
            expected
                .iter()
                .fold(Vec::new(), |mut acc, (level, module, message)| {
                    acc.extend(format!("{} [{}] {}", level, module, message).bytes());
                    acc
                });
        assert_eq!(*data, expected_data);
    }
}

#[test]
fn test_custom_log_writer() {
    let handle = Logger::with_str("info")
        .log_target(LogTarget::Writer(Box::new(CustomWriter {
            data: Mutex::new(Vec::new()),
        })))
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message - you must not see it!");
    trace!("This is a trace message - you must not see it!");

    handle.validate_logs(&[
        (
            "ERROR",
            "test_custom_log_writer",
            "This is an error message",
        ),
        ("WARN", "test_custom_log_writer", "This is a warning"),
        ("INFO", "test_custom_log_writer", "This is an info message"),
    ]);
}
