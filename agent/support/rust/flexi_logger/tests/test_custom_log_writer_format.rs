use std::sync::Mutex;

use flexi_logger::writers::LogWriter;
use flexi_logger::{default_format, DeferredNow, FormatFunction, LogTarget, Logger};
use log::*;

pub struct CustomWriter {
    data: Mutex<Vec<u8>>,
    format: FormatFunction,
}

impl LogWriter for CustomWriter {
    fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
        let mut data = self.data.lock().unwrap();
        (self.format)(&mut *data, now, record)
    }

    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn format(&mut self, format: FormatFunction) {
        self.format = format;
    }

    fn max_log_level(&self) -> log::LevelFilter {
        log::LevelFilter::Trace
    }

    fn validate_logs(&self, expected: &[(&'static str, &'static str, &'static str)]) {
        let data = self.data.lock().unwrap();
        let expected_data =
            expected
                .iter()
                .fold(Vec::new(), |mut acc, (level, _module, message)| {
                    acc.extend(format!("{}: {}", level, message).bytes());
                    acc
                });
        assert_eq!(*data, expected_data);
    }
}

fn custom_format(
    writer: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    // Only write the message and the level, without the module
    write!(writer, "{}: {}", record.level(), &record.args())
}

#[test]
fn test_custom_log_writer_custom_format() {
    let handle = Logger::with_str("info")
        .log_target(LogTarget::Writer(Box::new(CustomWriter {
            data: Mutex::new(Vec::new()),
            format: default_format,
        })))
        .format(custom_format)
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
