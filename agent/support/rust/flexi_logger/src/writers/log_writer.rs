use crate::deferred_now::DeferredNow;
use crate::FormatFunction;
use log::Record;

/// Writes to a single log output stream.
///
/// Boxed instances of `LogWriter` can be used as additional log targets
/// (see [module description](index.html) for more details).
pub trait LogWriter: Sync + Send {
    /// Writes out a log line.
    ///
    /// # Errors
    ///
    /// `std::io::Error`
    fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()>;

    /// Flushes any buffered records.
    ///
    /// # Errors
    ///
    /// `std::io::Error`
    fn flush(&self) -> std::io::Result<()>;

    /// Provides the maximum log level that is to be written.
    fn max_log_level(&self) -> log::LevelFilter;

    /// Sets the format function.
    /// Defaults to ([`formats::default_format`](fn.default_format.html)),
    /// but can be changed with a call to
    /// [`Logger::format_for_writer`](struct.Logger.html#method.format_for_writer).
    ///
    /// The default implementation is a no-op.
    fn format(&mut self, format: FormatFunction) {
        let _ = format;
    }

    /// Cleanup open resources, if necessary.
    fn shutdown(&self) {}

    /// Takes a vec with three patterns per line that represent the log out,
    /// compares the written log with the expected lines,
    /// and asserts that both are in sync.
    ///
    /// This function is not meant for productive code, only for tests.
    #[doc(hidden)]
    fn validate_logs(&self, _expected: &[(&'static str, &'static str, &'static str)]) {
        unimplemented!("only useful for tests");
    }
}
