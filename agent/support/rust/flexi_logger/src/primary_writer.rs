use log::Record;
use std::cell::RefCell;
use std::io::Write;

use crate::deferred_now::DeferredNow;
use crate::logger::Duplicate;
use crate::writers::LogWriter;
use crate::FormatFunction;

// Writes either to stdout, or to stderr,
// or to a file (with optional duplication to stderr),
// or to nowhere (with optional "duplication" to stderr).
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrimaryWriter {
    StdOut(StdOutWriter),
    StdErr(StdErrWriter),
    Multi(MultiWriter),
}
impl PrimaryWriter {
    pub fn multi(
        duplicate_stderr: Duplicate,
        duplicate_stdout: Duplicate,
        format_for_stderr: FormatFunction,
        format_for_stdout: FormatFunction,
        writers: Vec<Box<dyn LogWriter>>,
    ) -> Self {
        Self::Multi(MultiWriter {
            duplicate_stderr,
            duplicate_stdout,
            format_for_stderr,
            format_for_stdout,
            writers,
        })
    }
    pub fn stderr(format: FormatFunction) -> Self {
        Self::StdErr(StdErrWriter::new(format))
    }

    pub fn stdout(format: FormatFunction) -> Self {
        Self::StdOut(StdOutWriter::new(format))
    }

    pub fn black_hole(
        duplicate_err: Duplicate,
        duplicate_out: Duplicate,
        format_for_stderr: FormatFunction,
        format_for_stdout: FormatFunction,
    ) -> Self {
        Self::multi(
            duplicate_err,
            duplicate_out,
            format_for_stderr,
            format_for_stdout,
            vec![],
        )
    }

    // Write out a log line.
    pub fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
        match *self {
            Self::StdErr(ref w) => w.write(now, record),
            Self::StdOut(ref w) => w.write(now, record),
            Self::Multi(ref w) => w.write(now, record),
        }
    }

    // Flush any buffered records.
    pub fn flush(&self) -> std::io::Result<()> {
        match *self {
            Self::StdErr(ref w) => w.flush(),
            Self::StdOut(ref w) => w.flush(),
            Self::Multi(ref w) => w.flush(),
        }
    }

    pub fn validate_logs(&self, expected: &[(&'static str, &'static str, &'static str)]) {
        if let Self::Multi(ref w) = *self {
            w.validate_logs(expected);
        }
    }
}

// `StdErrWriter` writes logs to stderr.
pub(crate) struct StdErrWriter {
    format: FormatFunction,
}

impl StdErrWriter {
    fn new(format: FormatFunction) -> Self {
        Self { format }
    }
    #[inline]
    fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
        write_buffered(self.format, now, record, &mut std::io::stderr())
    }

    #[inline]
    fn flush(&self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

// `StdOutWriter` writes logs to stdout.
pub(crate) struct StdOutWriter {
    format: FormatFunction,
}

impl StdOutWriter {
    fn new(format: FormatFunction) -> Self {
        Self { format }
    }
    #[inline]
    fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
        write_buffered(self.format, now, record, &mut std::io::stdout())
    }

    #[inline]
    fn flush(&self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

// The `MultiWriter` writes logs to stderr or to a set of `Writer`s, and in the latter case
// can duplicate messages to stderr.
pub(crate) struct MultiWriter {
    duplicate_stderr: Duplicate,
    duplicate_stdout: Duplicate,
    format_for_stderr: FormatFunction,
    format_for_stdout: FormatFunction,
    writers: Vec<Box<dyn LogWriter>>,
}

impl LogWriter for MultiWriter {
    fn validate_logs(&self, expected: &[(&'static str, &'static str, &'static str)]) {
        for writer in &self.writers {
            (*writer).validate_logs(expected);
        }
    }

    fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
        if match self.duplicate_stderr {
            Duplicate::Error => record.level() == log::Level::Error,
            Duplicate::Warn => record.level() <= log::Level::Warn,
            Duplicate::Info => record.level() <= log::Level::Info,
            Duplicate::Debug => record.level() <= log::Level::Debug,
            Duplicate::Trace | Duplicate::All => true,
            Duplicate::None => false,
        } {
            write_buffered(self.format_for_stderr, now, record, &mut std::io::stderr())?;
        }

        if match self.duplicate_stdout {
            Duplicate::Error => record.level() == log::Level::Error,
            Duplicate::Warn => record.level() <= log::Level::Warn,
            Duplicate::Info => record.level() <= log::Level::Info,
            Duplicate::Debug => record.level() <= log::Level::Debug,
            Duplicate::Trace | Duplicate::All => true,
            Duplicate::None => false,
        } {
            write_buffered(self.format_for_stdout, now, record, &mut std::io::stdout())?;
        }

        for writer in &self.writers {
            writer.write(now, record)?;
        }
        Ok(())
    }

    /// Provides the maximum log level that is to be written.
    fn max_log_level(&self) -> log::LevelFilter {
        self.writers
            .iter()
            .map(|w| w.max_log_level())
            .max()
            .unwrap()
    }

    fn flush(&self) -> std::io::Result<()> {
        for writer in &self.writers {
            writer.flush()?;
        }
        std::io::stderr().flush()
    }
    fn shutdown(&self) {
        for writer in &self.writers {
            writer.shutdown();
        }
    }
}

// Use a thread-local buffer for writing to stderr or stdout
fn write_buffered(
    format_function: FormatFunction,
    now: &mut DeferredNow,
    record: &Record,
    w: &mut dyn Write,
) -> Result<(), std::io::Error> {
    let mut result: Result<(), std::io::Error> = Ok(());

    buffer_with(|tl_buf| match tl_buf.try_borrow_mut() {
        Ok(mut buffer) => {
            (format_function)(&mut *buffer, now, record)
                .unwrap_or_else(|e| write_err(ERR_FORMATTING, &e));
            buffer
                .write_all(b"\n")
                .unwrap_or_else(|e| write_err(ERR_FORMATTING, &e));

            result = w.write_all(&*buffer).map_err(|e| {
                write_err(ERR_WRITING, &e);
                e
            });

            buffer.clear();
        }
        Err(_e) => {
            // We arrive here in the rare cases of recursive logging
            // (e.g. log calls in Debug or Display implementations)
            // we print the inner calls, in chronological order, before finally the
            // outer most message is printed
            let mut tmp_buf = Vec::<u8>::with_capacity(200);
            (format_function)(&mut tmp_buf, now, record)
                .unwrap_or_else(|e| write_err(ERR_FORMATTING, &e));
            tmp_buf
                .write_all(b"\n")
                .unwrap_or_else(|e| write_err(ERR_FORMATTING, &e));

            result = w.write_all(&tmp_buf).map_err(|e| {
                write_err(ERR_WRITING, &e);
                e
            });
        }
    });
    result
}

pub(crate) fn buffer_with<F>(f: F)
where
    F: FnOnce(&RefCell<Vec<u8>>),
{
    thread_local! {
        static BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(200));
    }
    BUFFER.with(f);
}

const ERR_FORMATTING: &str = "formatting failed with ";
const ERR_WRITING: &str = "writing failed with ";

fn write_err(msg: &str, err: &std::io::Error) {
    eprintln!("[flexi_logger] {} with {}", msg, err);
}
