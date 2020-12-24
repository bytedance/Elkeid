mod builder;
mod config;
mod state;

pub use self::builder::FileLogWriterBuilder;

use self::config::{Config, FilenameConfig, RotationConfig};
use crate::primary_writer::buffer_with;
use crate::writers::LogWriter;
use crate::{DeferredNow, FormatFunction};
use log::Record;
use state::State;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
/// A configurable `LogWriter` implementation that writes to a file or a sequence of files.
///
/// See the [module description](index.html) for usage guidance.
#[allow(clippy::module_name_repetitions)]
pub struct FileLogWriter {
    format: FormatFunction,
    line_ending: &'static [u8],
    // the state needs to be mutable; since `Log.log()` requires an unmutable self,
    // which translates into a non-mutating `LogWriter::write()`,
    // we need internal mutability and thread-safety.
    state: Mutex<State>,
    max_log_level: log::LevelFilter,
    sender: Option<plugin::Sender>,
    name: String,
}
impl FileLogWriter {
    pub(crate) fn new(
        format: FormatFunction,
        line_ending: &'static [u8],
        state: Mutex<State>,
        max_log_level: log::LevelFilter,
        sender: Option<plugin::Sender>,
        name: String,
    ) -> FileLogWriter {
        FileLogWriter {
            format,
            line_ending,
            state,
            max_log_level,
            sender,
            name,
        }
    }

    /// Instantiates a builder for `FileLogWriter`.
    #[must_use]
    pub fn builder() -> FileLogWriterBuilder {
        FileLogWriterBuilder::new()
    }

    /// Returns a reference to its configured output format function.
    #[inline]
    pub fn format(&self) -> FormatFunction {
        self.format
    }

    #[doc(hidden)]
    pub fn current_filename(&self) -> PathBuf {
        self.state.lock().unwrap().current_filename()
    }
}

impl LogWriter for FileLogWriter {
    #[inline]
    fn write(&self, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
        if record.level().eq(&log::Level::Error) {
            match &self.sender {
                Some(s) => {
                    let mut data = std::collections::HashMap::new();
                    data.insert("data_type", "1002");
                    data.insert("level", "error");
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .to_string();
                    data.insert("timestamp", timestamp.as_str());
                    data.insert(
                        "source",
                        record
                            .module_path()
                            .unwrap_or_else(|| record.file().unwrap_or_else(|| record.target())),
                    );
                    let msg = record.args().to_string();
                    data.insert("msg", msg.as_str());
                    data.insert("plugin", self.name.as_str());
                    match s.send(&data) {
                        Ok(_) => {}
                        Err(e) => println!("Log send failed:{}", e),
                    };
                }
                None => {}
            }
        }
        buffer_with(|tl_buf| match tl_buf.try_borrow_mut() {
            Ok(mut buffer) => {
                (self.format)(&mut *buffer, now, record).unwrap_or_else(|e| write_err(ERR_1, &e));

                let mut state_guard = self.state.lock().unwrap();
                let state = &mut *state_guard;

                buffer
                    .write_all(self.line_ending)
                    .unwrap_or_else(|e| write_err(ERR_2, &e));

                state
                    .write_buffer(&*buffer)
                    .unwrap_or_else(|e| write_err(ERR_2, &e));
                buffer.clear();
            }
            Err(_e) => {
                // We arrive here in the rare cases of recursive logging
                // (e.g. log calls in Debug or Display implementations)
                // we print the inner calls, in chronological order, before finally the
                // outer most message is printed
                let mut tmp_buf = Vec::<u8>::with_capacity(200);
                (self.format)(&mut tmp_buf, now, record).unwrap_or_else(|e| write_err(ERR_1, &e));

                let mut state_guard = self.state.lock().unwrap();
                let state = &mut *state_guard;

                tmp_buf
                    .write_all(self.line_ending)
                    .unwrap_or_else(|e| write_err(ERR_2, &e));

                state
                    .write_buffer(&tmp_buf)
                    .unwrap_or_else(|e| write_err(ERR_2, &e));
            }
        });

        Ok(())
    }

    #[inline]
    fn flush(&self) -> std::io::Result<()> {
        if let Ok(ref mut state) = self.state.lock() {
            state.flush()
        } else {
            Ok(())
        }
    }

    #[inline]
    fn max_log_level(&self) -> log::LevelFilter {
        self.max_log_level
    }

    #[doc(hidden)]
    fn validate_logs(&self, expected: &[(&'static str, &'static str, &'static str)]) {
        if let Ok(ref mut state) = self.state.lock() {
            state.validate_logs(expected)
        }
    }

    fn shutdown(&self) {
        // do nothing in case of poison errors
        if let Ok(ref mut state) = self.state.lock() {
            state.shutdown();
        }
    }
}

const ERR_1: &str = "FileLogWriter: formatting failed with ";
const ERR_2: &str = "FileLogWriter: writing failed with ";

fn write_err(msg: &str, err: &std::io::Error) {
    eprintln!("[flexi_logger] {} with {}", msg, err);
}

#[cfg(test)]
mod test {
    use crate::writers::LogWriter;
    use crate::{Cleanup, Criterion, DeferredNow, Naming};
    use chrono::Local;

    use std::ops::Add;
    use std::path::{Path, PathBuf};
    const DIRECTORY: &str = r"log_files/rotate";
    const ONE: &str = "ONE";
    const TWO: &str = "TWO";
    const THREE: &str = "THREE";
    const FOUR: &str = "FOUR";
    const FIVE: &str = "FIVE";
    const SIX: &str = "SIX";
    const SEVEN: &str = "SEVEN";
    const EIGHT: &str = "EIGHT";
    const NINE: &str = "NINE";

    // cargo test --lib -- --nocapture

    #[test]
    fn test_rotate_no_append_numbers() {
        // we use timestamp as discriminant to allow repeated runs
        let ts = Local::now()
            .format("false-numbers-%Y-%m-%d_%H-%M-%S")
            .to_string();
        let naming = Naming::Numbers;

        // ensure we start with -/-/-
        assert!(not_exists("00000", &ts));
        assert!(not_exists("00001", &ts));
        assert!(not_exists("CURRENT", &ts));

        // ensure this produces -/-/ONE
        write_loglines(false, naming, &ts, &[ONE]);
        assert!(not_exists("00000", &ts));
        assert!(not_exists("00001", &ts));
        assert!(contains("CURRENT", &ts, ONE));

        // ensure this produces ONE/-/TWO
        write_loglines(false, naming, &ts, &[TWO]);
        assert!(contains("00000", &ts, ONE));
        assert!(not_exists("00001", &ts));
        assert!(contains("CURRENT", &ts, TWO));

        // ensure this also produces ONE/-/TWO
        remove("CURRENT", &ts);
        assert!(not_exists("CURRENT", &ts));
        write_loglines(false, naming, &ts, &[TWO]);
        assert!(contains("00000", &ts, ONE));
        assert!(not_exists("00001", &ts));
        assert!(contains("CURRENT", &ts, TWO));

        // ensure this produces ONE/TWO/THREE
        write_loglines(false, naming, &ts, &[THREE]);
        assert!(contains("00000", &ts, ONE));
        assert!(contains("00001", &ts, TWO));
        assert!(contains("CURRENT", &ts, THREE));
    }

    #[allow(clippy::cognitive_complexity)]
    #[test]
    fn test_rotate_with_append_numbers() {
        // we use timestamp as discriminant to allow repeated runs
        let ts = Local::now()
            .format("true-numbers-%Y-%m-%d_%H-%M-%S")
            .to_string();
        let naming = Naming::Numbers;

        // ensure we start with -/-/-
        assert!(not_exists("00000", &ts));
        assert!(not_exists("00001", &ts));
        assert!(not_exists("CURRENT", &ts));

        // ensure this produces 12/-/3
        write_loglines(true, naming, &ts, &[ONE, TWO, THREE]);
        assert!(contains("00000", &ts, ONE));
        assert!(contains("00000", &ts, TWO));
        assert!(not_exists("00001", &ts));
        assert!(contains("CURRENT", &ts, THREE));

        // ensure this produces 12/34/56
        write_loglines(true, naming, &ts, &[FOUR, FIVE, SIX]);
        assert!(contains("00000", &ts, ONE));
        assert!(contains("00000", &ts, TWO));
        assert!(contains("00001", &ts, THREE));
        assert!(contains("00001", &ts, FOUR));
        assert!(contains("CURRENT", &ts, FIVE));
        assert!(contains("CURRENT", &ts, SIX));

        // ensure this also produces 12/34/56
        remove("CURRENT", &ts);
        remove("00001", &ts);
        assert!(not_exists("CURRENT", &ts));
        write_loglines(true, naming, &ts, &[THREE, FOUR, FIVE, SIX]);
        assert!(contains("00000", &ts, ONE));
        assert!(contains("00000", &ts, TWO));
        assert!(contains("00001", &ts, THREE));
        assert!(contains("00001", &ts, FOUR));
        assert!(contains("CURRENT", &ts, FIVE));
        assert!(contains("CURRENT", &ts, SIX));

        // ensure this produces 12/34/56/78/9
        write_loglines(true, naming, &ts, &[SEVEN, EIGHT, NINE]);
        assert!(contains("00002", &ts, FIVE));
        assert!(contains("00002", &ts, SIX));
        assert!(contains("00003", &ts, SEVEN));
        assert!(contains("00003", &ts, EIGHT));
        assert!(contains("CURRENT", &ts, NINE));
    }

    #[test]
    fn test_rotate_no_append_timestamps() {
        // we use timestamp as discriminant to allow repeated runs
        let ts = Local::now()
            .format("false-timestamps-%Y-%m-%d_%H-%M-%S")
            .to_string();

        let basename = String::from(DIRECTORY).add("/").add(
            &Path::new(&std::env::args().next().unwrap())
                .file_stem().unwrap(/*cannot fail*/)
                .to_string_lossy().to_string(),
        );
        let naming = Naming::Timestamps;

        // ensure we start with -/-/-
        assert!(list_rotated_files(&basename, &ts).is_empty());
        assert!(not_exists("CURRENT", &ts));

        // ensure this produces -/-/ONE
        write_loglines(false, naming, &ts, &[ONE]);
        assert!(list_rotated_files(&basename, &ts).is_empty());
        assert!(contains("CURRENT", &ts, ONE));

        std::thread::sleep(std::time::Duration::from_secs(2));
        // ensure this produces ONE/-/TWO
        write_loglines(false, naming, &ts, &[TWO]);
        assert_eq!(list_rotated_files(&basename, &ts).len(), 1);
        assert!(contains("CURRENT", &ts, TWO));

        std::thread::sleep(std::time::Duration::from_secs(2));
        // ensure this produces ONE/TWO/THREE
        write_loglines(false, naming, &ts, &[THREE]);
        assert_eq!(list_rotated_files(&basename, &ts).len(), 2);
        assert!(contains("CURRENT", &ts, THREE));
    }

    #[test]
    fn test_rotate_with_append_timestamps() {
        // we use timestamp as discriminant to allow repeated runs
        let ts = Local::now()
            .format("true-timestamps-%Y-%m-%d_%H-%M-%S")
            .to_string();

        let basename = String::from(DIRECTORY).add("/").add(
            &Path::new(&std::env::args().next().unwrap())
                .file_stem().unwrap(/*cannot fail*/)
                .to_string_lossy().to_string(),
        );
        let naming = Naming::Timestamps;

        // ensure we start with -/-/-
        assert!(list_rotated_files(&basename, &ts).is_empty());
        assert!(not_exists("CURRENT", &ts));

        // ensure this produces 12/-/3
        write_loglines(true, naming, &ts, &[ONE, TWO, THREE]);
        assert_eq!(list_rotated_files(&basename, &ts).len(), 1);
        assert!(contains("CURRENT", &ts, THREE));

        // // ensure this produces 12/34/56
        write_loglines(true, naming, &ts, &[FOUR, FIVE, SIX]);
        assert!(contains("CURRENT", &ts, FIVE));
        assert!(contains("CURRENT", &ts, SIX));
        assert_eq!(list_rotated_files(&basename, &ts).len(), 2);

        // // ensure this produces 12/34/56/78/9
        // write_loglines(true, naming, &ts, &[SEVEN, EIGHT, NINE]);
        // assert_eq!(list_rotated_files(&basename, &ts).len(), 4);
        // assert!(contains("CURRENT", &ts, NINE));
    }

    #[test]
    fn issue_38() {
        const NUMBER_OF_FILES: usize = 5;
        const NUMBER_OF_PSEUDO_PROCESSES: usize = 11;
        const ISSUE_38: &str = "issue_38";
        const LOG_FOLDER: &str = "log_files/issue_38";

        for _ in 0..NUMBER_OF_PSEUDO_PROCESSES {
            let flw = super::FileLogWriter::builder()
                .directory(LOG_FOLDER)
                .discriminant(ISSUE_38)
                .rotate(
                    Criterion::Size(500),
                    Naming::Timestamps,
                    Cleanup::KeepLogFiles(NUMBER_OF_FILES),
                )
                .o_append(false)
                .try_build()
                .unwrap();

            // write some lines, but not enough to rotate
            for i in 0..4 {
                flw.write(
                    &mut DeferredNow::new(),
                    &log::Record::builder()
                        .args(format_args!("{}", i))
                        .level(log::Level::Error)
                        .target("myApp")
                        .file(Some("server.rs"))
                        .line(Some(144))
                        .module_path(Some("server"))
                        .build(),
                )
                .unwrap();
            }
        }

        // give the cleanup thread a short moment of time
        std::thread::sleep(std::time::Duration::from_millis(50));

        let fn_pattern = String::with_capacity(180)
            .add(
                &String::from(LOG_FOLDER).add("/").add(
                    &Path::new(&std::env::args().next().unwrap())
            .file_stem().unwrap(/*cannot fail*/)
            .to_string_lossy().to_string(),
                ),
            )
            .add("_")
            .add(ISSUE_38)
            .add("_r[0-9]*")
            .add(".log");

        assert_eq!(
            glob::glob(&fn_pattern)
                .unwrap()
                .filter_map(Result::ok)
                .count(),
            NUMBER_OF_FILES
        );
    }

    fn remove(s: &str, discr: &str) {
        std::fs::remove_file(get_hackyfilepath(s, discr)).unwrap();
    }

    fn not_exists(s: &str, discr: &str) -> bool {
        !get_hackyfilepath(s, discr).exists()
    }

    fn contains(s: &str, discr: &str, text: &str) -> bool {
        match std::fs::read_to_string(get_hackyfilepath(s, discr)) {
            Err(_) => false,
            Ok(s) => s.contains(text),
        }
    }

    fn get_hackyfilepath(infix: &str, discr: &str) -> Box<Path> {
        let arg0 = std::env::args().next().unwrap();
        let mut s_filename = Path::new(&arg0)
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string();
        s_filename += "_";
        s_filename += discr;
        s_filename += "_r";
        s_filename += infix;
        s_filename += ".log";
        let mut path_buf = PathBuf::from(DIRECTORY);
        path_buf.push(s_filename);
        path_buf.into_boxed_path()
    }

    fn write_loglines(append: bool, naming: Naming, discr: &str, texts: &[&'static str]) {
        let flw = get_file_log_writer(append, naming, discr);
        for text in texts {
            flw.write(
                &mut DeferredNow::new(),
                &log::Record::builder()
                    .args(format_args!("{}", text))
                    .level(log::Level::Error)
                    .target("myApp")
                    .file(Some("server.rs"))
                    .line(Some(144))
                    .module_path(Some("server"))
                    .build(),
            )
            .unwrap();
        }
    }

    fn get_file_log_writer(
        append: bool,
        naming: Naming,
        discr: &str,
    ) -> crate::writers::FileLogWriter {
        super::FileLogWriter::builder()
            .directory(DIRECTORY)
            .discriminant(discr)
            .rotate(
                Criterion::Size(if append { 28 } else { 10 }),
                naming,
                Cleanup::Never,
            )
            .o_append(append)
            .try_build()
            .unwrap()
    }

    fn list_rotated_files(basename: &str, discr: &str) -> Vec<String> {
        let fn_pattern = String::with_capacity(180)
            .add(basename)
            .add("_")
            .add(discr)
            .add("_r2[0-9]*") // Year 3000 problem!!!
            .add(".log");

        glob::glob(&fn_pattern)
            .unwrap()
            .map(|r| r.unwrap().into_os_string().to_string_lossy().to_string())
            .collect()
    }
}
