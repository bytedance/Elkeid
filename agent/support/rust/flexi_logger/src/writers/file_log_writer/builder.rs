use crate::flexi_error::FlexiLoggerError;
use crate::formats::default_format;
use crate::FormatFunction;
use crate::{Cleanup, Criterion, Naming};
use chrono::Local;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{Config, FileLogWriter, RotationConfig, State};

/// Builder for `FileLogWriter`.
#[allow(clippy::module_name_repetitions)]
pub struct FileLogWriterBuilder {
    discriminant: Option<String>,
    config: Config,
    format: FormatFunction,
    o_rotation_config: Option<RotationConfig>,
    max_log_level: log::LevelFilter,
    cleanup_in_background_thread: bool,
    sender: Option<plugin::Sender>,
    name: String,
}

/// Simple methods for influencing the behavior of the `FileLogWriter`.
impl FileLogWriterBuilder {
    pub(crate) fn new() -> FileLogWriterBuilder {
        FileLogWriterBuilder {
            name: String::from("default"),
            sender: None,
            discriminant: None,
            o_rotation_config: None,
            config: Config::default(),
            format: default_format,
            max_log_level: log::LevelFilter::Trace,
            cleanup_in_background_thread: true,
        }
    }
    /// Set name.
    #[must_use]
    pub fn name(mut self, name: String) -> Self {
        self.name = name;
        self
    }
    ///  Add a grpc sender.
    #[must_use]
    pub fn sender(mut self, sender: plugin::Sender) -> Self {
        self.sender = Some(sender);
        self
    }
    /// Makes the `FileLogWriter` print an info message to stdout
    /// when a new file is used for log-output.
    #[must_use]
    pub fn print_message(mut self) -> Self {
        self.config.print_message = true;
        self
    }

    /// Makes the `FileLogWriter` use the provided format function for the log entries,
    /// rather than the default ([`formats::default_format`](fn.default_format.html)).
    pub fn format(mut self, format: FormatFunction) -> Self {
        self.format = format;
        self
    }

    /// Specifies a folder for the log files.
    ///
    /// If the specified folder does not exist, the initialization will fail.
    /// By default, the log files are created in the folder where the program was started.
    pub fn directory<P: Into<PathBuf>>(mut self, directory: P) -> Self {
        self.config.filename_config.directory = directory.into();
        self
    }

    /// Specifies a suffix for the log files. The default is "log".
    pub fn suffix<S: Into<String>>(mut self, suffix: S) -> Self {
        self.config.filename_config.suffix = suffix.into();
        self
    }

    /// Makes the logger not include a timestamp into the names of the log files
    #[must_use]
    pub fn suppress_timestamp(mut self) -> Self {
        self.config.filename_config.use_timestamp = false;
        self
    }

    /// When rotation is used with some `Cleanup` variant, then this option defines
    /// if the cleanup activities (finding files, deleting files, evtl compressing files) is done
    /// in the current thread (in the current log-call), or whether cleanup is delegated to a
    /// background thread.
    ///
    /// As of `flexi_logger` version `0.14.7`,
    /// the cleanup activities are done by default in a background thread.
    /// This minimizes the blocking impact to your application caused by IO operations.
    ///
    /// In earlier versions of `flexi_logger`, or if you call this method with
    /// `use_background_thread = false`,
    /// the cleanup is done in the thread that is currently causing a file rotation.
    #[must_use]
    pub fn cleanup_in_background_thread(mut self, use_background_thread: bool) -> Self {
        self.cleanup_in_background_thread = use_background_thread;
        self
    }

    /// Use rotation to prevent indefinite growth of log files.
    ///
    /// By default, the log file is fixed while your program is running and will grow indefinitely.
    /// With this option being used, when the log file reaches the specified criterion,
    /// the file will be closed and a new file will be opened.
    ///
    /// Note that also the filename pattern changes:
    ///
    /// - by default, no timestamp is added to the filename
    /// - the logs are always written to a file with infix `_rCURRENT`
    /// - when the rotation criterion is fulfilled, it is closed and renamed to a file
    ///   with another infix (see `Naming`),
    ///   and then the logging continues again to the (fresh) file with infix `_rCURRENT`.
    ///
    /// Example:
    ///
    /// After some logging with your program `my_prog` and rotation with `Naming::Numbers`,
    /// you will find files like
    ///
    /// ```text
    /// my_prog_r00000.log
    /// my_prog_r00001.log
    /// my_prog_r00002.log
    /// my_prog_rCURRENT.log
    /// ```
    ///
    /// The cleanup parameter allows defining the strategy for dealing with older files.
    /// See [Cleanup](enum.Cleanup.html) for details.
    #[must_use]
    pub fn rotate(mut self, criterion: Criterion, naming: Naming, cleanup: Cleanup) -> Self {
        self.o_rotation_config = Some(RotationConfig {
            criterion,
            naming,
            cleanup,
        });
        self.config.filename_config.use_timestamp = false;
        self
    }

    /// Makes the logger append to the given file, if it exists; by default, the file would be
    /// truncated.
    #[must_use]
    pub fn append(mut self) -> Self {
        self.config.append = true;
        self
    }

    /// The specified String is added to the log file name.
    pub fn discriminant<S: Into<String>>(mut self, discriminant: S) -> Self {
        self.discriminant = Some(discriminant.into());
        self
    }

    /// The specified String will be used on linux systems to create in the current folder
    /// a symbolic link to the current log file.
    pub fn create_symlink<P: Into<PathBuf>>(mut self, symlink: P) -> Self {
        self.config.o_create_symlink = Some(symlink.into());
        self
    }

    /// Use Windows line endings, rather than just `\n`.
    #[must_use]
    pub fn use_windows_line_ending(mut self) -> Self {
        self.config.use_windows_line_ending = true;
        self
    }

    /// Produces the `FileLogWriter`.
    ///
    /// # Errors
    ///
    /// `FlexiLoggerError::Io`.
    pub fn try_build(mut self) -> Result<FileLogWriter, FlexiLoggerError> {
        // make sure the folder exists or create it
        let p_directory = Path::new(&self.config.filename_config.directory);
        std::fs::create_dir_all(&p_directory)?;
        if !std::fs::metadata(&p_directory)?.is_dir() {
            return Err(FlexiLoggerError::OutputBadDirectory);
        };

        let arg0 = env::args().next().unwrap_or_else(|| "rs".to_owned());
        self.config.filename_config.file_basename =
            Path::new(&arg0).file_stem().unwrap(/*cannot fail*/).to_string_lossy().to_string();

        if let Some(discriminant) = self.discriminant {
            self.config.filename_config.file_basename += &format!("_{}", discriminant);
        }
        if self.config.filename_config.use_timestamp {
            self.config.filename_config.file_basename +=
                &Local::now().format("_%Y-%m-%d_%H-%M-%S").to_string();
        };

        Ok(FileLogWriter::new(
            self.format,
            if self.config.use_windows_line_ending {
                b"\r\n"
            } else {
                b"\n"
            },
            Mutex::new(State::try_new(
                self.config,
                self.o_rotation_config,
                self.cleanup_in_background_thread,
            )?),
            self.max_log_level,
            self.sender,
            self.name,
        ))
    }
}

/// Alternative set of methods to control the behavior of the `FileLogWriterBuilder`.
/// Use these methods when you want to control the settings flexibly,
/// e.g. with commandline arguments via `docopts` or `clap`.
impl FileLogWriterBuilder {
    /// With true, makes the `FileLogWriterBuilder` print an info message to stdout, each time
    /// when a new file is used for log-output.
    #[must_use]
    pub fn o_print_message(mut self, print_message: bool) -> Self {
        self.config.print_message = print_message;
        self
    }

    /// Specifies a folder for the log files.
    ///
    /// If the specified folder does not exist, the initialization will fail.
    /// With None, the log files are created in the folder where the program was started.
    pub fn o_directory<P: Into<PathBuf>>(mut self, directory: Option<P>) -> Self {
        self.config.filename_config.directory =
            directory.map_or_else(|| PathBuf::from("."), Into::into);
        self
    }

    /// With true, makes the `FileLogWriterBuilder` include a timestamp into the names of the
    /// log files.
    #[must_use]
    pub fn o_timestamp(mut self, use_timestamp: bool) -> Self {
        self.config.filename_config.use_timestamp = use_timestamp;
        self
    }

    /// By default, and with None, the log file will grow indefinitely.
    /// If a `rotate_config` is set, when the log file reaches or exceeds the specified size,
    /// the file will be closed and a new file will be opened.
    /// Also the filename pattern changes: instead of the timestamp, a serial number
    /// is included into the filename.
    ///
    /// The size is given in bytes, e.g. `o_rotate_over_size(Some(1_000))` will rotate
    /// files once they reach a size of 1 kB.
    ///
    /// The cleanup strategy allows delimiting the used space on disk.
    #[must_use]
    pub fn o_rotate(mut self, rotate_config: Option<(Criterion, Naming, Cleanup)>) -> Self {
        if let Some((criterion, naming, cleanup)) = rotate_config {
            self.o_rotation_config = Some(RotationConfig {
                criterion,
                naming,
                cleanup,
            });
            self.config.filename_config.use_timestamp = false;
        } else {
            self.o_rotation_config = None;
            self.config.filename_config.use_timestamp = true;
        }
        self
    }

    /// If append is set to true, makes the logger append to the given file, if it exists.
    /// By default, or with false, the file would be truncated.
    #[must_use]
    pub fn o_append(mut self, append: bool) -> Self {
        self.config.append = append;
        self
    }

    /// The specified String is added to the log file name.
    pub fn o_discriminant<S: Into<String>>(mut self, discriminant: Option<S>) -> Self {
        self.discriminant = discriminant.map(Into::into);
        self
    }

    /// If a String is specified, it will be used on linux systems to create in the current folder
    /// a symbolic link with this name to the current log file.
    pub fn o_create_symlink<S: Into<PathBuf>>(mut self, symlink: Option<S>) -> Self {
        self.config.o_create_symlink = symlink.map(Into::into);
        self
    }
}
