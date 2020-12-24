//! Here are some examples for the `flexi_logger` initialization.
//!
//!
//! ## Write logs to stderr
//!
//! Expect the log specification in the environment variable `RUST_LOG`:
//!
//! ` Logger::`[`with_env()`](../struct.Logger.html#method.with_env)`.start()?;`
//!
//! (if `RUST_LOG` is not set, or if its value cannot be interpreted, nothing is logged)
//!
//! or provide the log spec programmatically:
//!
//! ` Logger::`[`with_str("info")`](../struct.Logger.html#method.with_str)`.start()?;`
//!
//! or combine both options:
//!
//! ` Logger::`[`with_env_or_str("info")`](../struct.Logger.html#method.with_env_or_str)`.start()?;`
//!
//! After that, you just use the log-macros from the log crate.
//!
//! ## Choose the log output channel
//!
//! By default, logs are written to `stderr`.
//! With [`Logger::log_target`](../struct.Logger.html#method.log_target)
//! you can send the logs to `stdout`, a file, an implementation of `LogWriter`,
//! or write them not at all.
//!
//! When writing to files, you sometimes want to have parts of the log still on the terminal;
//! this can be achieved with
//! [`Logger::duplicate_to_stderr`](../struct.Logger.html#method.duplicate_to_stderr) or
//! [`Logger::duplicate_to_stdout`](../struct.Logger.html#method.duplicate_to_stdout),
//! which duplicate log messages to the terminal.
//!
//! ```rust
//! # use flexi_logger::{LogTarget,Logger,Duplicate};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Logger::with_str("info")
//!    .log_target(LogTarget::File)              // write logs to file
//!    .duplicate_to_stderr(Duplicate::Warn)     // print warnings and errors also to the console
//!    .start()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Influence the location and name of the log file
//!
//! By default, the log files are created in the current directory (where the program was started).
//! With [`Logger:directory`](../struct.Logger.html#method.directory)
//! you can specify a concrete folder in which the files should be created.
//!
//! Using [`Logger::discriminant`](../struct.Logger.html#method.discriminant)
//! you can add a discriminating infix to the log file name.
//!
//! With [`Logger::suffix`](../struct.Logger.html#method.suffix)
//! you can change the suffix that is used for the log files.
//!
//! When writing to files, especially when they are in a distant folder, you may want to let the
//! user know where the log file is.
//!
//! [`Logger::print_message`](../struct.Logger.html#method.print_message)
//! prints an info to `stdout` to which file the log is written.
//!
//! `create_symlink(path)` creates (on unix-systems only) a symbolic link at the
//! specified path that points to the log file.
//!
//! ```rust
//! # use flexi_logger::Logger;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Logger::with_str("info")
//!    .log_to_file()                            // write logs to file
//!    .directory("traces")                      // create files in folder ./traces
//!    .discriminant("Sample4711A")              // use infix in log file name
//!    .suffix("trc")                            // use suffix .trc instead of .log
//!    .print_message()                          //
//!    .create_symlink("current_run")            // create a symbolic link to the current log file
//!    .start()?;
//! # Ok(())
//! # }
//! ```
//!
//! This example will print a message
//! "Log is written to `./traces/foo_Sample4711A_2020-11-17_19-24-35.trc`"
//! and, on unix, create a symbolic link called `current_run`.
//!
//! ## Specify the format for the log lines explicitly
//!
//! With [`Logger::format`](../struct.Logger.html#method.format)
//! you set the format for all used output channels of `flexi_logger`.
//!
//! `flexi_logger` provides a couple of format functions, and you can also create and use your own,
//! e.g. by copying and modifying one of the provided format functions.
//!
//! Depending on the configuration, `flexi_logger` can write logs to multiple channels
//! (stdout, stderr, files, or additional writers)
//! at the same time. You can control the format for each output channel individually, using
//! [`Logger::format_for_files`](../struct.Logger.html#method.format_for_files),
//! [`Logger::format_for_stderr`](../struct.Logger.html#method.format_for_stderr),
//! [`Logger::format_for_stdout`](../struct.Logger.html#method.format_for_stdout), or
//! [`Logger::format_for_writer`](../struct.Logger.html#method.format_for_writer).
//!
//!  As argument for these functions you can use one of the provided non-coloring format functions
//!
//!  - [`default_format`](../fn.default_format.html)
//!  - [`detailed_format`](../fn.detailed_format.html)
//!  - [`opt_format`](../fn.opt_format.html)
//!  - [`with_thread`](../fn.with_thread.html),
//!
//! or one of their coloring pendants
//!
//!  - [`colored_default_format`](../fn.colored_default_format.html)
//!  - [`colored_detailed_format`](../fn.colored_detailed_format.html)
//!  - [`colored_opt_format`](../fn.colored_opt_format.html).
//!  - [`colored_with_thread`](../fn.colored_with_thread.html).
//!
//! ### Adaptive Coloring
//!
//! You can use coloring for `stdout` and/or `stderr`
//! conditionally, such that colors are used when the output goes to a tty,
//! and suppressed if you e.g. pipe the output to some other program.
//! With
//! [`Logger::adaptive_format_for_stderr`](../struct.Logger.html#method.adaptive_format_for_stderr) or
//! [`Logger::adaptive_format_for_stdout`](../struct.Logger.html#method.adaptive_format_for_stdout)
//! you can specify one of the provided format pairs
//! (which are based on the format functions listed above),
//! or you can provide your own colored and non-colored format functions.
//!
//! ### Defaults
//!
//! `flexi_logger` initializes by default equivalently to this:
//!
//! ```rust,ignore
//! # use flexi_logger::{Logger,AdaptiveFormat,default_format};
//! # use log::{debug, error, info, trace, warn};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # Logger::with_str("info")      // Write all error, warn, and info messages
//! #   .directory(std::env::temp_dir())
//!     .adaptive_format_for_stderr(AdaptiveFormat::Default)
//!     .adaptive_format_for_stdout(AdaptiveFormat::Default)
//!     .format_for_files(default_format)
//!     .format_for_writer(default_format)
//! #    .start()?;
//! # error!("This is an error message");
//! # warn!("This is a warning");
//! # info!("This is an info message");
//! # debug!("This is a debug message - you must not see it!");
//! # trace!("This is a trace message - you must not see it!");
//! #  run()
//! # }
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {Ok(())}
//! ```
//!
//! ## Use a fixed log file, and truncate or append the file on each program start
//!
//! With [`Logger::log_to_file`](../struct.Logger.html#method.log_to_file) and without rotation,
//! `flexi_logger` uses by default files with a timestamp in the name, like
//! `foo_2020-11-16_08-37-44.log` (for a program called `foo`), which are quite unique for each
//! program start.
//!
//! With [`Logger::suppress_timestamp`](../struct.Logger.html#method.suppress_timestamp)
//! you get a simple fixed filename, like `foo.log`.
//!
//! In that case, a restart of the program will truncate an existing log file.
//!
//! Use additionally [`Logger::append`](../struct.Logger.html#method.append)
//! to append the logs of each new run to the existing file.
//!
//! ```rust
//! # use flexi_logger::Logger;
//! # use log::{debug, error, info, trace, warn};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Logger::with_str("info")      // Write all error, warn, and info messages
//! #   .directory(std::env::temp_dir())
//!     .log_to_file()            // Write the log to a file
//!     .suppress_timestamp()     // use a simple filename without a timestamp
//!     .append()                 // do not truncate the log file when the program is restarted
//!     .start()?;
//!
//! # error!("This is an error message");
//! # warn!("This is a warning");
//! # info!("This is an info message");
//! # debug!("This is a debug message - you must not see it!");
//! # trace!("This is a trace message - you must not see it!");
//! #  run()
//! # }
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {Ok(())}
//! ```
//!
//! ## Rotate the log file
//!
//! With rotation, the logs are always written to a file
//! with the infix `rCURRENT`, like e.g. `foo_rCURRENT.log`.
//!
//! [`Logger::rotation`](../struct.Logger.html#method.rotation)
//! takes three enum arguments to define its behavior:
//!
//! - [`Criterion`](../enum.Criterion.html)
//!    - with `Criterion::Age` the rotation happens
//!      when the clock switches to a new day, hour, minute, or second
//!    - with `Criterion::Size` the rotation happens when the current log file exceeds
//!      the specified limit
//!    - with `Criterion::AgeOrSize` the rotation happens when either of the two limits is reached
//!
//! - [`Naming`](../enum.Naming.html)<br>The current file is then renamed
//!   - with `Naming::Timestamps` to something like `foo_r2020-11-16_08-56-52.log`
//!   - with `Naming::Numbers` to something like `foo_r00000.log`
//!
//!   and a fresh `rCURRENT` file is created.
//!
//! - [`Cleanup`](../enum.Cleanup.html) defines if and how you
//!   avoid accumulating log files indefinitely:
//!   - with `Cleanup::KeepLogFiles` you specify the number of log files that should be retained;
//!     if there are more, the older ones are getting deleted
//!   - with `Cleanup::KeepCompressedFiles` you specify the number of log files that should be
//!     retained, and these are being compressed additionally
//!   - with `Cleanup::KeepLogAndCompressedFiles` you specify the number of log files that should be
//!     retained as is, and an additional number that are being compressed
//!   - with `Cleanup::Never` no cleanup is done, all files are retained.
//!
//! ```rust
//! # use flexi_logger::{Age, Cleanup, Criterion, Logger, Naming};
//! # use log::{debug, error, info, trace, warn};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Logger::with_str("info")          // Write all error, warn, and info messages
//! #   .directory(std::env::temp_dir())
//!     .log_to_file()                // Write the log to a file
//!     .rotate(                      // If the program runs long enough,
//!         Criterion::Age(Age::Day), // - create a new file every day
//!         Naming::Timestamps,       // - let the rotated files have a timestamp in their name
//!         Cleanup::KeepLogFiles(7), // - keep at most 7 log files
//!     )
//!     .start()?;
//!
//! #   error!("This is an error message");
//! #   warn!("This is a warning");
//! #   info!("This is an info message");
//! #   debug!("This is a debug message - you must not see it!");
//! #   trace!("This is a trace message - you must not see it!");
//! #    run()
//! # }
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {Ok(())}
//! ```
//!
//! ## Reconfigure the log specification programmatically
//!
//! This can be especially handy in debugging situations where you want to see
//! traces only for a short instant.
//!
//! Obtain the `ReconfigurationHandle`
//!
//! ```rust
//! # use flexi_logger::Logger;
//! let mut log_handle = Logger::with_str("info")
//!     // ... logger configuration ...
//!     .start()
//!     .unwrap();
//! ```
//!
//! and modify the effective log specification from within your code:
//!
//! ```rust, ignore
//! // ...
//! log_handle.parse_and_push_temp_spec("info, critical_mod = trace");
//! // ... critical calls ...
//! log_handle.pop_temp_spec();
//! // ... continue with the log spec you had before.
//! ```
//!
//! ## Reconfigure the log specification dynamically by editing a spec-file
//!
//! If you start `flexi_logger` with a specfile,
//!
//! ```rust,ignore
//! # use flexi_logger::Logger;
//! Logger::with_str("info")
//!     // ... logger configuration ...
//!    .start_with_specfile("/server/config/logspec.toml")
//!    .unwrap();
//! ```
//!
//! then you can change the log specification dynamically, *while your program is running*,
//! by editing the specfile. This can be a great help e.g. if you want to get detailed traces
//! for _some_ requests to a long running server.
//!
//! See [`Logger::start_with_specfile`](../struct.Logger.html#method.start_with_specfile)
//! for more information.
//!
//! ## Miscellaneous
//!
//! For the sake of completeness, we refer here to some more configuration methods.
//! See their documentation for more details.
//!
//! [`Logger::check_parser_error`](../struct.Logger.html#method.check_parser_error)
//!
//! [`Logger::set_palette`](../struct.Logger.html#method.set_palette)
//!
//! [`Logger::cleanup_in_background_thread`](../struct.Logger.html#method.cleanup_in_background_thread)
//!
//! [`Logger::use_windows_line_ending`](../struct.Logger.html#method.use_windows_line_ending)
//!
//! [`Logger::add_writer`](../struct.Logger.html#method.add_writer)
