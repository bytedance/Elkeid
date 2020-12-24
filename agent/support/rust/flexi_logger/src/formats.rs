use crate::DeferredNow;
use log::Record;
use std::thread;
#[cfg(feature = "colors")]
use yansi::{Color, Paint, Style};

/// Function type for Format functions.
///
/// If you want to write the log lines in your own format,
/// implement a function with this signature and provide it to one of the methods
/// [`Logger::format()`](struct.Logger.html#method.format),
/// [`Logger::format_for_files()`](struct.Logger.html#method.format_for_files),
/// or [`Logger::format_for_stderr()`](struct.Logger.html#method.format_for_stderr).
///
/// Checkout the code of the provided [format functions](index.html#functions)
/// if you want to start with a template.
///
/// ## Parameters
///
/// - `write`: the output stream
///
/// - `now`: the timestamp that you should use if you want a timestamp to appear in the log line
///
/// - `record`: the log line's content and metadata, as provided by the log crate's macros.
///
pub type FormatFunction = fn(
    write: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error>;

/// A logline-formatter that produces log lines like <br>
/// ```INFO [my_prog::some_submodule] Task successfully read from conf.json```
///
/// # Errors
///
/// See `std::write`
pub fn default_format(
    w: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(
        w,
        "{} [{}] {}",
        record.level(),
        record.module_path().unwrap_or("<unnamed>"),
        record.args()
    )
}

#[allow(clippy::doc_markdown)]
/// A colored version of the logline-formatter `default_format`
/// that produces log lines like <br>
/// <code><span style="color:red">ERROR</span> &#91;my_prog::some_submodule&#93; <span
/// style="color:red">File not found</span></code>
///
/// See method [style](fn.style.html) if you want to influence coloring.
///
/// Only available with feature `colors`.
///
/// # Errors
///
/// See `std::write`
#[cfg(feature = "colors")]
pub fn colored_default_format(
    w: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "{} [{}] {}",
        style(level, level),
        record.module_path().unwrap_or("<unnamed>"),
        style(level, record.args())
    )
}

/// A logline-formatter that produces log lines with timestamp and file location, like
/// <br>
/// ```[2016-01-13 15:25:01.640870 +01:00] INFO [src/foo/bar:26] Task successfully read from conf.json```
/// <br>
///
/// # Errors
///
/// See `std::write`
pub fn opt_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(
        w,
        "[{}] {} [{}:{}] {}",
        now.now().format("%Y-%m-%d %H:%M:%S%.6f %:z"),
        record.level(),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
        &record.args()
    )
}

/// A colored version of the logline-formatter `opt_format`.
///
/// See method [style](fn.style.html) if you want to influence coloring.
///
/// Only available with feature `colors`.
///
/// # Errors
///
/// See `std::write`
#[cfg(feature = "colors")]
pub fn colored_opt_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "[{}] {} [{}:{}] {}",
        style(level, now.now().format("%Y-%m-%d %H:%M:%S%.6f %:z")),
        style(level, level),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
        style(level, &record.args())
    )
}

/// A logline-formatter that produces log lines like
/// <br>
/// ```[2016-01-13 15:25:01.640870 +01:00] INFO [foo::bar] src/foo/bar.rs:26: Task successfully read from conf.json```
/// <br>
/// i.e. with timestamp, module path and file location.
///
/// # Errors
///
/// See `std::write`
pub fn detailed_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(
        w,
        "[{}] {} [{}] {}:{}: {}",
        now.now().format("%Y-%m-%d %H:%M:%S%.6f %:z"),
        record.level(),
        record.module_path().unwrap_or("<unnamed>"),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
        &record.args()
    )
}

/// A colored version of the logline-formatter `detailed_format`.
///
/// See method [style](fn.style.html) if you want to influence coloring.
///
/// Only available with feature `colors`.
///
/// # Errors
///
/// See `std::write`
#[cfg(feature = "colors")]
pub fn colored_detailed_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "[{}] {} [{}] {}:{}: {}",
        style(level, now.now().format("%Y-%m-%d %H:%M:%S%.6f %:z")),
        style(level, record.level()),
        record.module_path().unwrap_or("<unnamed>"),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
        style(level, &record.args())
    )
}

/// A logline-formatter that produces log lines like
/// <br>
/// ```[2016-01-13 15:25:01.640870 +01:00] T[taskreader] INFO [src/foo/bar:26] Task successfully read from conf.json```
/// <br>
/// i.e. with timestamp, thread name and file location.
///
/// # Errors
///
/// See `std::write`
pub fn with_thread(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(
        w,
        "[{}] T[{:?}] {} [{}:{}] {}",
        now.now().format("%Y-%m-%d %H:%M:%S%.6f %:z"),
        thread::current().name().unwrap_or("<unnamed>"),
        record.level(),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
        &record.args()
    )
}

/// A colored version of the logline-formatter `with_thread`.
///
/// See method [style](fn.style.html) if you want to influence coloring.
///
/// Only available with feature `colors`.
///
/// # Errors
///
/// See `std::write`
#[cfg(feature = "colors")]
pub fn colored_with_thread(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "[{}] T[{:?}] {} [{}:{}] {}",
        style(level, now.now().format("%Y-%m-%d %H:%M:%S%.6f %:z")),
        style(level, thread::current().name().unwrap_or("<unnamed>")),
        style(level, level),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
        style(level, &record.args())
    )
}

/// Helper function that is used in the provided coloring format functions to apply
/// colors based on the log level and the effective color palette.
///
/// See [`Logger::set_palette`](struct.Logger.html#method.set_palette) if you want to
/// modify the color palette.
///
/// Only available with feature `colors`.
#[cfg(feature = "colors")]
pub fn style<T>(level: log::Level, item: T) -> Paint<T> {
    let palette = &*(PALETTE.read().unwrap());
    match level {
        log::Level::Error => palette.error,
        log::Level::Warn => palette.warn,
        log::Level::Info => palette.info,
        log::Level::Debug => palette.debug,
        log::Level::Trace => palette.trace,
    }
    .paint(item)
}

#[cfg(feature = "colors")]
lazy_static::lazy_static! {
    static ref PALETTE: std::sync::RwLock<Palette> = std::sync::RwLock::new(Palette::default());
}

// Overwrites the default PALETTE value either from the environment, if set,
// or from the parameter, if filled.
// Returns an error if parsing failed.
#[cfg(feature = "colors")]
pub(crate) fn set_palette(input: &Option<String>) -> Result<(), std::num::ParseIntError> {
    match std::env::var_os("FLEXI_LOGGER_PALETTE") {
        Some(ref env_osstring) => {
            *(PALETTE.write().unwrap()) = Palette::from(env_osstring.to_string_lossy().as_ref())?;
        }
        None => match input {
            Some(ref input_string) => {
                *(PALETTE.write().unwrap()) = Palette::from(input_string)?;
            }
            None => {}
        },
    }
    Ok(())
}

#[cfg(feature = "colors")]
#[derive(Debug)]
struct Palette {
    pub error: Style,
    pub warn: Style,
    pub info: Style,
    pub debug: Style,
    pub trace: Style,
}
#[cfg(feature = "colors")]
impl Palette {
    fn default() -> Palette {
        Palette {
            error: Style::new(Color::Fixed(196)).bold(),
            warn: Style::new(Color::Fixed(208)).bold(),
            info: Style::new(Color::Unset),
            debug: Style::new(Color::Fixed(7)),
            trace: Style::new(Color::Fixed(8)),
        }
    }

    fn from(palette: &str) -> Result<Palette, std::num::ParseIntError> {
        let mut items = palette.split(';');
        Ok(Palette {
            error: parse_style(items.next().unwrap_or("196").trim())?,
            warn: parse_style(items.next().unwrap_or("208").trim())?,
            info: parse_style(items.next().unwrap_or("-").trim())?,
            debug: parse_style(items.next().unwrap_or("7").trim())?,
            trace: parse_style(items.next().unwrap_or("8").trim())?,
        })
    }
}

#[cfg(feature = "colors")]
fn parse_style(input: &str) -> Result<Style, std::num::ParseIntError> {
    Ok(if input == "-" {
        Style::new(Color::Unset)
    } else {
        Style::new(Color::Fixed(input.parse()?))
    })
}

/// Specifies the `FormatFunction` and decides if coloring should be used.
///
/// Is used in
/// [`Logger::adaptive_format_for_stderr`](struct.Logger.html#method.adaptive_format_for_stderr) and
/// [`Logger::adaptive_format_for_stdout`](struct.Logger.html#method.adaptive_format_for_stdout).
/// The coloring format functions are used if the output channel is a tty.
///
/// Only available with feature `atty`.
#[cfg(feature = "atty")]
#[derive(Clone, Copy)]
pub enum AdaptiveFormat {
    /// Chooses between [`default_format`](fn.default_format.html)
    /// and [`colored_default_format`](fn.colored_default_format.html).
    ///
    /// Only available with feature `colors`.
    #[cfg(feature = "colors")]
    Default,
    /// Chooses between [`detailed_format`](fn.detailed_format.html)
    /// and [`colored_detailed_format`](fn.colored_detailed_format.html).
    ///
    /// Only available with feature `colors`.
    #[cfg(feature = "colors")]
    Detailed,
    /// Chooses between [`opt_format`](fn.opt_format.html)
    /// and [`colored_opt_format`](fn.colored_opt_format.html).
    ///
    /// Only available with feature `colors`.
    #[cfg(feature = "colors")]
    Opt,
    /// Chooses between [`with_thread`](fn.with_thread.html)
    /// and [`colored_with_thread`](fn.colored_with_thread.html).
    ///
    /// Only available with feature `colors`.
    #[cfg(feature = "colors")]
    WithThread,
    /// Chooses between the first format function (which is supposed to be uncolored)
    /// and the second (which is supposed to be colored).
    ///
    /// Allows providing own format functions, with freely choosable coloring technique,
    /// _and_ making use of the tty detection.
    Custom(FormatFunction, FormatFunction),
}

#[cfg(feature = "atty")]
impl AdaptiveFormat {
    #[must_use]
    pub(crate) fn format_function(self, stream: Stream) -> FormatFunction {
        if stream.is_tty() {
            match self {
                #[cfg(feature = "colors")]
                Self::Default => colored_default_format,
                #[cfg(feature = "colors")]
                Self::Detailed => colored_detailed_format,
                #[cfg(feature = "colors")]
                Self::Opt => colored_opt_format,
                #[cfg(feature = "colors")]
                Self::WithThread => colored_with_thread,
                Self::Custom(_, colored) => colored,
            }
        } else {
            match self {
                #[cfg(feature = "colors")]
                Self::Default => default_format,
                #[cfg(feature = "colors")]
                Self::Detailed => detailed_format,
                #[cfg(feature = "colors")]
                Self::Opt => opt_format,
                #[cfg(feature = "colors")]
                Self::WithThread => with_thread,
                Self::Custom(uncolored, _) => uncolored,
            }
        }
    }
}

#[cfg(feature = "atty")]
#[derive(Clone, Copy)]
pub(crate) enum Stream {
    StdOut,
    StdErr,
}
#[cfg(feature = "atty")]
impl Stream {
    #[must_use]
    pub fn is_tty(self) -> bool {
        match self {
            Self::StdOut => atty::is(atty::Stream::Stdout),
            Self::StdErr => atty::is(atty::Stream::Stderr),
        }
    }
}
