use crate::log_specification::LogSpecification;
// use std::backtrace::Backtrace;
use thiserror::Error;

/// Describes errors in the initialization of `flexi_logger`.
#[derive(Error, Debug)]
pub enum FlexiLoggerError {
    /// Log file cannot be written because the specified path is not a directory.
    #[error("Log file cannot be written because the specified path is not a directory")]
    OutputBadDirectory,

    /// Spawning the cleanup thread failed.
    ///
    /// This error can safely be avoided with `Logger::cleanup_in_background_thread(false)`.
    #[error("Spawning the cleanup thread failed.")]
    OutputCleanupThread(std::io::Error),

    /// Log cannot be written, e.g. because the configured output directory is not accessible.
    #[error(
        "Log cannot be written, e.g. because the configured output directory is not accessible"
    )]
    OutputIo(#[from] std::io::Error),

    /// Filesystem notifications for the specfile could not be set up.
    #[error("Filesystem notifications for the specfile could not be set up")]
    #[cfg(feature = "specfile")]
    SpecfileNotify(#[from] notify::Error),

    /// Parsing the configured logspec toml-file failed.
    #[error("Parsing the configured logspec toml-file failed")]
    #[cfg(feature = "specfile_without_notification")]
    SpecfileToml(#[from] toml::de::Error),

    /// Specfile cannot be accessed or created.
    #[error("Specfile cannot be accessed or created")]
    #[cfg(feature = "specfile_without_notification")]
    SpecfileIo(std::io::Error),

    /// Specfile has an unsupported extension.
    #[error("Specfile has an unsupported extension")]
    #[cfg(feature = "specfile_without_notification")]
    SpecfileExtension(&'static str),

    /// Invalid level filter.
    #[error("Invalid level filter")]
    LevelFilter(String),

    /// Failed to parse log specification.
    #[error("Failed to parse log specification: {0}")]
    Parse(String, LogSpecification),

    /// Logger initialization failed.
    #[error("Logger initialization failed")]
    Log(#[from] log::SetLoggerError),

    /// Some synchronization object is poisoned.
    #[error("Some synchronization object is poisoned")]
    Poison,

    /// Palette parsing failed
    #[error("Palette parsing failed")]
    Palette(#[from] std::num::ParseIntError),
}
