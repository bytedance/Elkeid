use crate::flexi_error::FlexiLoggerError;
use crate::LevelFilter;

#[cfg(feature = "textfilter")]
use regex::Regex;
use std::collections::HashMap;
use std::env;

///
/// Immutable struct that defines which loglines are to be written,
/// based on the module, the log level, and the text.
///
/// The loglevel specification via string (relevant for methods
/// [parse()](struct.LogSpecification.html#method.parse) and
/// [env()](struct.LogSpecification.html#method.env))
/// works essentially like with `env_logger`,
/// but we are a bit more tolerant with spaces. Its functionality can be
/// described with some Backus-Naur-form:
///
/// ```text
/// <log_level_spec> ::= single_log_level_spec[{,single_log_level_spec}][/<text_filter>]
/// <single_log_level_spec> ::= <path_to_module>|<log_level>|<path_to_module>=<log_level>
/// <text_filter> ::= <regex>
/// ```
///
/// * Examples:
///
///   * `"info"`: all logs with info, warn, or error level are written
///   * `"crate1"`: all logs of this crate are written, but nothing else
///   * `"warn, crate2::mod_a=debug, mod_x::mod_y=trace"`: all crates log warnings and errors,
///     `mod_a` additionally debug messages, and `mod_x::mod_y` is fully traced
///
/// * If you just specify the module, without `log_level`, all levels will be traced for this
///   module.
/// * If you just specify a log level, this will be applied as default to all modules without
///   explicit log level assigment.
///   (You see that for modules named error, warn, info, debug or trace,
///   it is necessary to specify their loglevel explicitly).
/// * The module names are compared as Strings, with the side effect that a specified module filter
///   affects all modules whose name starts with this String.<br>
///   Example: ```"foo"``` affects e.g.
///
///   * `foo`
///   * `foo::bar`
///   * `foobaz` (!)
///   * `foobaz::bar` (!)
///
/// The optional text filter is applied for all modules.
///
/// Note that external module names are to be specified like in ```"extern crate ..."```, i.e.,
/// for crates with a dash in their name this means: the dash is to be replaced with
/// the underscore (e.g. ```karl_heinz```, not ```karl-heinz```).
/// See
/// [https://github.com/rust-lang/rfcs/pull/940/files](https://github.com/rust-lang/rfcs/pull/940/files)
/// for an explanation of the different naming conventions in Cargo (packages allow hyphen) and
/// rustc (“extern crate” does not allow hyphens).
#[derive(Clone, Debug, Default)]
pub struct LogSpecification {
    module_filters: Vec<ModuleFilter>,
    #[cfg(feature = "textfilter")]
    textfilter: Option<Regex>,
}

/// Defines which loglevel filter to use for the specified module.
///
/// A `ModuleFilter`, whose `module_name` is not set, describes the default loglevel filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleFilter {
    /// The module name.
    pub module_name: Option<String>,
    /// The level filter.
    pub level_filter: LevelFilter,
}

impl LogSpecification {
    pub(crate) fn update_from(&mut self, other: Self) {
        self.module_filters = other.module_filters;

        #[cfg(feature = "textfilter")]
        {
            self.textfilter = other.textfilter;
        }
    }

    pub(crate) fn max_level(&self) -> log::LevelFilter {
        self.module_filters
            .iter()
            .map(|d| d.level_filter)
            .max()
            .unwrap_or(log::LevelFilter::Off)
    }

    /// Returns true if messages on the specified level from the writing module should be written
    pub fn enabled(&self, level: log::Level, writing_module: &str) -> bool {
        // Search for the longest match, the vector is assumed to be pre-sorted.
        for module_filter in &self.module_filters {
            match module_filter.module_name {
                Some(ref module_name) => {
                    if writing_module.starts_with(module_name) {
                        return level <= module_filter.level_filter;
                    }
                }
                None => return level <= module_filter.level_filter,
            }
        }
        false
    }

    /// Returns a `LogSpecification` where all traces are switched off.
    #[must_use]
    pub fn off() -> Self {
        #[allow(clippy::default_trait_access)]
        Default::default()
    }

    /// Returns a log specification from a String.
    ///
    /// # Errors
    ///
    /// `FlexiLoggerError::Parse` if the input is malformed.
    pub fn parse(spec: &str) -> Result<Self, FlexiLoggerError> {
        let mut parse_errs = String::new();
        let mut dirs = Vec::<ModuleFilter>::new();

        let mut parts = spec.split('/');
        let mods = parts.next();
        #[cfg(feature = "textfilter")]
        let filter = parts.next();
        if parts.next().is_some() {
            push_err(
                &format!("invalid log spec '{}' (too many '/'s), ignoring it", spec),
                &mut parse_errs,
            );
            return parse_err(parse_errs, Self::off());
        }
        if let Some(m) = mods {
            for s in m.split(',') {
                let s = s.trim();
                if s.is_empty() {
                    continue;
                }
                let mut parts = s.split('=');
                let (log_level, name) = match (
                    parts.next().map(str::trim),
                    parts.next().map(str::trim),
                    parts.next(),
                ) {
                    (Some(part_0), None, None) => {
                        if contains_whitespace(part_0, &mut parse_errs) {
                            continue;
                        }
                        // if the single argument is a log-level string or number,
                        // treat that as a global fallback setting
                        match parse_level_filter(part_0.trim()) {
                            Ok(num) => (num, None),
                            Err(_) => (LevelFilter::max(), Some(part_0)),
                        }
                    }

                    (Some(part_0), Some(""), None) => {
                        if contains_whitespace(part_0, &mut parse_errs) {
                            continue;
                        }
                        (LevelFilter::max(), Some(part_0))
                    }

                    (Some(part_0), Some(part_1), None) => {
                        if contains_whitespace(part_0, &mut parse_errs) {
                            continue;
                        }
                        match parse_level_filter(part_1.trim()) {
                            Ok(num) => (num, Some(part_0.trim())),
                            Err(e) => {
                                push_err(&e.to_string(), &mut parse_errs);
                                continue;
                            }
                        }
                    }
                    _ => {
                        push_err(
                            &format!("invalid part in log spec '{}', ignoring it", s),
                            &mut parse_errs,
                        );
                        continue;
                    }
                };
                dirs.push(ModuleFilter {
                    module_name: name.map(ToString::to_string),
                    level_filter: log_level,
                });
            }
        }

        #[cfg(feature = "textfilter")]
        let textfilter = filter.and_then(|filter| match Regex::new(filter) {
            Ok(re) => Some(re),
            Err(e) => {
                push_err(&format!("invalid regex filter - {}", e), &mut parse_errs);
                None
            }
        });

        let logspec = Self {
            module_filters: dirs.level_sort(),
            #[cfg(feature = "textfilter")]
            textfilter,
        };

        if parse_errs.is_empty() {
            Ok(logspec)
        } else {
            parse_err(parse_errs, logspec)
        }
    }

    /// Returns a log specification based on the value of the environment variable `RUST_LOG`,
    /// or an empty one.
    ///
    /// # Errors
    ///
    /// `FlexiLoggerError::Parse` if the input is malformed.
    pub fn env() -> Result<Self, FlexiLoggerError> {
        match env::var("RUST_LOG") {
            Ok(spec) => Self::parse(&spec),
            Err(..) => Ok(Self::off()),
        }
    }

    /// Returns a log specification based on the value of the environment variable `RUST_LOG`,
    /// if it exists and can be parsed, or on the given String.
    ///
    /// # Errors
    ///
    /// `FlexiLoggerError::Parse` if the given spec is malformed.
    pub fn env_or_parse<S: AsRef<str>>(given_spec: S) -> Result<Self, FlexiLoggerError> {
        env::var("RUST_LOG")
            .map_err(|_e| FlexiLoggerError::Poison /*wrong, but only dummy*/)
            .and_then(|value| Self::parse(&value))
            .or_else(|_| Self::parse(given_spec.as_ref()))
    }

    /// Reads a log specification from an appropriate toml document.
    ///
    /// This method is only avaible with feature `specfile`.
    ///
    /// # Errors
    ///
    /// `FlexiLoggerError::Parse` if the input is malformed.
    #[cfg(feature = "specfile_without_notification")]
    pub fn from_toml(s: &str) -> Result<Self, FlexiLoggerError> {
        #[derive(Clone, Debug, serde_derive::Deserialize)]
        struct LogSpecFileFormat {
            pub global_level: Option<String>,
            pub global_pattern: Option<String>,
            pub modules: Option<std::collections::BTreeMap<String, String>>,
        }

        let logspec_ff: LogSpecFileFormat = toml::from_str(s)?;
        let mut parse_errs = String::new();
        let mut module_filters = Vec::<ModuleFilter>::new();

        if let Some(s) = logspec_ff.global_level {
            module_filters.push(ModuleFilter {
                module_name: None,
                level_filter: parse_level_filter(s)?,
            });
        }

        for (k, v) in logspec_ff.modules.unwrap_or_default() {
            module_filters.push(ModuleFilter {
                module_name: Some(k),
                level_filter: parse_level_filter(v)?,
            });
        }

        #[cfg(feature = "textfilter")]
        let textfilter = match logspec_ff.global_pattern {
            None => None,
            Some(s) => match Regex::new(&s) {
                Ok(re) => Some(re),
                Err(e) => {
                    push_err(&format!("invalid regex filter - {}", e), &mut parse_errs);
                    None
                }
            },
        };

        let logspec = Self {
            module_filters: module_filters.level_sort(),
            #[cfg(feature = "textfilter")]
            textfilter,
        };
        if parse_errs.is_empty() {
            Ok(logspec)
        } else {
            parse_err(parse_errs, logspec)
        }
    }

    /// Serializes itself in toml format.
    ///
    /// This method is only avaible with feature `specfile`.
    ///
    /// # Errors
    ///
    /// `FlexiLoggerError::Io` if writing fails.
    #[cfg(feature = "specfile_without_notification")]
    pub fn to_toml(&self, w: &mut dyn std::io::Write) -> Result<(), FlexiLoggerError> {
        w.write_all(b"### Optional: Default log level\n")?;
        let last = self.module_filters.last();
        if last.is_some() && last.as_ref().unwrap().module_name.is_none() {
            w.write_all(
                format!(
                    "global_level = '{}'\n",
                    last.as_ref()
                        .unwrap()
                        .level_filter
                        .to_string()
                        .to_lowercase()
                )
                .as_bytes(),
            )?;
        } else {
            w.write_all(b"#global_level = 'info'\n")?;
        }

        w.write_all(
            b"\n### Optional: specify a regular expression to suppress all messages that don't match\n",
        )?;
        w.write_all(b"#global_pattern = 'foo'\n")?;

        w.write_all(
            b"\n### Specific log levels per module are optionally defined in this section\n",
        )?;
        w.write_all(b"[modules]\n")?;
        if self.module_filters.is_empty() || self.module_filters[0].module_name.is_none() {
            w.write_all(b"#'mod1' = 'warn'\n")?;
            w.write_all(b"#'mod2' = 'debug'\n")?;
            w.write_all(b"#'mod2::mod3' = 'trace'\n")?;
        }
        for mf in &self.module_filters {
            if mf.module_name.is_some() {
                w.write_all(
                    format!(
                        "'{}' = '{}'\n",
                        mf.module_name.as_ref().unwrap(),
                        mf.level_filter.to_string().to_lowercase()
                    )
                    .as_bytes(),
                )?;
            }
        }
        Ok(())
    }

    /// Creates a `LogSpecBuilder`, setting the default log level.
    #[must_use]
    pub fn default(level_filter: LevelFilter) -> LogSpecBuilder {
        LogSpecBuilder::from_module_filters(&[ModuleFilter {
            module_name: None,
            level_filter,
        }])
    }

    /// Provides a reference to the module filters.
    pub fn module_filters(&self) -> &Vec<ModuleFilter> {
        &self.module_filters
    }

    /// Provides a reference to the text filter.
    ///
    /// This method is only avaible with feature `textfilter`, which is a default feature.
    #[cfg(feature = "textfilter")]
    pub fn text_filter(&self) -> &Option<Regex> {
        &(self.textfilter)
    }
}

fn push_err(s: &str, parse_errs: &mut String) {
    if !parse_errs.is_empty() {
        parse_errs.push_str("; ");
    }
    parse_errs.push_str(s);
}

fn parse_err(
    errors: String,
    logspec: LogSpecification,
) -> Result<LogSpecification, FlexiLoggerError> {
    Err(FlexiLoggerError::Parse(errors, logspec))
}

fn parse_level_filter<S: AsRef<str>>(s: S) -> Result<LevelFilter, FlexiLoggerError> {
    match s.as_ref().to_lowercase().as_ref() {
        "off" => Ok(LevelFilter::Off),
        "error" => Ok(LevelFilter::Error),
        "warn" => Ok(LevelFilter::Warn),
        "info" => Ok(LevelFilter::Info),
        "debug" => Ok(LevelFilter::Debug),
        "trace" => Ok(LevelFilter::Trace),
        _ => Err(FlexiLoggerError::LevelFilter(format!(
            "unknown level filter: {}",
            s.as_ref()
        ))),
    }
}

fn contains_whitespace(s: &str, parse_errs: &mut String) -> bool {
    let result = s.chars().any(char::is_whitespace);
    if result {
        push_err(
            &format!(
                "ignoring invalid part in log spec '{}' (contains a whitespace)",
                s
            ),
            parse_errs,
        );
    }
    result
}

#[allow(clippy::needless_doctest_main)]
/// Builder for `LogSpecification`.
///
/// # Example
///
/// Use the reconfigurability feature and build the log spec programmatically.
///
/// ```rust
/// use flexi_logger::{Logger, LogSpecBuilder};
/// use log::LevelFilter;
///
/// fn main() {
///     // Build the initial log specification
///     let mut builder = LogSpecBuilder::new();  // default is LevelFilter::Off
///     builder.default(LevelFilter::Info);
///     builder.module("karl", LevelFilter::Debug);
///
///     // Initialize Logger, keep builder alive
///     let mut logger_reconf_handle = Logger::with(builder.build())
///         // your logger configuration goes here, as usual
///         .start()
///         .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));
///
///     // ...
///
///     // Modify builder and update the logger
///     builder.default(LevelFilter::Error);
///     builder.remove("karl");
///     builder.module("emma", LevelFilter::Trace);
///
///     logger_reconf_handle.set_new_spec(builder.build());
///
///     // ...
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct LogSpecBuilder {
    module_filters: HashMap<Option<String>, LevelFilter>,
}

impl LogSpecBuilder {
    /// Creates a `LogSpecBuilder` with all logging turned off.
    #[must_use]
    pub fn new() -> Self {
        let mut modfilmap = HashMap::new();
        modfilmap.insert(None, LevelFilter::Off);
        Self {
            module_filters: modfilmap,
        }
    }

    /// Creates a `LogSpecBuilder` from given module filters.
    #[must_use]
    pub fn from_module_filters(module_filters: &[ModuleFilter]) -> Self {
        let mut modfilmap = HashMap::new();
        for mf in module_filters {
            modfilmap.insert(mf.module_name.clone(), mf.level_filter);
        }
        Self {
            module_filters: modfilmap,
        }
    }

    /// Adds a default log level filter, or updates the default log level filter.
    pub fn default(&mut self, lf: LevelFilter) -> &mut Self {
        self.module_filters.insert(None, lf);
        self
    }

    /// Adds a log level filter, or updates the log level filter, for a module.
    pub fn module<M: AsRef<str>>(&mut self, module_name: M, lf: LevelFilter) -> &mut Self {
        self.module_filters
            .insert(Some(module_name.as_ref().to_owned()), lf);
        self
    }

    /// Adds a log level filter, or updates the log level filter, for a module.
    pub fn remove<M: AsRef<str>>(&mut self, module_name: M) -> &mut Self {
        self.module_filters
            .remove(&Some(module_name.as_ref().to_owned()));
        self
    }

    /// Adds log level filters from a `LogSpecification`.
    pub fn insert_modules_from(&mut self, other: LogSpecification) -> &mut Self {
        for module_filter in other.module_filters {
            self.module_filters
                .insert(module_filter.module_name, module_filter.level_filter);
        }
        self
    }

    /// Creates a log specification without text filter.
    #[must_use]
    pub fn finalize(self) -> LogSpecification {
        LogSpecification {
            module_filters: self.module_filters.into_vec_module_filter(),
            #[cfg(feature = "textfilter")]
            textfilter: None,
        }
    }

    /// Creates a log specification with text filter.
    ///
    /// This method is only avaible with feature `textfilter`, which is a default feature.
    #[cfg(feature = "textfilter")]
    pub fn finalize_with_textfilter(self, tf: Regex) -> LogSpecification {
        LogSpecification {
            module_filters: self.module_filters.into_vec_module_filter(),
            textfilter: Some(tf),
        }
    }

    /// Creates a log specification without being consumed.
    #[must_use]
    pub fn build(&self) -> LogSpecification {
        LogSpecification {
            module_filters: self.module_filters.clone().into_vec_module_filter(),
            #[cfg(feature = "textfilter")]
            textfilter: None,
        }
    }

    /// Creates a log specification without being consumed, optionally with a text filter.
    ///
    /// This method is only avaible with feature `textfilter`, which is a default feature.
    #[cfg(feature = "textfilter")]
    pub fn build_with_textfilter(&self, tf: Option<Regex>) -> LogSpecification {
        LogSpecification {
            module_filters: self.module_filters.clone().into_vec_module_filter(),
            textfilter: tf,
        }
    }
}

trait IntoVecModuleFilter {
    fn into_vec_module_filter(self) -> Vec<ModuleFilter>;
}
impl IntoVecModuleFilter for HashMap<Option<String>, LevelFilter> {
    fn into_vec_module_filter(self) -> Vec<ModuleFilter> {
        let mf: Vec<ModuleFilter> = self
            .into_iter()
            .map(|(k, v)| ModuleFilter {
                module_name: k,
                level_filter: v,
            })
            .collect();
        mf.level_sort()
    }
}

trait LevelSort {
    fn level_sort(self) -> Vec<ModuleFilter>;
}
impl LevelSort for Vec<ModuleFilter> {
    /// Sort the module filters by length of their name,
    /// this allows a little more efficient lookup at runtime.
    fn level_sort(mut self) -> Vec<ModuleFilter> {
        self.sort_by(|a, b| {
            let a_len = a.module_name.as_ref().map_or(0, String::len);
            let b_len = b.module_name.as_ref().map_or(0, String::len);
            b_len.cmp(&a_len)
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::LogSpecification;
    use log::{Level, LevelFilter};

    #[test]
    fn parse_logging_spec_valid() {
        let spec = LogSpecification::parse("crate1::mod1=error,crate1::mod2,crate2=debug").unwrap();
        assert_eq!(spec.module_filters().len(), 3);
        assert_eq!(
            spec.module_filters()[0].module_name,
            Some("crate1::mod1".to_string())
        );
        assert_eq!(spec.module_filters()[0].level_filter, LevelFilter::Error);

        assert_eq!(
            spec.module_filters()[1].module_name,
            Some("crate1::mod2".to_string())
        );
        assert_eq!(spec.module_filters()[1].level_filter, LevelFilter::max());

        assert_eq!(
            spec.module_filters()[2].module_name,
            Some("crate2".to_string())
        );
        assert_eq!(spec.module_filters()[2].level_filter, LevelFilter::Debug);

        #[cfg(feature = "textfilter")]
        assert!(spec.text_filter().is_none());
    }

    #[test]
    fn parse_logging_spec_invalid_crate() {
        // test parse_logging_spec with multiple = in specification
        assert!(LogSpecification::parse("crate1::mod1=warn=info,crate2=debug").is_err());
    }

    #[test]
    fn parse_logging_spec_wrong_log_level() {
        assert!(LogSpecification::parse("crate1::mod1=wrong, crate2=warn").is_err());
    }

    #[test]
    fn parse_logging_spec_empty_log_level() {
        assert!(LogSpecification::parse("crate1::mod1=wrong, crate2=").is_err());
    }

    #[test]
    fn parse_logging_spec_global() {
        let spec = LogSpecification::parse("warn,crate2=debug").unwrap();
        assert_eq!(spec.module_filters().len(), 2);

        assert_eq!(spec.module_filters()[1].module_name, None);
        assert_eq!(spec.module_filters()[1].level_filter, LevelFilter::Warn);

        assert_eq!(
            spec.module_filters()[0].module_name,
            Some("crate2".to_string())
        );
        assert_eq!(spec.module_filters()[0].level_filter, LevelFilter::Debug);

        #[cfg(feature = "textfilter")]
        assert!(spec.text_filter().is_none());
    }

    #[test]
    #[cfg(feature = "textfilter")]
    fn parse_logging_spec_valid_filter() {
        let spec = LogSpecification::parse(" crate1::mod1 = error , crate1::mod2,crate2=debug/abc")
            .unwrap();
        assert_eq!(spec.module_filters().len(), 3);

        assert_eq!(
            spec.module_filters()[0].module_name,
            Some("crate1::mod1".to_string())
        );
        assert_eq!(spec.module_filters()[0].level_filter, LevelFilter::Error);

        assert_eq!(
            spec.module_filters()[1].module_name,
            Some("crate1::mod2".to_string())
        );
        assert_eq!(spec.module_filters()[1].level_filter, LevelFilter::max());

        assert_eq!(
            spec.module_filters()[2].module_name,
            Some("crate2".to_string())
        );
        assert_eq!(spec.module_filters()[2].level_filter, LevelFilter::Debug);
        assert!(
            spec.text_filter().is_some()
                && spec.text_filter().as_ref().unwrap().to_string() == "abc"
        );
    }

    #[test]
    fn parse_logging_spec_invalid_crate_filter() {
        assert!(LogSpecification::parse("crate1::mod1=error=warn,crate2=debug/a.c").is_err());
    }

    #[test]
    #[cfg(feature = "textfilter")]
    fn parse_logging_spec_empty_with_filter() {
        let spec = LogSpecification::parse("crate1/a*c").unwrap();
        assert_eq!(spec.module_filters().len(), 1);
        assert_eq!(
            spec.module_filters()[0].module_name,
            Some("crate1".to_string())
        );
        assert_eq!(spec.module_filters()[0].level_filter, LevelFilter::max());
        assert!(
            spec.text_filter().is_some()
                && spec.text_filter().as_ref().unwrap().to_string() == "a*c"
        );
    }

    #[test]
    fn reuse_logspec_builder() {
        let mut builder = crate::LogSpecBuilder::new();

        builder.default(LevelFilter::Info);
        builder.module("carlo", LevelFilter::Debug);
        builder.module("toni", LevelFilter::Warn);
        let spec1 = builder.build();

        assert_eq!(
            spec1.module_filters()[0].module_name,
            Some("carlo".to_string())
        );
        assert_eq!(spec1.module_filters()[0].level_filter, LevelFilter::Debug);

        assert_eq!(
            spec1.module_filters()[1].module_name,
            Some("toni".to_string())
        );
        assert_eq!(spec1.module_filters()[1].level_filter, LevelFilter::Warn);

        assert_eq!(spec1.module_filters().len(), 3);
        assert_eq!(spec1.module_filters()[2].module_name, None);
        assert_eq!(spec1.module_filters()[2].level_filter, LevelFilter::Info);

        builder.default(LevelFilter::Error);
        builder.remove("carlo");
        builder.module("greta", LevelFilter::Trace);
        let spec2 = builder.build();

        assert_eq!(spec2.module_filters().len(), 3);
        assert_eq!(spec2.module_filters()[2].module_name, None);
        assert_eq!(spec2.module_filters()[2].level_filter, LevelFilter::Error);

        assert_eq!(
            spec2.module_filters()[0].module_name,
            Some("greta".to_string())
        );
        assert_eq!(spec2.module_filters()[0].level_filter, LevelFilter::Trace);

        assert_eq!(
            spec2.module_filters()[1].module_name,
            Some("toni".to_string())
        );
        assert_eq!(spec2.module_filters()[1].level_filter, LevelFilter::Warn);
    }

    ///////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////
    #[test]
    fn match_full_path() {
        let spec = LogSpecification::parse("crate2=info,crate1::mod1=warn").unwrap();
        assert!(spec.enabled(Level::Warn, "crate1::mod1"));
        assert!(!spec.enabled(Level::Info, "crate1::mod1"));
        assert!(spec.enabled(Level::Info, "crate2"));
        assert!(!spec.enabled(Level::Debug, "crate2"));
    }

    #[test]
    fn no_match() {
        let spec = LogSpecification::parse("crate2=info,crate1::mod1=warn").unwrap();
        assert!(!spec.enabled(Level::Warn, "crate3"));
    }

    #[test]
    fn match_beginning() {
        let spec = LogSpecification::parse("crate2=info,crate1::mod1=warn").unwrap();
        assert!(spec.enabled(Level::Info, "crate2::mod1"));
    }

    #[test]
    fn match_beginning_longest_match() {
        let spec = LogSpecification::parse(
            "abcd = info, abcd::mod1 = error, klmn::mod = debug, klmn = info",
        )
        .unwrap();
        assert!(spec.enabled(Level::Error, "abcd::mod1::foo"));
        assert!(!spec.enabled(Level::Warn, "abcd::mod1::foo"));
        assert!(spec.enabled(Level::Warn, "abcd::mod2::foo"));
        assert!(!spec.enabled(Level::Debug, "abcd::mod2::foo"));

        assert!(!spec.enabled(Level::Debug, "klmn"));
        assert!(!spec.enabled(Level::Debug, "klmn::foo::bar"));
        assert!(spec.enabled(Level::Info, "klmn::foo::bar"));
    }

    #[test]
    fn match_default1() {
        let spec = LogSpecification::parse("info,abcd::mod1=warn").unwrap();
        assert!(spec.enabled(Level::Warn, "abcd::mod1"));
        assert!(spec.enabled(Level::Info, "crate2::mod2"));
    }

    #[test]
    fn match_default2() {
        let spec = LogSpecification::parse("modxyz=error, info, abcd::mod1=warn").unwrap();
        assert!(spec.enabled(Level::Warn, "abcd::mod1"));
        assert!(spec.enabled(Level::Info, "crate2::mod2"));
    }

    #[test]
    fn rocket() {
        let spec = LogSpecification::parse("info, rocket=off, serenity=off").unwrap();
        assert!(spec.enabled(Level::Info, "itsme"));
        assert!(spec.enabled(Level::Warn, "abcd::mod1"));
        assert!(!spec.enabled(Level::Debug, "abcd::mod1"));
        assert!(!spec.enabled(Level::Error, "rocket::rocket"));
        assert!(!spec.enabled(Level::Warn, "rocket::rocket"));
        assert!(!spec.enabled(Level::Info, "rocket::rocket"));
    }

    #[test]
    fn add_filters() {
        let mut builder = crate::LogSpecBuilder::new();

        builder.default(LevelFilter::Debug);
        builder.module("carlo", LevelFilter::Debug);
        builder.module("toni", LevelFilter::Warn);

        builder.insert_modules_from(
            LogSpecification::parse("info, may=error, toni::heart = trace").unwrap(),
        );
        let spec = builder.build();

        assert_eq!(spec.module_filters().len(), 5);

        assert_eq!(
            spec.module_filters()[0].module_name,
            Some("toni::heart".to_string())
        );
        assert_eq!(spec.module_filters()[0].level_filter, LevelFilter::Trace);

        assert_eq!(
            spec.module_filters()[1].module_name,
            Some("carlo".to_string())
        );
        assert_eq!(spec.module_filters()[1].level_filter, LevelFilter::Debug);

        assert_eq!(
            spec.module_filters()[2].module_name,
            Some("toni".to_string())
        );
        assert_eq!(spec.module_filters()[2].level_filter, LevelFilter::Warn);

        assert_eq!(
            spec.module_filters()[3].module_name,
            Some("may".to_string())
        );
        assert_eq!(spec.module_filters()[3].level_filter, LevelFilter::Error);

        assert_eq!(spec.module_filters()[4].module_name, None);
        assert_eq!(spec.module_filters()[4].level_filter, LevelFilter::Info);
    }

    #[test]
    fn zero_level() {
        let spec = LogSpecification::parse("info,crate1::mod1=off").unwrap();
        assert!(!spec.enabled(Level::Error, "crate1::mod1"));
        assert!(spec.enabled(Level::Info, "crate2::mod2"));
    }
}

#[cfg(test)]
#[cfg(feature = "specfile_without_notification")]
mod test_with_specfile {
    #[cfg(feature = "specfile_without_notification")]
    use crate::LogSpecification;

    #[test]
    fn specfile() {
        compare_specs("", "");

        compare_specs(
            "[modules]\n\
             ",
            "",
        );

        compare_specs(
            "global_level = 'info'\n\
             \n\
             [modules]\n\
             ",
            "info",
        );

        compare_specs(
            "global_level = 'info'\n\
             \n\
             [modules]\n\
             'mod1::mod2' = 'debug'\n\
             'mod3' = 'trace'\n\
             ",
            "info, mod1::mod2 = debug, mod3 = trace",
        );

        compare_specs(
            "global_level = 'info'\n\
             global_pattern = 'Foo'\n\
             \n\
             [modules]\n\
             'mod1::mod2' = 'debug'\n\
             'mod3' = 'trace'\n\
             ",
            "info, mod1::mod2 = debug, mod3 = trace /Foo",
        );
    }

    #[cfg(feature = "specfile_without_notification")]
    fn compare_specs(toml: &str, spec_string: &str) {
        let ls_toml = LogSpecification::from_toml(toml).unwrap();
        let ls_spec = LogSpecification::parse(spec_string).unwrap();

        assert_eq!(ls_toml.module_filters, ls_spec.module_filters);
        assert_eq!(ls_toml.textfilter.is_none(), ls_spec.textfilter.is_none());
        if ls_toml.textfilter.is_some() && ls_spec.textfilter.is_some() {
            assert_eq!(
                ls_toml.textfilter.unwrap().to_string(),
                ls_spec.textfilter.unwrap().to_string()
            );
        }
    }
}
