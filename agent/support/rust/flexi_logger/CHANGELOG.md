# Changelog for flexi_logger

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.2] - 2020-11-18

Add module
[code-examples](https://docs.rs/flexi_logger/latest/flexi_logger/code_examples/index.html)
with additional usage documentation.
This is a follow-up of a PR, kudos goes to [devzbysiu](https://github.com/devzbysiu)!

## [0.16.1] - 2020-09-20

Support empty toml spec files (kudos to ijackson for
[pull request 66](https://github.com/emabee/flexi_logger/pull/66))
(was supposed to be part of 0.16.0, but I had forgotten to merge it).

## [0.16.0] - 2020-09-19

If file logging is used, do not create the output file if no log is written.
Solves [issue-62](https://github.com/emabee/flexi_logger/issues/62).

Improve color handling

- introduce AdaptiveFormat for a clearer API
- Support using feature `atty` without provided coloring
- Extend example `colors` to provide insight in how AdaptiveFormat works
- Remove the deprecated method `Logger::do_not_log()`; use `log_target()` with `LogTarget::DevNull` instead.
- Remove deprecated method `Logger::o_log_to_file()`; use  `log_target()` instead. The clearer convenience method `Logger::log_to_file()` is still available.

Improve the compression feature. Solves [issue-65](https://github.com/emabee/flexi_logger/issues/65).

- breaking change: change the file suffix for the compressed log files from `.zip` to `.gz`
- Fix wrong wording in code and documentation
- deprecate the feature name `ziplog` and call the feature now `compress`
- rename `Cleanup::KeepZipFiles` into `Cleanup::KeepCompressedFiles`
   and `Cleanup::KeepLogAndZipFiles` into `Cleanup::KeepLogAndCompressedFiles`
  - the old names still work but are deprecated

If file logging is used, do not create the output file if no log is written
Solves issue [issue-62](https://github.com/emabee/flexi_logger/issues/62).

## [0.15.12] - 2020-28-08

Make `1.37.0` the minimal rust version for `flexi_logger`.

## [0.15.11] - 2020-08-07

Introduce feature `specfile_without_notification` to allow coping with OS issues
(solves [issue-59](https://github.com/emabee/flexi_logger/issues/59)).

## [0.15.10] - 2020-07-22

Minor code maintenance.

## [0.15.9] - 2020-07-21

Allow using the log target with fantasy names, like with `env_logger`.
Solves [issue-56](https://github.com/emabee/flexi_logger/issues/56).

## [0.15.8] - 2020-07-20

Allow modifying the coloring palette through the environment variable `FLEXI_LOGGER_PALETTE`.
See function [style](https://docs.rs/flexi_logger/latest/flexi_logger/fn.style.html) for details.
Solves [issue-55](https://github.com/emabee/flexi_logger/issues/55).

By default, don't use colors if stdout or stderr are not a terminal
Solves [issue-57](https://github.com/emabee/flexi_logger/issues/57).

Add variant Criterion::AgeOrSize
(kudos to
[pscott](https://github.com/pscott),
[PR-54](https://github.com/emabee/flexi_logger/pull/54)).

## [0.15.7] - 2020-07-02

Add some Debug derives
(kudos to
[pscott](https://github.com/pscott),
[PR-52](https://github.com/emabee/flexi_logger/pull/52)).

## [0.15.6] - 2020-07-02

Introduce separate formatting for stdout
(kudos to
[pscott](https://github.com/pscott),
[PR-51](https://github.com/emabee/flexi_logger/pull/51)).

Deprecate `Logger::do_not_log()`.

## [0.15.5] - 2020-06-18

Add `Logger::duplicate_to_stdout()` to fix
[issue-47](https://github.com/emabee/flexi_logger/issues/47).

## [0.15.4] - 2020-06-09

Fix [issue-45](https://github.com/emabee/flexi_logger/issues/45), which was a panic in
the specfile watcher when some log files were deleted manually while the program was running
(kudos to
[avl](https://github.com/avl),
[PR-46](https://github.com/emabee/flexi_logger/pull/46)).

## [0.15.3] - 2020-06-04

Add compatibility with multi_log by adding methods
`Logger::build` and `Logger::build_with_specfile` (fixes issue-44).

Add `LogSpecBuilder::insert_modules_from()` (fixes issue-43).

## [0.15.2] - 2020-03-24

Improve handling of parse-errors.

Fix default format for files (was and is documented to be uncolored, but was colored).

## [0.15.1] - 2020-03-04

Make the textfilter functionality an optional default feature;
deselecting it removes the regex crate as a required dependency,
which reduces the size overhead for any binary using `flexi_logger`
(kudos to [Petre Eftime](petre.eftime@gmail.com)).

## [0.15.0] - 2020-02-27

Refine and rename error variants to allow e.g. differentiating
between errors related to the output (files)
and errors related to the specfile.

## [0.14.8] - 2020-02-06

Make cleanup more robust, and allow controlling the cleanup-thread also with
`Logger::start_with_specfile()`.

## [0.14.7] - 2020-02-04

If rotation is used with cleanup, do the cleanup by default in a background thread
(solves [issue 39](https://github.com/emabee/flexi_logger/issues/39)).

For the ziplog feature, switch from `zip` crate to `flate2`.

## [0.14.6] - 2020-01-28

Fix [issue 38](https://github.com/emabee/flexi_logger/issues/38)
(Old log files are not removed if rCURRENT doesn't overflow).

## [0.14.5] - 2019-11-06

Pass format option into custom loggers (pull request 37).

## [0.14.4] - 2019-09-25

Fix bug in specfile handling ([issue 36](https://github.com/emabee/flexi_logger/issues/36)).

Improve docu and implementation of create_symlink.

Minor other stuff.

## [0.14.3] - 2019-08-04

Allow defining custom handlers for the default log target
(solves [issue 32](https://github.com/emabee/flexi_logger/issues/32)).

## [0.14.2] - 2019-08-04

Use implicit locking of stderr in StdErrWriter.

Allow failures in travis' windows build.

Add license files.

## [0.14.1] - 2019-08-04

Support recursive logging also with FileLogWriter, sharing the buffer with the PrimaryWriter.

Fix multi-threading issue (incorrect line-break handling with stderr).

## [0.14.0] - 2019-07-22

Further stabilize the specfile feature.

Remove `LogSpecification::ensure_specfile_exists()` and `LogSpecification::from_file()`
from public API, where they should not be (-> version bump).

Harmonize all eprintln! calls to
prefix the output with "`[flexi_logger]` ".

## [0.13.4] - 2019-07-19

Only relevant for the `specfile` feature:
initialize the logger before dealing in any way with the specfile,
and do the initial read of the specfile in the main thread,
i.e. synchronously, to ensure a deterministic behavior during startup
(fixes [issue 31](https://github.com/emabee/flexi_logger/issues/31)).

## [0.13.3] - 2019-07-08

Improve the file watch for the specfile to make the `specfile` feature more robust.
E.g. allow editing the specfile on linux
with editors that move the original file to a backup name.

Add an option to write the log to stdout, as recommended for
[twelve-factor apps](https://12factor.net/logs).

## [0.13.2] - 2019-06-02

Make get_creation_date() more robust on all platforms.

## [0.13.1] - 2019-05-29

Fix fatal issue with get_creation_date() on linux
(see <https://github.com/emabee/flexi_logger/pull/30>).

## [0.13.0] - 2019-05-28

Improve performance for plain stderr logging.

Improve robustnesss for recursive log calls.

## [0.12.0] - 2019-05-24

Revise handling of record.metadata().target() versus record.module_path().

Incompatible API modification: Logger.rotate() takes now three parameters.

Suppport different formatting for stderr and files.

Add feature `colors` (see `README.md` for details).

Remove the deprecated `Logger::start_reconfigurable()` and `Logger::rotate_over_size()`.

## [0.11.5] - 2019-05-15

Fix [issue 26](https://github.com/emabee/flexi_logger/issues/26) (logging off for specific modules).

Fix [issue 27](https://github.com/emabee/flexi_logger/issues/27) (log files blank after restart).

Fix [issue 28](https://github.com/emabee/flexi_logger/issues/28)
(add a corresponding set of unit tests to FileLogWriter).

## [0.11.4] - 2019-04-01

Version updates of dependencies.

## [0.11.3] - 2019-03-28

Add SyslogWriter.

## [0.11.2] - 2019-03-22

Change API to more idiomatic parameter types, in a compatible way.

Add first implementation of a SyslogWriter.

## [0.11.1] - 2019-03-06

Add option to write windows line endings, rather than a plain `\n`.

## [0.11.0] - 2019-03-02

Add options to cleanup rotated log files, by deleting and/or zipping older files.

Remove some deprecated methods.

## [0.10.7] - 2019-02-27

Let the BlackHoleLogger, although it doesn't write a log, still duplicate to stderr.

## [0.10.6] - 2019-02-26

Deprecate `Logger::start_reconfigurable()`, let `Logger::start()` return a reconfiguration handle.

Add an option to write all logs to nowhere (i.e., do not write any logs).

## [0.10.5] - 2019-01-15

Eliminate performance penalty for using reconfigurability.

## [0.10.4] - 2019-01-07

Add methods to modify the log spec temporarily.

## [0.10.3] - 2018-12-08

Advance to edition 2018.

## [0.10.2] - 2018-12-07

Log-spec parsing is improved, more whitespace is tolerated.

## [0.10.1] - 2018-11-08

When file rotation is used, the name of the file to which the logs are written is now stable.

Details:

- the logs are always written to a file with infix _rCURRENT
- if this file exceeds the specified rotate-over-size, it is closed and renamed
  to a file with a sequential number infix, and then the logging continues again
  to the (fresh) file with infix _rCURRENT

Example:

After some logging with your program my_prog, you will find files like

```text
my_prog_r00000.log
my_prog_r00001.log
my_prog_r00002.log
my_prog_rCURRENT.log
```

## [0.10.0] - 2018-10-30

`LogSpecification::parse()` now returns a `Result<LogSpecification, FlexiLoggerError>`, rather than
a log spec directly (-> version bump).
This enables a more reliable usage of FlexiLogger in non-trivial cases.

For the sake of compatibility for the normal usecases, the Logger methods `with_str()` etc.
remain unchanged. An extra method is added to retrieve parser errors, if desired.

## [0.9.3] - 2018-10-27

Docu improvement.

## [0.9.2] - 2018-08-13

Fix incorrect filename generation with rotation,
i.e., switch off timestamp usage when rotation is used.

## [0.9.1] - 2018-08-12

Introduce `Logger::duplicate_to_stderr()`, as a more flexible replacement for `duplicate_error()`
and `duplicate_info()`.

## [0.9.0] - 2018-07-06

### Eliminate String allocation

Get rid of the unneccessary String allocation we've been
carrying with us since ages. This implies changing the signature of the format functions.

In case you provide your own format function, you'll need to adapt it to the new signature.
Luckily, the effort is low.

As an example, here is how the definition of the `opt_format` function changed:

```rust
- pub fn opt_format(record: &Record) -> String {
-     format!(
---
+ pub fn opt_format(w: &mut io::Write, record: &Record) -> Result<(), io::Error> {
+     write!(
+         w,
```

Similarly, if you're using the advanced feature of providing your own implementation of LogWriter,
you need to adapt it. The change again is trivial, and should even slightly
simplify your code (you can return io errors and don't have to catch them yourself).

### Misc

The docu generation on docs.rs is now configured to considers all features, we thus
expose `Logger.start_with_specfile()` only if the specfile feature is used. So we can revert the
change done with 0.8.1.

## [0.8.4] - 2018-06-18

Add flexi_logger to category `development-tools::debugging`

## [0.8.3] - 2018-05-14

Make append() also work for rotating log files

## [0.8.2] - 2018-04-03

Add option to append to existing log files, rather than always truncating them

## [0.8.1] - 2018-3-19

Expose `Logger.start_with_specfile()` always
...and not only if the feature "specfile" is used - otherwise it does not appear
in the auto-generated docu (because it does not use --allfeatures)

## [0.8.0] - 2018-03-18

Add specfile feature

- Add a feature that allows to specify the LogSpecification via a file
  that can be edited while the program is running
_ Remove/hide deprecated APIs
- As a consequence, cleanup code, get rid of duplicate stuff.

## [0.7.1] - 2018-03-07

Bugfix: do not create empty files when used in env_logger style.
Update docu and the description in cargo.toml

## [0.7.0] - 2018-02-25

Add support for multiple log output streams

- replace FlexiWriter with DefaultLogWriter, which wraps a FileLogWriter
- add test where a SecurityWriter and an AlertWriter are added
- add docu
- move deprecated structs to separate package
- move benches to folder benches

## [0.6.13] 2018-02-09

Add Logger::with_env_or_str()

## [0.6.12] 2018-2-07

Add ReconfigurationHandle::parse_new_spec()

## [0.6.11] 2017-12-29

Fix README.md

## [0.6.10] 2017-12-29

Publish version based on log 0.4

## (...)

## [0.6.0] 2017-07-13

Use builder pattern for LogSpecification and Logger

- deprecate outdated API
- "objectify" LogSpecification
- improve documentation, e.g. document the dash/underscore issue
