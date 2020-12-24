# flexi_logger

**A flexible and easy-to-use logger that writes logs to stderr and/or to files, and/or to
other output streams, and that can be influenced while the program is running.**

[![Latest version](https://img.shields.io/crates/v/flexi_logger.svg)](https://crates.io/crates/flexi_logger)
[![Documentation](https://docs.rs/flexi_logger/badge.svg)](https://docs.rs/flexi_logger)
![License](https://img.shields.io/crates/l/flexi_logger.svg)
[![Travis CI](https://travis-ci.org/emabee/flexi_logger.svg?branch=master)](https://travis-ci.org/emabee/flexi_logger)

## Usage

Add flexi_logger to the dependencies section in your project's `Cargo.toml`, with

```toml
[dependencies]
flexi_logger = "0.16"
log = "0.4"
```

or, if you want to use some of the optional features, with something like

```toml
[dependencies]
flexi_logger = { version = "0.16", features = ["specfile", "compress"] }
log = "0.4"
```

or, to get the smallest footprint (and no colors), with

```toml
[dependencies]
flexi_logger = { version = "0.16", default_features = false }
log = "0.4"
```

Note: `log` is needed because `flexi_logger` plugs into the standard Rust logging facade given
by the [log crate](https://crates.io/crates/log),
and you use the ```log``` macros to write log lines from your code.

## Code examples

See the documentation of module
[code_examples](https://docs.rs/flexi_logger/latest/flexi_logger/code_examples/index.html).

## Options

There are configuration options to e.g.

* decide whether you want to write your logs to stderr or to a file,
* configure the path and the filenames of the log files,
* use file rotation,
* specify the line format for the log lines,
* define additional log streams, e.g for alert or security messages,
* support changing the log specification on the fly, while the program is running,

See the API documentation for a complete reference.

## Crate Features

Make use of any of these features by specifying them in your `Cargo.toml`
(see above in the usage section).

### **`colors`**

Getting colored output is also possible without this feature,
by implementing and using your own coloring format function.

The default feature `colors` simplifies this by doing three things:

* it activates the optional dependency to `yansi` and
* provides additional colored pendants to the existing uncolored format functions
* it uses `colored_default_format()` for the output to stderr,
  and the non-colored `default_format()` for the output to files
* it activates the optional dependency to `atty` to being able to switch off
  coloring if the output is not sent to a terminal but e.g. piped to another program.

**<span style="color:red">C</span><span style="color:blue">o</span><span style="color:green">l</span><span style="color:orange">o</span><span style="color:magenta">r</span><span style="color:darkturquoise">s</span>**,
or styles in general, are a matter of taste, and no choice will fit every need. So you can override the default formatting and coloring in various ways.

With `--no-default-features --features="atty"` you can remove the yansi-based coloring but keep the capability to switch off your own coloring.

### **`compress`**

The `compress` feature adds two options to the `Logger::Cleanup` `enum`, which allow keeping some
or all rotated log files in compressed form (`.gz`) rather than as plain text files.

The feature was previously called `ziplogs`. The old name still works, but is deprecated and
should be replaced.

### **`specfile`**

The `specfile` feature adds a method `Logger::start_with_specfile(specfile)`.

If started with this method, `flexi_logger` uses the log specification
that was given to the factory method (one of `Logger::with...()`) as initial spec
and then tries to read the log specification from the named file.

If the file does not exist, it is created and filled with the initial spec.

By editing the log specification in the file while the program is running,
you can change the logging behavior in real-time.

The implementation of this feature uses some additional crates that you might
not want to depend on with your program if you don't use this functionality.
For that reason the feature is not active by default.

### **`specfile_without_notification`**

Pretty much like `specfile`, except that updates to the file are being ignored.
See [issue-59](https://github.com/emabee/flexi_logger/issues/59) for more details.

### **`textfilter`**

Removes the ability to filter logs by text, but also removes the dependency on the regex crate.

### **`syslog`**

This is still an experimental feature, likely working, but not well tested.
Feedback of all kinds is highly appreciated.

## Versions

See the [change log](https://github.com/emabee/flexi_logger/blob/master/CHANGELOG.md).
