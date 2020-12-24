#[test]
#[cfg(feature = "textfilter")]
fn test_textfilter() {
    use flexi_logger::{default_format, LogSpecification, Logger};
    use log::*;

    use std::env;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    let logspec = LogSpecification::parse("info/Hello").unwrap();
    Logger::with(logspec)
        .format(default_format)
        .print_message()
        .log_to_file()
        .suppress_timestamp()
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message - you must not see it!");
    trace!("This is a trace message - you must not see it!");

    error!("Hello, this is an error message");
    warn!("This is a warning! Hello!!");
    info!("Hello, this is an info message! Hello");
    debug!("Hello, this is a debug message - you must not see it!");
    trace!("Hello, this is a trace message - you must not see it!");

    let arg0 = env::args().next().unwrap();
    let progname = Path::new(&arg0).file_stem().unwrap().to_string_lossy();
    let filename = format!("{}.log", &progname);

    let f = File::open(&filename)
        .unwrap_or_else(|e| panic!("Cannot open file {:?} due to {}", filename, e));
    let mut reader = BufReader::new(f);
    let mut buffer = String::new();
    let mut count = 0;
    while reader.read_line(&mut buffer).unwrap() > 0 {
        if buffer.find("Hello").is_none() {
            panic!(
                "line in log file without Hello {:?}: \"{}\"",
                filename, buffer
            );
        } else {
            count += 1;
        }
        buffer.clear();
    }
    assert_eq!(count, 3);
}
