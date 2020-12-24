use flexi_logger::{detailed_format, Logger};
use log::*;

#[test]
fn test_recursion() {
    Logger::with_str("info")
        .format(detailed_format)
        .log_to_file()
        // .duplicate_to_stderr(Duplicate::All)
        // .duplicate_to_stdout(Duplicate::All)
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed because: {}", e));

    let dummy = Dummy();

    for _ in 0..10 {
        error!("This is an error message for {}", dummy);
        warn!("This is a warning for {}", dummy);
        info!("This is an info message for {}", dummy);
        debug!("This is a debug message for {}", dummy);
        trace!("This is a trace message for {}", dummy);
    }
}

struct Dummy();
impl std::fmt::Display for Dummy {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        info!("Here comes the inner message :-| ");
        f.write_str("Dummy!!")?;
        Ok(())
    }
}
