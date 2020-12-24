use log::*;

#[test]
fn you_must_see_exactly_three_messages_above_1_err_1_warn_1_info() {
    flexi_logger::Logger::with_str("info").start().unwrap();

    error!("This is an error message");
    warn!("This is a warning");
    info!("This is an info message");
    debug!("This is a debug message - you must not see it!");
    trace!("This is a trace message - you must not see it!");
}
