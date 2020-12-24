#![feature(extern_crate_item_prelude)]
#![feature(test)]

extern crate flexi_logger;
extern crate test;
#[macro_use]
extern crate log;

use flexi_logger::Logger;
use test::Bencher;

#[bench]
fn b10_no_logger_active(b: &mut Bencher) {
    b.iter(use_error);
}

#[bench]
fn b20_initialize_logger(_: &mut Bencher) {
    Logger::with_str("info")
        .log_to_file()
        .directory("log_files")
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));
}

#[bench]
fn b30_relevant_logs(b: &mut Bencher) {
    b.iter(use_error);
}

#[bench]
fn b40_suppressed_logs(b: &mut Bencher) {
    b.iter(use_trace);
}

fn use_error() {
    for _ in 1..100 {
        error!("This is an error message");
    }
}
fn use_trace() {
    for _ in 1..100 {
        trace!("This is a trace message");
    }
}
