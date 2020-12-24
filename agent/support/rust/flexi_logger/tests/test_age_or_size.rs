use chrono::Local;
use flexi_logger::{Age, Cleanup, Criterion, Duplicate, Logger, Naming};
use glob::glob;
use log::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Add;

#[test]
fn test_age_or_size() {
    let directory = define_directory();
    Logger::with_str("trace")
        .log_to_file()
        .duplicate_to_stderr(Duplicate::Info)
        .directory(directory.clone())
        .rotate(
            Criterion::AgeOrSize(Age::Second, 80),
            Naming::Numbers,
            Cleanup::Never,
        )
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));
    // info!("test correct rotation by age or size");

    write_log_lines();

    verify_logs(&directory);
}

fn write_log_lines() {
    // Fill first three files by size
    trace!("{}", 'a');
    trace!("{}", 'b');
    trace!("{}", 'c');

    trace!("{}", 'd');
    trace!("{}", 'e');
    trace!("{}", 'f');

    trace!("{}", 'g');
    trace!("{}", 'h');
    trace!("{}", 'i');

    trace!("{}", 'j');

    // now wait to enforce a rotation with a smaller file
    std::thread::sleep(std::time::Duration::from_secs(2));
    trace!("{}", 'k');

    // now wait to enforce a rotation with a smaller file
    std::thread::sleep(std::time::Duration::from_secs(2));
    trace!("{}", 'l');

    // then again fill a file by size
    trace!("{}", 'm');
    trace!("{}", 'n');

    // and do the final rotation:
    trace!("{}", 'o');

    // trace!("{}",'p');
    // trace!("{}",'q');
    // trace!("{}",'r');
    // trace!("{}",'s');
    // trace!("{}",'t');
}

fn define_directory() -> String {
    format!(
        "./log_files/age_or_size/{}",
        Local::now().format("%Y-%m-%d_%H-%M-%S")
    )
}

fn verify_logs(directory: &str) {
    let expected_line_counts = [3, 3, 3, 1, 1, 3, 1];
    // read all files
    let pattern = String::from(directory).add("/*");
    let globresults = match glob(&pattern) {
        Err(e) => panic!(
            "Is this ({}) really a directory? Listing failed with {}",
            pattern, e
        ),
        Ok(globresults) => globresults,
    };
    let mut no_of_log_files = 0;
    let mut total_line_count = 0_usize;
    for (index, globresult) in globresults.into_iter().enumerate() {
        let mut line_count = 0_usize;
        let pathbuf = globresult.unwrap_or_else(|e| panic!("Ups - error occured: {}", e));
        let f = File::open(&pathbuf)
            .unwrap_or_else(|e| panic!("Cannot open file {:?} due to {}", pathbuf, e));
        no_of_log_files += 1;
        let mut reader = BufReader::new(f);
        let mut buffer = String::new();
        while reader.read_line(&mut buffer).unwrap() > 0 {
            line_count += 1;
            buffer.clear();
        }
        assert_eq!(
            line_count, expected_line_counts[index],
            "file has wrong size"
        );
        total_line_count += line_count;
    }

    assert_eq!(no_of_log_files, 7, "wrong file count");
    assert_eq!(total_line_count, 15, "wrong line count!");
}
