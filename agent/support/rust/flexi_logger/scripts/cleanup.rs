//! Cleans up all files and folders that were produced by test runs.
//!
//! ```cargo
//! [dependencies]
//! glob = "*"
//! ```
extern crate glob;

fn main() {
    for pattern in &[
        "./*.log",
        "./*.alerts",
        "./*.seclog",
        "./*logspec.toml",
        "./log_files/**/*.log",
        "./log_files/**/*.zip",
        "./log_files/**/*.gz",
        "./test_spec/*.toml",
    ] {
        for globresult in glob::glob(pattern).unwrap() {
            match globresult {
                Err(e) => eprintln!("Evaluating pattern {:?} produced error {}", pattern, e),
                Ok(pathbuf) => {
                    std::fs::remove_file(&pathbuf).unwrap();
                }
            }
        }
    }

    let dirs: Vec<std::path::PathBuf> = glob::glob("./log_files/**")
        .unwrap()
        .filter_map(|r| match r {
            Err(e) => {
                eprintln!("Searching for folders produced error {}", e);
                None
            }
            Ok(_) => Some(r.unwrap()),
        })
        .collect();
    for pathbuf in dirs.iter().rev() {
        std::fs::remove_dir(&pathbuf).unwrap();
    }

    std::fs::remove_dir("./log_files/").ok();
    std::fs::remove_dir("./test_spec/").ok();
}
