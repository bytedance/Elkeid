use log::*;

use plugins::logger::*;

use std::{env, path::PathBuf, process::exit};

use scanner::model::engine::clamav::updater;

pub const WAIT_INTERVAL_DAILY: u64 = 3600;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let args_count = args.len();

    let mut fpath = "";

    if args_count != 2 {
        println!("Usage ./scanner_cli fname ");
        return;
    } else {
        fpath = &args[1];
    }

    let fp = std::path::Path::new(fpath);
    if !std::path::Path::new(fpath).exists() {
        error!("path not exists");
        return;
    }

    // set logger
    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./scanner_cli.log"),
        file_level: LevelFilter::Info,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: None,
    });

    match set_boxed_logger(Box::new(logger)) {
        Ok(_) => {}
        Err(e) => {
            error!("Err {:?}", e)
        }
    };

    info!("init db manager");
    let db_manager = match env::var("DETAIL") {
        Ok(val) => {
            let dm: updater::DBManager = match serde_json::from_str(&val) {
                Ok(t) => t,
                Err(e) => {
                    error!("{:?} rule Deserialize err : {:?}", &val, e);
                    if let Ok(db) = updater::DBManager::new(
                        updater::ARCHIVE_DB_VERSION,
                        updater::ARCHIVE_DB_HASH,
                        updater::ARCHIVE_DB_PWD,
                        updater::DB_URLS,
                    ) {
                        db
                    } else {
                        error!("db init err");
                        return;
                    }
                }
            };
            dm
        }
        Err(_) => {
            if let Ok(db) = updater::DBManager::new(
                updater::ARCHIVE_DB_VERSION,
                updater::ARCHIVE_DB_HASH,
                updater::ARCHIVE_DB_PWD,
                updater::DB_URLS,
            ) {
                db
            } else {
                error!("db init err");
                return;
            }
        }
    };

    match db_manager.get() {
        Ok(_) => {
            info!("get db success!");
        }
        Err(e) => {
            error!("get db err {:?}", e);
            return;
        }
    }

<<<<<<< HEAD
    let mut scanner = match scanner::detector::Scanner::new("./dat") {
=======
    #[cfg(feature = "ai_php_local")]
    let mut scanner = match scanner_clamav::detector::Scanner::new(
        tflite::config::DB_DEFAULT,
        tflite::config::MODEL_PHP_PATH,
    ) {
>>>>>>> 158296b (update scanner)
        Ok(s) => s,
        Err(e) => {
            warn!("db init err, should exit : {:?}", e);
            exit(1);
        }
    };

    if fp.is_file() {
        match scanner.scan(fpath) {
            Ok((ftype, class, name, xhash, md5sum, matched_data)) => {
                if &ftype != "not_detected" {
                    info!(
                        "scan {} : ftype={}, class={}, name={}, xhash={}, md5sum={}",
                        fpath, ftype, class, name, xhash, md5sum
                    );
                    if let Some(mdata) = matched_data {
                        println!("YARA HIT: {:?}", mdata);
                    }
                }
            }
            Err(e) => {
                error!("scan {} : err :{}", fpath, e);
            }
        };
    } else if fp.is_dir() {
        let mut it = walkdir::WalkDir::new(fpath).into_iter();
        loop {
            let entry = match it.next() {
                None => break,
                Some(Err(err)) => panic!("ERROR: {}", err),
                Some(Ok(entry)) => entry,
            };
            if entry.path().is_dir() {
                continue;
            }
            let tfpath = entry.path().to_string_lossy().to_string();

            match scanner.scan(&tfpath) {
                Ok((ftype, class, name, xhash, md5sum, matched_data)) => {
                    if &ftype != "not_detected" {
                        println!(
                            "Catched file {} : ftype = {}, class = {}, name = {}, xhash = {}, md5sum={}",
                            &tfpath, &ftype, &class, &name, &xhash, &md5sum
                        );
                        if let Some(mdata) = matched_data {
                            println!("YARA HIT: {:?}", mdata);
                        }
                    }
                Err(e) => {
                    error!("scan {} : err :{}", &tfpath, e);
                }
            };
        }
    }
}
