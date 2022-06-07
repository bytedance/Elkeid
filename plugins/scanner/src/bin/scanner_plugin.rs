use crossbeam_channel::bounded;
use log::*;

use plugins::{logger::*, Client};

use std::{env, fs::File, path::PathBuf, thread, time::Duration};

use scanner::{
    detector::Detector,
    model::engine::clamav::{self, updater},
    model::functional::cronjob::Cronjob,
};

use fs2::FileExt;

pub const WAIT_INTERVAL_DAILY: u64 = 24 * 3600;

pub struct ProcessLock {
    file: File,
}

// scanner locker
impl ProcessLock {
    pub fn new() -> Self {
        let file_path = "/var/run/elkeid_scanners_plugin.pid";
        let file = File::create(file_path).unwrap();
        Self { file }
    }
    pub fn process_lock(&self) -> bool {
        return match self.file.try_lock_exclusive() {
            Ok(_) => true,
            Err(_) => false,
        };
    }
}

fn main() {
    /* flock */
    let process_lock = ProcessLock::new();
    if !process_lock.process_lock() {
        eprintln!("Clamav running duplicate, exit");
        return;
    };

    let pid = std::process::id();
    info!("pid : {:?}", pid);

    #[cfg(feature = "cg_ctrl")]
    scanner::setup_cgroup(pid, 1024 * 1024 * 180, 10000);

    let client = Client::new(true);

    // set logger
    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./scanner.log"),
        file_level: LevelFilter::Info,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: Some(client.clone()),
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

    let client_c = client.clone();

    info!("scanner start!");

    let (s, r) = bounded(256);
    let (s_lock, r_lock) = bounded(0);

    // main detector worker
    let s_recv_worker = s.clone();
    let s_recv_lock = s_lock.clone();

    let mut mworker = Detector::new(
        pid,
        client_c,
        s_recv_worker,
        r,
        s_recv_lock,
        clamav::config::DB_DEFAULT,
        db_manager,
    );

    thread::spawn(move || loop {
        let mut _timeout = 300;
        mworker.work(Duration::from_secs(_timeout));
    });

    // cronjob scan dir and proc
    let s_cron_worker = s.clone();
    let s_cron_lock = s_lock.clone();
    let _cronjob_t = Cronjob::new(s_cron_worker, s_cron_lock, WAIT_INTERVAL_DAILY);

    // wait childs
    let _: () = r_lock.recv().unwrap();

    info!("[Main exit] bye ~");
}
