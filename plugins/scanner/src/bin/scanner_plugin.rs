use crossbeam_channel::bounded;
use log::*;

use plugins::{logger::*, Client};

use std::{env, fs::File, path::PathBuf, str::FromStr, thread, time::Duration};

use scanner::{
    config::{
        ARCHIVE_DB_HASH, ARCHIVE_DB_PWD, ARCHIVE_DB_VERSION, DB_DEFAULT, DB_URLS,
        SERVICE_DEFAULT_CG_CPU, SERVICE_DEFAULT_CG_MEM, SERVICE_DEFAULT_LOG_LEVEL,
        SERVICE_DEFAULT_LOG_MAX_BAK, SERVICE_DEFAULT_LOG_PATH, SERVICE_DEFAULT_LOG_RLEVEL,
        SERVICE_PID_LOCK_PATH,
    },
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
        let file = File::create(&*SERVICE_PID_LOCK_PATH).unwrap();
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
    if let Err(e) = scanner::setup_cgroup(
        pid,
        1024 * 1024 * (*SERVICE_DEFAULT_CG_MEM),
        1000 * (*SERVICE_DEFAULT_CG_CPU),
    ) {
        return;
    }

    let client = Client::new(true);

    // set logger
    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from(format!("{}scanner.log", &*SERVICE_DEFAULT_LOG_PATH)),
        file_level: LevelFilter::from_str(&*SERVICE_DEFAULT_LOG_LEVEL).unwrap(),
        remote_level: LevelFilter::from_str(&*SERVICE_DEFAULT_LOG_RLEVEL).unwrap(),
        max_backups: *SERVICE_DEFAULT_LOG_MAX_BAK as _,
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
                        &*ARCHIVE_DB_VERSION,
                        &*ARCHIVE_DB_HASH,
                        &*ARCHIVE_DB_PWD,
                        &*DB_URLS,
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
                &*ARCHIVE_DB_VERSION,
                &*ARCHIVE_DB_HASH,
                &*ARCHIVE_DB_PWD,
                &*DB_URLS,
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

    let (s, r) = bounded(8192);
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
        &*DB_DEFAULT,
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
