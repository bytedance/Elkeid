use crate::{
    config::{self, LOAD_MMAP_MAX_SIZE, WAIT_INTERVAL_DIR_SCAN, WAIT_INTERVAL_PROC_SCAN},
    detector::{get_file_bmtime, DetectTask},
    filter::Filter,
};
use anyhow::*;
use coarsetime::Clock;
use log::*;
use std::{
    fs::{self},
    path::Path,
    thread::{self, JoinHandle},
    time::Duration,
};
use walkdir::WalkDir;

// Cronjob
pub struct Cronjob {
    pub job: JoinHandle<i32>,
}

impl Cronjob {
    pub fn new(
        sender: crossbeam_channel::Sender<DetectTask>,
        s_locker: crossbeam_channel::Sender<()>,
        cron_interval: u64,
    ) -> Self {
        let filter = Filter::new(100);
        let job = thread::spawn(move || loop {
            // step-1
            // scan config dirs
            for conf in config::SCAN_DIR_CONFIG {
                let mut w_dir = WalkDir::new(conf.fpath)
                    .max_depth(conf.max_depth)
                    .follow_links(false)
                    .into_iter();
                loop {
                    let entry = match w_dir.next() {
                        None => break,
                        Some(Err(err)) => {
                            error!("ERROR: '{}' scanning :'{}'", err, conf.fpath);
                            break;
                        }
                        Some(Ok(entry)) => entry,
                    };
                    let filter_flag = filter.catch(&entry.path());
                    if filter_flag == 1 {
                        continue;
                    } else if filter_flag == 2 {
                        w_dir.skip_current_dir();
                    }
                    // speed limit
                    std::thread::sleep(WAIT_INTERVAL_DIR_SCAN);
                    let fp = entry.path();
                    let (fsize, btime) = match fp.metadata() {
                        Ok(p) => {
                            if p.is_dir() {
                                continue;
                            }
                            let fsize = p.len() as usize;
                            let btime = get_file_bmtime(&p);
                            (fsize, btime)
                        }
                        Err(_) => {
                            continue;
                        }
                    };
                    if fsize <= 1 || fsize > LOAD_MMAP_MAX_SIZE {
                        continue;
                    }
                    // send to scan
                    let task = DetectTask {
                        task_type: "6001".to_string(),
                        pid: -1,
                        path: format!("{}", fp.display()),
                        rpath: format!("{}", fp.display()),
                        size: fsize,
                        btime: btime.0,
                        mtime: btime.1,
                        token: "".to_string(),
                    };
                    // scan channal is full wait 2 second
                    while sender.is_full() {
                        std::thread::sleep(Duration::from_secs(2));
                    }
                    match sender.try_send(task) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("internal task send err {:?}", e);
                            s_locker.send(()).unwrap();
                        }
                    };
                }
            }
            // step-2
            // proc scan
            let dir_p = fs::read_dir("/proc").unwrap();
            for each in dir_p {
                let each_en = match each {
                    Ok(en) => en,
                    Err(_) => continue,
                };
                let pid = match each_en.file_name().to_string_lossy().parse::<i32>() {
                    Ok(opid) => opid,
                    Err(_) => continue,
                };
                // speed limit
                std::thread::sleep(WAIT_INTERVAL_PROC_SCAN);
                // scan the process lived 10mins
                if let Ok(pid_live_time) = get_pid_live_time(pid) {
                    if pid_live_time < 60 * 10 {
                        continue;
                    }
                }
                let pstr: &str = &format!("/proc/{}/exe", pid);
                let fp = Path::new(pstr);
                let exe_real = match fs::read_link(fp) {
                    Ok(pf) => pf.to_string_lossy().to_string(),
                    Err(_) => continue,
                };

                // proc filter
                let filter_flag = filter.catch(Path::new(&exe_real));
                if filter_flag != 0 {
                    continue;
                }
                let rfp = Path::new(&exe_real);
                let (fsize, btime) = match rfp.metadata() {
                    Ok(p) => {
                        if p.is_dir() {
                            continue;
                        }
                        let fsize = p.len() as usize;
                        let btime = get_file_bmtime(&p);
                        (fsize, btime)
                    }
                    Err(_) => {
                        continue;
                    }
                };
                if fsize <= 0 || fsize > LOAD_MMAP_MAX_SIZE {
                    continue;
                }
                // send to scan
                let task = DetectTask {
                    task_type: "6002".to_string(),
                    pid: pid,
                    path: pstr.to_string(),
                    rpath: exe_real,
                    size: fsize,
                    btime: btime.0,
                    mtime: btime.1,
                    token: "".to_string(),
                };
                // scan channal is full wait 2 second
                while sender.is_full() {
                    std::thread::sleep(Duration::from_secs(2));
                }

                match sender.try_send(task) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("internal task send err {:?}", e);
                        s_locker.send(()).unwrap();
                    }
                };
            }
            // sleep cron_interval
            thread::sleep(Duration::from_secs(cron_interval))
        });
        return Self { job };
    }
}

// get process running test from /proc/
// /proc/pid/stat
pub fn get_pid_live_time(pid: i32) -> Result<u64> {
    let ticks = procfs::ticks_per_second()? as f32;
    let boottime = procfs::boot_time_secs()?;
    let process = procfs::process::Process::new(pid)?;
    let start_time = process.stat.starttime as f32;
    let seconds_since_boot = ((start_time / ticks) as i64) as u64;
    let timestamp = Clock::now_since_epoch().as_secs();
    return Ok(timestamp - seconds_since_boot - boottime);
}
