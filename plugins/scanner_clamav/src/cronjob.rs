use std::{
    fs,
    path::Path,
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{anyhow, Result};
use coarsetime::Clock;
use lazy_static::lazy_static;
use log::*;
use walkdir::WalkDir;

use crate::{
    configs::{self, CLAMAV_MAX_FILESIZE},
    detector::DetectTask,
    filter::Filter,
    get_file_btime,
};

lazy_static! {
    static ref CPU_TICKS: f32 = procfs::ticks_per_second().unwrap() as f32;
    static ref CPU_BOOTTIME: u64 = procfs::boot_time_secs().unwrap();
}

pub fn get_pid_live_time(pid: i32) -> Result<u64> {
    let process = procfs::process::Process::new(pid)?;
    let start_time = process.stat.starttime as f32;
    let seconds_since_boot = (start_time / *CPU_TICKS) as u64;
    let timestamp = Clock::now_since_epoch().as_secs();
    if seconds_since_boot + *CPU_BOOTTIME > timestamp {
        return Err(anyhow!("timestamp underflowed"));
    }
    return Ok(timestamp - seconds_since_boot - *CPU_BOOTTIME);
}

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
            let start_timestap = Clock::now_since_epoch().as_secs();
            // step-1
            // scan config dirs
            for conf in configs::SCAN_DIR_CONFIG {
                let mut w_dir = WalkDir::new(conf.fpath)
                    .max_depth(conf.max_depth)
                    .follow_links(false)
                    .into_iter();
                loop {
                    let entry = match w_dir.next() {
                        None => break,
                        Some(Err(_err)) => {
                            break;
                        }
                        Some(Ok(entry)) => entry,
                    };
                    let filter_flag = filter.catch(&entry.path());
                    if filter_flag == 1 {
                        continue;
                    } else if filter_flag == 2 {
                        w_dir.skip_current_dir();
                        debug!("skip cur dir{:?}", &entry.path());
                        continue;
                    }

                    let fp = entry.path();
                    let (fsize, btime) = match fp.metadata() {
                        Ok(p) => {
                            if p.is_dir() {
                                continue;
                            }
                            let fsize = p.len() as usize;
                            let btime = get_file_btime(&p);
                            (fsize, btime)
                        }
                        Err(_) => {
                            continue;
                        }
                    };
                    if fsize <= 1 || fsize > CLAMAV_MAX_FILESIZE {
                        continue;
                    }
                    // send to scan
                    let task = DetectTask {
                        task_type: "6051".to_string(),
                        pid: -1,
                        path: fp.to_string_lossy().to_string(),
                        rpath: fp.to_string_lossy().to_string(),
                        size: fsize,
                        btime: btime.0,
                        mtime: btime.1,
                        token: "".to_string(),
                    };

                    while sender.len() > 2 {
                        std::thread::sleep(Duration::from_secs(8));
                    }

                    match sender.send(task) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("internal task send err {:?}", e);
                            s_locker.send(()).unwrap();
                        }
                    };
                    std::thread::sleep(Duration::from_secs(20));
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
                // scan the process lived 10mins
                if let Ok(pid_live_time) = get_pid_live_time(pid) {
                    if pid_live_time <= 300 {
                        continue;
                    }
                } else {
                    continue;
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
                        let btime = get_file_btime(&p);
                        (fsize, btime)
                    }
                    Err(_) => {
                        continue;
                    }
                };
                if fsize <= 0 || fsize > CLAMAV_MAX_FILESIZE {
                    continue;
                }
                // send to scan
                let task = DetectTask {
                    task_type: "6052".to_string(),
                    pid: pid,
                    path: pstr.to_string(),
                    rpath: exe_real,
                    size: fsize,
                    btime: btime.0,
                    mtime: btime.1,
                    token: "".to_string(),
                };
                while sender.len() > 2 {
                    std::thread::sleep(Duration::from_secs(8));
                }
                match sender.send(task) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("internal task send err {:?}", e);
                        s_locker.send(()).unwrap();
                    }
                };
                std::thread::sleep(Duration::from_secs(20));
            }
            // sleep cron_interval
            let timecost = Clock::now_since_epoch().as_secs() - start_timestap;
            thread::sleep(Duration::from_secs(3600 * 24 - (timecost % (3600 * 24))));
        });
        return Self { job };
    }
}
