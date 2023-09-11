use std::{
    fs,
    path::Path,
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::Result;
use coarsetime::Clock;
use lazy_static::lazy_static;
use log::*;
use std::collections::HashMap;
use walkdir::WalkDir;

use crate::data_type::{ScanTaskProcExe, ScanTaskStaticFile, DETECT_TASK};
use crate::{
    config::CLAMAV_MAX_FILESIZE, filter::Filter, get_file_btime, get_file_xhash,
    is_filetype_filter_skipped,
};

use sysinfo::{
    Gid, Pid, PidExt, Process, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt, Uid,
};

use lru_cache::LruCache;

lazy_static! {
    static ref CPU_TICKS: f32 = procfs::ticks_per_second().unwrap() as f32;
    static ref CPU_BOOTTIME: u64 = procfs::boot_time_secs().unwrap();
}

pub fn get_pid_live_time(pid: i32) -> Result<u64> {
    let process = procfs::process::Process::new(pid)?;
    let start_time = process.stat()?.starttime as f32;
    let seconds_since_boot = (start_time / *CPU_TICKS) as u64;
    let timestamp = Clock::now_since_epoch().as_secs();
    return Ok(timestamp - seconds_since_boot - *CPU_BOOTTIME);
}

pub struct Cronjob {
    pub job_dir: JoinHandle<i32>,
    pub job_proc: JoinHandle<i32>,
}

impl Cronjob {
    pub fn new(
        sender: crossbeam_channel::Sender<DETECT_TASK>,
        s_locker: crossbeam_channel::Sender<()>,
        cron_interval: u64,
    ) -> Self {
        let filter_proc = Filter::new(100);
        let filter_dir = Filter::new(100);
        let sender_proc = sender.clone();
        let s_locker_proc = s_locker.clone();
        let s_locker_dir = s_locker.clone();
        let job_dir = thread::spawn(move || {
            let mut init_flag = false;
            loop {
                let start_timestamp = Clock::now_since_epoch().as_secs();
                info!("[CronjobDir] Scan started at : {}", start_timestamp);
                for conf in &*crate::config::SCAN_DIR_CONFIG {
                    let mut w_dir = WalkDir::new(&conf.fpath)
                        .max_depth(conf.max_depth)
                        .same_file_system(true)
                        .follow_links(false)
                        .into_iter();
                    loop {
                        let entry = match w_dir.next() {
                            None => break,
                            Some(Err(_err)) => {
                                //warn!("walkdir err while cronjob:{:?}", _err);
                                continue;
                            }
                            Some(Ok(entry)) => entry,
                        };

                        match filter_dir.catch(&entry.path()) {
                            1 => {
                                continue;
                            }
                            2 => {
                                w_dir.skip_current_dir();
                                debug!("skip cur dir{:?}", &entry.path());
                                continue;
                            }
                            _ => {}
                        };

                        let fp = entry.path();
                        let (fsize, btime) = match fp.metadata() {
                            Ok(p) => {
                                if p.is_dir() || p.is_symlink() {
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
                        // add last_motify < 3 day
                        if init_flag && start_timestamp - btime.1 < 3600 * 24 * 3 {
                            continue;
                        }
                        if fsize <= 4 || fsize > *CLAMAV_MAX_FILESIZE {
                            continue;
                        }
                        let fpath_str = fp.to_string_lossy().to_string();
                        if let Ok(false) = is_filetype_filter_skipped(&fpath_str) {
                            // send to scan
                            let task = ScanTaskStaticFile {
                                scan_path: fp.to_string_lossy().to_string(),
                                size: fsize,
                                btime: btime,
                            };
                            while sender.len() > 2 {
                                std::thread::sleep(Duration::from_secs(8));
                            }
                            match sender.send(DETECT_TASK::TASK_6051_STATIC_FILE(task)) {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("internal task send err {:?}", e);
                                    s_locker_dir.send(()).unwrap();
                                }
                            };
                        }
                        std::thread::sleep(Duration::from_secs(20));
                    }
                }
                let end_timestamp = Clock::now_since_epoch().as_secs();
                let timecost = end_timestamp - start_timestamp;
                let left_sleep = 3600 * 24 * 3 - (timecost % (3600 * 24 * 3));
                info!(
                    "[CronjobDir]Scan end at {}, start at {}, cost {}, will sleep {}.",
                    end_timestamp, start_timestamp, timecost, left_sleep
                );
                if !init_flag {
                    init_flag = true
                }
                // sleep cron_interval
                thread::sleep(Duration::from_secs(left_sleep));
            }
        });

        let mut proc_last_started = Clock::now_since_epoch().as_secs();
        let mut proc_first_run = true;
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        let mut scaned_cache = LruCache::new(20480);
        let job_proc = thread::spawn(move || loop {
            let start_timestamp = Clock::now_since_epoch().as_secs();
            info!("[CronjobProc] Scan started at : {}", start_timestamp);
            sys.refresh_all();
            let proc_length = sys.processes().len();
            for (pid, process) in sys.processes() {
                if !proc_first_run && (process.start_time() < proc_last_started) {
                    continue;
                }
                let target_path = process.exe();
                if filter_proc.catch(target_path) != 0 {
                    continue;
                }
                let (mut fsize, mut btime) = (0, (0, 0));
                (fsize, btime) = match target_path.metadata() {
                    Ok(p) => {
                        let fsize = p.len() as usize;
                        let btime = get_file_btime(&p);
                        (fsize, btime)
                    }
                    Err(_) => (0, (0, 0)),
                };

                if fsize <= 8 || fsize > *CLAMAV_MAX_FILESIZE {
                    continue;
                }
                let exe_hash = get_file_xhash(&format!("/proc/{}/exe", process.pid().as_u32()));
                if let Some(_) = scaned_cache.get_mut(&exe_hash) {
                    continue;
                }
                // send to scan
                let task = ScanTaskProcExe {
                    pid: pid.as_u32() as _,
                    pid_exe: process.exe().display().to_string(),
                    scan_path: process.exe().display().to_string(),
                    size: fsize,
                    btime,
                };
                while sender_proc.len() > 512 {
                    std::thread::sleep(Duration::from_secs(4));
                }
                match sender_proc.send(DETECT_TASK::TASK_6052_PROC_EXE(task)) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("internal task send err {:?}", e);
                        s_locker_proc.send(()).unwrap();
                    }
                };
                scaned_cache.insert(exe_hash, true);
            }
            proc_first_run = false;
        });
        return Self { job_dir, job_proc };
    }
}
