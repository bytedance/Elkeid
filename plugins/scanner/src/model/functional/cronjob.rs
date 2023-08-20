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
    config::CLAMAV_MAX_FILESIZE, filter::Filter, get_file_btime, is_filetype_filter_skipped,
};

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
                            while sender_proc.len() > 2 {
                                std::thread::sleep(Duration::from_secs(8));
                            }
                            match sender_proc.send(DETECT_TASK::TASK_6051_STATIC_FILE(task)) {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("internal task send err {:?}", e);
                                    s_locker_proc.send(()).unwrap();
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

        let mut scan_cache: HashMap<(i32, String), bool> = HashMap::new();

        let job_proc = thread::spawn(move || loop {
            let start_timestamp = Clock::now_since_epoch().as_secs();
            info!("[CronjobProc] Scan started at : {}", start_timestamp);
            let dir_p = fs::read_dir("/proc").unwrap();

            let mut scan_cache_tmp: HashMap<(i32, String), bool> = HashMap::new();

            for each in dir_p {
                let each_en = match each {
                    Ok(en) => en,
                    Err(_) => continue,
                };

                let pid = match each_en.file_name().to_string_lossy().parse::<i32>() {
                    Ok(opid) => opid,
                    Err(_) => continue,
                };

                let pstr: &str = &format!("/proc/{}/exe", pid);
                let fp = Path::new(pstr);
                let (mut fsize, mut btime) = (0, (0, 0));
                let exe_real = match fs::read_link(fp) {
                    Ok(pf) => pf.to_string_lossy().to_string(),
                    Err(_) => "-3".to_string(),
                };

                if filter_proc.catch(Path::new(&exe_real)) != 0 {
                    continue;
                }

                let pfstr = format!("/proc/{}/root{}", pid, &exe_real);

                (fsize, btime) = match Path::new(&pfstr).metadata() {
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

                if let Some(_) = scan_cache.get(&(pid, exe_real.to_string())) {
                    scan_cache_tmp.insert((pid, exe_real.to_string()), true);
                    continue;
                }

                // send to scan
                let task = ScanTaskProcExe {
                    pid: pid,
                    pid_exe: pstr.to_string(),
                    scan_path: exe_real.to_string(),
                    size: fsize,
                    btime,
                };

                while sender.len() > 8 {
                    std::thread::sleep(Duration::from_secs(8));
                }

                match sender.send(DETECT_TASK::TASK_6052_PROC_EXE(task)) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("internal task send err {:?}", e);
                        s_locker.send(()).unwrap();
                    }
                };
                scan_cache_tmp.insert((pid, exe_real.to_string()), true);
                std::thread::sleep(Duration::from_secs(8));
            }

            scan_cache.clear();
            for ((ipid, iexe), v) in scan_cache_tmp.into_iter() {
                scan_cache.insert((ipid, iexe.to_string()), v);
            }

            // sleep cron_interval
            let end_timestamp = Clock::now_since_epoch().as_secs();
            let timecost = end_timestamp - start_timestamp;
            let left_sleep = 3600 - (timecost % 3600);
            info!(
                "[CronjobProc]Scan end at {}, start at {}, cost {}, will sleep {}.",
                end_timestamp, start_timestamp, timecost, left_sleep
            );
            thread::sleep(Duration::from_secs(left_sleep));
        });
        return Self { job_dir, job_proc };
    }
}
