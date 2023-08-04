use std::{
    collections::HashMap,
    fs,
    path::Path,
    thread::{self, JoinHandle},
    time::Duration,
};

use super::cronjob::get_pid_live_time;
use anyhow::{anyhow, Result};
use coarsetime::Clock;
use crossbeam_channel::{after, bounded, select, tick};
use log::*;
use serde::{self, Deserialize, Serialize};
use serde_json;
use walkdir::WalkDir;

use crate::{
    config::{
        FULLSCAN_CPU_IDLE_INTERVAL, FULLSCAN_CPU_QUOTA_DEFAULT_MAX, FULLSCAN_CPU_QUOTA_DEFAULT_MIN,
        FULLSCAN_MAX_SCAN_ENGINES, FULLSCAN_SCAN_MODE_QUICK, SCAN_DIR_CONFIG,
    },
    data_type::{
        DetectFileEvent, DetectProcEvent, FullScanTask, ScanTaskProcExe, ScanTaskStaticFile,
        DETECT_TASK,
    },
    detector::Scanner,
    filter::Filter,
    get_available_worker_cpu_quota, get_file_btime, is_filetype_filter_skipped,
    model::engine::clamav::{updater, Clamav},
    ToAgentRecord,
};

#[derive(PartialEq)]
pub enum FullScanResult {
    FULLSCANN_SUCCEED,
    FULLSCANN_TIMEOUT,
    FULLSCANN_FAILED,
}

impl std::fmt::Display for FullScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let result: &str = match &self {
            FullScanResult::FULLSCANN_SUCCEED => "succeed",
            FullScanResult::FULLSCANN_TIMEOUT => "failed",
            FullScanResult::FULLSCANN_FAILED => "failed",
        };
        write!(f, "{}", result)
    }
}

pub struct SuperDetector {
    pub client: plugins::Client,
    pub task_receiver: crossbeam_channel::Receiver<DETECT_TASK>,
    scanner: Scanner,
    exit_timeout: u64,
    token: String,
}

impl SuperDetector {
    pub fn new(
        client: plugins::Client,
        task_receiver: crossbeam_channel::Receiver<DETECT_TASK>,
        engine: &Clamav,
        exit_timeout: u64,
        token: String,
    ) -> Self {
        return Self {
            client: client,
            task_receiver: task_receiver,
            scanner: Scanner {
                inner: engine.clone(),
            },
            exit_timeout: exit_timeout,
            token: token,
        };
    }
    pub fn work(&mut self, recv_timeout: Duration) -> Result<FullScanResult> {
        let mut first = true;
        let exit_timeout_ticker = tick(Duration::from_secs(self.exit_timeout * 3600));

        loop {
            select! {
                recv(self.task_receiver)->data=>{
                    let task:DETECT_TASK = match data{
                        Ok(d) =>d,
                        Err(_) =>{
                            info!("[FulScan] Child exit");
                            return Ok(FullScanResult::FULLSCANN_SUCCEED);
                        },
                    };
                    match task{
                        DETECT_TASK::TASK_6051_STATIC_FILE(t) =>{
                                debug!("scan {:?}",t.scan_path);
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = self.scanner.scan_fast(&t.scan_path){
                                    let event = DetectFileEvent {
                                        types: ftype.to_string(),
                                        class:fclass.to_string(),
                                        name: fname.to_string(),
                                        exe: t.scan_path.to_string(),
                                        static_file: t.scan_path.to_string(),
                                        exe_size: t.size.to_string(),
                                        create_at:t.btime.0.to_string(),
                                        modify_at:t.btime.1.to_string(),
                                        exe_hash: xhash.to_string(),
                                        md5_hash: md5sum.to_string(),
                                        matched_data: matched_data
                                    };

                                    if &ftype != "not_detected"{
                                        info!("filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{} name:{}",
                                            &t.scan_path,
                                            &t.size,
                                            &md5sum,
                                            &t.btime.0,
                                            &t.btime.1,
                                            &ftype,
                                            &fclass,
                                            &fname
                                        );
                                        if let Err(e) = self.client.send_record(&event.to_record_token(&self.token.to_string())) {
                                            warn!("send err, should exit : {:?}",e);
                                            return Err(anyhow!("FullScan Child client_send err return : {:?}",e));
                                        };
                                    }
                                }
                        },
                        DETECT_TASK::TASK_6052_PROC_EXE(t) =>{
                            debug!("scan pid {:?}",t.pid);
                            match self.scanner.scan_fast(&t.scan_path){
                                Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) => {
                                    let event = DetectProcEvent::new(
                                            t.pid,
                                            &ftype,
                                            &fclass,
                                            &fname,
                                            &t.scan_path,
                                            &xhash,
                                            &md5sum,
                                            t.size,
                                            t.btime.0,
                                            t.btime.1,
                                            matched_data,
                                        );

                                    if &ftype != "not_detected"{
                                        info!("[FullScan]filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{}name:{}",
                                            &t.scan_path,
                                            &t.size,
                                            &md5sum,
                                            &t.btime.0,
                                            &t.btime.1,
                                            &ftype,
                                            &fclass,
                                            &fname
                                        );
                                            if let Err(e) = self.client.send_record(&event.to_record_token(&self.token.to_string())) {
                                            warn!("send err, should exit : {:?}",e);
                                            return Err(anyhow!("FullScan Child client_send err return : {:?}",e));
                                        };
                                    }
                                },
                                Err(e) => {
                                    warn!("error {:?} while scann {:?}",e,&t.scan_path);
                                },
                            };
                        },
                        _=>{},
                   }
                }
                recv(after(recv_timeout)) -> _ => {
                    info!("[FullScan] work recv timed out, clean buf");
                    return Ok(FullScanResult::FULLSCANN_SUCCEED)
                }
                recv(exit_timeout_ticker) -> _ =>{
                    info!("[FullScan] work exit timed out, clean buf");
                    return Ok(FullScanResult::FULLSCANN_TIMEOUT)
                }
            }
        }
    }
}

pub fn FullScan(
    pid: u32,
    client: plugins::Client,
    engine: &Scanner,
    fullscan_cfg: &FullScanTask,
) -> (JoinHandle<()>, Vec<JoinHandle<Result<FullScanResult>>>) {
    // unlimit_cgroup
    info!("[FullScan] init: bankai");
    let mut engine_count = 1;
    let fullscan_mode = fullscan_cfg.scan_mode_full;

    let (s, r) = bounded(64);
    let sender = s.clone();

    let mut filter = Filter::new(100);
    let job = thread::spawn(move || {
        // step-1
        // proc scan
        info!("[FullScan] step-1: /proc/pid/exe");
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

            let pstr: &str = &format!("/proc/{}/exe", pid);
            let fp = Path::new(pstr);
            let (mut fsize, mut btime) = (0, (0, 0));
            let exe_real = match fs::read_link(fp) {
                Ok(pf) => pf.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            // proc filter
            if filter.catch(Path::new(&exe_real)) != 0 {
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

            if fsize <= 8 || fsize > 1024 * 1024 * 100 {
                continue;
            }
            // send to scan
            let task = ScanTaskProcExe {
                pid: pid,
                pid_exe: pstr.to_string(),
                scan_path: exe_real,
                size: fsize,
                btime: btime,
            };
            match sender.send(DETECT_TASK::TASK_6052_PROC_EXE(task)) {
                Ok(_) => {}
                Err(e) => {
                    warn!("internal task send err {:?}", e);
                    break;
                }
            };
        }

        // step-2
        info!("[FullScan] step-2: fulldisk");
        match fullscan_mode {
            true => {
                filter.add("/proc");
                // scan full mode
                let mut w_dir = WalkDir::new("/").follow_links(false).into_iter();
                loop {
                    let entry = match w_dir.next() {
                        None => break,
                        Some(Err(_err)) => {
                            warn!("walkdir err while full:{:?}", _err);
                            continue;
                        }
                        Some(Ok(entry)) => entry,
                    };

                    match filter.catch(&entry.path()) {
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
                            if p.is_dir() {
                                continue;
                            }
                            let fsize = p.len() as usize;
                            let btime = get_file_btime(&p);
                            (fsize, btime)
                        }
                        Err(_err) => {
                            //warn!("walkdir err while full: get {:?} metadata {:?}", fp, _err);
                            continue;
                        }
                    };
                    if fsize <= 4 || fsize > 1024 * 1024 * 100 {
                        continue;
                    }
                    let fpath_str = fp.to_string_lossy().to_string();
                    if let Ok(false) = is_filetype_filter_skipped(&fpath_str) {
                        // send to scan
                        let task = ScanTaskStaticFile {
                            scan_path: fpath_str.to_string(),
                            size: fsize,
                            btime: btime,
                        };

                        match sender.send(DETECT_TASK::TASK_6051_STATIC_FILE(task)) {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("internal task send err {:?}", e);
                                break;
                            }
                        };
                    }
                }
            }
            false => {
                for conf in &*SCAN_DIR_CONFIG {
                    let mut w_dir = WalkDir::new(&conf.fpath)
                        .same_file_system(true)
                        .follow_links(false)
                        .into_iter();
                    loop {
                        let entry = match w_dir.next() {
                            None => break,
                            Some(Err(_err)) => {
                                warn!("walkdir err while full:{:?}", _err);
                                continue;
                            }
                            Some(Ok(entry)) => entry,
                        };
                        match filter.catch(&entry.path()) {
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
                                if p.is_dir() {
                                    continue;
                                }
                                let fsize = p.len() as usize;
                                let btime = get_file_btime(&p);
                                (fsize, btime)
                            }
                            Err(_err) => {
                                //warn!("walkdir err while full: get {:?} metadata {:?}", fp, _err);
                                continue;
                            }
                        };
                        if fsize <= 4 || fsize > 1024 * 1024 * 100 {
                            continue;
                        }
                        let fpath_str = fp.to_string_lossy().to_string();
                        if let Ok(false) = is_filetype_filter_skipped(&fpath_str) {
                            // send to scan
                            let task = ScanTaskStaticFile {
                                scan_path: fpath_str.to_string(),
                                size: fsize,
                                btime: btime,
                            };

                            match sender.send(DETECT_TASK::TASK_6051_STATIC_FILE(task)) {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("internal task send err {:?}", e);
                                    break;
                                }
                            };
                        }
                    }
                }
            }
        };
        info!("[FullScan] finished");
    });

    let mut worker_job = Vec::new();
    let exit_timeout = fullscan_cfg.max_scan_timeout_hour;

    for i in 0..engine_count {
        let nt_client = client.clone();
        let nt_recv = r.clone();
        let nt_engine = engine.inner.clone();
        let token = fullscan_cfg.token.to_string();
        let tmp_job = thread::spawn(move || {
            let mut tmp_sdetector =
                SuperDetector::new(nt_client, nt_recv, &nt_engine, exit_timeout, token);
            return tmp_sdetector.work(Duration::from_secs(30));
        });
        worker_job.push(tmp_job);
        std::thread::sleep(Duration::from_secs(2));
    }
    return (job, worker_job);
}
