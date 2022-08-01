use std::{
    collections::HashMap,
    fs,
    path::Path,
    thread::{self, JoinHandle},
    time::{self, Duration},
};

use coarsetime::Clock;
use crossbeam_channel::{after, bounded, select, tick};
use log::*;
use walkdir::WalkDir;

use crate::{
    configs,
    detector::{self, DetectFileEvent, DetectProcEvent, DetectTask, Scanner},
    filter::Filter,
    get_file_btime, is_filetype_filter_skipped,
    model::engine::clamav::{updater, Clamav},
    ToAgentRecord,
};

use super::cronjob::get_pid_live_time;

use serde::{self, Deserialize, Serialize};
use serde_json;

pub const MAX_SCAN_ENGINES: u32 = 6;
pub const MAX_SCAN_CPU_100: u32 = 600;
pub const MAX_SCAN_MEM_MB: u32 = 512;
pub const SCAN_MODE_FULL: &str = "full";
pub const SCAN_MODE_QUICK: &str = "quick";

pub struct SuperDetector {
    pub client: plugins::Client,
    pub task_receiver: crossbeam_channel::Receiver<DetectTask>,
    scanner: Scanner,
}

impl SuperDetector {
    pub fn new(
        client: plugins::Client,
        task_receiver: crossbeam_channel::Receiver<DetectTask>,
        engine: &Clamav,
    ) -> Self {
        return Self {
            client: client,
            task_receiver: task_receiver,
            scanner: Scanner {
                inner: engine.clone(),
            },
        };
    }
    pub fn work(&mut self, timeout: time::Duration) {
        let mut first = true;
        loop {
            select! {
                recv(self.task_receiver)->data=>{
                    let task:DetectTask = match data{
                        Ok(d) =>d,
                        Err(e) =>{
                            info!("[FulScan] Child exit");
                            return;
                        },
                    };
                    match &task.task_type[..]{
                        "6051" =>{
                                debug!("scan {:?}",task.path);
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = self.scanner.scan_fast(&task.path){
                                    let t = DetectFileEvent {
                                        types: ftype.to_string(),
                                        class:fclass.to_string(),
                                        name: fname.to_string(),
                                        exe: task.rpath.to_string(),
                                        exe_size: task.size.to_string(),
                                        create_at:task.btime.to_string(),
                                        modify_at:task.mtime.to_string(),
                                        exe_hash: xhash.to_string(),
                                        md5_hash: md5sum.to_string(),
                                        matched_data: matched_data
                                    };

                                    if &ftype != "not_detected"{
                                        info!("filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{} name:{}",
                                            &task.path,
                                            &task.size,
                                            &md5sum,
                                            &task.btime,
                                            &task.mtime,
                                            &ftype,
                                            &fclass,
                                            &fname
                                        );
                                        if let Err(e) = self.client.send_record(&t.to_record()) {
                                            warn!("send err, should exit : {:?}",e);
                                            return
                                        };
                                    }
                                }

                        },
                        "6052" =>{
                            debug!("scan {:?}",task.path);
                            match self.scanner.scan_fast(&task.path){
                                Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) => {
                                    let t = DetectProcEvent::new(
                                            task.pid,
                                            &ftype,
                                            &fclass,
                                            &fname,
                                            &task.rpath,
                                            &xhash,
                                            &md5sum,
                                            task.size,
                                            task.btime,
                                            task.mtime,
                                            matched_data,
                                        ).unwrap_or_default();

                                    if &ftype != "not_detected"{
                                        info!("[FullScan]filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{}name:{}",
                                            &task.path,
                                            &task.size,
                                            &md5sum,
                                            &task.btime,
                                            &task.mtime,
                                            &ftype,
                                            &fclass,
                                            &fname
                                        );
                                            if let Err(e) = self.client.send_record(&t.to_record()) {
                                            warn!("send err, should exit : {:?}",e);
                                            return
                                        };
                                    }
                                },
                                Err(e) => {
                                    warn!("error {:?} while scann {:?}",e,&task.path);
                                },
                            };
                        },
                        _=>{},
                   }

                }
                recv(after(timeout)) -> _ => {
                    info!("[FullScan] work timed out, clean buf");
                    return
                }
            }
        }
    }
}

pub fn FullScan(
    pid: u32,
    client: plugins::Client,
    worker_count: u32,
    cpu: u32,
    mem: u32,
    engine: &detector::Scanner,
    mode: String,
) -> (JoinHandle<()>, Vec<JoinHandle<()>>) {
    // unlimit_cgroup
    info!("[FullScan] init: bankai");
    crate::setup_cgroup(pid, (1024 * 1024 * mem).into(), (1000 * cpu).into());

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
            if fsize <= 4 || fsize > 1024 * 1024 * 100 {
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
                add_ons: None,
                finished: None,
            };
            match sender.send(task) {
                Ok(_) => {}
                Err(e) => {
                    warn!("internal task send err {:?}", e);
                }
            };
        }

        // step-2
        info!("[FullScan] step-2: fulldisk");
        match mode.as_str() {
            SCAN_MODE_FULL => {
                filter.add("/proc");
                // scan full mode
                let mut w_dir = WalkDir::new("/").follow_links(false).into_iter();
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
                            //if p.is_dir() {
                            if !p.is_file() {
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
                    if fsize <= 4 || fsize > 1024 * 1024 * 100 {
                        continue;
                    }
                    let fpath_str = fp.to_string_lossy().to_string();
                    if let Ok(t) = is_filetype_filter_skipped(&fpath_str) {
                        if t {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    // send to scan
                    let task = DetectTask {
                        task_type: "6051".to_string(),
                        pid: -1,
                        path: fpath_str.to_string(),
                        rpath: fpath_str,
                        size: fsize,
                        btime: btime.0,
                        mtime: btime.1,
                        token: "".to_string(),
                        add_ons: None,
                        finished: None,
                    };
                    match sender.send(task) {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("internal task send err {:?}", e);
                        }
                    };
                }
            }
            SCAN_MODE_QUICK | _ => {
                for conf in configs::SCAN_DIR_CONFIG {
                    let mut w_dir = WalkDir::new(conf.fpath)
                        .same_file_system(true)
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
                        if fsize <= 4 || fsize > 1024 * 1024 * 100 {
                            continue;
                        }
                        let fpath_str = fp.to_string_lossy().to_string();
                        if let Ok(t) = is_filetype_filter_skipped(&fpath_str) {
                            if t {
                                continue;
                            }
                        } else {
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
                            add_ons: None,
                            finished: None,
                        };
                        match sender.send(task) {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("internal task send err {:?}", e);
                            }
                        };
                    }
                }
            }
        };
        info!("[FullScan] finished");
    });

    let mut worker_job = Vec::new();

    for i in 0..worker_count {
        let nt_client = client.clone();
        let nt_recv = r.clone();
        let nt_engine = engine.inner.clone();
        let tmp_job = thread::spawn(move || {
            let mut tmp_sdetector = SuperDetector::new(nt_client, nt_recv, &nt_engine);
            tmp_sdetector.work(Duration::from_secs(30));
        });
        worker_job.push(tmp_job);
        std::thread::sleep(Duration::from_secs(2));
    }
    return (job, worker_job);
}
