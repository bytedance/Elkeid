use crate::{
    config::{
        self, FULLSCAN_CPU_IDLE_100PCT, FULLSCAN_CPU_IDLE_INTERVAL, FULLSCAN_CPU_QUOTA_DEFAULT_MAX,
        FULLSCAN_CPU_QUOTA_DEFAULT_MIN, FULLSCAN_MAX_SCAN_CPU_100, FULLSCAN_MAX_SCAN_ENGINES,
        FULLSCAN_MAX_SCAN_MEM_MB, FULLSCAN_MAX_SCAN_TIMEOUT_FULL, FULLSCAN_MAX_SCAN_TIMEOUT_QUICK,
        FULLSCAN_SCAN_MODE_FULL, FULLSCAN_SCAN_MODE_QUICK, SERVICE_DEFAULT_CG_CPU,
        SERVICE_DEFAULT_CG_MEM,
    },
    data_type::{
        self, AntiRansomEvent, DetectFileEvent, DetectOneTaskEvent, DetectProcEvent, FanotifyEvent,
        FullScanTask, RegReport, ScanFinished, ScanTaskUserTask, DETECT_TASK,
    },
    get_file_btime, get_file_md5, get_file_md5_fast, get_file_xhash,
    model::{
        engine::{
            clamav::{self, updater, Clamav},
            ScanEngine,
        },
        functional::{
            anti_ransom::HoneyPot,
            fulldiskscan::{FullScan, FullScanResult},
        },
    },
    ToAgentRecord,
};

use anyhow::{anyhow, Result};
use coarsetime::Clock;
use crossbeam_channel::{after, bounded, select};
use log::*;
use std::{collections::HashMap, path::Path, thread, time};
use walkdir::WalkDir;

use serde::{self, Deserialize, Serialize};
use serde_json;

pub struct Scanner {
    pub inner: Clamav,
}

impl Scanner {
    pub fn new(db_path: &str) -> Result<Self> {
        let mut scanner: Clamav = ScanEngine::new(db_path)?;
        info!("clamav init ok!");
        return Ok(Self { inner: scanner });
    }

    pub fn scan_fast(
        self: &mut Self,
        fpath: &str,
    ) -> Result<(String, String, String, String, String, Option<Vec<String>>)> {
        match self.inner.scan_file(fpath) {
            Ok((result, mut matched_data)) => {
                let mut res: Vec<String> = Vec::new();
                let xhash = get_file_xhash(fpath);
                let md5sum = get_file_md5_fast(fpath);
                let mut ftype = "not_detected".to_string();
                let mut class = "".to_string();
                let mut name = "".to_string();

                // not_detected
                if &result == "OK" {
                    return Ok((
                        "not_detected".to_string(),
                        "".to_string(),
                        "".to_string(),
                        xhash.to_string(),
                        md5sum.to_string(),
                        None,
                    ));
                }

                // format clamav result
                if result.starts_with("YARA.") {
                    res = result
                        .trim_start_matches("YARA.")
                        .trim_end_matches(".UNOFFICIAL")
                        .splitn(3, '_')
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect();
                } else {
                    res = result
                        .trim_end_matches(".UNOFFICIAL")
                        .splitn(3, '.')
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect();
                }

                // format clamav result len
                if res.len() != 3 {
                    // result is not formated, return origin rule name.
                    ftype = "".to_string();
                    class = "".to_string();
                    name = result;
                } else {
                    ftype = res[0].to_string();
                    class = res[1].to_string();
                    name = res[2].to_string();
                }

                /*
                if (ftype.starts_with("Php")
                    && class.starts_with("Webshell")
                    && !fpath.ends_with(".php"))
                    || (ftype.starts_with("Jsp")
                        && class.starts_with("Webshell")
                        && !fpath.ends_with(".jsp"))
                {
                    ftype = "not_detected".to_string();
                    class = "".to_string();
                    name = "".to_string();
                }
                 */
                if &ftype != "not_detected" {
                    info!(
                        "[Catch] filepath:{} result:{}.{}.{}",
                        &fpath, &ftype, &class, &name
                    );
                }

                return Ok((ftype, class, name, xhash, md5sum, matched_data));
            }
            Err(err) => {
                return Err(err);
            }
        }
    }

    pub fn scan(
        self: &mut Self,
        fpath: &str,
    ) -> Result<(String, String, String, String, String, Option<Vec<String>>)> {
        match self.inner.scan_file(fpath) {
            Ok((result, mut matched_data)) => {
                let mut res: Vec<String> = Vec::new();
                let xhash = get_file_xhash(fpath);
                let md5sum = get_file_md5(fpath);
                let mut ftype = "not_detected".to_string();
                let mut class = "".to_string();
                let mut name = "".to_string();

                // not_detected
                if &result == "OK" {
                    return Ok((
                        "not_detected".to_string(),
                        "".to_string(),
                        "".to_string(),
                        xhash.to_string(),
                        md5sum.to_string(),
                        None,
                    ));
                }

                // format clamav result
                if result.starts_with("YARA.") {
                    res = result
                        .trim_start_matches("YARA.")
                        .trim_end_matches(".UNOFFICIAL")
                        .splitn(3, '_')
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect();
                } else {
                    res = result
                        .trim_end_matches(".UNOFFICIAL")
                        .splitn(3, '.')
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect();
                }

                // format clamav result len
                if res.len() != 3 {
                    // result is not formated, return origin rule name.
                    ftype = "".to_string();
                    class = "".to_string();
                    name = result;
                } else {
                    ftype = res[0].to_string();
                    class = res[1].to_string();
                    name = res[2].to_string();
                }

                /*
                if (ftype.starts_with("Php")
                    && class.starts_with("Webshell")
                    && !fpath.ends_with(".php"))
                    || (ftype.starts_with("Jsp")
                        && class.starts_with("Webshell")
                        && !fpath.ends_with(".jsp"))
                {
                    ftype = "not_detected".to_string();
                    class = "".to_string();
                    name = "".to_string();
                }
                 */
                if &ftype != "not_detected" {
                    info!(
                        "[Catch] filepath:{} result:{}.{}.{}",
                        &fpath, &ftype, &class, &name
                    );
                }

                return Ok((ftype, class, name, xhash, md5sum, matched_data));
            }
            Err(err) => {
                return Err(err);
            }
        };
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        info!("drop scanner, clean resource.");
    }
}

pub struct Detector {
    pub client: plugins::Client,
    pub task_receiver: crossbeam_channel::Receiver<DETECT_TASK>,
    s_locker: crossbeam_channel::Sender<()>,
    db_path: String,
    scanner: Option<Scanner>,
    _recv_worker: thread::JoinHandle<()>,
    rule_updater: crossbeam_channel::Receiver<String>,
    db_manager: updater::DBManager,
    ppid: u32,
}

impl Detector {
    pub fn new(
        ppid: u32,
        client: plugins::Client,
        task_sender: crossbeam_channel::Sender<DETECT_TASK>,
        task_receiver: crossbeam_channel::Receiver<DETECT_TASK>,
        s_locker: crossbeam_channel::Sender<()>,
        db_path: &str,
        db_manager: updater::DBManager,
    ) -> Self {
        let recv_worker_s_locker = s_locker.clone();
        let (s, r) = bounded(0);
        // Receive One-time-scan-task : Path
        let mut r_client = client.clone();
        clamav::clamav_init().unwrap();
        let recv_worker = thread::spawn(move || {
            let mut _arf_t: Option<HoneyPot> = None;
            let s_arf_worker = task_sender.clone();
            let s_arf_lock = recv_worker_s_locker.clone();

            _arf_t = match HoneyPot::new(s_arf_worker, s_arf_lock) {
                Ok(mut hp) => {
                    info!("fanotify turn on.");
                    hp.run_cronjob();
                    Some(hp)
                }
                Err(e) => {
                    error!("fanotify init failed in HoneyPot:new with {}", e);
                    None
                }
            };

            loop {
                match r_client.receive() {
                    Ok(t) => {
                        info!("recv task.data {:?}", &t.get_data());
                        match t.data_type {
                            6053 => {
                                // Scan task
                                if task_sender.len() >= 4096 {
                                    warn!(
                                            "recv too many task, drop one : data_type:{},token:{},data:{}",
                                            t.data_type,
                                            t.get_token(),
                                            t.get_data()
                                        );
                                    continue;
                                }
                                let task_map: HashMap<String, String> =
                                    match serde_json::from_str(&t.data) {
                                        Ok(data) => data,
                                        Err(e) => {
                                            warn!("error decode &t.data {:?}", &t.data);
                                            let end_flag = ScanFinished {
                                                data: "failed".to_string(),
                                                error: format!("recv serde_json err {:?}", t.data),
                                            };
                                            continue;
                                        }
                                    };
                                let mut target_path = "".to_string();

                                if let Some(task_exe_scan) = task_map.get("exe") {
                                    if !task_exe_scan.starts_with("/") {
                                        warn!("recv 6053 but not a fullpath {:?}", t.data);
                                        let end_flag = ScanFinished {
                                            data: "failed".to_string(),
                                            error: format!(
                                                "recv 6053 but not a fullpath {:?}",
                                                t.data
                                            ),
                                        };
                                        if let Err(e) = r_client
                                            .send_record(&end_flag.to_record_token(&t.get_token()))
                                        {
                                            warn!("send err, should exit : {:?}", e);
                                        };
                                        continue;
                                        // ignored if not a fullpath from root /
                                    }
                                    target_path = task_exe_scan.to_string();
                                } else {
                                    continue;
                                }

                                let target_p = Path::new(&target_path);
                                if !target_p.exists() {
                                    warn!("6053 target not exists:{}", &target_path);
                                    let end_flag = ScanFinished {
                                        data: "failed".to_string(),
                                        error: format!("6053 target not exists:{}", &target_path),
                                    };
                                    if let Err(e) = r_client
                                        .send_record(&end_flag.to_record_token(&t.get_token()))
                                    {
                                        warn!("send err, should exit : {:?}", e);
                                    };
                                    continue;
                                }
                                if target_p.is_dir() {
                                    let mut w_dir = WalkDir::new(&target_path)
                                        .max_depth(2)
                                        .follow_links(true)
                                        .into_iter();
                                    loop {
                                        let entry = match w_dir.next() {
                                            None => {
                                                let task = ScanTaskUserTask::with_finished(
                                                    t.get_token(),
                                                    "succeed",
                                                    "",
                                                );
                                                if let Err(e) = task_sender.try_send(
                                                    DETECT_TASK::TASK_6053_USER_TASK(task),
                                                ) {
                                                    warn!("internal send task err : {:?}", e);
                                                    let end_flag = ScanFinished {
                                                        data: "failed".to_string(),
                                                        error: e.to_string(),
                                                    };
                                                    if let Err(e) = r_client.send_record(
                                                        &end_flag.to_record_token(&t.get_token()),
                                                    ) {
                                                        warn!("send err, should exit : {:?}", e);
                                                    };
                                                    break;
                                                }
                                                break;
                                            }
                                            Some(Err(_err)) => {
                                                let end_flag = ScanFinished {
                                                    data: "failed".to_string(),
                                                    error: _err.to_string(),
                                                };
                                                if let Err(e) = r_client.send_record(
                                                    &end_flag.to_record_token(&t.get_token()),
                                                ) {
                                                    warn!("send err, should exit : {:?}", e);
                                                };
                                                break;
                                            }
                                            Some(Ok(entry)) => entry,
                                        };
                                        let fp = entry.path();
                                        if fp.is_dir() {
                                            continue;
                                        }
                                        let task = ScanTaskUserTask::with_path(
                                            t.get_token(),
                                            &fp.to_string_lossy(),
                                            Some(task_map.clone()),
                                        );
                                        if let Err(e) = task_sender
                                            .try_send(DETECT_TASK::TASK_6053_USER_TASK(task))
                                        {
                                            warn!("internal send task err : {:?}", e);
                                            let end_flag = ScanFinished {
                                                data: "failed".to_string(),
                                                error: format!("internal task error {:?}", t.data),
                                            };

                                            break;
                                        }
                                    }
                                    continue;
                                }
                                let task = ScanTaskUserTask {
                                    token: t.token,
                                    scan_path: target_path,
                                    add_ons: Some(task_map),
                                    finished: Some(ScanFinished {
                                        data: "succeed".to_string(),
                                        error: "".to_string(),
                                    }),
                                };

                                if let Err(e) =
                                    task_sender.send(DETECT_TASK::TASK_6053_USER_TASK(task))
                                {
                                    warn!("internal send task err : {:?}", e);
                                    continue;
                                }
                            }
                            6050 => {
                                // DB update task
                                // drop resource and renew scanner
                                match s.send(t.data) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        warn!("{}", e);
                                        recv_worker_s_locker.send(()).unwrap();
                                        // Exit if plugin recive task failed.
                                        return;
                                    }
                                };
                            }
                            6051 => {
                                // turn on anti-ransom funcs
                                if let Some(ref mut arf) = _arf_t {
                                    arf.reset_antiransome();
                                    info!("Anti-ransom has been turn on.");
                                } else {
                                    info!("Anti-ransom has been downgrade.");
                                }
                            }
                            6052 => {
                                // turn off anti-ransom funcs
                                if let Some(ref mut arf) = _arf_t {
                                    arf.reset_fanotify();
                                }
                                info!("Anti-ransom has been turn off.");
                            }
                            6054 => {
                                // reset anti-ransom honeypots
                                if let Some(ref mut arf_t) = _arf_t {
                                    arf_t.reset_antiransome();
                                    info!("Anti-ransom has been reset.");
                                } else {
                                    info!("Anti-ransom is off ,will not be reset.");
                                }
                            }
                            6057 => {
                                info!("[Full Disk Scan] Started !");

                                let task_map: HashMap<String, String> =
                                    match serde_json::from_str(&t.data) {
                                        Ok(data) => data,
                                        Err(e) => {
                                            error!("error decode &t.data {:?}", &t.data);
                                            continue;
                                        }
                                    };

                                // supper mode for fulldisk scan
                                let mut full_scan_config = FullScanTask::new_default();
                                full_scan_config.token = t.get_token().to_string();
                                if let Some(worker_c) = task_map.get("worker") {
                                    let worker_cu32: u32 = worker_c.parse().unwrap_or_default();
                                    if worker_cu32 != 0 {
                                        full_scan_config.max_scan_engine = worker_cu32;
                                    }
                                }
                                if let Some(worker_c) = task_map.get("cpu_idle") {
                                    let worker_cu64: u64 = worker_c.parse().unwrap_or_default();
                                    if worker_cu64 != 0 {
                                        full_scan_config.cpu_idle_100pct = worker_cu64;
                                    }
                                }
                                if let Some(worker_c) = task_map.get("cpu") {
                                    let worker_cu32: u32 = worker_c.parse().unwrap_or_default();
                                    if worker_cu32 != 0 {
                                        full_scan_config.max_scan_cpu100 = worker_cu32;
                                    }
                                }

                                if let Some(worker_c) = task_map.get("mem") {
                                    let worker_cu32: u32 = worker_c.parse().unwrap_or_default();
                                    if worker_cu32 != 0 {
                                        full_scan_config.max_scan_mem_mb = worker_cu32;
                                    }
                                }
                                if let Some(worker_c) = task_map.get("mode") {
                                    match worker_c.as_str() {
                                        FULLSCAN_SCAN_MODE_FULL => {
                                            full_scan_config.scan_mode_full = true;
                                            full_scan_config.max_scan_timeout_hour =
                                                *FULLSCAN_MAX_SCAN_TIMEOUT_FULL;
                                        }
                                        _ => {}
                                    };
                                }
                                if let Some(worker_c) = task_map.get("timeout") {
                                    let worker_cu64: u64 = worker_c.parse().unwrap_or_default();
                                    if worker_cu64 != 0 {
                                        full_scan_config.max_scan_timeout_hour = worker_cu64;
                                    }
                                }

                                if let Err(e) = task_sender
                                    .try_send(DETECT_TASK::TASK_6057_FULLSCAN(full_scan_config))
                                {
                                    warn!("internal send task err : {:?}", e);

                                    continue;
                                }
                            }
                            _ => {
                                error!(
                                    "unknown data_type {:?} with task {:?}",
                                    t.data_type, t.data
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                        recv_worker_s_locker.send(()).unwrap();
                        // Exit if plugin recive task failed.
                        return;
                    }
                }
            }
        });

        return Self {
            ppid: ppid,
            client: client,
            task_receiver: task_receiver,
            s_locker: s_locker,
            db_path: db_path.into(),
            scanner: None,
            _recv_worker: recv_worker,
            rule_updater: r,
            db_manager: db_manager,
        };
    }

    pub fn refresh_scanner(&mut self) {
        if let None = self.scanner {
            if let Err(e) = self.db_manager.load() {
                error!("archive db load err: {:?}", e);
                self.s_locker.send(()).unwrap();
                return;
            }
            match Scanner::new(&self.db_path) {
                Ok(s) => {
                    self.scanner = Some(s);
                }
                Err(e) => {
                    warn!("db init err, should exit : {:?}", e);
                    self.s_locker.send(()).unwrap();
                    return;
                }
            };
        }
    }

    pub fn work(&mut self, timeout: time::Duration) {
        info!("start work");
        let work_s_locker = self.s_locker.clone();
        loop {
            select! {
                recv(self.rule_updater)->rules=>{
                    // recv from rule updater
                    match rules{
                        Ok(rdata)=>{
                            let dm :updater::DBManager = match serde_json::from_str(&rdata){
                                Ok(t) =>{t},
                                Err(e) =>{
                                    error!("{:?} rule Deserialize err : {:?}", &rdata, e);
                                    continue; // ignore wrong rule format
                                },
                            };
                            if let Err(e) = self.db_manager.update(
                                &dm.version,
                                &dm.sha256,
                                &dm.passwd,
                                &dm.url.iter().map(|url| url as &str).collect(),
                            ){
                                error!("{:?} db update err : {:?}",dm, e);
                            }
                            let dbinfo = RegReport{
                                db_version: &dm.version,
                                db_sha256: &dm.sha256
                            };

                            if let Err(e) = self.client.send_record(&dbinfo.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                        },
                        Err(e)=>{
                            error!("recv rule err : {:?}", e);
                        }
                    };
                    self.scanner = None;
                    if let Err(e) = self.db_manager.load(){
                        error!("archive db load err: {:?}",e);
                        work_s_locker.send(()).unwrap();
                        return
                    }
                    match Scanner::new(&self.db_path){
                        Ok(s) =>{
                            self.scanner = Some(
                                s
                            );
                        },
                        Err(e) =>{
                            warn!("db init err, should exit : {:?}",e);
                            work_s_locker.send(()).unwrap();
                            return
                        }
                    };
                    info!("rule update ok");
                },
                recv(self.task_receiver)->data=>{
                    // recv scan task
                    debug!("recv work {:?}",data);
                    let task:DETECT_TASK = data.unwrap();
                    match task{
                        DETECT_TASK::TASK_6051_STATIC_FILE(task_data) =>{
                            self.refresh_scanner();
                            debug!("recv work 6051");
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan {:?}",&task_data.scan_path);
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = t.scan(&task_data.scan_path){
                                    let t = DetectFileEvent {
                                        types: ftype.to_string(),
                                        class:fclass.to_string(),
                                        name: fname.to_string(),
                                        exe: task_data.scan_path.to_string(),
                                        static_file: task_data.scan_path.to_string(),
                                        exe_size: task_data.size.to_string(),
                                        create_at: task_data.btime.0.to_string(),
                                        modify_at: task_data.btime.1.to_string(),

                                        exe_hash: xhash.to_string(),
                                        md5_hash: md5sum.to_string(),
                                        matched_data: matched_data
                                    };

                                    if &ftype != "not_detected"{
                                        info!("filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{} name:{}",
                                            &task_data.scan_path,
                                            &task_data.size,
                                            &md5sum,
                                            &task_data.btime.0,
                                            &task_data.btime.1,

                                            &ftype,
                                            &fclass,
                                            &fname
                                        );
                                        if let Err(e) = self.client.send_record(&t.to_record()) {
                                            warn!("send err, should exit : {:?}",e);
                                            work_s_locker.send(()).unwrap();
                                            return
                                        };
                                    }
                                }
                            }
                        },// dir

                        DETECT_TASK::TASK_6052_PROC_EXE(task_data) =>{
                            debug!("recv work 6052");
                            self.refresh_scanner();
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan pid {} {:?}",&task_data.pid, &task_data.scan_path);
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = t.scan(&format!("/proc/{}/exe",task_data.pid)){
                                    let t = DetectProcEvent::new(
                                            task_data.pid,
                                            &ftype,
                                            &fclass,
                                            &fname,
                                            &task_data.scan_path,
                                            &xhash,
                                            &md5sum,
                                            task_data.size,
                                            task_data.btime.0,
                                            task_data.btime.1,
                                            matched_data,
                                    );
                                    if &ftype != "not_detected" &&  &fname != ""{
                                        info!("filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{} name:{}",
                                            &task_data.scan_path,
                                            &task_data.size,
                                            &md5sum,
                                            &task_data.btime.0,
                                            &task_data.btime.1,
                                            &ftype,
                                            &fclass,
                                            &fname
                                        );
                                        if let Err(e) = self.client.send_record(&t.to_record()) {
                                            warn!("send err, should exit : {:?}",e);
                                            work_s_locker.send(()).unwrap();
                                            return
                                        };
                                    }
                                }
                            }
                        }, // proc

                        DETECT_TASK::TASK_6053_USER_TASK(task_data) =>{
                            debug!("recv work 6053");
                            self.refresh_scanner();
                            if let Some(finished) = &task_data.finished{
                                if let Err(e) = self.client.send_record(
                                    &finished.to_record_token(&task_data.token),
                                    ) {
                                        warn!("send err, should exit : {:?}", e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                continue
                            }

                            let fp = Path::new(&task_data.scan_path);
                            let meta = match fp.metadata(){
                                Ok(m)=>m,
                                Err(e)=>{
                                    let resp = &DetectOneTaskEvent{
                                        types: "".to_string(),
                                        class:"".to_string(),
                                        name: "".to_string(),
                                        exe: task_data.scan_path.to_string(),
                                        static_file: task_data.scan_path.to_string(),
                                        exe_size: "".to_string(),
                                        exe_hash: "".to_string(),
                                        md5_hash: "".to_string(),
                                        create_at:"".to_string(),
                                        modify_at:"".to_string(),
                                        error: format!("{:?}",e),
                                        token: task_data.token.to_string(),
                                        matched_data:None,
                                    };
                                    warn!("err scan {}, with {:?}",&task_data.scan_path,e);
                                    if let Err(e) = self.client.send_record(&resp.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                    return
                                }
                            };
                            let btime = get_file_btime(&meta);
                            if let Some(t) = &mut self.scanner{
                                debug!("scan {:?}",&task_data.scan_path);
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = t.scan(&task_data.scan_path){
                                    let event = DetectOneTaskEvent{
                                        types: ftype.to_string(),
                                        class:fclass.to_string(),
                                        name: fname.to_string(),
                                        exe: task_data.scan_path.to_string(),
                                        static_file: task_data.scan_path.to_string(),
                                        exe_size: meta.len().to_string(),
                                        exe_hash: xhash.to_string(),
                                        md5_hash: md5sum.to_string(),
                                        create_at:btime.0.to_string(),
                                        modify_at:btime.1.to_string(),
                                        error: "".to_string(),
                                        token: task_data.token.to_string(),
                                        matched_data:matched_data,
                                    };
                                    if &ftype != "not_detected"{
                                        info!("Catch filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{} name:{}",
                                            &task_data.scan_path,
                                            &event.exe_size,
                                            &md5sum,
                                            &event.create_at,
                                            &event.modify_at,
                                            &ftype,
                                            &fclass,
                                            &fname
                                        );
                                    }
                                    if let Some(addonsmap) = &task_data.add_ons{
                                        if let Err(e) = self.client.send_record(&event.to_record_with_add_on(&addonsmap)) {
                                            warn!("send err, should exit : {:?}",e);
                                            work_s_locker.send(()).unwrap();
                                            return
                                        };
                                        continue;
                                    }else {
                                        if let Err(e) = self.client.send_record(&event.to_record()) {
                                            warn!("send err, should exit : {:?}",e);
                                            work_s_locker.send(()).unwrap();
                                            return
                                        };
                                    }
                                }
                            }
                        }, // one-time-task
                        DETECT_TASK::TASK_6054_ANTIVIRUS(task_data) =>{
                            debug!("recv work 6054");
                            self.refresh_scanner();
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan {:?}",&task_data.pid_exe);
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = t.scan(&task_data.pid_exe){
                                    let mut event = AntiRansomEvent::new(
                                        task_data.pid,
                                        &ftype,
                                        "anti_ransom",
                                        &fname,
                                        &task_data.pid_exe,
                                        &xhash,
                                        &md5sum,
                                        task_data.size,
                                        task_data.btime.0,
                                        task_data.btime.1,
                                        &task_data.event_file_path,
                                        //&task_data.event_file_hash,
                                        &task_data.event_file_mask,
                                        matched_data,
                                    );
                                    info!("filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{} name:{}",
                                        &task_data.pid_exe,
                                        &task_data.size,
                                        &md5sum,
                                        &task_data.btime.0,
                                        &task_data.btime.1,
                                        &ftype,
                                        &fclass,
                                        &fname
                                    );
                                    if let Err(e) = self.client.send_record(&event.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                }
                            }
                        }, // anti_ransom
                        DETECT_TASK::TASK_6054_FANOTIFY(task_data) =>{
                            let mut event = FanotifyEvent::new(
                                task_data.pid,
                                &task_data.pid_exe,
                                task_data.size,//exe_size,
                                task_data.btime.0,
                                task_data.btime.1,
                                &task_data.event_file_path,
                                &task_data.event_file_hash,
                                &task_data.event_file_mask,
                            );
                            if let Err(e) = self.client.send_record(&event.to_record()) {
                                warn!("send err, should exit : {:?}",e);
                                work_s_locker.send(()).unwrap();
                                return
                            };
                        }, // fanotify
                        DETECT_TASK::TASK_6054_TASK_6054_ANTIVIRUS_STATUS(arf_status) => {
                            if let Err(e) = self.client.send_record(&arf_status.to_record()) {
                                warn!("send err, should exit : {:?}",e);
                                work_s_locker.send(()).unwrap();
                                return
                            };
                        },// arf status
                        DETECT_TASK::TASK_6057_FULLSCAN(fullscantask) =>{
                            self.refresh_scanner();
                            if let Some(t) = &mut self.scanner{
                                // fullscan job handler
                                let (mut fullscan_job, mut worker_jobs) = FullScan(
                                    self.ppid,
                                    self.client.clone(),
                                    &t,
                                    &fullscantask,
                                );
                                fullscan_job.join();
                                let mut state = FullScanResult::FULLSCANN_SUCCEED;
                                let mut error_msg = String::new();
                                for each_job in worker_jobs {
                                    match each_job.join(){
                                        Ok(result)=> {
                                            match result{
                                                Ok(task_result) => {
                                                    if task_result == FullScanResult::FULLSCANN_TIMEOUT{
                                                        error_msg = "FullScan TimeOut.".to_string();
                                                    }
                                                    state = task_result;
                                                }
                                                Err(e) => {
                                                    error_msg = format!("FullScan child return error with msg: {:?}",&e);
                                                    state = FullScanResult::FULLSCANN_FAILED;
                                                }
                                            };
                                        },
                                        Err(e)=> {
                                            error_msg = format!("FullScan child process exit unexpected with : {:?}",&e);
                                            state = FullScanResult::FULLSCANN_FAILED;
                                        }
                                    };
                                }
                                self.scanner = None;
                                info!("[FullScan] All job Cleaned.");
                                let end_flag = ScanFinished {
                                    data: state.to_string(),
                                    error: error_msg.to_string(),
                                };
                                if let Err(e) =
                                    self.client.send_record(&end_flag.to_record_token(&fullscantask.token))
                                {
                                    warn!("send err, should exit : {:?}", e);
                                };
                                crate::setup_cgroup(
                                    self.ppid,
                                    1024 * 1024 * (*SERVICE_DEFAULT_CG_MEM),
                                    1000 * (*SERVICE_DEFAULT_CG_CPU),
                                );

                            }
                        }
                         _ =>{
                            debug!("nothing");
                            continue
                        },
                    }
                }
                recv(after(timeout)) -> _ => {
                    debug!("worker timed out, clean buf");
                    self.scanner = None;
                    continue
                }
            }
        }
    }
}
