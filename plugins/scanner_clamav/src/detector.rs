use crate::{
    configs, get_file_btime, get_file_md5, get_file_sha256, updater, Clamav, ToAgentRecord,
};

use anyhow::Result;
use coarsetime::Clock;
use crossbeam_channel::{after, bounded, select};
use log::*;
use std::os::linux::fs::MetadataExt;
use std::{collections::HashMap, path::Path, thread, time};

use serde::{Deserialize, Serialize};
use serde_json;

// DetectFileEvent = Static file detect event
#[derive(Serialize, Debug)]
pub struct DetectFileEvent<'a> {
    types: &'a str,    // rule type
    class: &'a str,    // class
    name: &'a str,     // name
    exe: &'a str,      // * file path
    exe_size: &'a str, // file_size
    exe_hash: &'a str, // * xhash
    md5_hash: &'a str, // * md5
    create_at: &'a str,
    modify_at: &'a str,
}

impl ToAgentRecord for DetectFileEvent<'_> {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6001);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("class".to_string(), self.class.to_string());
        hmp.insert("name".to_string(), self.name.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("md5_hash".to_string(), self.md5_hash.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("modify_at".to_string(), self.modify_at.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

// DetectProcEvent = Proc pid/exe detect event
#[derive(Serialize, Debug, Default)]
pub struct DetectProcEvent {
    types: String,    // rule type
    class: String,    // class
    name: String,     // name
    pid: String,      //
    exe_hash: String, // exe sha256
    md5_hash: String,
    exe_size: String,
    exe: String, //
    create_at: String,
    modify_at: String,
    ppid: String,      //  status|stat - PID of parent process.
    pgid: String,      //  stat - The process group ID
    tgid: String,      //  status - Thread group ID
    argv: String,      //  /proc/pid/cmdline
    comm: String, // status: Name | stat: comm - The filename of the executable TASK_COMM_LEN (16)
    sessionid: String, //  stat  - session id
    uid: String,  // * real user uid
    pns: String,
}

impl ToAgentRecord for DetectProcEvent {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6002);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("class".to_string(), self.class.to_string());
        hmp.insert("name".to_string(), self.name.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("md5_hash".to_string(), self.md5_hash.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("modify_at".to_string(), self.modify_at.to_string());
        hmp.insert("pid".to_string(), self.pid.to_string());
        hmp.insert("ppid".to_string(), self.ppid.to_string());
        hmp.insert("pgid".to_string(), self.pgid.to_string());
        hmp.insert("tgid".to_string(), self.tgid.to_string());
        hmp.insert("argv".to_string(), self.argv.to_string());
        hmp.insert("comm".to_string(), self.comm.to_string());
        hmp.insert("sessionid".to_string(), self.sessionid.to_string());
        hmp.insert("uid".to_string(), self.uid.to_string());
        hmp.insert("pns".to_string(), self.pns.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }
}

//DetectProcEvent get pid info from proc
impl DetectProcEvent {
    pub fn new(
        pid: i32,
        ftype: &str,
        fclass: &str,
        fname: &str,
        exe: &str,
        xhash: &str,
        md5sum: &str,
        size: usize,
        create_at: u64,
        modify_at: u64,
    ) -> Result<Self> {
        let p = procfs::process::Process::new(pid)?;
        let mut pf = Self::default();
        pf.pid = pid.to_string();
        pf.types = ftype.to_string();
        pf.class = fclass.to_string();
        pf.name = fname.to_string();
        pf.exe = exe.to_string();
        pf.exe_hash = xhash.to_string();
        pf.md5_hash = md5sum.to_string();
        pf.exe_size = size.to_string();
        pf.create_at = create_at.to_string();
        pf.modify_at = modify_at.to_string();
        pf.comm = "-3".to_string();
        pf.ppid = "-3".to_string();
        pf.uid = "-3".to_string();
        pf.tgid = "-3".to_string();
        pf.pns = "-3".to_string();
        pf.pgid = "-3".to_string();
        pf.sessionid = "-3".to_string();
        pf.argv = "-3".to_string();

        if let Ok(ps) = p.status() {
            pf.comm = ps.name.to_owned();
            pf.ppid = ps.ppid.to_string();
            pf.uid = ps.ruid.to_string();
            pf.tgid = ps.tgid.to_string();

            let pidns_file = format!("/proc/{}/ns/pid", pid);
            if let Ok(m) = std::fs::metadata(pidns_file) {
                pf.pns = m.st_ino().to_string();
            }
        }
        if let Ok(ps) = p.stat() {
            pf.pgid = ps.pgrp.to_string();
            pf.sessionid = ps.session.to_string();
        }

        if let Ok(ps) = p.cmdline() {
            pf.argv = ps.join(" ");
        }
        return Ok(pf);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DetectTask {
    pub task_type: String,
    pub pid: i32,
    pub path: String,
    pub rpath: String,
    pub size: usize,
    pub btime: u64,
    pub mtime: u64,
    pub token: String,
    pub add_ons: Option<HashMap<String, String>>,
}

#[derive(Serialize, Debug)]
pub struct DetectOneTaskEvent<'a> {
    types: &'a str,    // rule type
    class: &'a str,    // class
    name: &'a str,     // name
    exe: &'a str,      // file path
    exe_size: &'a str, // file size
    exe_hash: &'a str, // xhash 32k
    md5_hash: &'a str, // md5
    create_at: &'a str,
    modify_at: &'a str,
    error: &'a str, // error
    token: &'a str, // task token
}

impl DetectOneTaskEvent<'_> {
    fn to_record_with_add_on(&self, addons: &HashMap<String, String>) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6003);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("class".to_string(), self.class.to_string());
        hmp.insert("name".to_string(), self.name.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("md5_hash".to_string(), self.md5_hash.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("modify_at".to_string(), self.modify_at.to_string());
        for (k, v) in addons.into_iter() {
            hmp.insert(k.to_string(), v.to_string());
        }
        hmp.insert("error".to_string(), self.error.to_string());
        hmp.insert("token".to_string(), self.token.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

impl ToAgentRecord for DetectOneTaskEvent<'_> {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6003);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("class".to_string(), self.class.to_string());
        hmp.insert("name".to_string(), self.name.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("md5_hash".to_string(), self.md5_hash.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("modify_at".to_string(), self.modify_at.to_string());
        hmp.insert("error".to_string(), self.error.to_string());
        hmp.insert("token".to_string(), self.token.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

#[derive(Serialize, Debug)]
pub struct RegReport<'a> {
    db_version: &'a str,
    db_sha256: &'a str,
}

impl ToAgentRecord for RegReport<'_> {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6000);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("version".to_string(), self.db_version.to_string());
        hmp.insert("exe_hash".to_string(), self.db_sha256.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

pub struct Scanner {
    inner: Clamav,
}

impl Scanner {
    // create yara scanner with rule strings
    pub fn new(db_path: &str) -> Result<Self> {
        let mut scanner = Clamav::new().unwrap();
        info!("clamav init ok!");
        if let Err(e) = scanner.set_max_size(
            configs::CLAMAV_MAX_FILESIZE as i64,
            configs::CLAMAV_MAX_SCANSIZE,
        ) {
            return Err(e);
        }
        info!("clamav set maxsize ok!");
        if let Err(e) = scanner.load_db(db_path) {
            return Err(e);
        }
        info!("clamav load_db ok!");
        if let Err(e) = scanner.compile_engine() {
            return Err(e);
        }
        info!("clamav compile_engine ok!");
        return Ok(Self { inner: scanner });
    }
    pub fn scan(self: &mut Self, fpath: &str) -> Result<(String, String, String, String, String)> {
        match self.inner.scan_file(fpath) {
            Ok(result) => {
                let mut res: Vec<String> = Vec::new();

                // not_detected
                if &result == "OK" {
                    return Ok((
                        "not_detected".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                    ));
                }

                let xhash = get_file_sha256(fpath);
                let md5sum = get_file_md5(fpath);
                let mut ftype = "not_detected".to_string();
                let mut class = "".to_string();
                let mut name = "".to_string();

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
                return Ok((ftype, class, name, xhash, md5sum));
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
    pub task_receiver: crossbeam_channel::Receiver<DetectTask>,
    s_locker: crossbeam_channel::Sender<()>,
    db_path: String,
    scanner: Option<Scanner>,
    _recv_worker: thread::JoinHandle<()>,
    rule_updater: crossbeam_channel::Receiver<String>,
    db_manager: updater::DBManager,
}

impl Detector {
    pub fn new(
        client: plugins::Client,
        task_sender: crossbeam_channel::Sender<DetectTask>,
        task_receiver: crossbeam_channel::Receiver<DetectTask>,
        s_locker: crossbeam_channel::Sender<()>,
        db_path: &str,
        db_manager: updater::DBManager,
    ) -> Self {
        let recv_worker_s_locker = s_locker.clone();
        let (s, r) = bounded(0);
        // Receive One-time-scan-task : Path
        let mut r_client = client.clone();
        let recv_worker = thread::spawn(move || loop {
            match r_client.receive() {
                Ok(t) => {
                    info!("recv task.data {:?}", &t.get_data());
                    match t.data_type {
                        6053 => {
                            // Scan task
                            if task_sender.len() >= 18 {
                                error!(
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
                                        error!("error decode &t.data {:?}", &t.data);
                                        continue;
                                    }
                                };
                            let mut target_path = "".to_string();

                            if let Some(task_exe_scan) = task_map.get("exe") {
                                if !task_exe_scan.starts_with("/") {
                                    info!("recv 6053 but not a fullpath {:?}", t.data);
                                    continue;
                                    // ignored if not a fullpath from root /
                                }
                                target_path = task_exe_scan.to_string();
                            } else {
                                continue;
                            }
                            let task = DetectTask {
                                task_type: "6053".to_string(),
                                pid: 0,
                                path: target_path,
                                rpath: "".to_string(),
                                token: t.token,
                                btime: 0,
                                mtime: 0,
                                size: 0,
                                add_ons: Some(task_map),
                            };
                            if let Err(e) = task_sender.try_send(task) {
                                error!("internal send task err : {:?}", e);
                                continue;
                            }
                        }
                        6050 => {
                            // DB update task
                            // drop resource and renew scanner
                            match s.send(t.data) {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("{}", e);
                                    recv_worker_s_locker.send(()).unwrap();
                                    // Exit if plugin recive task failed.
                                    return;
                                }
                            };
                        }
                        _ => {
                            error!("unknown data_type {:?} with tash {:?}", t.data_type, t.data)
                        }
                    }
                }
                Err(e) => {
                    error!("{}", e);
                    recv_worker_s_locker.send(()).unwrap();
                    // Exit if plugin recive task failed.
                    return;
                }
            }
        });

        return Self {
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
                    match self.scanner{
                        None => {
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
                        },
                        Some(_) =>{},
                    }
                    debug!("recv work {:?}",data);
                    let task:DetectTask = data.unwrap();
                    match &task.task_type[..]{
                        "6051" =>{
                            debug!("recv work 6051");
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan {:?}",task.path);
                                if let Ok((ftype,fclass,fname,xhash,md5sum)) = t.scan(&task.path){
                                    let t = DetectFileEvent {
                                        types: &ftype,
                                        class:&fclass,
                                        name: &fname,
                                        exe: &task.rpath,
                                        exe_size: &task.size.to_string(),
                                        create_at:&task.btime.to_string(),
                                        modify_at:&task.mtime.to_string(),
                                        exe_hash: &xhash,
                                        md5_hash: &md5sum
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
                                            work_s_locker.send(()).unwrap();
                                            return
                                        };
                                    }
                                }
                            }
                        },// dir

                        "6052" =>{
                            debug!("recv work 6052");
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan {:?}",task.path);
                                match t.scan(&task.path){
                                    Ok((ftype,fclass,fname,xhash,md5sum)) => {
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
                                        ).unwrap_or_default();

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
                                                work_s_locker.send(()).unwrap();
                                                return
                                            };
                                        }
                                    },
                                    Err(e) => {
                                        error!("error {:?} while scann {:?}",e,&task.path);
                                    },
                                };
                            }
                        }, // proc

                        "6053" =>{
                            debug!("recv work 6053");
                            // TODO. CUSTOM RULES TO USED HERE
                            let fp = Path::new(&task.path);
                            let meta = match fp.metadata(){
                                Ok(m)=>m,
                                Err(e)=>{
                                    let resp = &DetectOneTaskEvent{
                                        types: "",
                                        class:"",
                                        name: "",
                                        exe: &task.path,
                                        exe_size: "",
                                        exe_hash: "",
                                        md5_hash: "",
                                        create_at:"",
                                        modify_at:"",
                                        error: &format!("{:?}",e),
                                        token: &task.token,
                                    };
                                    warn!("err scan {}, with {:?}",&task.path,e);
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
                                debug!("scan {:?}",task.path);
                                if let Ok((ftype,fclass,fname,xhash,md5sum)) = t.scan(&task.path){
                                    let event = &DetectOneTaskEvent{
                                        types: &ftype,
                                        class:&fclass,
                                        name: &fname,
                                        exe: &task.path,
                                        exe_size: &meta.len().to_string(),
                                        exe_hash: &xhash,
                                        md5_hash: &md5sum,
                                        create_at:&btime.0.to_string(),
                                        modify_at:&btime.1.to_string(),
                                        error: "",
                                        token: &task.token,
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

                                    }
                                    if let Some(addonsmap) = &task.add_ons{
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
                         _ =>{
                            debug!("nothing");
                            continue
                        },
                    }
                    std::thread::sleep(configs::WAIT_INTERVAL_SCAN);
                }
                recv(after(timeout)) -> _ => {
                    debug!("work timed out, clean buf");
                    self.scanner = None;
                    continue
                }
            }
        }
    }
}
