use crate::{config::LOAD_MMAP_MAX_SIZE, ToAgentRecord};
use anyhow::*;
use coarsetime::Clock;
use crossbeam_channel::{after, bounded, select, tick};
use log::*;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::Path,
    thread::{self, JoinHandle},
    time::{Duration, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DetectTask {
    pub task_type: String, // 6003
    pub pid: i32,          // process id
    pub path: String,      // file path
    pub rpath: String,     // file real path (prob. path is the same as rpath)
    pub size: usize,       // file size
    pub btime: u64,        // file create time / birthtime
    pub mtime: u64,        // file last modified time / mtime
    pub token: String,     // task token
}

// DetectOneTaskEvent = One Task : Static file detect event
#[derive(Serialize, Debug)]
pub struct DetectOneTaskEvent<'a> {
    data_type: &'a str, // 6003
    types: &'a str,     // rule type / yara identifier
    exe: &'a str,       // file path
    exe_size: &'a str,  // file size
    exe_hash: &'a str,  // sha256
    data: &'a str,      // script content
    create_at: &'a str, // file create time / birthtime
    motify_at: &'a str, // file last modified time / mtime
    error: &'a str,     // error
    token: &'a str,     // task token
}

impl ToAgentRecord for DetectOneTaskEvent<'_> {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6003);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("data".to_string(), self.data.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("motify_at".to_string(), self.motify_at.to_string());
        hmp.insert("error".to_string(), self.error.to_string());
        hmp.insert("token".to_string(), self.token.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

// DetectFileEvent = Static file detect event
#[derive(Serialize, Debug)]
pub struct DetectFileEvent<'a> {
    data_type: &'a str, // 6001
    types: &'a str,     // rule type / yara identifier
    exe: &'a str,       // file path
    exe_size: &'a str,  // file_size
    exe_hash: &'a str,  // sha256
    create_at: &'a str, // file create time / birthtime
    motify_at: &'a str, // file last modified time / mtime
    data: &'a str,      // script content
}

impl ToAgentRecord for DetectFileEvent<'_> {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6001);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("data".to_string(), self.data.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("motify_at".to_string(), self.motify_at.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

// DetectFanoEvent = Proc pid/exe detect event
#[derive(Serialize, Debug)]
pub struct DetectFanoEvent<'a> {
    data_type: &'a str, // 6004
    types: &'a str,     // rule type / yara identifier
    pid: &'a str,       // process id
    exe_hash: &'a str,  // sha256
    exe_size: &'a str,  // file_size
    exe: &'a str,       // file path
    data: &'a str,      // script content
    create_at: &'a str, // file create time = btime = birth_time
    motify_at: &'a str, // file last modified time / mtime
}

impl ToAgentRecord for DetectFanoEvent<'_> {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6004);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("data".to_string(), self.data.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("motify_at".to_string(), self.motify_at.to_string());
        hmp.insert("pid".to_string(), self.pid.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }
}

// DetectProcEvent = Proc pid/exe detect event
#[derive(Serialize, Debug, Default)]
pub struct DetectProcEvent {
    data_type: String, // 6002
    types: String,     // rule type
    pid: String,       // rule type / yara identifier
    exe_hash: String,  // exe sha256
    exe_size: String,  // file_size
    exe: String,       // file path
    data: String,      // script content
    create_at: String, // file create time = btime = birth_time
    motify_at: String, // file last modified time / mtime
    ppid: String,      // status|stat - PID of parent process.
    pgid: String,      // stat - The process group ID
    tgid: String,      // status - Thread group ID
    argv: String,      // /proc/pid/cmdline
    comm: String,      // status: Name
    sessionid: String, // stat  - session id
    uid: String,       // real user uid
    pns: String,       // process ns
}

impl ToAgentRecord for DetectProcEvent {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6002);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = ::std::collections::HashMap::with_capacity(6);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("data".to_string(), self.data.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("motify_at".to_string(), self.motify_at.to_string());
        hmp.insert("pid".to_string(), self.pid.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }
}

//DetectProcEvent get pid info from proc
impl DetectProcEvent {
    pub fn new(
        pid: i32,
        rule: &str,
        exe: String,
        sha256: &str,
        size: usize,
        data: &str,
        data_type: String,
        create_at: u64,
        motify_at: u64,
    ) -> Result<Self> {
        let p = procfs::process::Process::new(pid)?;
        let mut pf = Self::default();
        pf.data_type = data_type;
        pf.pid = pid.to_string();
        pf.types = rule.to_string();
        pf.exe = exe.to_string();
        pf.exe_hash = sha256.to_string();
        pf.exe_size = size.to_string();
        pf.data = data.to_string();
        pf.create_at = create_at.to_string();
        pf.motify_at = motify_at.to_string();
        if let Ok(ps) = p.status() {
            pf.comm = ps.name.to_owned();
            pf.ppid = ps.ppid.to_string();
            pf.uid = ps.ruid.to_string();
            pf.tgid = ps.tgid.to_string();
            if let Some(nspid) = ps.nspid {
                pf.pns = nspid.into_iter().map(|i| i.to_string()).collect::<String>();
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

// Scanner
struct Scanner {
    inner: yara::Rules,
    buffer: Vec<u8>,
}

impl Scanner {
    pub fn new(rule_str: &str) -> Self {
        let mut compiler = yara::Compiler::new().unwrap();
        match compiler.add_rules_str(rule_str) {
            Ok(_) => {}
            Err(e) => {
                error!("this rule is not working, {} \n {}", rule_str, e);
                compiler = yara::Compiler::new().unwrap();
                compiler.add_rules_str(crate::config::RULES_SET).unwrap();
            }
        };
        let mut inner = match compiler.compile_rules() {
            Ok(i) => i,
            Err(e) => {
                error!("this rule is not working, {} \n {}", rule_str, e);
                let mut compiler = yara::Compiler::new().unwrap();
                compiler.add_rules_str(crate::config::RULES_SET).unwrap();
                compiler.compile_rules().unwrap()
            }
        };
        inner.set_flags(13); // set quick scan mode
        let buffer: Vec<u8> = Vec::with_capacity(LOAD_MMAP_MAX_SIZE);
        return Self {
            inner: inner,
            buffer: buffer,
        };
    }
}

// Detector wocker
pub struct Detector {
    pub client: plugins::Client,
    pub task_receiver: crossbeam_channel::Receiver<DetectTask>,
    s_locker: crossbeam_channel::Sender<()>,
    rule_str: String,
    scanner: Option<Scanner>,
    _recv_worker: JoinHandle<()>,
    malware_cache: lru::LruCache<String, String>,
    rule_updater: crossbeam_channel::Receiver<String>,
    cache_size: usize,
}

impl Detector {
    pub fn new(
        client: plugins::Client,
        task_sender: crossbeam_channel::Sender<DetectTask>,
        task_receiver: crossbeam_channel::Receiver<DetectTask>,
        s_locker: crossbeam_channel::Sender<()>,
        rule_str: &str,
        cache_size: usize,
    ) -> Self {
        let recv_worker_s_locker = s_locker.clone();
        let (s, r) = bounded(0);
        // Receive One-time-scan-task : Path
        let mut r_client = client.clone();
        let recv_worker = thread::spawn(move || loop {
            match r_client.receive() {
                Ok(t) => {
                    info!("recv task.data {:?}", &t.get_data());
                    if !t.data.starts_with("/") {
                        if t.data.starts_with("rule") {
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
                        continue;
                    }

                    let task = DetectTask {
                        task_type: "6003".to_string(),
                        pid: 0,
                        path: t.data.to_string(),
                        rpath: "".to_string(),
                        token: t.token,
                        btime: 0,
                        mtime: 0,
                        size: 0,
                    };
                    if let Err(e) = task_sender.try_send(task) {
                        error!("internal send task err : {:?}", e);
                        continue;
                    }
                }
                Err(e) => {
                    warn!("{}", e);
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
            rule_str: rule_str.into(),
            scanner: Some(Scanner::new(&rule_str)),
            _recv_worker: recv_worker,
            rule_updater: r,
            malware_cache: LruCache::new(cache_size),
            cache_size: cache_size,
        };
    }

    pub fn work(&mut self, timeout: Duration) {
        info!("start work");
        let work_s_locker = self.s_locker.clone();
        let ticker = tick(Duration::from_secs(3600 * 24 + 60));
        loop {
            select! {
                recv(ticker)-> _ =>{
                    // cron to clear cache
                    self.malware_cache= LruCache::new(self.cache_size);
                },
                recv(self.rule_updater)->rules=>{
                    let rule_str = match rules{
                        Ok(s)=>{s},
                        Err(e)=>{
                            error!("recv rule err : {:?}", e);
                            self.rule_str.clone()
                        }
                    };
                    self.rule_str = rule_str;
                    self.scanner = Some(Scanner::new(&self.rule_str));
                    info!("rule update ok");
                },
                recv(self.task_receiver)->data=>{
                    // recv scan task
                    match self.scanner{
                        None => {
                            self.scanner = Some(Scanner::new(&self.rule_str));
                        },
                        Some(_) =>{},
                    }

                    debug!("recv work {:?}",data);
                    let task:DetectTask = data.unwrap();
                    if let Some(_)= self.malware_cache.get(&task.rpath){
                        continue;
                    }
                    match &task.task_type[..]{
                        "6001" =>{
                            debug!("recv work 6001");
                            let fp = Path::new(&task.path);
                            let mut f = match File::open(fp) {
                                Ok(f) => f,
                                Err(e) => {
                                    warn!("err open file {:?}, {:?}",&task.path,e);
                                    continue
                                },
                            };
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan {:?}",task.path);
                                t.buffer.clear();
                                let _ = match f.read_to_end(&mut t.buffer) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        t.buffer.clear();
                                        warn!("Error read_to_end_file {}", e);
                                        continue;
                                    }
                                };
                                let result = match t.inner.scan_mem(&t.buffer, 180){
                                    Ok(r) => {r},
                                    Err(e) => {
                                        warn!("Error scan_mem {}", e);
                                        continue
                                    }
                                }; // maybe timeout
                                if result.len() > 0 {
                                    let sha256 = Sha256::digest(&t.buffer);
                                    let sha256sum = format!("{:x}", sha256);
                                    let first_result = &result[0];
                                    self.malware_cache.put(task.rpath.to_string(), first_result.identifier.to_string());
                                    warn!(
                                        "[Catch file] Type={}, Path={}",
                                        first_result.identifier,
                                        fp.display()
                                    );
                                    let mut rawc = "";
                                    if first_result.identifier.ends_with("script") {
                                        rawc = std::str::from_utf8(&t.buffer).unwrap_or_default();
                                    }
                                    let t = &DetectFileEvent {
                                        data_type: "6001",
                                        types: first_result.identifier,
                                        exe: &task.rpath,
                                        exe_size: &task.size.to_string(),
                                        data: rawc,
                                        create_at:&task.btime.to_string(),
                                        motify_at:&task.mtime.to_string(),
                                        exe_hash: &sha256sum,
                                    };
                                    if let Err(e) = self.client.send_record(&t.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };

                                }
                            }
                        },// dir
                        "6002" =>{
                            debug!("recv work 6002");

                            let fp = Path::new(&task.path);
                            let mut f = match File::open(fp) {
                                Ok(f) => f,
                                Err(e) => {
                                    warn!("err open file {:?}, {:?}",&task.path,e);
                                    continue
                                },
                            };
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan {:?}",task.path);

                                t.buffer.clear();
                                let _ = match f.read_to_end(&mut t.buffer) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        t.buffer.clear();
                                        warn!("Error read_to_end_file {}", e);
                                        continue;
                                    }
                                };
                                let result = match t.inner.scan_mem(&t.buffer, 180){
                                    Ok(r) => {r},
                                    Err(e) => {
                                        warn!("Error scan_mem {}", e);
                                        continue
                                    }
                                }; // maybe timeout
                                if result.len() > 0 {
                                    let sha256 = Sha256::digest(&t.buffer);
                                    let sha256sum = format!("{:x}", sha256);
                                    let first_result = &result[0];
                                    warn!(
                                        "[Catch file] Type={}, Path={}",
                                        first_result.identifier,
                                        fp.display()
                                    );
                                    let mut rawc = "";
                                    if first_result.identifier.ends_with("script")  {
                                        rawc = std::str::from_utf8(&t.buffer).unwrap_or_default();
                                    }
                                    self.malware_cache.put(task.rpath.to_string(), first_result.identifier.to_string());
                                    let t = DetectProcEvent::new(
                                        task.pid,
                                        first_result.identifier,
                                        task.rpath,
                                        &sha256sum,
                                        task.size,
                                        rawc,
                                        "6002".to_string(),
                                        task.btime,
                                        task.mtime,
                                    ).unwrap_or_default();
                                    if let Err(e) = self.client.send_record(&t.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                }
                            }
                        }, // proc

                        "6003" =>{
                            debug!("recv work 6003");
                            let fp = Path::new(&task.path);
                            let meta = match fp.metadata(){
                                Ok(m)=>m,
                                Err(e)=>{
                                    let resp = &DetectOneTaskEvent{
                                        data_type:"6003",
                                        types: "",
                                        exe: &task.path,
                                        exe_size: "",
                                        exe_hash: "",
                                        data: "",
                                        create_at:"",
                                        motify_at:"",
                                        error: &format!("{:?}",e),
                                        token: &task.token,
                                    };
                                    if let Err(e) = self.client.send_record(&resp.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                    continue
                                }
                            };
                            let btime = get_file_bmtime(&meta);
                            let mut f = match File::open(fp) {
                                Ok(f) => f,
                                Err(e) => {
                                    warn!("err open file {:?}, {:?}",&task.path,e);
                                    let resp = &DetectOneTaskEvent{
                                        data_type:"6003",
                                        types: "",
                                        exe: &task.path,
                                        exe_size: "",
                                        exe_hash: "",
                                        data: "",
                                        create_at:&btime.0.to_string(),
                                        motify_at:&btime.1.to_string(),

                                        error: &format!("err open file {:?}",e),
                                        token: &task.token,
                                    };
                                    if let Err(e) = self.client.send_record(&resp.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                    return
                                },
                            };
                            if let Some(t) =  &mut self.scanner{
                                t.buffer.clear();
                                match f.read_to_end(&mut t.buffer) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        t.buffer.clear();
                                        error!("Error read_to_end_file {}", e);
                                        let resp = &DetectOneTaskEvent{
                                            data_type:"6003",
                                            types: "",
                                            exe: &task.path,
                                            exe_size: "",
                                            exe_hash: "",
                                            data: "",
                                            create_at:&btime.0.to_string(),
                                            motify_at:&btime.1.to_string(),
                                            error: &format!("Error read_to_end_file:{:?}",e),
                                            token: &task.token,
                                        };
                                        if let Err(e) = self.client.send_record(&resp.to_record()) {
                                            warn!("send err, should exit : {:?}",e);
                                            work_s_locker.send(()).unwrap();
                                            return
                                        };
                                        continue;
                                    }
                                }
                                let fsize = t.buffer.len() as usize;
                                let result = t.inner.scan_mem(&t.buffer, 600).unwrap();
                                let sha256 = Sha256::digest(&t.buffer);
                                let sha256sum = format!("{:x}", sha256);
                                if result.len() > 0 {
                                    let first_result = &result[0];
                                    warn!(
                                        "[Catch file] Type={}, Path={}",
                                        first_result.identifier,
                                        fp.display()
                                    );
                                    let mut rawc = "";
                                    if first_result.identifier.ends_with("script")  {
                                        rawc = std::str::from_utf8(&t.buffer).unwrap_or_default();
                                    }

                                    let t = &DetectOneTaskEvent{
                                        data_type:"6003",
                                        types: &first_result.identifier,
                                        exe: &task.path,
                                        exe_size: &fsize.to_string(),
                                        exe_hash: &sha256sum,
                                        data: &rawc,
                                        create_at:&btime.0.to_string(),
                                        motify_at:&btime.1.to_string(),
                                        error: "",
                                        token: &task.token,
                                    };
                                    if let Err(e) = self.client.send_record(&t.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                }else{
                                    let t = &DetectOneTaskEvent{
                                        data_type:"6003",
                                        types: "not_detected",
                                        exe: &task.path,
                                        exe_size: &fsize.to_string(),
                                        exe_hash: &sha256sum,
                                        data: "",
                                        create_at:&btime.0.to_string(),
                                        motify_at:&btime.1.to_string(),
                                        error: "",
                                        token: &task.token,
                                    };
                                    if let Err(e) = self.client.send_record(&t.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                }
                            }
                        }, // one-time-task
                        "6004" =>{
                            debug!("recv work 6004");
                            let fp = Path::new(&task.path);
                            let meta = match fp.metadata() {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!("err open file {:?}, {:?}",&task.path,e);
                                    continue
                                },
                            };
                            let (ctime,mtime) = get_file_bmtime(&meta);
                            let mut f = match File::open(fp) {
                                Ok(f) => f,
                                Err(e) => {
                                    warn!("err open file {:?}, {:?}",&task.path,e);
                                    continue
                                },
                            };
                            if let Some(t) =  &mut self.scanner{
                                t.buffer.clear();
                                match f.read_to_end(&mut t.buffer) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        t.buffer.clear();
                                        error!("Error read_to_end_file {}", e);
                                        continue;
                                    }
                                }
                                let fsize = t.buffer.len() as usize;
                                let result = t.inner.scan_mem(&t.buffer, 600).unwrap();
                                if result.len() > 0 {
                                    let sha256 = Sha256::digest(&t.buffer);
                                    let sha256sum = format!("{:x}", sha256);
                                    let first_result = &result[0];
                                    let mut rawc = "";
                                    if first_result.identifier.ends_with("script") {
                                        rawc = std::str::from_utf8(&t.buffer).unwrap_or_default();
                                    }
                                    warn!(
                                        "[Catch file] Type={}, Path={}",
                                        first_result.identifier,
                                        fp.display()
                                    );
                                    self.malware_cache.put(task.rpath.to_string(), first_result.identifier.to_string());
                                    let t = DetectFanoEvent{
                                        data_type:"6004",
                                        types:&first_result.identifier,
                                        pid:&task.pid.to_string(),
                                        exe:&task.rpath,
                                        exe_hash:&sha256sum,
                                        exe_size:&fsize.to_string(),
                                        data:&rawc,
                                        create_at:&ctime.to_string(),
                                        motify_at:&mtime.to_string(),
                                    };
                                    if let Err(e) = self.client.send_record(&t.to_record()) {
                                        warn!("send err, should exit : {:?}",e);
                                        work_s_locker.send(()).unwrap();
                                        return
                                    };
                                }
                            }
                        }, // fanotify
                         _ =>{
                            debug!("nothing");
                            continue
                        },
                    }
                }
                // clear scan buf and yara buf after timeout
                recv(after(timeout)) -> _ => {
                    debug!("work timed out, clean buf");
                    self.scanner = None;
                    continue
                }
            }
        }
    }
}

// get file brithtime and last modified time
pub fn get_file_bmtime(m: &std::fs::Metadata) -> (u64, u64) {
    let ct = match m.created() {
        Ok(m) => {
            let cti = match m.duration_since(UNIX_EPOCH) {
                Ok(mi) => mi.as_secs(),
                Err(e) => {
                    //error!("{:?}", e);
                    0
                }
            };
            cti
        }
        Err(e) => {
            //error!("{:?}", e);
            0
        }
    };
    let mt = match m.modified() {
        Ok(m) => {
            let cti = match m.duration_since(UNIX_EPOCH) {
                Ok(mi) => mi.as_secs(),
                Err(e) => {
                    //error!("{:?}", e);
                    0
                }
            };
            cti
        }
        Err(e) => {
            //error!("{:?}", e);
            0
        }
    };
    return (ct, mt);
}
