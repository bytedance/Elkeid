use crate::{
    get_file_md5_fast,
    model::functional::{
        anti_ransom::HoneyPot,
        fulldiskscan::{
            FullScan, FulllScanFinished, MAX_SCAN_CPU_100, MAX_SCAN_ENGINES, MAX_SCAN_MEM_MB,
        },
    },
};

use anyhow::{anyhow, Result};
use coarsetime::Clock;
use crossbeam_channel::{after, bounded, select};
use log::*;
use std::{collections::HashMap, path::Path, thread, time};

use serde::{self, Deserialize, Serialize};
use serde_json;

// DetectFileEvent = Static file detect event
#[derive(Serialize, Debug)]
pub struct DetectFileEvent {
    pub types: String,    // rule type
    pub class: String,    // class
    pub name: String,     // name
    pub exe: String,      // *
    pub exe_size: String, // file_size
    pub exe_hash: String, // * xhash
    pub md5_hash: String, // * md5
    pub create_at: String,
    pub modify_at: String,
    pub matched_data: Option<Vec<String>>,
}

impl ToAgentRecord for DetectFileEvent {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6001);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(16);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("class".to_string(), self.class.to_string());
        hmp.insert("name".to_string(), self.name.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("md5_hash".to_string(), self.md5_hash.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("modify_at".to_string(), self.modify_at.to_string());
        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }

    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6001);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(16);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("class".to_string(), self.class.to_string());
        hmp.insert("name".to_string(), self.name.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
        hmp.insert("exe_hash".to_string(), self.exe_hash.to_string());
        hmp.insert("md5_hash".to_string(), self.md5_hash.to_string());
        hmp.insert("create_at".to_string(), self.create_at.to_string());
        hmp.insert("modify_at".to_string(), self.modify_at.to_string());
        hmp.insert("token".to_string(), token.to_string());
        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

// DetectProcEvent = Proc pid/exe detect event
#[derive(Serialize, Debug, Default)]
pub struct AntiRansomEvent {
    types: String,    // rule type
    class: String,    // class
    name: String,     // name
    pid: String,      //
    exe_hash: String, //  exe sha256
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

    file_path: String, // honeypot file
    file_hash: String, // honeypot file sha256

    matched_data: Option<Vec<String>>,
}

impl ToAgentRecord for AntiRansomEvent {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6005);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(32);
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

        hmp.insert("file_path".to_string(), self.file_path.to_string());
        hmp.insert("file_hash".to_string(), self.file_hash.to_string());

        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }
        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }

    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6005);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(32);
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
        hmp.insert("token".to_string(), token.to_string());

        hmp.insert("file_path".to_string(), self.file_path.to_string());
        hmp.insert("file_hash".to_string(), self.file_hash.to_string());

        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }

        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }
}

//DetectProcEvent get pid info from proc
impl AntiRansomEvent {
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
        file_path: &str,
        file_hash: &str,
        matched_data: Option<Vec<String>>,
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

        pf.file_path = file_path.to_string();
        pf.file_hash = file_hash.to_string();
        pf.matched_data = matched_data;

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

            let pidns = format!("/proc/{}/ns/pid", pid);
            if let Ok(pns) = std::fs::read_link(&pidns) {
                if let Some(pns_str) = pns.to_str() {
                    pf.pns = pns_str
                        .trim_start_matches("pid:[")
                        .trim_end_matches("]")
                        .to_string();
                }
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

// DetectProcEvent = Proc pid/exe detect event
#[derive(Serialize, Debug, Default)]
pub struct DetectProcEvent {
    types: String,    // rule type
    class: String,    // class
    name: String,     // name
    pid: String,      //
    exe_hash: String, //  exe sha256
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

    matched_data: Option<Vec<String>>,
}

impl ToAgentRecord for DetectProcEvent {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6002);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(32);
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

        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }

        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }

    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6002);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(32);
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
        hmp.insert("token".to_string(), token.to_string());

        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }

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
        matched_data: Option<Vec<String>>,
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

            let pidns = format!("/proc/{}/ns/pid", pid);
            if let Ok(pns) = std::fs::read_link(&pidns) {
                if let Some(pns_str) = pns.to_str() {
                    pf.pns = pns_str
                        .trim_start_matches("pid:[")
                        .trim_end_matches("]")
                        .to_string();
                }
            }
        }
        if let Ok(ps) = p.stat() {
            pf.pgid = ps.pgrp.to_string();
            pf.sessionid = ps.session.to_string();
        }

        if let Ok(ps) = p.cmdline() {
            pf.argv = ps.join(" ");
        }
        pf.matched_data = matched_data;
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

#[derive(Serialize, Debug, Default)]
pub struct DetectOneTaskEvent {
    types: String,    // rule type
    class: String,    // class
    name: String,     // name
    exe: String,      // file path
    exe_size: String, // file size
    exe_hash: String, // xhash 32k
    md5_hash: String, // md5
    create_at: String,
    modify_at: String,
    error: String, // error
    token: String, // task token

    matched_data: Option<Vec<String>>,
}

impl DetectOneTaskEvent {
    fn to_record_with_add_on(&self, addons: &HashMap<String, String>) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6003);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(16);
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

        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

impl ToAgentRecord for DetectOneTaskEvent {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6003);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(16);
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

        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }

    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6003);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(16);
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
        hmp.insert("token".to_string(), token.to_string());

        if let Some(mdata) = &self.matched_data {
            hmp.insert(
                "hit_data".to_string(),
                serde_json::to_string(&mdata).unwrap_or_default(),
            );
        }

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
        r.set_data_type(6010);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(4);
        hmp.insert("version".to_string(), self.db_version.to_string());
        hmp.insert("exe_hash".to_string(), self.db_sha256.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }

    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6010);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(4);
        hmp.insert("version".to_string(), self.db_version.to_string());
        hmp.insert("exe_hash".to_string(), self.db_sha256.to_string());
        hmp.insert("token".to_string(), token.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

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
            Ok((result, matched_data)) => {
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

                if ftype.starts_with("Php")
                    && class.starts_with("Webshell")
                    && !fpath.ends_with(".php")
                    || ftype.starts_with("Jsp")
                        && class.starts_with("Webshell")
                        && !fpath.ends_with(".jsp")
                {
                    ftype = "not_detected".to_string();
                    class = "".to_string();
                    name = "".to_string();
                }

                if &ftype != "not_detected" {
                    info!(
                        "[Catch] filepath:{} result:{}.{}.{}",
                        &fpath, &ftype, &class, &name
                    );
                    if let Some(data) = &matched_data {
                        info!("[Catch] yara hit data:{:?}", data);
                    }
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
            Ok((result, matched_data)) => {
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

                if ftype.starts_with("Php")
                    && class.starts_with("Webshell")
                    && !fpath.ends_with(".php")
                    || ftype.starts_with("Jsp")
                        && class.starts_with("Webshell")
                        && !fpath.ends_with(".jsp")
                {
                    ftype = "not_detected".to_string();
                    class = "".to_string();
                    name = "".to_string();
                }

                if &ftype != "not_detected" {
                    info!(
                        "[Catch] filepath:{} result:{}.{}.{}",
                        &fpath, &ftype, &class, &name
                    );
                    if let Some(data) = &matched_data {
                        info!("[Catch] yara hit data:{:?}", data);
                    }
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
    pub task_receiver: crossbeam_channel::Receiver<DetectTask>,
    s_locker: crossbeam_channel::Sender<()>,
    db_path: String,
    scanner: Option<Scanner>,
    _recv_worker: thread::JoinHandle<()>,
    rule_updater: crossbeam_channel::Receiver<String>,
    db_manager: updater::DBManager,
    model_php: String,
    ppid: u32,
    supper_mode: bool,
}

impl Detector {
    pub fn new(
        ppid: u32,
        client: plugins::Client,
        task_sender: crossbeam_channel::Sender<DetectTask>,
        task_receiver: crossbeam_channel::Receiver<DetectTask>,
        s_locker: crossbeam_channel::Sender<()>,
        db_path: &str,
        db_manager: updater::DBManager,
        model_php: &str,
    ) -> Self {
        let recv_worker_s_locker = s_locker.clone();
        let (s, r) = bounded(0);
        // Receive One-time-scan-task : Path
        let mut r_client = client.clone();
        clamav::clamav_init().unwrap();
        let recv_worker = thread::spawn(move || {
            let mut _arf_t: Option<HoneyPot> = None;
            loop {
                match r_client.receive() {
                    Ok(t) => {
                        info!("recv task.data {:?}", &t.get_data());
                        match t.data_type {
                            6053 => {
                                // Scan task
                                if task_sender.len() >= 250 {
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
                            6051 => {
                                // turn on anti-ransom funcs
                                if let Some(_) = _arf_t {
                                    info!("anti-ransom is already on.");
                                    continue;
                                }
                                let s_arf_worker = task_sender.clone();
                                let s_arf_lock = recv_worker_s_locker.clone();
                                _arf_t = match HoneyPot::new(s_arf_worker, s_arf_lock) {
                                    Ok(hp) => {
                                        info!("anti-ransom turn on.");
                                        Some(hp)
                                    }
                                    Err(e) => {
                                        error!(
                                            "anti-ransom init failed in HoneyPot:new with {}",
                                            e
                                        );
                                        None
                                    }
                                };
                            }
                            6052 => {
                                // turn off anti-ransom funcs
                                _arf_t = None;
                                info!("Anti-ransom has been turn off.");
                            }
                            6054 => {
                                // reset anti-ransom honeypots
                                if let Some(ref mut arf_t) = _arf_t {
                                    arf_t.reset();
                                    info!("Anti-ransom has been reset.");
                                } else {
                                    info!("Anti-ransom is off ,will not be reset.");
                                }
                            }
                            6055 => {
                                // turn on supper mode
                                let task = DetectTask {
                                    task_type: "6055".to_string(),
                                    pid: 0,
                                    path: "".to_string(),
                                    rpath: "".to_string(),
                                    token: "".to_string(),
                                    btime: 0,
                                    mtime: 0,
                                    size: 0,
                                    add_ons: None,
                                };
                                if let Err(e) = task_sender.try_send(task) {
                                    error!("internal send task err : {:?}", e);
                                    continue;
                                }
                            }
                            6056 => {
                                // turn off supper mode
                                let task = DetectTask {
                                    task_type: "6056".to_string(),
                                    pid: 0,
                                    path: "".to_string(),
                                    rpath: "".to_string(),
                                    token: "".to_string(),
                                    btime: 0,
                                    mtime: 0,
                                    size: 0,
                                    add_ons: None,
                                };
                                if let Err(e) = task_sender.try_send(task) {
                                    error!("internal send task err : {:?}", e);
                                    continue;
                                }
                                crate::setup_cgroup(ppid, 1024 * 1024 * 180, 10000);
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
                                let mut worker_count = MAX_SCAN_ENGINES;
                                let mut worker_cpu = MAX_SCAN_CPU_100;
                                let mut worker_mem = MAX_SCAN_MEM_MB;

                                if let Some(worker_c) = task_map.get("worker") {
                                    let worker_cu32: u32 = worker_c.parse().unwrap_or_default();
                                    if worker_cu32 != 0 {
                                        worker_count = worker_cu32;
                                    }
                                }

                                if let Some(worker_c) = task_map.get("cpu") {
                                    let worker_cu32: u32 = worker_c.parse().unwrap_or_default();
                                    if worker_cu32 != 0 {
                                        worker_cpu = worker_cu32;
                                    }
                                }

                                if let Some(worker_c) = task_map.get("mem") {
                                    let worker_cu32: u32 = worker_c.parse().unwrap_or_default();
                                    if worker_cu32 != 0 {
                                        worker_mem = worker_cu32;
                                    }
                                }

                                // supper mode for fulldisk scan
                                let task = DetectTask {
                                    task_type: "6057".to_string(),
                                    pid: ppid as i32,
                                    path: "".to_string(),
                                    rpath: "".to_string(),
                                    token: t.get_token().to_string(),
                                    btime: worker_count as u64,
                                    mtime: worker_cpu as u64,
                                    size: worker_mem as usize,
                                    add_ons: None,
                                };
                                if let Err(e) = task_sender.try_send(task) {
                                    error!("internal send task err : {:?}", e);
                                    continue;
                                }
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
            model_php: model_php.into(),
            supper_mode: false,
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
                    if let Err(e) = self.db_manager.load(){
                        error!("archive db load err: {:?}",e);
                        work_s_locker.send(()).unwrap();
                        return
                    }
                    match Scanner::new(&self.db_path,&self.model_php){
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
                            match Scanner::new(&self.db_path,&self.model_php){
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
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = t.scan(&task.path){
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
                                        types: "".to_string(),
                                        class:"".to_string(),
                                        name: "".to_string(),
                                        exe: task.path.to_string(),
                                        exe_size: "".to_string(),
                                        exe_hash: "".to_string(),
                                        md5_hash: "".to_string(),
                                        create_at:"".to_string(),
                                        modify_at:"".to_string(),
                                        error: format!("{:?}",e),
                                        token: task.token.to_string(),
                                        matched_data:None,
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
                                if let Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) = t.scan(&task.path){
                                    let event = DetectOneTaskEvent{
                                        types: ftype.to_string(),
                                        class:fclass.to_string(),
                                        name: fname.to_string(),
                                        exe: task.path.to_string(),
                                        exe_size: meta.len().to_string(),
                                        exe_hash: xhash.to_string(),
                                        md5_hash: md5sum.to_string(),
                                        create_at:btime.0.to_string(),
                                        modify_at:btime.1.to_string(),
                                        error: "".to_string(),
                                        token:task.token.to_string(),
                                        matched_data:matched_data,
                                    };
                                    if &ftype != "not_detected"{
                                        info!("Catch filepath:{} filesize:{} md5sum:{} create_at:{} motidy_at:{} types:{} class:{} name:{}",
                                            &task.path,
                                            &event.exe_size,
                                            &md5sum,
                                            &event.create_at,
                                            &event.modify_at,
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
                        "6054" =>{
                            debug!("recv work 6054");
                            if let Some(t) =  &mut self.scanner{
                                debug!("scan {:?}",task.path);
                                match t.scan(&task.path){
                                    Ok((ftype,fclass,fname,xhash,md5sum,matched_data)) => {
                                        let mut event = AntiRansomEvent::new(
                                            task.pid,
                                            &ftype,
                                            "anti_ransom",
                                            &fname,
                                            &task.path,
                                            &xhash,
                                            &md5sum,
                                            task.size,
                                            task.btime,
                                            task.mtime,
                                            &task.rpath,
                                            &task.token,
                                            matched_data,
                                        ).unwrap_or_default();

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

                                        if let Err(e) = self.client.send_record(&event.to_record()) {
                                            warn!("send err, should exit : {:?}",e);
                                            work_s_locker.send(()).unwrap();
                                            return
                                        };
                                    },
                                    Err(e) => {
                                        error!("error {:?} while scann {:?}",e,&task.path);
                                    },
                                };
                            }
                        }, // anti_ransom
                        "6055" =>{
                            // turn on supper mode
                            self.supper_mode = true;
                        }

                        "6056" =>{
                             // turn off supper mode
                            self.supper_mode = false;
                        }

                        "6057" =>{
                            if let Some(t) = &mut self.scanner{
                                // fullscan job handler
                                let (mut fullscan_job, mut worker_jobs) = FullScan(
                                    self.ppid,
                                    self.client.clone(),
                                    task.btime as u32,
                                    task.mtime as u32,
                                    task.size as u32,
                                    &t,
                                );
                                fullscan_job.join();
                                for each_job in worker_jobs {
                                    each_job.join();
                                }
                                self.scanner = None;
                                info!("[FullScan] All job Cleaned.");
                                let end_flag = FulllScanFinished {};
                                if let Err(e) =
                                    self.client.send_record(&end_flag.to_record_token(&task.token))
                                {
                                    warn!("send err, should exit : {:?}", e);
                                };
                                crate::setup_cgroup(self.ppid, 1024 * 1024 * 180, 10000);

                            }
                        }
                         _ =>{
                            debug!("nothing");
                            continue
                        },
                    }
                    if !self.supper_mode{
                        std::thread::sleep(configs::WAIT_INTERVAL_SCAN);
                    }
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
