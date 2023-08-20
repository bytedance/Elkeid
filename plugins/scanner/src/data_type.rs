use anyhow::{anyhow, Result};
use coarsetime::Clock;
use serde::{self, Deserialize, Serialize};
use serde_json;
use std::{collections::HashMap, hash::Hash};

use crate::{
    config::{
        FULLSCAN_CPU_IDLE_100PCT, FULLSCAN_CPU_IDLE_INTERVAL, FULLSCAN_CPU_MAX_TIME_SECS,
        FULLSCAN_CPU_QUOTA_DEFAULT_MAX, FULLSCAN_CPU_QUOTA_DEFAULT_MIN, FULLSCAN_MAX_SCAN_CPU_100,
        FULLSCAN_MAX_SCAN_ENGINES, FULLSCAN_MAX_SCAN_MEM_MB, FULLSCAN_MAX_SCAN_TIMEOUT_FULL,
        FULLSCAN_MAX_SCAN_TIMEOUT_QUICK, FULLSCAN_SCAN_MODE_FULL, FULLSCAN_SCAN_MODE_QUICK,
    },
    get_file_md5, get_file_xhash, pid_to_docker_id, ToAgentRecord,
};

// fullscan finished datatype
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanFinished {
    pub data: String,
    pub error: String,
}

impl ToAgentRecord for ScanFinished {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6000);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(4);
        hmp.insert("status".to_string(), self.data.to_string());
        hmp.insert("msg".to_string(), self.error.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }

    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6000);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(4);
        hmp.insert("token".to_string(), token.to_string());
        hmp.insert("status".to_string(), self.data.to_string());
        hmp.insert("msg".to_string(), self.error.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

// DetectFileEvent = Static file detect event
#[derive(Serialize, Debug)]
pub struct DetectFileEvent {
    pub types: String,       // rule type
    pub class: String,       // class
    pub name: String,        // name
    pub exe: String,         // *
    pub static_file: String, // *
    pub exe_size: String,    // file_size
    pub exe_hash: String,    // * xhash
    pub md5_hash: String,    // * md5
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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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

// DetectFanotifyEvent = Proc pid/exe detect event
#[derive(Serialize, Deserialize, Debug)]
pub struct AnitRansomFunc {
    pub status: String,
}

impl ToAgentRecord for AnitRansomFunc {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6011);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(4);
        hmp.insert("status".to_string(), self.status.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }

    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6011);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(4);
        hmp.insert("status".to_string(), self.status.to_string());
        hmp.insert("token".to_string(), token.to_string());
        pld.set_fields(hmp);
        r.set_data(pld);
        return r;
    }
}

// DetectFanotifyEvent = Proc pid/exe detect event
#[derive(Serialize, Debug, Default)]
pub struct FanotifyEvent {
    pub pid: String, //
    //pub exe_hash: String, //  exe sha256
    //pub md5_hash: String,
    pub exe_size: String,
    pub exe: String, //

    pub create_at: String,
    pub modify_at: String,
    pub ppid: String,      //  status|stat - PID of parent process.
    pub pgid: String,      //  stat - The process group ID
    pub tgid: String,      //  status - Thread group ID
    pub argv: String,      //  /proc/pid/cmdline
    pub comm: String, // status: Name | stat: comm - The filename of the executable TASK_COMM_LEN (16)
    pub sessionid: String, //  stat  - session id
    pub uid: String,  // * real user uid
    pub pns: String,

    pub file_path: String, // notify file
    //pub file_hash: String, // notify file sha256
    pub file_mask: String, // notify file fanotify_metadata.mask
    pub docker_id: String,
}

impl ToAgentRecord for FanotifyEvent {
    fn to_record(&self) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6012);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(32);
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
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

        hmp.insert("docker_id".to_string(), self.docker_id.to_string());

        hmp.insert("file_path".to_string(), self.file_path.to_string());
        //hmp.insert("file_hash".to_string(), self.file_hash.to_string());
        hmp.insert("file_mask".to_string(), self.file_mask.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }
    fn to_record_token(&self, token: &str) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6012);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(32);
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("exe_size".to_string(), self.exe_size.to_string());
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

        hmp.insert("docker_id".to_string(), self.docker_id.to_string());

        hmp.insert("file_path".to_string(), self.file_path.to_string());
        //hmp.insert("file_hash".to_string(), self.file_hash.to_string());
        hmp.insert("file_mask".to_string(), self.file_mask.to_string());

        pld.set_fields(hmp);
        r.set_data(pld);

        return r;
    }
}

//AntiRansomEvent get pid info from proc
impl FanotifyEvent {
    pub fn new(
        pid: i32,
        exe: &str,
        size: usize,
        create_at: u64,
        modify_at: u64,
        file_path: &str,
        //file_hash: &str,
        file_mask: &str,
    ) -> Self {
        let mut pf = Self::default();
        pf.pid = pid.to_string();

        pf.exe = exe.to_string();
        pf.exe_size = size.to_string();
        pf.create_at = create_at.to_string();
        pf.modify_at = modify_at.to_string();

        pf.file_path = file_path.to_string();
        //pf.file_hash = file_hash.to_string();
        pf.file_mask = file_mask.to_string();

        pf.comm = "-3".to_string();
        pf.ppid = "-3".to_string();
        pf.uid = "-3".to_string();
        pf.tgid = "-3".to_string();
        pf.pns = "-3".to_string();
        pf.pgid = "-3".to_string();
        pf.sessionid = "-3".to_string();
        pf.argv = "-3".to_string();

        if let Some(docker_id) = pid_to_docker_id(pid) {
            pf.docker_id = docker_id;
        }

        let p = match procfs::process::Process::new(pid) {
            Ok(pinner) => pinner,
            Err(_) => return pf,
        };

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
        return pf;
    }
}

// DetectAntiRansomEvent = Proc pid/exe detect event
#[derive(Serialize, Debug, Default)]
pub struct AntiRansomEvent {
    pub types: String,    // rule type
    pub class: String,    // class
    pub name: String,     // name
    pub pid: String,      //
    pub exe_hash: String, //  exe sha256
    pub md5_hash: String,
    pub exe_size: String,
    pub exe: String,         //
    pub static_file: String, //
    pub create_at: String,
    pub modify_at: String,
    pub ppid: String,      //  status|stat - PID of parent process.
    pub pgid: String,      //  stat - The process group ID
    pub tgid: String,      //  status - Thread group ID
    pub argv: String,      //  /proc/pid/cmdline
    pub comm: String, // status: Name | stat: comm - The filename of the executable TASK_COMM_LEN (16)
    pub sessionid: String, //  stat  - session id
    pub uid: String,  // * real user uid
    pub pns: String,

    pub file_path: String, // honeypot file
    //pub file_hash: String, // honeypot file sha256
    pub file_mask: String,

    pub matched_data: Option<Vec<String>>,
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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
        //hmp.insert("file_hash".to_string(), self.file_hash.to_string());
        hmp.insert("file_mask".to_string(), self.file_mask.to_string());

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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
        //hmp.insert("file_hash".to_string(), self.file_hash.to_string());
        hmp.insert("file_mask".to_string(), self.file_mask.to_string());

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

//AntiRansomEvent get pid info from proc
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
        //file_hash: &str,
        file_mask: &str,
        matched_data: Option<Vec<String>>,
    ) -> Self {
        let mut pf = Self::default();
        pf.pid = pid.to_string();
        pf.types = ftype.to_string();
        pf.class = fclass.to_string();
        pf.name = fname.to_string();
        pf.exe = exe.to_string();
        pf.static_file = exe.to_string();
        pf.exe_hash = xhash.to_string();
        pf.md5_hash = md5sum.to_string();
        pf.exe_size = size.to_string();
        pf.create_at = create_at.to_string();
        pf.modify_at = modify_at.to_string();

        pf.file_path = file_path.to_string();
        //pf.file_hash = file_hash.to_string();
        pf.file_mask = file_mask.to_string();
        pf.matched_data = matched_data;

        pf.comm = "-3".to_string();
        pf.ppid = "-3".to_string();
        pf.uid = "-3".to_string();
        pf.tgid = "-3".to_string();
        pf.pns = "-3".to_string();
        pf.pgid = "-3".to_string();
        pf.sessionid = "-3".to_string();
        pf.argv = "-3".to_string();

        let p = match procfs::process::Process::new(pid) {
            Ok(pinner) => pinner,
            Err(_) => return pf,
        };

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
        return pf;
    }
}

// DetectProcEvent = Proc pid/exe detect event
#[derive(Serialize, Debug, Default)]
pub struct DetectProcEvent {
    pub types: String,    // rule type
    pub class: String,    // class
    pub name: String,     // name
    pub pid: String,      //
    pub exe_hash: String, //  exe sha256
    pub md5_hash: String,
    pub exe_size: String,
    pub exe: String,         //
    pub static_file: String, //
    pub create_at: String,
    pub modify_at: String,
    pub ppid: String,      //  status|stat - PID of parent process.
    pub pgid: String,      //  stat - The process group ID
    pub tgid: String,      //  status - Thread group ID
    pub argv: String,      //  /proc/pid/cmdline
    pub comm: String, // status: Name | stat: comm - The filename of the executable TASK_COMM_LEN (16)
    pub sessionid: String, //  stat  - session id
    pub uid: String,  // * real user uid
    pub pns: String,

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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
    ) -> Self {
        let mut pf = Self::default();
        pf.pid = pid.to_string();
        pf.types = ftype.to_string();
        pf.class = fclass.to_string();
        pf.name = fname.to_string();
        pf.exe = exe.to_string();
        pf.static_file = exe.to_string();
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

        let p = match procfs::process::Process::new(pid) {
            Ok(pinner) => pinner,
            Err(_) => return pf,
        };
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
        return pf;
    }
}

#[derive(Serialize, Debug, Default)]
pub struct DetectOneTaskEvent {
    pub types: String, // rule type
    pub class: String, // class
    pub name: String,  // name
    pub exe: String,   // file path
    pub static_file: String,
    pub exe_size: String, // file size
    pub exe_hash: String, // xhash 32k
    pub md5_hash: String, // md5
    pub create_at: String,
    pub modify_at: String,
    pub error: String, // error
    pub token: String, // task token

    pub matched_data: Option<Vec<String>>,
}

impl DetectOneTaskEvent {
    pub fn to_record_with_add_on(&self, addons: &HashMap<String, String>) -> plugins::Record {
        let mut r = plugins::Record::new();
        let mut pld = plugins::Payload::new();
        r.set_data_type(6003);
        r.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut hmp = HashMap::with_capacity(16);
        hmp.insert("types".to_string(), self.types.to_string());
        hmp.insert("class".to_string(), self.class.to_string());
        hmp.insert("name".to_string(), self.name.to_string());
        hmp.insert("exe".to_string(), self.exe.to_string());
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
        hmp.insert("static_file".to_string(), self.static_file.to_string());
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
    pub db_version: &'a str,
    pub db_sha256: &'a str,
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

#[derive(Serialize, Deserialize, Debug)]
pub enum DETECT_TASK {
    TASK_6051_STATIC_FILE(ScanTaskStaticFile),
    TASK_6052_PROC_EXE(ScanTaskProcExe),
    TASK_6053_USER_TASK(ScanTaskUserTask),
    TASK_6054_ANTIVIRUS(ScanTaskFanotify),
    TASK_6054_FANOTIFY(ScanTaskFanotify),
    TASK_6054_TASK_6054_ANTIVIRUS_STATUS(AnitRansomFunc),
    //TASK_6054_RESET_HONEYPOT,
    TASK_6057_FULLSCAN(FullScanTask),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanTaskStaticFile {
    pub scan_path: String,
    pub size: usize,
    pub btime: (u64, u64),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanTaskProcExe {
    pub pid: i32,
    pub pid_exe: String,
    pub scan_path: String,
    pub size: usize,
    pub btime: (u64, u64),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanTaskUserTask {
    pub token: String,
    pub scan_path: String,
    pub add_ons: Option<HashMap<String, String>>,
    pub finished: Option<ScanFinished>,
}

impl ScanTaskUserTask {
    pub fn with_path(token: &str, fpath: &str, add_ons: Option<HashMap<String, String>>) -> Self {
        Self {
            token: token.to_string(),
            scan_path: fpath.to_string(),
            add_ons,
            finished: None,
        }
    }
    pub fn with_finished(token: &str, data: &str, error: &str) -> Self {
        Self {
            token: token.to_string(),
            scan_path: "".to_string(),
            add_ons: None,
            finished: Some(ScanFinished {
                data: data.to_string(),
                error: error.to_string(),
            }),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanTaskFanotify {
    pub pid: i32,
    pub pid_exe: String,
    pub size: usize,
    pub btime: (u64, u64),
    //pub event_file_hash: String,
    pub event_file_path: String,
    pub event_file_mask: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullScanTask {
    pub cpu_idle_interval: u64,
    pub cpu_idle_100pct: u64,
    pub cpu_quota_default_min: u64,
    pub cpu_quota_default_max: u64,
    pub cpu_max_time_secs: u64,
    pub max_scan_engine: u32,
    pub max_scan_cpu100: u32,
    pub max_scan_mem_mb: u32,
    pub max_scan_timeout: u64,
    pub scan_mode_full: bool,
    pub token: String,
}

impl FullScanTask {
    pub fn new_default() -> Self {
        Self {
            cpu_idle_interval: *FULLSCAN_CPU_IDLE_INTERVAL,
            cpu_idle_100pct: *FULLSCAN_CPU_IDLE_100PCT,
            cpu_quota_default_min: *FULLSCAN_CPU_QUOTA_DEFAULT_MIN,
            cpu_quota_default_max: *FULLSCAN_CPU_QUOTA_DEFAULT_MAX,
            cpu_max_time_secs: *FULLSCAN_CPU_MAX_TIME_SECS,
            max_scan_engine: *FULLSCAN_MAX_SCAN_ENGINES,
            max_scan_cpu100: *FULLSCAN_MAX_SCAN_CPU_100,
            max_scan_mem_mb: *FULLSCAN_MAX_SCAN_MEM_MB,
            max_scan_timeout: *FULLSCAN_MAX_SCAN_TIMEOUT_FULL,
            scan_mode_full: false,
            token: "".to_string(),
        }
    }

    pub fn setup(&self) -> Result<()> {
        return Ok(());
    }
}
