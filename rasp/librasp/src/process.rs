use anyhow::{anyhow, Result as AnyhowResult};
use log::*;
use std::{collections::HashMap, ffi::OsString};
use std::path::Path;
use std::fs;
use std::io;
use std::io::BufRead;

use crate::runtime::Runtime;
use coarsetime::Clock;
use libc::stat;
use procfs::process::{Namespaces, Process};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: i32,
    pub cmdline: Option<String>,
    pub exe_name: Option<String>,
    pub exe_path: Option<String>,
    pub sid: i32,
    pub ruid: u32,
    pub rgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fuid: u32,
    pub fgid: u32,
    pub ppid: i32,
    pub tgid: i32,
    pub environ: Option<HashMap<OsString, OsString>>,
    pub namespace_info: Option<Namespaces>,

    pub tracing_state: Option<TracingState>,
    pub auto_attach: bool,
    pub runtime: Option<Runtime>,

    pub attach_start_time: Option<String>,
    pub attach_end_time: Option<String>,
    pub failed_time: Option<String>,
    pub missing_time: Option<String>,
    pub start_time: Option<f32>,
    pub try_attach_count: u16,
    pub attached_count: u16,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum TracingState {
    WAIT_INSPECT,
    INSPECTED,
    WAIT_ATTACH,
    ATTACHED,
    CLOSING,
}

impl std::fmt::Display for TracingState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


impl ProcessInfo {
    pub fn new(pid: i32) -> Self {
        let mut default = Self::default();
        default.pid = pid;
        default

    }
    pub fn from_pid(pid: i32) -> AnyhowResult<Self> {
        let mut pi = Self::new(pid);
        let process = Process::new(pid)?;
        pi.update_exe(&process)?;
        pi.update_all_env(&process)?;
        pi.update_cmdline(&process)?;
        pi.update_ns_info(&process)?;
        pi.update_ppid(&process)?;
        pi.update_tgid(&process)?;
        pi.update_cmdline(&process)?;
        pi.update_id(&process)?;
        Ok(pi)

    }
    fn current_time(&self) -> String {
        let mills = Clock::now_since_epoch().as_secs().to_string();
        mills
    }
    pub fn update_attach_end_time(&mut self) {
        self.attach_end_time = Some(self.current_time());
    }
    pub fn update_failed_time(&mut self) {
        self.failed_time = Some(self.current_time());
    }
    pub fn update_missing_time(&mut self) {
        self.missing_time = Some(self.current_time());
    }
    pub fn update_try_attach_count(&mut self) {
        self.try_attach_count += 1;
    }
    pub fn update_attached_count(&mut self) {
        self.attached_count += 1;
    }
    pub fn update_attach_start_time(&mut self) {
        self.attach_start_time = Some(self.current_time());
    }
    pub fn update_id(&mut self, process: &Process) -> AnyhowResult<()> {
        let status = process.status()?;
        self.ruid = status.ruid;
        self.rgid = status.rgid;
        self.euid = status.euid;
        self.egid = status.egid;
        self.suid = status.suid;
        self.sgid = status.sgid;
        self.fuid = status.fuid;
        self.fgid = status.fgid;
        Ok(())
    }
    pub fn update_start_time(&mut self, process: &Process) ->AnyhowResult<f32> {
        if let Some(st) = self.start_time {
            return Ok(st.clone());
        }
        let start_time = process.stat.starttime as f32;
        self.start_time = Some(start_time.clone());
        Ok(start_time)
    }
    pub fn update_exe(&mut self, process: &Process) -> AnyhowResult<(String, String)> {
        if self.exe_name.is_some() && self.exe_path.is_some() {
            return Ok((
                self.exe_name.clone().unwrap(),
                self.exe_path.clone().unwrap(),
            ));
        }
        let exe = process.exe()?;
        let exe_name = exe
            .file_name()
            .ok_or(anyhow!("fetch file name failed: {:?}", exe))?
            .to_str()
            .ok_or(anyhow!("convert osstr to str failed: {:?}", exe))?
            .to_string();
        let exe_path = match exe.into_os_string().into_string() {
            Ok(ep) => ep,
            Err(eposs) => {
                return Err(anyhow!("convert osstr to string failed: {:?}", &eposs));
            }
        };
        self.exe_name = Some(exe_name.clone());
        self.exe_path = Some(exe_path.clone());
        Ok((exe_name, exe_path))
    }
    pub fn update_cmdline(&mut self, process: &Process) -> AnyhowResult<String> {
        if self.cmdline.is_none() {
            let cmdline = process.cmdline()?.join(" ");
            self.cmdline = Some(cmdline);
        }
        Ok(self.cmdline.clone().unwrap())
    }
    pub fn update_all_env(
        &mut self,
        process: &Process,
    ) -> AnyhowResult<()> {
        let envs = process.environ()?;
        let mut map = HashMap::new();
        for (k, v) in envs {
            map.insert(k.clone(), v.clone());
        }
        self.environ = Some(map);
        Ok(())
    }

    pub fn update_env(
        &mut self,
        process: &Process,
        collect: &Vec<String>,
    ) -> AnyhowResult<HashMap<String, String>> {
        let mut keys = collect.clone();
        let mut result: HashMap<String, String> = HashMap::new();
        if self.environ.is_some() {
            let environ = self.environ.as_ref().unwrap();
            let mut remove = Vec::new();
            for (index, key) in keys.iter_mut().enumerate() {
                match environ.get(&std::ffi::OsString::from(key.clone())) {
                    Some(v) => match v.clone().into_string() {
                        Ok(s) => {
                            let _ = result.insert(key.to_string(), s);
                            remove.push(index);
                        }
                        Err(_) => {}
                    },
                    None => {}
                }
            }
            for i in remove.iter() {
                keys.remove(*i);
            }
        } else {
            self.environ = Some(HashMap::new());
        }
        let self_environ = self.environ.as_mut().unwrap();
        let envs = process.environ()?;
        for key in keys.iter() {
            let v = match envs.get(&std::ffi::OsString::from(key)) {
                Some(v) => {
                    self_environ.insert(std::ffi::OsString::from(key), v.clone());
                    match v.clone().into_string() {
                        Ok(s) => s,
                        Err(_) => String::new(),
                    }
                }
                None => String::new(),
            };
            result.insert(key.to_string(), v);
        }
        Ok(result)
    }

    pub fn update_ns_info(&mut self, process: &Process) -> AnyhowResult<Namespaces> {
        if self.namespace_info.is_none() {
            self.namespace_info = Some(process.ns()?);
        }
        Ok(self.namespace_info.clone().unwrap())
    }
    pub fn get_mnt_ns(&self) -> AnyhowResult<String> {
        if let Some(ref ns) = self.namespace_info {
            return match ns.mnt.clone() {
                Some(mnt_ns) => Ok(mnt_ns),
                None => Err(anyhow!("process mnt ns empty: {}", self.pid)),
            };
        }
        Err(anyhow!("fetch process ns failed: {}", self.pid))
    }
    pub fn update_ppid(&mut self, process: &Process) -> AnyhowResult<i32> {
        if self.ppid != 0 {
            return Ok(self.ppid.clone());
        }
        let ppid = process.stat.ppid;
        self.ppid = ppid.clone();
        return Ok(ppid);
    }
    pub fn update_tgid(&mut self, process: &Process) -> AnyhowResult<i32> {
        if self.tgid != 0 {
            return Ok(self.tgid.clone());
        }
        let tgid = process.status()?.tgid;
        self.tgid = tgid.clone();
        Ok(tgid)
    }
    pub fn update_sid(&mut self, process: &Process) -> AnyhowResult<i32> {
        if self.sid != 0 {
            return Ok(self.sid.clone());
        }
        let sid = process.stat.session;
        self.sid = sid.clone();
        Ok(sid)
    }

    pub fn read_nspid(pid: i32) -> AnyhowResult<Option<i32>> {
        let current_pid_path = match std::fs::read_link("/proc/self/ns/pid") {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("can not read nspid: {:?}", e));
            }
        };
        let target_pid_path = match std::fs::read_link(format!("/proc/{}/ns/pid", pid)) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("can not read nspid: {:?}", e));
            }
        };
        if current_pid_path == target_pid_path {
            return Ok(Some(pid));
        }
        let process = match Process::new(pid) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("{}", e.to_string()));
            }
        };
        // check process ns pid
        let status = match process.status() {
            Ok(st) => st,
            Err(e) => {
                return Err(anyhow!("{}", e.to_string()));
            }
        };
        match status.nspid {
            Some(nspid_vec) => {
                if nspid_vec.len() == 2 {
                    return Ok(Some(nspid_vec[1]));
                }
            }
            None => {}
        };
        /*
        https://github.com/apangin/jattach/blob/master/src/posix/psutil.c#L70
        // Linux kernels < 4.1 do not export NStgid field in /proc/pid/status.
        // Fortunately, /proc/pid/sched in a container exposes a host PID,
        // so the idea is to scan all container PIDs to find which one matches the host PID.
        */
        let pids = match traverse_proc(pid) {
            Ok(v) => v,
            Err(e) => {
                return Err(anyhow!("{}", e.to_string()));
            }
        };
        for p in pids.iter() {
            let sched_pid = match sched_get_host_pid(format!("/proc/{}/root/proc/{}/sched", pid, p))
            {
                Ok(sched_pid) => sched_pid,
                Err(e) => {
                    warn!("read pid from sched failed: {}", e);
                    continue;
                }
            };
            if sched_pid == pid {
                return Ok(Some(*p));
            }
        }
        Ok(None)
    }
}

fn traverse_proc(pid: i32) -> AnyhowResult<Vec<i32>> {
    let mut pids = Vec::new();
    for entry in read_dir(format!("/proc/{}/root/proc", pid))? {
        let filename = entry.file_name();

        if let Ok(pid) = filename.to_string_lossy().parse::<i32>() {
            pids.push(pid);
        }
    }
    Ok(pids)
}

// copy from https://github.com/rust-psutil/rust-psutil/blob/b50a3fbc77fbf042c58b6f9ca9345e2c3c8d449b/src/errors.rs#L88
fn read_dir<P>(path: P) -> AnyhowResult<Vec<fs::DirEntry>>
    where
        P: AsRef<Path>,
{
    fs::read_dir(&path)
        .map_err(|err| anyhow!("Failed to read file '{:?}': {}", path.as_ref(), err))?
        .map(|entry| {
            entry.map_err(|err| anyhow!("Failed to read file '{:?}': {}", path.as_ref(), err))
        })
        .collect()
}


fn sched_get_host_pid<P>(path: P) -> AnyhowResult<i32>
    where
        P: AsRef<Path>,
{
    let file = fs::File::open(path)?;
    let mut line = String::new();
    io::BufReader::new(file).read_line(&mut line)?;
    let re = regex::Regex::new(r"\((\d+),")?;
    let pid = match re.captures(&line) {
        Some(c) => c.get(1).map_or("", |m| m.as_str()),
        None => return Err(anyhow!(String::from("can not find sched pid"))),
    };
    let pid = match pid.parse::<i32>() {
        Ok(vm) => vm,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    Ok(pid)
}
