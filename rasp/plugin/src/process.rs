use crate::filter::Filters;
use anyhow::{anyhow, Result as AnyhowResult};
use coarsetime::Clock;
use librasp::runtime::Runtime;
// use log::*;
use procfs::process::{Namespaces, Process};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: i32,
    pub cmdline: Option<String>,
    pub exe_name: Option<String>,
    pub exe_path: Option<String>,
    pub environ: Option<HashMap<OsString, OsString>>,
    pub namespace_info: Option<Namespaces>,

    pub tracing_state: Option<TracingState>,
    pub auto_attach: bool,
    pub runtime: Option<Runtime>,

    pub attach_start_time: Option<String>,
    pub attach_end_time: Option<String>,
    pub failed_time: Option<String>,
    pub missing_time: Option<String>,
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
    pub fn collect(pid: i32, filters: &Filters) -> AnyhowResult<Self> {
        let mut pi = Self::new(pid);

        let process = Process::new(pid)?;
        let (exe_name, exe_path) = pi.update_exe(&process)?;
        for ignore_path in filters.ignore_exe_path.iter() {
            if exe_path.starts_with(ignore_path) {
                return Err(anyhow!("hit global exe_path filter: {}, ignore prcess", ignore_path));
            }
        }
        for ignore_name in filters.ignore_exe_name.iter() {
            if &exe_name == ignore_name {
                return Err(anyhow!("hit global exe_path filter: {}, ignore prcess", ignore_name));
            }
        }
        if filters.collect_all_env {
            log::debug!("collect_all_env");
            pi.update_all_env(&process)?
        } else {
            pi.update_env(&process, &filters.collect_env)?;
        }
        pi.update_cmdline(&process)?;
        pi.update_ns_info(&process)?;
        log::debug!("collect_all_env: {:?}", pi.environ);
        Ok(pi)
    }
    fn update_exe(&mut self, process: &Process) -> AnyhowResult<(String, String)> {
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
    fn update_all_env(
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
    fn update_env(
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
    pub fn read_ns_pid(pid: i32) -> Result<Option<i32>, String> {
        let process = match Process::new(pid) {
            Ok(p) => p,
            Err(e) => {
                return Err(e.to_string());
            }
        };
        // check process ns pid
        let status = match process.status() {
            Ok(st) => st,
            Err(e) => {
                return Err(e.to_string());
            }
        };
        let ns_pid = match status.nspid {
            Some(nspid_vec) => {
                if nspid_vec.len() == 2 {
                    Some(nspid_vec[1])
                } else {
                    None
                }
            }
            None => None,
        };
        Ok(ns_pid)
    }

    fn update_cmdline(&mut self, process: &Process) -> AnyhowResult<String> {
        if self.cmdline.is_none() {
            let cmdline = process.cmdline()?.join(" ");
            self.cmdline = Some(cmdline);
        }
        Ok(self.cmdline.clone().unwrap())
    }
    fn current_time(&self) -> String {
        let mills = Clock::now_since_epoch().as_secs().to_string();
        mills
    }
    pub fn update_attach_start_time(&mut self) {
        self.attach_start_time = Some(self.current_time());
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
}

pub fn poll_pid_func(tracking_pid: &Vec<i32>) -> AnyhowResult<(Vec<i32>, Vec<i32>)> {
    let all_pids = traverse_proc()?;
    let mut need_inspect_pids: Vec<i32> = Vec::new();
    // new pid filter
    for p in all_pids.iter() {
        // pid didn't pass filter
        if !tracking_pid.contains(p) {
            need_inspect_pids.push(p.clone());
        }
    }
    Ok((all_pids, need_inspect_pids))
}

fn traverse_proc() -> AnyhowResult<Vec<i32>> {
    let mut pids = Vec::new();
    for entry in read_dir("/proc")? {
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


pub fn process_health(traced_processes: &HashMap<i32, ProcessInfo>) -> Vec<i32> {
    let mut result = Vec::new();
    for (pid, _) in traced_processes.iter() {
        if let Ok(p) = Process::new(*pid) {
            // zombie check
            if let Ok(_) = p.status() {
                continue;
            } else {
                result.push(pid.clone());
            }
        } else {
            result.push(pid.clone());
        }
    }
    result
}
