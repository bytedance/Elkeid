use anyhow::{anyhow, Result as AnyhowResult};
use log::*;
use std::path::PathBuf;
use std::{collections::HashMap, ffi::OsString};

use crate::runtime::Runtime;
use coarsetime::Clock;
use procfs::process::{Namespaces, Process};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub exe_path: Option<String>,
    pub process_self: Process,
    pub process_tree: Option<Vec<Process>>,
    pub runtime_info: Option<Runtime>,
    pub container_info: Option<String>,
    pub namespace_info: Option<Namespaces>,
    pub cmdline: Option<String>,
    pub environ: Option<HashMap<OsString, OsString>>,
    pub exe: Option<PathBuf>,
    pub attach_time: Option<String>,
    pub failed_time: Option<String>,
    pub missing_time: Option<String>,
}

impl ProcessInfo {
    pub fn new(pid: i32) -> Result<Self, String> {
        let process = match Process::new(pid) {
            Ok(p) => ProcessInfo {
                pid,
                exe_path: None,
                process_self: p,
                process_tree: None,
                runtime_info: None,
                container_info: None,
                namespace_info: None,
                cmdline: None,
                environ: None,
                exe: None,
                attach_time: None,
                failed_time: None,
                missing_time: None,
            },
            Err(e) => {
                return Err(e.to_string());
            }
        };
        Ok(process)
    }
    fn current_time(&self) -> String {
        let mills = Clock::now_since_epoch().as_secs().to_string();
        mills
    }
    pub fn update_attach_time(&mut self) {
        self.attach_time = Some(self.current_time());
    }
    pub fn update_failed_time(&mut self) {
        self.failed_time = Some(self.current_time());
    }
    pub fn update_missing_time(&mut self) {
        self.missing_time = Some(self.current_time());
    }
    pub fn update_cmdline(&mut self) -> Result<String, String> {
        if self.cmdline.is_some() {
            return Ok(self.cmdline.clone().unwrap());
        }
        return match self.process_self.cmdline() {
            Ok(c) => {
                let cl = c.join(" ");
                self.cmdline = Some(cl.clone());
                Ok(cl)
            }
            Err(e) => {
                let msg = format!("read process cmdline failed {} {}", self.pid, e.to_string());
                warn!("{}", msg);
                Err(msg)
            }
        };
    }
    pub fn update_environ(&mut self) -> Result<HashMap<OsString, OsString>, String> {
        if self.environ.is_some() {
            let env = self.environ.clone().unwrap();
            return Ok(env);
        }
        return match self.process_self.environ() {
            Ok(env) => {
                self.environ = Some(env.clone());
                Ok(env)
            }
            Err(e) => {
                let msg = format!("read process environ failed {} {}", self.pid, e.to_string());
                warn!("{}", msg);
                Err(msg)
            }
        };
    }

    pub fn update_ns_info(&mut self) -> Result<(), String> {
        match self.process_self.ns() {
            Ok(ns) => {
                self.namespace_info = Some(ns);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }
    pub fn update_exe(&mut self) -> AnyhowResult<PathBuf> {
        if self.exe.is_some() {
            return Ok(self.exe.clone().unwrap());
        }
        let process_exe = match self.process_self.exe() {
            Ok(exe) => {
                self.exe = Some(exe.clone());
                exe
            }
            Err(e) => {
                debug!("cannot read exe name: {}", self.pid);
                return Err(anyhow!(e.to_string()));
            }
        };
        return Ok(process_exe);
    }
    pub fn update_exe_path(&mut self) -> AnyhowResult<String> {
        if self.exe_path.is_some() {
            return Ok(self.exe_path.clone().unwrap());
        }
        let process_exe = match self.update_exe() {
            Ok(exe) => exe,
            Err(e) => {
                debug!("cannot read exe name: {}", self.pid);
                return Err(anyhow!(e.to_string()));
            }
        };
        let process_exe_file = match process_exe.file_name() {
            Some(file_name) => match file_name.to_str() {
                Some(fname) => String::from(fname),
                None => return Err(anyhow!("convert osstr to str failed")),
            },
            None => {
                return Err(anyhow!("can not find exe file name"));
            }
        };
        self.exe_path = Some(process_exe_file.clone());
        Ok(process_exe_file)
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

    pub fn cmdline(&self) -> Result<String, String> {
        match self.process_self.cmdline() {
            Ok(cmdline_vec) => return Ok(cmdline_vec.join(" ")),
            Err(e) => {
                return Err(e.to_string());
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncFilter {
    pub white: Option<Vec<ProcessFilter>>,
    pub black: Option<Vec<ProcessFilter>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProcessFilter {
    pub cmdline: Option<Vec<String>>,
    pub env: Option<Vec<(String, String)>>,
    pub exe: Option<Vec<String>>,
    pub runtime: Option<String>,
}

impl ProcessFilter {
    pub fn new() -> Self {
        Self {
            cmdline: None,
            env: None,
            exe: None,
            runtime: None,
        }
    }

    pub fn defaut() -> Self {
        ProcessFilter::new()
    }

    pub fn update_runtime(mut self, runtime_name: String) -> Self {
        self.runtime = Some(runtime_name);
        self
    }
    pub fn match_runtime(&self, runtime: &str) -> Result<bool, ()> {
        if let Some(rt) = &self.runtime {
            if rt == runtime {
                return Ok(true);
            } else {
                return Ok(false);
            }
        } else {
            return Ok(true);
        }
    }

    pub fn add_env_filter(mut self, env_name: String, env_value: String) -> Self {
        let env_vec = match self.env {
            Some(mut env_origin_vec) => {
                env_origin_vec.push((env_name, env_value));
                env_origin_vec
            }
            None => {
                let mut new_vec = Vec::new();
                new_vec.push((env_name, env_value));
                new_vec
            }
        };
        self.env = Some(env_vec);
        self
    }

    pub fn add_cmdline_filter(mut self, cmd_line_keyword: String) -> Self {
        let cmdline_vec = match self.cmdline {
            Some(mut cmdline_origin_vec) => {
                cmdline_origin_vec.push(cmd_line_keyword);
                cmdline_origin_vec
            }
            None => {
                let mut new_vec = Vec::new();
                new_vec.push(cmd_line_keyword);
                new_vec
            }
        };
        self.cmdline = Some(cmdline_vec);
        self
    }

    pub fn add_exe_filter(mut self, exe_full_match_word: String) -> Self {
        let exe_vec = match self.exe {
            Some(mut exe_origin_vec) => {
                exe_origin_vec.push(exe_full_match_word);
                exe_origin_vec
            }
            None => {
                let mut new_vec = Vec::new();
                new_vec.push(exe_full_match_word);
                new_vec
            }
        };
        self.exe = Some(exe_vec);
        self
    }
    pub fn match_exe(&self, target_exe: &String) -> Result<bool, ()> {
        if self.exe.is_none() {
            return Ok(false);
        }
        let exe_vec = self.exe.as_ref().unwrap();
        for exe in exe_vec.iter() {
            if target_exe == exe {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn match_cmdline(&self, target_cmdline: &String) -> Result<bool, ()> {
        if self.cmdline.is_none() {
            return Ok(true);
        }
        let cmdlines = self.cmdline.as_ref().unwrap();
        for cmdline in cmdlines.iter() {
            if target_cmdline.starts_with(cmdline) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn match_env(&self, target_env: &HashMap<OsString, OsString>) -> Result<bool, ()> {
        if self.env.is_none() {
            return Ok(true);
        }
        let mut count = 0;
        let envs = self.env.as_ref().unwrap();
        let env_count = envs.len();
        for env in envs.iter() {
            if let Some(target_env_value) = target_env.get(&OsString::from(env.0.clone())) {
                if (*target_env_value) == OsString::from(env.1.clone()) {
                    count += 1;
                } else {
                    return Ok(false);
                }
            }
        }
        if count == env_count {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn match_process_info(
        &self,
        cmdline: &String,
        environ: &HashMap<OsString, OsString>,
        runtime_name: &String,
    ) -> Result<bool, ()> {
        if self.cmdline.is_none() && self.env.is_none() {
            return Err(());
        }
        let runtime_match_result = match self.match_runtime(runtime_name) {
            Ok(b) => b,
            Err(_) => false,
        };
        //debug!("runtime match: {:?}", &runtime_match_result);
        let cmdline_match_result = match self.match_cmdline(cmdline) {
            Ok(b) => b,
            Err(_) => false,
        };
        //debug!("cmdline match: {:?}", &cmdline_match_result);
        let env_match_result = match self.match_env(environ) {
            Ok(b) => b,
            Err(_) => false,
        };
        //debug!("env match: {:?}", &env_match_result);
        if cmdline_match_result && env_match_result && runtime_match_result {
            return Ok(true);
        }
        return Ok(false);
    }
}
