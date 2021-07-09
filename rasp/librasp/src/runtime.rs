use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use log::*;
use serde_json;

use crate::golang::golang_bin_inspect;
use crate::jvm::vm_version;
use crate::nodejs::nodejs_version;
use crate::process::{ProcessFilter, ProcessInfo};

const DEFAULT_JVM_FILTER_JSON_STR: &str = r#"{"exe": ["java"]}"#;
const DEFAULT_CPYTHON_FILTER_JSON_STR: &str = r#"{"exe": ["python","python2", "python3","python2.7", "python3.5", "python3.6", "python3.7", "python3.8", "python3.9", "uwsgi"]}"#;
const DEFAULT_NODEJS_FILTER_JSON_STR: &str = r#"{"exe": ["node"]}"#;

impl RuntimeInspect for ProcessInfo {}

#[derive(Debug, Clone)]
pub struct Runtime {
    pub name: &'static str,
    pub version: String,
}

impl Display for Runtime {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.name, self.version)
    }
}

pub enum ProbeState {
    Attached,
    NotAttach,
}
pub trait ProbeStateInspect {
    fn inspect_pid(pid: i32) -> Result<ProbeState> {
        // procfs::process::Process
        let process_info = match ProcessInfo::new(pid) {
            Ok(pi) => pi,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };
        // inspect process
        Self::inspect_process(&process_info)
    }
    fn inspect_process(process_info: &ProcessInfo) -> Result<ProbeState>;
}
pub trait RuntimeInspect {
    fn inspect_from_process_info(process_info: &mut ProcessInfo) -> Result<Option<Runtime>> {
        let process_exe_file = process_info.update_exe_path()?;
        debug!("runtime inspect: exe file: {}", process_exe_file);
        let jvm_process_filter: ProcessFilter =
            match serde_json::from_str(DEFAULT_JVM_FILTER_JSON_STR) {
                Ok(jvm_filter) => jvm_filter,
                Err(e) => {
                    error!("filter deserialize failed: {}", e);
                    return Err(anyhow!("jvm filter deserialize failed: {}", e));
                }
            };
        if let Ok(jvm) = jvm_process_filter.match_exe(&process_exe_file) {
            if jvm {
                let version = vm_version(process_info.pid)?;
                let version_string = version.to_string();
                return Ok(Some(Runtime {
                    name: "JVM",
                    version: version_string,
                }));
            }
        }
        let cpython_process_filter: ProcessFilter =
            match serde_json::from_str(DEFAULT_CPYTHON_FILTER_JSON_STR) {
                Ok(cpython_filter) => cpython_filter,
                Err(e) => {
                    error!("filter deserialize failed: {}", e);
                    return Err(anyhow!("cpython filter deserialize failed: {}", e));
                }
            };
        let process_filter_check_result = match cpython_process_filter.match_exe(&process_exe_file)
        {
            Ok(o) => o,
            Err(_) => false,
        };
        if process_filter_check_result {
            return Ok(Some(Runtime {
                name: "CPython",
                version: String::new(),
            }));
        }
        let nodejs_process_filter: ProcessFilter =
            match serde_json::from_str(DEFAULT_NODEJS_FILTER_JSON_STR) {
                Ok(nodejs_filter) => nodejs_filter,
                Err(e) => {
                    error!("filter deserialize failed: {}", e);
                    return Err(anyhow!("cpython filter deserialize failed: {}", e));
                }
            };
        let nodejs_process_filter_check_reuslt =
            match nodejs_process_filter.match_exe(&process_exe_file) {
                Ok(o) => o,
                Err(_) => false,
            };
        if nodejs_process_filter_check_reuslt {
            let version = match nodejs_version(process_info.pid, &process_exe_file) {
                Ok((major, minor, v)) => {
                    if major < 8 {
                        let msg = format!("nodejs version lower than 8.6: {}", v);
                        return Err(anyhow!(msg));
                    }
                    if major == 8 {
                        if minor < 6 {
                            let msg = format!("nodejs version lower than 8.6: {}", v);
                            return Err(anyhow!(msg));
                        }
                    }
                    v
                }
                Err(e) => {
                    warn!("read nodejs version failed: {}", e);
                    String::new()
                }
            };
            return Ok(Some(Runtime {
                name: "NodeJS",
                version,
            }));
        }
        let pid = process_info.pid.clone();
        let exe_path = match process_info.process_self.exe() {
            Ok(e) => e,
            Err(e) => {
                let msg = format!("read exe path failed: {}", e.to_string());
                return Err(anyhow!(msg));
            }
        };
        // /proc/<pid><exe_path> for process in container
        let mut path = PathBuf::from(format!("/proc/{}/root/", pid));
        let exe_path_buf = PathBuf::from(exe_path);
        if !exe_path_buf.has_root() {
            path.push(exe_path_buf);
        } else {
            for p in exe_path_buf.iter() {
                if p == std::ffi::OsString::from("/") {
                    continue;
                }
                path.push(p);
            }
        }
        #[cfg(feature = "bin_mode")]
        match golang_bin_inspect(path) {
            Ok(res) => {
                if res {
                    return Ok(Some(Runtime {
                        name: "Golang",
                        version: String::new(),
                    }));
                }
            }
            Err(e) => {
                warn!("detect golang bin failed: {}", e.to_string());
            }
        };
        Ok(None)
    }
    fn inspect_from_pid(pid: i32) -> Result<Option<Runtime>> {
        let mut process_info = match ProcessInfo::new(pid) {
            Ok(pi) => pi,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };
        Self::inspect_from_process_info(&mut process_info)
    }
}
