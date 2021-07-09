use anyhow::{anyhow, Result};
use crossbeam::channel::{Receiver, Sender};
use fs_extra::dir::{copy, create_all, CopyOptions};
use log::*;
use lru_time_cache::LruCache;

use std::collections::VecDeque;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

use crate::cpython::{python_attach, CPythonProbeState};
use crate::golang::{golang_attach, golang_bin_inspect, GolangProbeState};
use crate::jvm::java_attach;
use crate::nodejs::nodejs_attach;
use crate::runtime::Runtime;
use crate::runtime::RuntimeInspect;
use crate::runtime::{ProbeState, ProbeStateInspect};
use crate::{
    comm::{Control, RASPServerManager},
    process::ProcessInfo,
};

pub struct RASPManager {
    pub namespace_tracer: MntNamespaceTracer,
    pub comm_manager: RASPServerManager,
    pub async_runtime_inspect_task_queue: Arc<Mutex<VecDeque<PathBuf>>>,
    pub async_runtime_inspect_result: Arc<Mutex<LruCache<PathBuf, Runtime>>>,
}

impl RASPManager {
    // comm
    pub fn start_comm(
        &mut self,
        process_info: &ProcessInfo,
        comm: (Sender<HashMap<&'static str, String>>, Receiver<String>),
        server_log_level: String,
        server_ctrl: Control,
    ) -> Result<()> {
        let mnt_namespace = if let Some(ref ns) = process_info.namespace_info {
            match ns.mnt.clone() {
                Some(mnt_ns) => mnt_ns,
                None => {
                    return Err(anyhow!("process mnt ns empty: {}", process_info.pid));
                }
            }
        } else {
            return Err(anyhow!("fetch process ns failed: {}", process_info.pid));
        };
        self.namespace_tracer
            .add(mnt_namespace.clone(), process_info.pid);
        if let Some(opened) = self.namespace_tracer.server_state(&mnt_namespace) {
            if opened {
                return Ok(());
            }
        }
        let (result_sender, command_receiver) = comm;
        return match self.comm_manager.start_new_rasp_server(
            process_info,
            result_sender,
            command_receiver,
            server_log_level,
            server_ctrl,
        ) {
            Ok(_) => {
                self.namespace_tracer.server_state_on(mnt_namespace);
                Ok(())
            }
            Err(e) => {
                self.namespace_tracer
                    .delete_pid(mnt_namespace, process_info.pid);
                Err(anyhow!(e))
            }
        };
    }
    pub fn stop_comm(&mut self, process_info: &ProcessInfo) -> Result<()> {
        let mnt_namespace = if let Some(ref ns) = process_info.namespace_info {
            match ns.mnt.clone() {
                Some(mnt_ns) => mnt_ns,
                None => {
                    return Err(anyhow!("process mnt ns empty: {}", process_info.pid));
                }
            }
        } else {
            return Err(anyhow!("fetch process ns failed: {}", process_info.pid));
        };
        let kill_check = self
            .namespace_tracer
            .server_state_off(&mnt_namespace, process_info.pid);
        // kill server
        if kill_check {
            match self.comm_manager.stop_rasp_server(&mnt_namespace) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(anyhow!(e));
                }
            };
        }
        Ok(())
    }
    pub fn send_config() {
        // TODO missing config
    }
}

pub const PROCESS_BALACK: &'static [&'static str] = &[
    // why don't care
    "/usr/sbin",
    "/lib/systemd",
    "/pause",
    "/bin",
    "/sbin",
];

impl RASPManager {
    // Inspect
    pub fn inspect(&mut self, pid: i32) -> Result<ProcessInfo> {
        // process dead or live
        let mut process_info = match ProcessInfo::new(pid) {
            Ok(pi) => pi,
            Err(e) => {
                let msg = format!("process pid: {} seems dead: {}", pid, e.to_string());
                warn!("{}", msg);
                return Err(anyhow!(msg));
            }
        };
        let exe_path = match process_info.process_self.exe() {
            Ok(p) => match p.into_os_string().into_string() {
                Ok(ps) => ps,
                Err(_) => return Err(anyhow!("convert osstring to string failed")),
            },
            Err(e) => {
                return Err(anyhow!(e));
            }
        };
        info!("process exe: {}", &exe_path);
        for proces_black_name in PROCESS_BALACK.iter() {
            if exe_path.starts_with(proces_black_name) {
                info!("process hit black list: {}", &proces_black_name);
                return Err(anyhow!("inspecting process hit black list"));
            }
        }
        // update namesapce
        if let Err(e) = process_info.update_ns_info() {
            return Err(anyhow!(e));
        };
        Ok(process_info)
    }
    pub fn runtime_inspect(&mut self, process_info: &mut ProcessInfo) -> Result<bool> {
        let runtime = ProcessInfo::inspect_from_process_info(process_info)?;
        #[cfg(not(feature = "bin_mode"))]
        if runtime.is_none() {
            debug!("can not inspect runtime");
            match self.new_async_inspect(&process_info.clone()) {
                Ok(option_runtime) => {
                    // inspecting
                    if option_runtime.is_none() {
                        debug!("waiting inspect");
                        // wait inspect
                        return Ok(false);
                    } else {
                        debug!("inspect done");
                        // hit result
                        // update process_info
                        process_info.runtime_info = option_runtime;
                        return Ok(true);
                    }
                }
                Err(e) => {
                    debug!("can not inspect runtime type");
                    // can not detect
                    return Err(e);
                }
            }
        }
        // update runtime
        process_info.runtime_info = runtime;
        Ok(true)
    }
    pub fn new_async_inspect(&mut self, process_info: &ProcessInfo) -> Result<Option<Runtime>> {
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
        debug!("inspect path: {:?}", path);
        // search exe cache first
        let mut async_result = self.async_runtime_inspect_result.lock().unwrap();
        match async_result.get(&path) {
            Some(runtime) => {
                debug!("hit cache, path: {} {:?}", runtime.name, path);
                if runtime.name == "unknow" {
                    return Err(anyhow!("unknow runtime"));
                }
                if runtime.name == "waiting" {
                    return Ok(None);
                }
		let runtime_result = runtime.clone();
		async_result.remove(&path);
                return Ok(Some(runtime_result));
            }
            None => {
                debug!("not hit cache, waiting");
                async_result.insert(
                    path.clone(),
                    Runtime {
                        name: "waiting",
                        version: String::new(),
                    },
                )
            }
        };
        // add inspect queue
        let mut queue = self.async_runtime_inspect_task_queue.lock().unwrap();
        debug!("add async inspect, path: {:?}", path);
        queue.push_back(path);
        drop(queue);
        Ok(None)
    }
    pub fn async_inspect_daemon(&mut self) {
        let task_queue = Arc::clone(&self.async_runtime_inspect_task_queue);
        let task_result = Arc::clone(&self.async_runtime_inspect_result);
        let _ = std::thread::Builder::new()
            .name("async_inspect_daemon".to_string())
            .spawn(move || {
                loop {
                    debug!("async inspect daemon looping");
                    // pop inspect target
                    let mut queue = task_queue.lock().unwrap();
                    let exe = if let Some(e) = queue.pop_front() {
                        e
                    } else {
                        drop(queue);
                        sleep(Duration::from_secs(5));
                        continue;
                    };
                    debug!("inspect daemon: {:?}", exe.clone());
                    drop(queue);
                    // golang inspect
                    let inspect_result = match golang_bin_inspect(exe.clone()) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("golang inspect failed: {}", e);
                            false
                        }
                    };
		    debug!("inspect done: {}", inspect_result);
                    // lock result
                    let mut result = task_result.lock().unwrap();
                    // save inspect result
                    if inspect_result {
                        result.insert(
                            exe.clone(),
                            Runtime {
                                name: "Golang",
                                version: "".to_string(),
                            },
                        );
                    } else {
                        result.insert(
                            exe.clone(),
                            Runtime {
                                name: "unknow",
                                version: String::new(),
                            },
                        );
                    }
                    drop(result);
                    sleep(Duration::from_secs(5));
                    continue;
                }
            });
    }
    pub fn attach(&mut self, process_info: &mut ProcessInfo) -> Result<()> {
        if let Some(runtime_info) = &process_info.runtime_info {
            let attach_result = match runtime_info.name {
                // TODO @Gaba
                "JVM" => java_attach(process_info.pid),
                "CPython" => match CPythonProbeState::inspect_process(process_info)? {
                    ProbeState::Attached => Ok(true),
                    ProbeState::NotAttach => python_attach(process_info.pid),
                },
                "Golang" => match GolangProbeState::inspect_process(process_info)? {
                    ProbeState::Attached => Ok(true),
                    ProbeState::NotAttach => golang_attach(process_info.pid),
                },
                "NodeJS" => {
		    let process_exe_file = process_info.update_exe()?;
		    let process_exe_file_str = match process_exe_file.to_str() {
			Some(s) => s,
			None => {
			    error!("nodejs attach failed, convert pathbuf to str failed");
			    return Err(anyhow!("nodejs attach failed, convert pathbuf to str failed"));
			}
		    };
		    let pid = process_info.pid;
		    let environ = match process_info.update_environ() {
			Ok(e) => e,
			Err(e) => return Err(anyhow!("can not fetch envrion {}", e))
		    };
                    nodejs_attach(pid, &environ, &process_exe_file_str)
                }
                _ => {
                    let msg = format!("can not attach to runtime: `{}`", runtime_info.name);
                    error!("{}", msg);
                    return Err(anyhow!(msg));
                }
            };
            return match attach_result {
                Ok(success) => {
                    if !success {
                        let msg = format!("attach failed: {:?}", process_info);
                        error!("{}", msg);
                        Err(anyhow!(msg))
                    } else {
                        Ok(())
                    }
                }
                Err(e) => Err(anyhow!(e)),
            };
        } else {
            let msg = "attaching to unknow runtime process";
            error!("{}", msg);
            return Err(anyhow!(msg));
        }
    }
    pub fn pause() {}
    pub fn resume() {}
}

impl RASPManager {
    pub fn init() -> Result<Self> {
        let time_to_live = Duration::from_secs(300);
        match RASPServerManager::new() {
            Ok(server) => Ok(RASPManager {
                namespace_tracer: MntNamespaceTracer::new(),
                comm_manager: server,
                async_runtime_inspect_task_queue: Arc::new(Mutex::new(VecDeque::<PathBuf>::new())),
                async_runtime_inspect_result: Arc::new(Mutex::new(
                    LruCache::<PathBuf, Runtime>::with_expiry_duration_and_capacity(
                        time_to_live,
                        300,
                    ),
                )),
            }),
            Err(e) => Err(anyhow!(e)),
        }
    }
    pub fn copy_to_dest(&self, dest_root: String) -> Result<()> {
        // check namespace before copy
        match create_all(
            format!("{}/etc/elkeid/plugin/RASP/rasp", dest_root),
            false,
        ) {
            Ok(_) => {}
            Err(e) => {
                warn!("create failed: {:?}", e);
            }
        };
        let mut options = CopyOptions::new();
        options.overwrite = true;
        return match copy(
            "/etc/elkeid/plugin/RASP/rasp",
            format!("{}/etc/elkeid/plugin/RASP/", dest_root),
            &options,
        ) {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("can not copy: {}", e);
                Err(anyhow!("copy failed: {}", dest_root))
            }
        };
    }
    pub fn copy_to_target_dir(&self, pid: i32, mnt_namespace: &String) -> Result<()> {
        // check namespace first
        if let Some(tracing) = self.namespace_tracer.server_state(&mnt_namespace) {
            if tracing {
                return Ok(());
            }
        }
        let root_dir = format!("/proc/{}/root", pid);
        self.copy_to_dest(root_dir)
    }
    pub fn root_dir(pid: i32) -> String {
        format!("/proc/{}/root", pid)
    }
}

pub struct MntNamespaceTracer {
    /// {<mnt namespace>: ([<pid>, <pid>...], <server_start_or_not>)}
    tracer: HashMap<String, (Vec<i32>, bool)>,
}

impl MntNamespaceTracer {
    pub fn new() -> Self {
        Self {
            tracer: HashMap::<String, (Vec<i32>, bool)>::new(),
        }
    }
    pub fn add(&mut self, mnt_namespace: String, pid: i32) {
        if let Some(value) = self.tracer.get_mut(&mnt_namespace) {
            if value.0.contains(&pid) {
                warn!(
                    "trying insert duplicate pid in mnt_namespace hashmap: {} {}",
                    mnt_namespace, pid
                );
            } else {
                value.0.push(pid)
            }
        } else {
            let mut new_pid_vec = Vec::new();
            new_pid_vec.push(pid);
            self.tracer.insert(mnt_namespace, (new_pid_vec, false));
        }
    }

    pub fn detele_namespace(&mut self, mnt_namespace: String) {
        self.tracer.remove(&mnt_namespace);
    }

    pub fn delete_pid(&mut self, mnt_namespace: String, pid: i32) {
        if let Some(value) = self.tracer.get_mut(&mnt_namespace) {
            let index = value.0.iter().position(|x| *x == pid);
            if let Some(i) = index {
                value.0.remove(i);
            }
        }
    }

    pub fn server_state(&self, mnt_namespace: &String) -> Option<bool> {
        if let Some(value) = self.tracer.get(mnt_namespace) {
            return Some(value.1);
        }
        None
    }
    pub fn server_state_on(&mut self, mnt_namespace: String) {
        if let Some(mut value) = self.tracer.get_mut(&mnt_namespace) {
            value.1 = true
        }
    }
    /// return boolean value for kill server process or not
    pub fn server_state_off(&mut self, mnt_namespace: &String, pid: i32) -> bool {
        if let Some(value) = self.tracer.get_mut(mnt_namespace) {
            if value.0.contains(&pid) {
                let index = value.0.iter().position(|x| *x == pid);
                if let Some(i) = index {
                    value.0.remove(i);
                }
            }
            if value.0.len() == 0 {
                self.tracer.remove(mnt_namespace);
                return true;
            }
        }
        return false;
    }
}
