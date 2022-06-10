use std::collections::HashMap;

use anyhow::{anyhow, Result, Result as AnyhowResult};
use crossbeam::channel::Sender;
use fs_extra::dir::{copy, CopyOptions, create_all};
use log::*;

use crate::{
    comm::{Control, RASPServerManager},
    process::ProcessInfo,
};
use crate::cpython::{CPythonProbeState, python_attach};
use crate::golang::{golang_attach, GolangProbeState};
use crate::jvm::java_attach;
use crate::nodejs::nodejs_attach;
use crate::runtime::{ProbeState, ProbeStateInspect, RuntimeInspect};

pub struct RASPManager {
    pub namespace_tracer: MntNamespaceTracer,
    pub comm_manager: RASPServerManager,
    // pub async_runtime_inspect_task_queue: Arc<Mutex<VecDeque<PathBuf>>>,
    // pub async_runtime_inspect_result: Arc<Mutex<LruCache<PathBuf, Runtime>>>,
}

impl RASPManager {
    // comm
    pub fn start_comm(
        &mut self,
        process_info: &ProcessInfo,
        result_sender: Sender<HashMap<&'static str, String>>,
        server_log_level: String,
        server_ctrl: Control,
    ) -> AnyhowResult<()> {
        debug!("starting comm with probe, target pid: {}", process_info.pid);
        let mnt_namespace = process_info.get_mnt_ns()?;
        self.namespace_tracer
            .add(mnt_namespace.clone(), process_info.pid);
        // check reopen
        if let Some(opened) = self.namespace_tracer.server_state(&mnt_namespace) {
            if opened {
                debug!("reusing stated server, mnt ns: {}", mnt_namespace);
                if let Some(runner) = self
                    .comm_manager
                    .mnt_namespace_server_map
                    .get_mut(&mnt_namespace)
                {
                    let nspid = if let Some(nspid) = ProcessInfo::read_nspid(process_info.pid)? {
                        nspid
                    } else {
                        process_info.pid
                    };
                    let mut patch_field = HashMap::new();
                    let sid = process_info.sid;
                    let pid = process_info.pid;
                    let ppid = process_info.ppid;
                    let tgid = process_info.tgid;
                    let exe = process_info.exe_path.clone().unwrap_or("".to_string());
                    let cmdline = process_info.cmdline.clone().unwrap_or("".to_string());
                    patch_field.insert("sid", sid.to_string());
                    patch_field.insert("pid", pid.to_string());
                    patch_field.insert("nspid", nspid.to_string());
                    patch_field.insert("ppid", ppid.to_string());
                    patch_field.insert("tgid", tgid.to_string());
                    patch_field.insert("argv", cmdline);
                    patch_field.insert("ruid", process_info.ruid.to_string());
                    patch_field.insert("rgid", process_info.rgid.to_string());
                    patch_field.insert("euid", process_info.euid.to_string());
                    patch_field.insert("egid", process_info.egid.to_string());
                    patch_field.insert("suid", process_info.suid.to_string());
                    patch_field.insert("sgid", process_info.sgid.to_string());
                    patch_field.insert("fuid", process_info.fuid.to_string());
                    patch_field.insert("fgid", process_info.fgid.to_string());
                    patch_field.insert("exe", exe);
                    debug!("update patch_field: {:?}", patch_field);
                    runner.update_patch_field(patch_field);
                }
                return Ok(());
            }
        }
        let nspid = if let Some(nspid) = ProcessInfo::read_nspid(process_info.pid)? {
            nspid
        } else {
            process_info.pid
        };
        let mut patch_field = HashMap::new();
        let sid = process_info.sid;
        let pid = process_info.pid;
        let ppid = process_info.ppid;
        let tgid = process_info.tgid;
        let exe = process_info.exe_path.clone().unwrap_or("".to_string());
        let cmdline = process_info.cmdline.clone().unwrap_or("".to_string());
        patch_field.insert("sid", sid.to_string());
        patch_field.insert("pid", pid.to_string());
        patch_field.insert("nspid", nspid.to_string());
        patch_field.insert("ppid", ppid.to_string());
        patch_field.insert("tgid", tgid.to_string());
        patch_field.insert("argv", cmdline);
        patch_field.insert("exe", exe);
        patch_field.insert("ruid", process_info.ruid.to_string());
        patch_field.insert("rgid", process_info.rgid.to_string());
        patch_field.insert("euid", process_info.euid.to_string());
        patch_field.insert("egid", process_info.egid.to_string());
        patch_field.insert("suid", process_info.suid.to_string());
        patch_field.insert("sgid", process_info.sgid.to_string());
        patch_field.insert("fuid", process_info.fuid.to_string());
        patch_field.insert("fgid", process_info.fgid.to_string());
        debug!("new patch_field: {:?}", patch_field);
        return match self.comm_manager.start_new_rasp_server(
            process_info,
            result_sender,
            server_log_level,
            server_ctrl,
            patch_field,
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
    pub fn inspect(&mut self, process_info: &ProcessInfo) -> Result<()> {
        let exe_path = if let Some(p) = &process_info.exe_path {
            p.clone()
        } else {
            return Err(anyhow!("missing exe path during inspect: {}", process_info.pid));
        };
        info!("process exe: {}", exe_path);
        for proces_black_name in PROCESS_BALACK.iter() {
            if exe_path.starts_with(proces_black_name) {
                info!("process hit black list: {}", &proces_black_name);
                return Err(anyhow!("inspecting process hit black list"));
            }
        }
        Ok(())
    }
    pub fn runtime_inspect(&mut self, process_info: &mut ProcessInfo) -> Result<bool> {
        let runtime = ProcessInfo::inspect_from_process_info(process_info)?;
        // update runtime
        process_info.runtime = runtime;
        Ok(true)
    }
    // Attach
    pub fn attach(&mut self, process_info: &ProcessInfo) -> Result<()> {
        if let Some(runtime_info) = &process_info.runtime {
            let attach_result = match runtime_info.name {
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
                    let process_exe_file = process_info.exe_path.clone().unwrap();
                    let pid = process_info.pid;
                    let environ = process_info.environ.clone().unwrap();
                    nodejs_attach(pid, &environ, &process_exe_file)
                }
                _ => {
                    let msg = format!("can not attach to runtime: `{}`", runtime_info.name);
                    error!("{}", msg);
                    return Err(anyhow!(msg));
                }
            };
            // println!("{:?}", attach_result);
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
    pub fn init() -> AnyhowResult<Self> {
        match RASPServerManager::new() {
            Ok(server) => Ok(RASPManager {
                namespace_tracer: MntNamespaceTracer::new(),
                comm_manager: server,
            }),
            Err(e) => Err(anyhow!(e)),
        }
    }
    pub fn copy_to_dest(&self, dest_root: String) -> Result<()> {
        let cwd_path = std::env::current_dir()?;
        let cwd = cwd_path.to_str().unwrap();
        debug!("current dir: {}", cwd);
        // check namespace before copy
        match create_all(format!("{}{}", dest_root, cwd), false) {
            Ok(_) => {}
            Err(e) => {
                warn!("create failed: {:?}", e);
            }
        };
        let mut options = CopyOptions::new();
        options.overwrite = true;
        return match copy(
            format!("{}/lib", cwd),
            format!("{}/{}/", dest_root, cwd),
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
