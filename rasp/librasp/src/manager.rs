use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Result, Result as AnyhowResult};
use crossbeam::channel::Sender;
use fs_extra::dir::{copy, CopyOptions, create_all};
use fs_extra::file::{copy as file_copy, CopyOptions as FileCopyOptions};
use log::*;

use crate::{
    comm::{Control, RASPComm, ThreadMode, ProcessMode},
    process::ProcessInfo,
    runtime::{ProbeState, ProbeStateInspect, RuntimeInspect, ProbeCopy},
};
use crate::php::{PHPProbeState, php_attach};
use crate::cpython::{CPythonProbe, CPythonProbeState, python_attach};
use crate::golang::{GolangProbe, golang_attach, GolangProbeState};
use crate::jvm::{JVMProbe, JVMProbeState, java_attach} ;
use crate::nodejs::{NodeJSProbe, nodejs_attach};

pub struct RASPManager {
    pub namespace_tracer: MntNamespaceTracer,
    pub thread_comm: Option<ThreadMode>,
    pub process_comm: Option<ProcessMode>,
}

impl RASPManager {
    // comm
    pub fn start_comm(
        &mut self,
        process_info: &ProcessInfo,
        result_sender: Sender<plugins::Record>,
        _server_log_level: String,
        _server_ctrl: Control,
    ) -> AnyhowResult<()> {
        debug!("starting comm with probe, target pid: {}", process_info.pid);
        let mnt_namespace = process_info.get_mnt_ns()?;
        let nspid = if let Some(nspid) = ProcessInfo::read_nspid(process_info.pid)? {
            nspid
        } else {
            process_info.pid
        };
        if let Some(comm) = self.thread_comm.as_mut() {
            comm.start_comm(
                process_info.pid, &mnt_namespace,
                result_sender, HashMap::new(),
            )?;
        } else if let Some(comm) = self.process_comm.as_mut() {
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
            debug!("update patch_field: {:?}", patch_field);

            // check reopen
            if let Some(opened) = self.namespace_tracer.server_state(&mnt_namespace) {
                if opened {
                    debug!("reusing stated server, mnt ns: {}", &mnt_namespace);
                    if let Some(runner) = comm
                        .mnt_namesapce_server_map
                        .get_mut(&mnt_namespace) {
                        runner.update_patch_field(patch_field);
                    }
                    return Ok(());
                }
            } else {
                comm.start_comm(
                    process_info.pid, &mnt_namespace,
                    result_sender.clone(), patch_field,
                )?;
            }
        } else {
            return Err(anyhow!("both thread && process comm mode not init"));
        }
        self.namespace_tracer
            .add(mnt_namespace.clone(), process_info.pid);
        self.namespace_tracer.server_state_on(mnt_namespace);
        Ok(())
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
            if let Some(comm) = self.thread_comm.as_mut() {
                comm.stop_comm(process_info.pid, &mnt_namespace)?;
            }
            if let Some(comm) = self.process_comm.as_mut() {
                comm.stop_comm(process_info.pid, &mnt_namespace)?;
            }
        }
        Ok(())
    }

    pub fn send_message_to_probe(&mut self, pid: i32, mnt_namespace: &String, message: &String) -> AnyhowResult<()> {
        // try to write probe to dir
        let nspid = ProcessInfo::read_nspid(pid)?.ok_or(anyhow!("can not fetch nspid: {}", pid))?;
        self.write_message_to_config_file(pid, nspid, message.clone())?;
        debug!("send message to probe: {} {} {}", pid, nspid, &message);
        // send through sock
        let messages: Vec<libraspserver::proto::PidMissingProbeConfig> = serde_json::from_str(message)?;
        for m in messages {
            let m_str = serde_json::json!(m);
            let m_string = match m_str.as_str() {
                Some(s) => String::from(s),
                None => continue,
            };
            if let Some(comm) = self.thread_comm.as_mut() {
                comm.send_message_to_probe(pid, mnt_namespace, &m_string)?;
            } else if let Some(comm) = self.process_comm.as_mut() {
                comm.send_message_to_probe(pid, mnt_namespace, &m_string)?;
            } else {
                return Err(anyhow!("both thread && process comm mode not init"));
            }
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
        if process_info.runtime.is_none() {
            let msg = "attaching to unknow runtime process";
            error!("{}", msg);
            return Err(anyhow!(msg));
        }
        let environ = match process_info.environ.clone() {
            Some(e) => e,
            None => return Err(anyhow!("can not fetch envrion {}", process_info.pid)),
        };
        let namespace = process_info.namespace_info.as_ref().unwrap();
        let mnt_namespace = namespace.mnt.as_ref().unwrap();
        let runtime_info = &process_info.runtime.clone().unwrap();
        let root_dir = format!("/proc/{}/root", process_info.pid);
        let pid = process_info.pid;
        let nspid = ProcessInfo::read_nspid(pid)?.ok_or(anyhow!("can not read nspid: {}", pid))?;
        // delete config
        self.delete_config_file(pid, nspid)?;
        let attach_result = match runtime_info.name {
            "JVM" => match JVMProbeState::inspect_process(process_info)? {
                ProbeState::Attached => {
                    info!("JVM attached process");
                    Ok(true)
                }
                ProbeState::NotAttach => {
                    if self.can_copy(mnt_namespace) {
                        for from in JVMProbe::names().0.iter() {
                            self.copy_file_from_to_dest(from.clone(), root_dir.clone())?;
                        }
                        for from in JVMProbe::names().1.iter() {
                            self.copy_dir_from_to_dest(from.clone(), root_dir.clone())?;
                        }
                    }
                    java_attach(process_info.pid)
                }
            },
            "CPython" => match CPythonProbeState::inspect_process(process_info)? {
                ProbeState::Attached => {
                    info!("CPython attached process");
                    Ok(true)
                }
                ProbeState::NotAttach => {
                    if self.can_copy(mnt_namespace) {
                        for from in CPythonProbe::names().0.iter() {
                            self.copy_file_from_to_dest(from.clone(), root_dir.clone())?;
                        }
                        for from in CPythonProbe::names().1.iter() {
                            self.copy_dir_from_to_dest(from.clone(), root_dir.clone())?;
                        }
                    }
                    python_attach(process_info.pid)
                }
            },
            "Golang" => match GolangProbeState::inspect_process(process_info)? {
                ProbeState::Attached => {
                    info!("Golang attached process");
                    Ok(true)
                }
                ProbeState::NotAttach => {
                    if self.can_copy(mnt_namespace) {
                        for from in GolangProbe::names().0.iter() {
                            self.copy_file_from_to_dest(from.clone(), root_dir.clone())?;
                        }
                        for from in GolangProbe::names().1.iter() {
                            self.copy_dir_from_to_dest(from.clone(), root_dir.clone())?;
                        }
                    }

                    golang_attach(pid)
                }
            },
            "NodeJS" => {
                if self.can_copy(mnt_namespace) {
                    for from in NodeJSProbe::names().0.iter() {
                        self.copy_file_from_to_dest(from.clone(), root_dir.clone())?;
                    }
                    for from in NodeJSProbe::names().1.iter() {
                        self.copy_dir_from_to_dest(from.clone(), root_dir.clone())?;
                    }
                }

                let process_exe_file = process_info.exe_path.clone().ok_or(
                    anyhow!("process exe path not found: {}", pid)
                )?;
                nodejs_attach(pid, &environ, &process_exe_file)
            }
            "PHP" => match PHPProbeState::inspect_process(&process_info)? {
                ProbeState::Attached => {
                    info!("PHP attached process");
                    Ok(true)
                }
                ProbeState::NotAttach => {
                    php_attach(process_info, runtime_info.version.clone())
                }
            }
            _ => {
                let msg = format!("can not attach to runtime: `{}`", runtime_info.name);
                error!("{}", msg);
                return Err(anyhow!(msg));
            }
        };
        match attach_result {
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
        }
    }
}

impl RASPManager {
    pub fn init(
        comm_mode: &str,
        log_level: String,
        ctrl: Control,
        message_sender: Sender<plugins::Record>,
        bind_path: String,
        linking_to: Option<String>,
    ) -> AnyhowResult<Self> {
        match comm_mode {
            "thread" => {
                Ok(RASPManager {
                    thread_comm: Some(ThreadMode::new(log_level, ctrl, message_sender.clone(), bind_path, linking_to)?),
                    namespace_tracer: MntNamespaceTracer::new(),
                    process_comm: None,
                })
            }

            "server" => {
                Ok(RASPManager {
                    process_comm: Some(ProcessMode::new(log_level, ctrl)),
                    namespace_tracer: MntNamespaceTracer::new(),
                    thread_comm: None,
                })
            }
            _ => {
                Err(anyhow!("{} is not a vavild comm mode", comm_mode))
            }
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
    pub fn create_dir_if_not_exist(&self, dir: String, dest_root: String) -> AnyhowResult<()> {
        let target = format!("{}{}", dest_root, dir);
        if Path::new(&target).exists() {
            return Ok(());
        }
        create_all(format!("{}{}", dest_root, dir), true)?;
        Ok(())
    }
    pub fn copy_file_from_to_dest(&self, from: String, dest_root: String) -> AnyhowResult<()> {
        let target = format!("{}/{}", dest_root, from);
        if Path::new(&target).exists() {
            return Ok(());
        }
        let dir = Path::new(&from).parent().unwrap();
        self.create_dir_if_not_exist(dir.to_str().unwrap().to_string(), dest_root.clone())?;
        let options = FileCopyOptions::new();
        debug!("copy file: {} {}", from.clone(), format!("{}/{}", dest_root, from));
        return match file_copy(from.clone(), format!("{}/{}", dest_root, from), &options) {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("can not copy: {}", e);
                Err(anyhow!(
		    "copy failed: from {} to {}: {}",
		    from,
		    format!("{}/{}", dest_root, from),
		    e
		))
            }
        };
    }
    pub fn copy_dir_from_to_dest(&self, from: String, dest_root: String) -> AnyhowResult<()> {
        let target = format!("{}{}", dest_root, from);
        if Path::new(&target).exists() {
            return Ok(());
        }
        let dir = Path::new(&from).parent().unwrap();
        self.create_dir_if_not_exist(dir.to_str().unwrap().to_string(), dest_root.clone())?;
        let mut options = CopyOptions::new();
        options.copy_inside = true;
        debug!("copy dir: {} {}", from.clone(), format!("{}/{}", dest_root, from));
        return match copy(from.clone(), format!("{}/{}", dest_root, from), &options) {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("can nout copy: {}", e);
                Err(anyhow!(
		    "copy failed: from {} to {}: {}",
		    from,
		    format!("{}/{}", dest_root, from),
		    e
		))
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
    pub fn can_copy(&self, _mnt_namesapce: &String) -> bool {
        // !self.namespace_tracer.server_state(&mnt_namesapce).is_some()
        true
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

impl RASPManager {
    pub fn write_message_to_config_file(&self, pid: i32, nspid: i32, message: String) -> AnyhowResult<()> {
        let config_path = format!("/proc/{}/root/var/run/elkeid_rasp/{}.json", pid, nspid);
        let config_path_bak = format!("{}.bak", config_path);
        fs_extra::file::write_all(&config_path_bak, message.as_str())?;
        let mut option = fs_extra::file::CopyOptions::new();
        option.overwrite = false;
        fs_extra::file::move_file(config_path_bak, config_path, &option)?;
        Ok(())
    }
    pub fn delete_config_file(&self, pid: i32, nspid: i32) -> AnyhowResult<()> {
        let config_path = format!("/proc/{}/root/var/run/elkeid_rasp/{}.json", pid, nspid);
        fs_extra::file::remove(config_path)?;
        Ok(())
    }
}
