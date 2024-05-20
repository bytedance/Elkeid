use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Result, Result as AnyhowResult};
use crossbeam::channel::Sender;
use fs_extra::dir::{copy, create_all, CopyOptions};
use fs_extra::file::{copy as file_copy, remove as file_remove, CopyOptions as FileCopyOptions};
use libraspserver::proto::{PidMissingProbeConfig, ProbeConfigData};
use log::*;

use crate::cpython::{python_attach, CPythonProbe, CPythonProbeState};
use crate::golang::{golang_attach, GolangProbe, GolangProbeState};
use crate::jvm::{java_attach, java_detach, JVMProbe, JVMProbeState};
use crate::nodejs::{nodejs_attach, NodeJSProbe};
use crate::php::{php_attach, PHPProbeState};
use crate::{
    comm::{Control, EbpfMode, ProcessMode, RASPComm, ThreadMode, check_need_mount},
    process::ProcessInfo,
    runtime::{ProbeCopy, ProbeState, ProbeStateInspect, RuntimeInspect},
    settings,
};

pub struct RASPManager {
    pub namespace_tracer: MntNamespaceTracer,
    pub thread_comm: Option<ThreadMode>,
    pub process_comm: Option<ProcessMode>,
    pub ebpf_comm: Option<EbpfMode>,
    pub runtime_dir: bool,
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
                process_info.pid,
                &mnt_namespace,
                result_sender,
                HashMap::new(),
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
                    if let Some(runner) = comm.mnt_namesapce_server_map.get_mut(&mnt_namespace) {
                        runner.update_patch_field(patch_field);
                    }
                    return Ok(());
                }
            } else {
                comm.start_comm(
                    process_info.pid,
                    &mnt_namespace,
                    result_sender.clone(),
                    patch_field,
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

    pub fn patch_message_handle(
        &self,
        valid_messages: &mut Vec<PidMissingProbeConfig>,
        pid: i32,
    ) -> AnyhowResult<Vec<PidMissingProbeConfig>> {
        for valid_m in valid_messages.iter_mut() {
            if let Some(patches) = valid_m.data.patches.as_mut() {
                let mut delete_index = Vec::new();
                for (index, patch) in patches.iter_mut().enumerate() {
                    if patch.path.is_none() {
                        delete_index.push(index);
                        continue;
                    }
                    if !self.runtime_dir {
                        warn!(
                            "due to missing runtime dir, patch ignored: {}",
                            patch.class_name
                        );
                        delete_index.push(index);
                        continue;
                    }
                    let path_path_str = patch.path.clone().unwrap();
                    let patch_path = Path::new(&path_path_str);
                    // check patch exist
                    if !patch_path.exists() {
                        delete_index.push(index);
                        continue;
                    } else {
                        let patch_file_name = patch_path
                            .file_name()
                            .unwrap_or(OsStr::new(""))
                            .to_string_lossy();
                        if patch_file_name == "" {
                            delete_index.push(index);
                            continue;
                        }
                        let dest_path = format!("/proc/{}/root", pid);
                        match self.copy_file_from_to_dest(path_path_str.clone(), dest_path.clone())
                        {
                            Ok(_) => {
                                patch.path = None;
                                patch.url = Some("file:///var/run/elkeid-agent/rasp/".to_string());
                            }
                            Err(e) => {
                                error!("copy patch failed: {}", e);
                                delete_index.push(index);
                                continue;
                            }
                        }
                    }
                }
                for index in delete_index.iter() {
                    patches.remove(*index);
                }
            }
        }
        Ok(valid_messages.clone())
    }

    pub fn send_message_to_probe(
        &mut self,
        pid: i32,
        mnt_namespace: &String,
        message: &String,
    ) -> AnyhowResult<()> {
        // try to write probe to dir
        let nspid = ProcessInfo::read_nspid(pid)?.ok_or(anyhow!("can not fetch nspid: {}", pid))?;
        debug!("send messages to probe: {} {} {}", pid, nspid, &message);
        // send through sock
        let mut messages: Vec<libraspserver::proto::PidMissingProbeConfig> =
            serde_json::from_str(message)?;
        let mut valid_messages: Vec<libraspserver::proto::PidMissingProbeConfig> = Vec::new();
        if messages.len() <= 0 {
            for message_type in [6, 7, 8, 9, 12, 13, 14] {
                messages.push(PidMissingProbeConfig {
                    message_type,
                    data: ProbeConfigData::empty(message_type)?,
                })
            }
        }
        for m in messages.iter() {
            if let Some(uuid) = &m.data.uuid {
                if uuid == "" {
                    valid_messages.push(PidMissingProbeConfig {
                        message_type: m.message_type,
                        data: ProbeConfigData::empty(m.message_type)?,
                    });
                } else {
                    let _ = match serde_json::to_string(&m) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("failed to convert json to string: {:?} {}", m, e);
                            continue;
                        }
                    };
                    valid_messages.push(m.clone());
                }
            }
            else {
                let _ = match serde_json::to_string(&m) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("failed to convert json to string: {:?} {}", m, e);
                        continue;
                    }
                };
                valid_messages.push(m.clone());
            }
        }
        // handle patches
        let valid_messages = self.patch_message_handle(&mut valid_messages, pid)?;
        for valid_m in valid_messages.iter() {
            let m_string = match serde_json::to_string(&valid_m) {
                Ok(s) => s,
                Err(e) => {
                    warn!("failed to convert json to string: {:?} {}", valid_m, e);
                    continue;
                }
            };
            debug!("sending message: {}", m_string);
            if let Some(comm) = self.thread_comm.as_mut() {
                comm.send_message_to_probe(pid, mnt_namespace, &m_string)?;
            } else if let Some(comm) = self.process_comm.as_mut() {
                comm.send_message_to_probe(pid, mnt_namespace, &m_string)?;
            } else {
                return Err(anyhow!("both thread && process comm mode not init"));
            }
        }

        let valid_messages_string = serde_json::to_string(&valid_messages)?;
        //self.write_message_to_config_file(pid, nspid, valid_messages_string)?;

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

pub enum BPFSelect {
    FORCE,
    FIRST,
    SECOND,
    DISABLE,
}

impl RASPManager {
    // Inspect
    pub fn inspect(&mut self, process_info: &ProcessInfo) -> Result<()> {
        let exe_path = if let Some(p) = &process_info.exe_path {
            p.clone()
        } else {
            return Err(anyhow!(
                "missing exe path during inspect: {}",
                process_info.pid
            ));
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
    pub fn attach(&mut self, process_info: &ProcessInfo, bpf: BPFSelect) -> Result<()> {
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
        // self.delete_config_file(pid, nspid)?;
        let attach_result = match runtime_info.name {
            "JVM" => match JVMProbeState::inspect_process(process_info)? {
                ProbeState::Attached => {
                    info!("JVM attached process {}", pid);
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
                ProbeState::AttachedVersionNotMatch => {
                    let mut diff_ns:bool = false;
                    match check_need_mount(mnt_namespace) {
                        Ok(value) => {
                            diff_ns = value;
                            if diff_ns {
                                let to = format!("{}{}",root_dir.clone(), settings::RASP_JAVA_AGENT_BIN());
                                self.copy_file_from_to_dest(settings::RASP_JAVA_AGENT_BIN(), root_dir.clone());
                                info!("copy from SmithAgent.jar to {}", to.clone());
                            }
                        }
                        Err(e) => {
                            warn!(
                                "check_need_mount failed, {}", e
                            );
                        }
                        
                    }
                    
                    match java_detach(pid) {
                        Ok(result) => {
                            if diff_ns {
                                Self::remove_dir_from_to_dest(format!("{}{}", root_dir.clone(), settings::RASP_JAVA_DIR()));
                            }
                            if self.can_copy(mnt_namespace) {
                                for from in JVMProbe::names().0.iter() {
                                    self.copy_file_from_to_dest(from.clone(), root_dir.clone())?;
                                }
                                for from in JVMProbe::names().1.iter() {
                                    self.copy_dir_from_to_dest(from.clone(), root_dir.clone())?;
                                }
                            }
                            java_attach(pid)
                        }
                        Err(e) => {
                            //process_info.tracing_state = ProbeState::Attached;
                            Err(anyhow!(e))
                        } 
                    }

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
                ProbeState::AttachedVersionNotMatch => {
                    let msg = format!("not support CPython update version now");
                    error!("{}", msg);
                    Err(anyhow!(msg))
                }
            },
            "Golang" => match GolangProbeState::inspect_process(process_info)? {
                ProbeState::Attached => {
                    info!("Golang attached process");
                    Ok(true)
                }
                ProbeState::NotAttach => {
                    let mut golang_attach = |pid: i32, bpf: bool| -> AnyhowResult<bool> {
                        if bpf {
                            if let Some(bpf_manager) = self.ebpf_comm.as_mut() {
                                bpf_manager.attach(pid)
                            } else {
                                Err(anyhow!(
                                    "FORCE BPF attach failed, golang ebpf daemon not running"
                                ))
                            }
                        } else {
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
                    };
                    match bpf {
                        BPFSelect::FORCE => golang_attach(pid, true),
                        BPFSelect::DISABLE => golang_attach(pid, false),
                        BPFSelect::FIRST => {
                            let bpf_result = golang_attach(pid, true);
                            match bpf_result {
                                Ok(true) => Ok(true),
                                Ok(false) => {
                                    warn!("FIRST BPF attach failed, trying golang attach");
                                    golang_attach(pid, false)
                                }
                                Err(e) => {
                                    warn!("FIRST BPF attach failed: {}, trying golang attach", e);
                                    golang_attach(pid, false)
                                }
                            }
                        }
                        BPFSelect::SECOND => {
                            let golang_attach_result = golang_attach(pid, false);
                            match golang_attach_result {
                                Ok(true) => Ok(true),
                                Ok(false) => {
                                    warn!("golang attach failed, trying BPF attach");
                                    golang_attach(pid, true)
                                }
                                Err(e) => {
                                    warn!("golang attach faild: {}, trying BPF attach", e);
                                    golang_attach(pid, true)
                                }
                            }
                        }
                    }
                }
                ProbeState::AttachedVersionNotMatch => {
                    let msg = format!("not support Golang update version now");
                    error!("{}", msg);
                    Err(anyhow!(msg))
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

                let process_exe_file = process_info
                    .exe_path
                    .clone()
                    .ok_or(anyhow!("process exe path not found: {}", pid))?;
                nodejs_attach(pid, &environ, &process_exe_file)
            }
            "PHP" => match PHPProbeState::inspect_process(&process_info)? {
                ProbeState::Attached => {
                    info!("PHP attached process");
                    Ok(true)
                }
                ProbeState::NotAttach => php_attach(process_info, runtime_info.version.clone()),
                ProbeState::AttachedVersionNotMatch => {
                    let msg = format!("not support PHP update version now");
                    error!("{}", msg);
                    Err(anyhow!(msg))
                }
            },
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

    pub fn detach(&mut self, process_info: &ProcessInfo) -> Result<()>  {
        if let Some(runtime) = process_info.runtime.clone() {
            if runtime.name != "JVM" {
                let msg = "attaching to not support runtime process";
                error!("{}, runtime: {}", msg, runtime);
                return Err(anyhow!(msg));
            }
        } else {
            let msg = "attaching to unknow runtime process";
            error!("{}", msg);
            return Err(anyhow!(msg));
        }
        match java_detach(process_info.pid) {
            Ok(success) => {
                if !success {
                    let msg = format!("detach failed: {:?}", process_info);
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
        using_mount: bool,
        ebpf_mode: BPFSelect,
    ) -> AnyhowResult<Self> {
        Self::clean_prev_lib()?;
        let runtime_dir = match Self::create_elkeid_rasp_dir(
            &String::from("/var/run/elkeid-agent"),
            &String::from("/rasp/com/security/patch"),
        ) {
            Ok(_) => true,
            Err(e) => {
                warn!("create runtime dir failed, due to: {}", e);
                false
            }
        };
        let ebpf_manager = |ebpf_mode: BPFSelect, ctrl: Control| -> Option<EbpfMode> {
            match ebpf_mode {
                BPFSelect::DISABLE => None,
                _ => match EbpfMode::new(ctrl) {
                    Ok(mut em) => {
			match em.start_server() {
			    Ok(_) => Some(em),
			    Err(e) => {
				error!("start golang eBPF daemon failed: {}", e);
				None
			    }
			}
		    },
                    Err(e) => {
                        error!("start golang eBPF daemon not support this machine: {}", e);
                        None
                    }
                },
            }
        };
        match comm_mode {
            "thread" => Ok(RASPManager {
                thread_comm: Some(ThreadMode::new(
                    log_level,
                    ctrl.clone(),
                    message_sender.clone(),
                    bind_path,
                    linking_to,
                    using_mount,
                )?),
                namespace_tracer: MntNamespaceTracer::new(),
                process_comm: None,
                ebpf_comm: ebpf_manager(ebpf_mode, ctrl),
                runtime_dir,
            }),

            "server" => Ok(RASPManager {
                process_comm: Some(ProcessMode::new(log_level, ctrl.clone())),
                namespace_tracer: MntNamespaceTracer::new(),
                thread_comm: None,
                ebpf_comm: ebpf_manager(ebpf_mode, ctrl),
                runtime_dir,
            }),
            _ => Err(anyhow!("{} is not a vaild comm mode", comm_mode)),
        }
    }

    fn create_elkeid_rasp_dir(
        agent_runtime_path: &String,
        rasp_runtime_path: &String,
    ) -> AnyhowResult<()> {
        info!("create rasp runtime path: {}", rasp_runtime_path);
        // dose Agent create `agent_runtime_path`?
        if !Path::new(agent_runtime_path).exists() {
            return Err(anyhow!(
                "can not found agent runtime path: {}",
                agent_runtime_path
            ));
        }
        let rasp_runtime_path_full = format!("{}{}", agent_runtime_path, rasp_runtime_path);
        let path = Path::new(&rasp_runtime_path_full);
        if path.exists() {
            return Ok(());
        }
        match fs_extra::dir::create_all(&rasp_runtime_path_full, false) {
            Ok(_) => {}
            Err(e) => {
                warn!("create dir failed: {} {}", rasp_runtime_path_full, e);
            }
        };
        if !path.exists() {
            return Err(anyhow!(
                "can not create rasp runtime dir: {}",
                rasp_runtime_path_full
            ));
        }
        Ok(())
    }

    fn clean_prev_lib() -> AnyhowResult<()> {
        info!("cleaning previous lib dir");
        for entry in read_dir("./")? {
            let filename = entry.file_name().to_string_lossy().to_string();
            if filename.contains("lib-") && !filename.contains(settings::RASP_VERSION) {
                info!("remove perv libs: {}", filename);
                fs_extra::dir::remove(format!("./{}", filename))?
            }
        }
        Ok(())
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
        debug!(
            "copy file: {} {}",
            from.clone(),
            format!("{}/{}", dest_root, from)
        );
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

    pub fn remove_dir_from_to_dest(dest_root: String) -> AnyhowResult<()> {
        if Path::new(&dest_root).exists() {
            return match std::fs::remove_dir_all(dest_root.clone()) {
                Ok(_) => {
                    info!("remove file: {}", dest_root);
                    Ok(())
                }
                Err(e) => {
                    warn!("can not remove: {}", e);
                    Err(anyhow!(
                        "remove failed: dir {}, err: {}",
                        dest_root.clone(), e))
                }
            }
        }
        return Ok(());
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
        debug!(
            "copy dir: {} {}",
            from.clone(),
            format!("{}/{}", dest_root, from)
        );
        return match copy(from.clone(), format!("{}/{}", dest_root, from), &options) {
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
    pub fn can_copy(&self, _mnt_namespace: &String) -> bool {
        // !self.namespace_tracer.server_state(&mnt_namespace).is_some()
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

    pub fn delete_namespace(&mut self, mnt_namespace: String) {
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
        if let Some(value) = self.tracer.get_mut(&mnt_namespace) {
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
    /* 
    pub fn write_message_to_config_file(
        &self,
        pid: i32,
        nspid: i32,
        message: String,
    ) -> AnyhowResult<()> {
        let config_dir = "/var/run/elkeid_rasp";
        let config_path = format!("{}/{}.json", config_dir, nspid);
        let config_path_bak = format!("{}.bak", config_path);
        debug!("write message to {} {}", config_path_bak, message);
        crate::async_command::run_async_process(
            Command::new(crate::settings::RASP_NS_ENTER_BIN()).args([
                "-m",
                "-t",
                pid.to_string().as_str(),
                "sh",
                "-c",
                "PATH=/bin:/usr/bin:/sbin",
                format!(
                    "mkdir -p {} && echo '{}' > {} && mv {} {}",
                    config_dir, message, config_path_bak, config_path_bak, config_path
                )
                .as_str(),
            ]),
        )?;
        let ns_thread = thread::Builder::new().spawn(move || -> AnyhowResult<()> {
            debug!("switch namespace");
            libraspserver::ns::switch_namespace(pid);
            if !Path::new(&config_dir).exists() {
                fs_extra::dir::create(config_dir, true)?;
            }
            fs_extra::file::write_all(&config_path_bak, message.as_str())?;
            let mut option = fs_extra::file::CopyOptions::new();
            option.overwrite = true;
            fs_extra::file::move_file(config_path_bak, config_path, &option)?;
            Ok(())
        }).unwrap();
        ns_thread.join()?;
         
        Ok(())
    }
    
    pub fn delete_config_file(&self, pid: i32, nspid: i32) -> AnyhowResult<()> {
        let config_path = format!("/var/run/elkeid_rasp/{}.json", nspid);
        if Path::new(&config_path).exists() {
            crate::async_command::run_async_process(
                Command::new(crate::settings::RASP_NS_ENTER_BIN()).args([
                    "-m",
                    "-t",
                    pid.to_string().as_str(),
                    "sh",
                    "-c",
                    format!("rm {}", config_path).as_str(),
                ]),
            )?;
        }
        Ok(())
    }
    */
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use libraspserver::proto::ProbeConfigPatch;

    #[test]
    fn patch_message() {
        let fake_patch = ProbeConfigPatch {
            class_name: "CVE202144228".to_string(),
            url: Some("file:///var/run/elkeid_rasp/".into()),
            path: Some("/run/elkeid_rasp/com/security/patch/CVE202144228".into()),
            sum_hash: None,
        };
        let mut fake_patches = Vec::new();
        fake_patches.push(fake_patch);
        let mut fake_configs = Vec::new();
        fake_configs.push(PidMissingProbeConfig {
            message_type: 9,
            data: ProbeConfigData {
                uuid: "fake".to_string(),
                blocks: None,
                filters: None,
                limits: None,
                patches: Some(fake_patches),
            },
        });
        let fake_manager = RASPManager {
            namespace_tracer: MntNamespaceTracer::new(),
            thread_comm: None,
            process_comm: None,
            runtime_dir: false,
        };
        println!("{:?}", fake_configs);
        let _ = fake_manager
            .patch_message_handle(&mut fake_configs, 35432)
            .unwrap();
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
