use std::collections::HashMap;

use anyhow::{anyhow, Result as AnyhowResult};
use crossbeam::channel::{bounded, Receiver, Sender};
use librasp::manager::RASPManager;
use log::*;
use procfs::process::Process;

use crate::{process::ProcessInfo, utils::Control};
use librasp::process::ProcessInfo as RASPProcessInfo;

pub struct Operator {
    rasp_manager: RASPManager,
    message_sender: Sender<HashMap<&'static str, String>>,
    command_channel_map: HashMap<i32, (Sender<String>, Receiver<String>)>,
    comm_ctrl: Control,
}

impl Operator {
    pub fn new(
        message_sender: Sender<HashMap<&'static str, String>>,
        comm_ctrl: Control,
    ) -> AnyhowResult<Self> {
        debug!("rasp manager initing");
        let rasp_manager = RASPManager::init()?;
        Ok(Self {
            rasp_manager,
            message_sender,
            command_channel_map: HashMap::new(),
            comm_ctrl,
        })
    }
    pub fn host_rasp_server(&mut self) -> AnyhowResult<()> {
        let mut process_info = RASPProcessInfo::new(1).unwrap();
        let _ = process_info.update_ns_info();
        self.new_comm(&process_info)?;
        Ok(())
    }
    pub fn new_comm(&mut self, process: &RASPProcessInfo) -> AnyhowResult<()> {
        if self.command_channel_map.get(&process.pid).is_some() {
            debug!("deplicated attach");
            return Ok(());
        }
        let (command_send_channel, command_recv_channel): (Sender<String>, Receiver<String>) =
            bounded(10);
        let command_recv_channel_in_comm = command_recv_channel.clone();
        let command_recv_channel_in_map = command_recv_channel.clone();
        let message_sender_clone = self.message_sender.clone();
        let comm = (message_sender_clone, command_recv_channel_in_comm);
        self.rasp_manager
            .start_comm(&process, comm, "info".to_string(), self.comm_ctrl.clone())?;
        self.command_channel_map.insert(
            process.pid,
            (command_send_channel, command_recv_channel_in_map),
        );
        Ok(())
    }
    pub fn stop_comm(&mut self, process: &RASPProcessInfo) -> AnyhowResult<()> {
        self.rasp_manager.stop_comm(&process)?;
        let _ = self.command_channel_map.remove(&process.pid);
        Ok(())
    }
    pub fn attach_process(&mut self, process: &mut ProcessInfo) -> AnyhowResult<()> {
        let mut rasp_process = match RASPProcessInfo::new(process.pid) {
            Ok(rp) => rp,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };
        info!("process: {:?}", rasp_process);
        /* stage one: copy probe binary to process namespace file path via /proc/<pid>/root */
        let proc_root = RASPManager::root_dir(process.pid);
        let namespace = process.namespace_info.as_ref().unwrap();
        let mnt_namespace = namespace.mnt.as_ref().unwrap();
        info!("copy rasp probe binary to: {}", proc_root);
        self.rasp_manager
            .copy_to_target_dir(process.pid, &mnt_namespace)?;
        /* stage two: spawn comm server waiting probe start */
        match rasp_process.update_ns_info() {
	    Ok(_) => {},
	    Err(e) => {
		return Err(anyhow!("update ns failed: {}", e))?;
	    }
	}
        self.new_comm(&rasp_process.clone())?;
        /* stage three: attach process, inject probe */
        if process.runtime.is_none() {
            return Err(anyhow!("pid: {} runtime not detected", process.pid));
        }
        rasp_process.runtime_info = process.runtime.clone();
        process.update_try_attach_count();
        process.update_attach_start_time();
        match self.rasp_manager.attach(&mut rasp_process) {
            Ok(_) => {
                process.update_attached_count();
                process.update_attach_end_time();
                info!(
                    "pid: {} runtime: {}, attach success",
                    process.pid,
                    process.runtime.as_ref().unwrap()
                );
            }
            Err(e) => {
                process.update_failed_time();
                warn!(
                    "pid: {} runtime: {}, attach failed",
                    process.pid,
                    process.runtime.as_ref().unwrap()
                );
                self.stop_comm(&rasp_process)?;
                return Err(anyhow!("attach failed: {}", e));
            }
        }
        Ok(())
    }
    pub fn handle_missing(&mut self, process: &mut ProcessInfo) -> AnyhowResult<()> {
        if process
            .tracing_state
            .ok_or(anyhow!("empty state found during handle missing"))?
            .to_string()
            == "ATTACHED"
        {
            process.update_missing_time();
        }
        let rasp_process = RASPProcessInfo {
            pid: process.pid,
            exe_path: None,
            process_self: Process::new(1).unwrap(),
            process_tree: None,
            runtime_info: None,
            container_info: None,
            namespace_info: Some(process.namespace_info.clone().unwrap()),
            cmdline: None,
            environ: None,
            exe: None,
            attach_time: None,
            failed_time: None,
            missing_time: None,
        };
        self.stop_comm(&rasp_process)?;
        return Ok(());
    }
    pub fn send_probe_message(&mut self, pid: i32, probe_message: &String) -> AnyhowResult<()> {
        let (sc, _) = match self.command_channel_map.get_mut(&pid) {
            Some((s, r)) => (s, r),
            None => {
                return Err(anyhow!(
                    "can not find probe comm in command channel, pid: {}",
                    pid
                ));
            }
        };
        sc.send(probe_message.to_string())?;
        Ok(())
    }
    pub fn op(
        &mut self,
        process: &mut ProcessInfo,
        state: String,
        probe_message: String,
    ) -> AnyhowResult<()> {
        match state.as_str() {
            "MISSING" => {
                self.handle_missing(process)?;
            }
            "WAIT_ATTACH" => {
                info!("attaching process: {:?}", process);
                self.attach_process(process)?;
                if probe_message != "" {
                    self.send_probe_message(process.pid, &probe_message)?;
                }
            }
            "CLOSING" => {
                // next release
            }
            _ => {}
        }
        return Ok(());
    }
}
