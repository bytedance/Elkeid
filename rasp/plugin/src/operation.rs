use std::collections::HashMap;

use anyhow::{anyhow, Result as AnyhowResult};
use crossbeam::channel::{Receiver, Sender};
use librasp::manager::RASPManager;
use log::*;

use crate::{utils::Control};
use librasp::process::ProcessInfo;

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
        let process_info = ProcessInfo::from_pid(1)?;
        self.new_comm(&process_info)?;
        Ok(())
    }
    pub fn new_comm(&mut self, process: &ProcessInfo) -> AnyhowResult<()> {
        if self.command_channel_map.get(&process.pid).is_some() {
            debug!("deplicated attach");
            return Ok(());
        }
        let message_sender_clone = self.message_sender.clone();
        self.rasp_manager
            .start_comm(&process, message_sender_clone, "info".to_string(), self.comm_ctrl.clone())?;
        Ok(())
    }
    pub fn stop_comm(&mut self, process: &ProcessInfo) -> AnyhowResult<()> {
        self.rasp_manager.stop_comm(&process)?;
        let _ = self.command_channel_map.remove(&process.pid);
        Ok(())
    }
    pub fn attach_process(&mut self, process: &mut ProcessInfo) -> AnyhowResult<()> {
        info!("process: {:?}", process);
        /* stage one: copy probe binary to process namespace file path via /proc/<pid>/root */
        let proc_root = RASPManager::root_dir(process.pid);
        let namespace = process.namespace_info.as_ref().unwrap();
        let mnt_namespace = namespace.mnt.as_ref().unwrap();
        info!("copy rasp probe binary to: {}", proc_root);
        self.rasp_manager
            .copy_to_target_dir(process.pid, &mnt_namespace)?;
        /* stage two: spawn comm server waiting probe start */
        self.new_comm(&process.clone())?;
        /* stage three: attach process, inject probe */
        if process.runtime.is_none() {
            return Err(anyhow!("pid: {} runtime not detected", process.pid));
        }
        process.update_try_attach_count();
        process.update_attach_start_time();
        match self.rasp_manager.attach(&process) {
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
                self.stop_comm(&process)?;
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
        self.stop_comm(&process)?;
        return Ok(());
    }
    pub fn send_probe_message(&mut self, pid: i32, probe_message: &String) -> AnyhowResult<()> {
        let (sc, _) = match self.command_channel_map.get_mut(&pid) {
            Some((s, r)) => (s, r),
            None => {
                return Err(anyhow!(
                    "can not find probe comm in command channel, pid: {}", pid
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
                if let Some(process_state) = process.tracing_state.as_ref() {
                    match process_state.to_string().as_str() {
                        "WAIT_ATTACH" => {
                            if probe_message != "" {
                                self.send_probe_message(process.pid, &probe_message)?;
                            }
                        }
                        _ => {
                            self.attach_process(process)?;
                            if probe_message != "" {
                                self.send_probe_message(process.pid, &probe_message)?;
                            }
                        }
                    }
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
