use anyhow::{anyhow, Result as AnyhowResult};
use crossbeam::channel::{Sender};
use librasp::manager::{BPFSelect, RASPManager};
use log::*;
use librasp::process::TracingState;
use crate::{utils::Control};
use librasp::process::ProcessInfo;
use crate::config::{settings_bool, settings_string};

pub struct Operator {
    rasp_manager: RASPManager,
    message_sender: Sender<plugins::Record>,
    comm_ctrl: Control,
}

impl Operator {
    pub fn new(
        message_sender: Sender<plugins::Record>,
        comm_ctrl: Control,
    ) -> AnyhowResult<Self> {
        debug!("rasp manager init");
        let comm_mode = settings_string("server", "mode")?;
        let log_level = settings_string("service", "log_level")?;
        let bind_path = settings_string("server", "bind_path")?;
        let linking_to = match settings_string("server", "linking_to") {
            Ok(s) => Some(s),
            Err(_) => None,
        };
        let using_mount = match settings_bool("server", "using_mount") {
            Ok(v) => v,
            Err(_) => false,
        };
	let ebpf_mode = match settings_string("eBPF", "golang_ebpf_priority")?.as_str() {
	    "DISABLE" => BPFSelect::DISABLE,
	    "FORCE" => BPFSelect::FORCE,
	    "FIRST" => BPFSelect::SECOND,
	    "SECOND" => BPFSelect::SECOND,
	    _ => {
		let msg = "[eBPF] golang_ebpf_mode: {} not in [`DISABLE` `FORCE` `FIRST` `SECOND`]";
		error!("{}", msg);
		return Err(anyhow!("{}", msg));
	    }
	};
        let rasp_manager = RASPManager::init(
            comm_mode.as_str(), log_level,
            comm_ctrl.clone(), message_sender.clone(),
            bind_path, linking_to, using_mount, ebpf_mode,
        )?;

        Ok(Self {
            rasp_manager,
            message_sender,
            comm_ctrl,
        })
    }
    pub fn host_rasp_server(&mut self) -> AnyhowResult<()> {
        let process_info = ProcessInfo::from_pid(1)?;
        self.new_comm(&process_info)?;
        Ok(())
    }
    pub fn new_comm(&mut self, process: &ProcessInfo) -> AnyhowResult<()> {
        let message_sender_clone = self.message_sender.clone();
        self.rasp_manager
            .start_comm(&process, message_sender_clone, "info".to_string(), self.comm_ctrl.clone())?;
        Ok(())
    }
    pub fn stop_comm(&mut self, process: &ProcessInfo) -> AnyhowResult<()> {
        self.rasp_manager.stop_comm(&process)?;
        Ok(())
    }
    pub fn attach_process(&mut self, process: &mut ProcessInfo) -> AnyhowResult<()> {
        info!("process: {:?}", process);
        // /* stage one: copy probe binary to process namespace file path via /proc/<pid>/root */
        // let proc_root = RASPManager::root_dir(process.pid);
        // let namespace = process.namespace_info.as_ref().unwrap();
        // let mnt_namespace = namespace.mnt.as_ref().unwrap();
        // info!("copy rasp probe binary to: {}", proc_root);
        // self.rasp_manager
        //     .copy_to_target_dir(process.pid, &mnt_namespace)?;
        /* stage two: spawn comm server waiting probe start */
        self.new_comm(&process.clone())?;
        /* stage three: attach process, inject probe */
        if process.runtime.is_none() {
            return Err(anyhow!("pid: {} runtime not detected", process.pid));
        }
        process.update_try_attach_count();
        process.update_attach_start_time();
        match self.rasp_manager.attach(&process, librasp::manager::BPFSelect::FIRST) {
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
                //if process.tracing_state != ProbeState::Attached {
                    self.rasp_manager.delete_config_file(process.pid, process.nspid)?;
                    process.update_failed_time();
                    warn!(
                        "pid: {} runtime: {}, attach failed",
                        process.pid,
                        process.runtime.as_ref().unwrap()
                    );
                    self.stop_comm(&process)?;
                    return Err(anyhow!("attach failed: {}", e));
               // }
            }
        }
        Ok(())
    }

    pub fn detach_process(&mut self, process: &mut ProcessInfo) -> AnyhowResult<()> {
        info!("process: {:?}", process);
        self.rasp_manager.detach(&process)
    }

    pub fn handle_missing(&mut self, process: &mut ProcessInfo) -> AnyhowResult<()> {
        // for count abnormal process
        process.update_missing_time();
        self.stop_comm(&process)?;
        return Ok(());
    }

    pub fn send_probe_message(&mut self, process_info: &ProcessInfo, probe_message: &String) -> AnyhowResult<()> {
        let pid = process_info.pid;
        let mnt_namespace = process_info
            .namespace_info.clone().ok_or(anyhow!("unable fetch namespace"))?
            .mnt.ok_or(anyhow!("unable fetch namespace"))?;
        // self.rasp_manager.write_message_to_config_file(pid, process_info.nspid, probe_message.clone());
        self.rasp_manager.delete_config_file(pid, process_info.nspid)?;
        self.rasp_manager.send_message_to_probe(pid, &mnt_namespace, probe_message)
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
            "WAIT_ATTACH" | "ATTACHED" => {
                info!("attaching process: {:?}", process);
                if let Some(process_state) = process.tracing_state.as_ref() {
                    match process_state.to_string().as_str() {
                        "ATTACHED" => {}
                        _ => {
                            self.attach_process(process)?;
                        }
                    }
                    if probe_message != "" {
                        match self.send_probe_message(&process, &probe_message) {
                            Ok(_) => {},
                            Err(e) => {
                                let msg = format!("send probe message failed: {}", e);
                                error!("{}", msg);
                                return Err(anyhow!(msg));
                            }
                        };
                    }
                }
            }
            "DETACH" => {
                info!("detaching process: {:?}", process);
                if let Some(process_state) = process.tracing_state.as_ref() {
                    match process_state.to_string().as_str() {
                        "ATTACHED" => {
                            match  self.detach_process(process) {
                                Ok(_) => {
                                    process.tracing_state = Some(TracingState::INSPECTED);
                                }
                                Err(e) => {
                                    return Err(anyhow!(e));
                                }
                               
                            }
                        }
                        _ => {}
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
