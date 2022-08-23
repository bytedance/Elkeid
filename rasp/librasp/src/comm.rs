use std::collections::HashMap;
// use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use crossbeam::channel::{bounded, Receiver, Sender, SendError};
use log::*;

// use super::process::ProcessInfo;
use anyhow::{anyhow, Result as AnyhowResult};
use crate::settings;

// https://stackoverflow.com/questions/35883390/how-to-check-if-a-thread-has-finished-in-rust
// https://stackoverflow.com/a/39615208
#[derive(Clone)]
pub struct Control {
    pub working_atomic: Arc<AtomicBool>,
    pub control: Weak<AtomicBool>,
}

impl Control {
    pub fn new() -> Self {
        let working = Arc::new(AtomicBool::new(true));
        let control = Arc::downgrade(&working);
        Control {
            working_atomic: working,
            control,
        }
    }
    pub fn check(&mut self) -> bool {
        (*self.working_atomic).load(Ordering::Relaxed)
    }
    pub fn stop(&mut self) -> Result<(), ()> {
        return match self.control.upgrade() {
            Some(working) => {
                (*working).store(false, Ordering::Relaxed);
                Ok(())
            }
            None => {
                // world stopped
                Err(())
            }
        };
    }
}

pub trait RASPComm {
    fn start_comm(
        &mut self,
        pid: i32,
        mnt_namespace: &String,
        probe_report_sender: Sender<plugins::Record>,
        patch_filed: HashMap<&'static str, String>,
    ) -> AnyhowResult<()>;
    fn stop_comm(
        &mut self,
        pid: i32,
        mnt_namespace: &String,
    ) -> AnyhowResult<()>;
    fn send_message_to_probe(
        &mut self, pid: i32, mnt_namespace: &String, message: &String,
    ) -> AnyhowResult<()>;
}

pub struct ThreadMode {
    pub ctrl: Control,
    pub log_level: String,
    pub bind_path: String,
    pub linking_to: Option<String>,
    pub agent_to_probe_sender: Sender<(i32, String)>,
}

impl ThreadMode {
    pub fn new(log_level: String, ctrl: Control,
               probe_report_sender: Sender<plugins::Record>,
               bind_path: String, linking_to: Option<String>
    ) -> AnyhowResult<Self> {
        let (sender, receiver) = bounded(50);
        libraspserver::thread_mode::start(
            bind_path.clone(),
            20,
            libraspserver::utils::Control {
                working_atomic: ctrl.working_atomic.clone(),
                control: ctrl.control.clone(),
            },
            probe_report_sender,
            receiver,
        );
        Ok(Self {
            ctrl,
            log_level,
            bind_path: bind_path,
            linking_to: linking_to,
            agent_to_probe_sender: sender,
        })
    }
}

pub struct ProcessMode {
    pub ctrl: Control,
    pub log_level: String,
    pub mnt_namesapce_server_map: HashMap<String, libraspserver::process_mode::RASPServerProcess>,
    pub mnt_namespace_comm_pair: HashMap<String, (Sender<String>, Receiver<String>)>,
}

impl ProcessMode {
    pub fn new(log_level: String, ctrl: Control) -> Self {
        Self {
            ctrl,
            log_level,
            mnt_namesapce_server_map: HashMap::new(),
            mnt_namespace_comm_pair: HashMap::new(),
        }
    }
}

impl RASPComm for ProcessMode {
    fn start_comm(&mut self, pid: i32, mnt_namespace: &String, probe_report_sender: Sender<plugins::Record>, patch_field: HashMap<&'static str, String>) -> AnyhowResult<()> {
        let (probe_mesasge_sender, probe_message_receiver) = bounded(50);
        let mut server_process =
            libraspserver::process_mode::RASPServerProcess::new(
                pid,
                probe_report_sender,
                probe_message_receiver.clone(),
                self.log_level.clone(),
                patch_field,
                libraspserver::utils::Control {
                    working_atomic: self.ctrl.working_atomic.clone(),
                    control: self.ctrl.control.clone(),
                },
            )?;
        server_process.spawn(settings::RASP_SERVER_BIN().as_str())?;
        self.mnt_namesapce_server_map.insert(mnt_namespace.clone(), server_process);
        self.mnt_namespace_comm_pair.insert(mnt_namespace.clone(), (probe_mesasge_sender, probe_message_receiver));
        Ok(())
    }

    fn stop_comm(&mut self, _pid: i32, mnt_namespace: &String) -> AnyhowResult<()> {
        info!("stop server: {}", mnt_namespace.clone());
        return if let Some(mut runner) = self.mnt_namesapce_server_map.remove(mnt_namespace) {
            runner.kill();
            Ok(())
        } else {
            Err(anyhow!("didn't start server for mnt namespace: {}", mnt_namespace.clone()))
        };
    }
    fn send_message_to_probe(&mut self, _pid: i32, mnt_namespace: &String, message: &String) -> AnyhowResult<()> {
        if let Some(p) = self.mnt_namespace_comm_pair.get(mnt_namespace) {
            if let Err(e) = p.0.send(message.clone()) {
                return Err(anyhow!("send to probe failed: {}", e.to_string()));
            }
        }
        Ok(())
    }
}

impl RASPComm for ThreadMode {
    fn start_comm(
        &mut self,
        pid: i32, _mnt_namespace: &String,
        _probe_report_sender: Sender<plugins::Record>,
        _patch_filed: HashMap<&'static str, String>,
    ) -> AnyhowResult<()> {
        if let Some(linking_to) = self.linking_to.clone() {
            match std::process::Command::new(settings::RASP_NS_ENTER_BIN())
                .args([
                    "-t",
                    pid.to_string().as_str(),
                    "-m",
                    "-i",
                    "-n",
                    "-p",
                    "/bin/ln",
                    "-sf",
                    self.bind_path.as_str(),
                    linking_to.as_str(),
                ])
                .output()
            {
                Ok(o) => {
                    info!("LN {} {:?} {:?}", o.status, o.stdout, o.stderr);
                }
                Err(e) => {
                    error!("LN can not run: {}", e);
                    return Err(anyhow!("link bind path failed: {}", e));
                }
            };
        }
        Ok(())
    }
    fn stop_comm(&mut self, _pid: i32, _mnt_namespace: &String) -> AnyhowResult<()> {
        Ok(())
    }
    fn send_message_to_probe(&mut self, pid: i32, _mnt_namespace: &String, message: &String) -> AnyhowResult<()> {
        match self.agent_to_probe_sender.send((pid, message.clone())) {
            Ok(_) => {
                debug!("sending to probe: {} {}", pid, message.clone());
            }
            Err(SendError(e)) => {
                error!("send error: {:?}", e);
                let _ = self.ctrl.stop();
                return Err(anyhow!("send message to probe failed: {} {}", e.0, e.1));
            }
        }
        Ok(())
    }
}