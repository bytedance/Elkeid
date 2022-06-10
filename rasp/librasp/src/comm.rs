use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use crossbeam::channel::{bounded, Receiver, Sender};
use log::*;

use super::process::ProcessInfo;
use anyhow::{anyhow, Result as AnyhowResult};
pub struct RASPServerManager {
    pub mnt_namespace_server_map: HashMap<String, libraspserver::process_mode::RASPServerProcess>,
    pub mnt_namespace_comm_pair: HashMap<String, (Sender<String>, Receiver<String>)>,
}

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

pub enum ServerStatus {
    WORKING,
    // not exitst
    NULL,
    // alived, but can not `wait` on child process
    MISSING,
}

impl Display for ServerStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ServerStatus::WORKING => write!(f, "WORKING"),
            ServerStatus::NULL => write!(f, "NULL"),
            ServerStatus::MISSING => write!(f, "MISSING"),
        }
    }
}

impl RASPServerManager {
    pub fn new() -> Result<Self, String> {
        let new_manager = Self {
            mnt_namespace_server_map: HashMap::new(),
            mnt_namespace_comm_pair: HashMap::new(),
        };
        Ok(new_manager)
    }
    pub fn send_to_probe(&self, mnt_namespace: &String, message: &String) -> Result<(), String> {
        if let Some(p) = self.mnt_namespace_comm_pair.get(mnt_namespace) {
            if let Err(e) = p.0.send(message.clone()) {
                return Err(format!("send probe config failed: {}", e.to_string()));
            }
        }
        Ok(())
    }

    pub fn start_new_rasp_server(
        &mut self,
        process_info: &ProcessInfo,
        message_sender: Sender<HashMap<&'static str, String>>,
        log_level: String,
        ctrl: Control,
        patch_field: HashMap<&'static str, String>,
    ) -> AnyhowResult<()> {
        let mnt_namespace = process_info.get_mnt_ns()?;
        let (_, r) = if let Some(p) = self.mnt_namespace_comm_pair.get(&mnt_namespace) {
            (p.0.clone(), p.1.clone())
        } else {
            let (s, r) = bounded(50);
            self.mnt_namespace_comm_pair
                .insert(mnt_namespace.clone(), (s.clone(), r.clone()));
            (s, r)
        };
        let runner = match libraspserver::process_mode::RASPServerProcess::new(
            process_info.pid,
            message_sender,
            r,
            log_level,
            patch_field,
            libraspserver::utils::Control {
                working_atomic: ctrl.working_atomic.clone(),
                control: ctrl.control.clone(),
            },
        ) {
            Err(e) => {
                return Err(anyhow!("{}", e.to_string()));
            }
            Ok(runner) => runner,
        };
        self.mnt_namespace_server_map
            .insert(mnt_namespace.clone(), runner);
        Ok(())
    }
    pub fn stop_rasp_server(&mut self, mnt_ns: &String) -> Result<(), String> {
        info!("stop server: {}", mnt_ns.clone());
        return if let Some(mut runner) = self.mnt_namespace_server_map.remove(mnt_ns) {
            runner.kill();
            Ok(())
        } else {
            Err(format!("didn't start server for pid: {}", mnt_ns.clone()))
        };
    }
}
