use std::collections::HashMap;
pub use librasp::comm::Control;
// use anyhow::Result as AnyhowResult;
use coarsetime::Clock;
use librasp::runtime::Runtime;
use serde_json::json;
use crate::process::{ProcessInfo, TracingState};

pub fn generate_seq_id() -> String {
    let timestamp = Clock::now_since_epoch().as_secs();
    format!("{}-{}", timestamp, "rand")
}

pub fn generate_heartbeat(watched_process: &ProcessInfo) -> HashMap<&'static str, String> {
    let mut message = HashMap::new();
    message.insert("pid", watched_process.pid.to_string());
    message.insert("cmdline", watched_process.cmdline.clone().unwrap_or("".to_string()));
    message.insert("exe_name", watched_process.exe_name.clone().unwrap_or("".to_string()));
    let environ = watched_process.environ.clone().unwrap_or(HashMap::new());
    message.insert("environ", json!(environ).to_string());
    message.insert("trace_state", watched_process.tracing_state.clone().unwrap_or(TracingState::INSPECTED).to_string());
    let runtime = watched_process.runtime.clone().unwrap_or(Runtime {
        name: "unknown",
        version: "unknown".to_string(),
    });

    message.insert("runtime", runtime.name.to_string());
    message.insert("runtime_version", runtime.version);
    message.insert("attach_start_time", watched_process.attach_start_time.clone().unwrap_or("".to_string()));
    message.insert("attach_end_time", watched_process.attach_end_time.clone().unwrap_or("".to_string()));
    message.insert("failed_time", watched_process.failed_time.clone().unwrap_or("".to_string()));
    message.insert("missing_time", watched_process.missing_time.clone().unwrap_or("".to_string()));
    message.insert("try_attach_count", watched_process.try_attach_count.to_string());
    message.insert("attached_count", watched_process.attached_count.to_string());

    message
}

/*
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

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
                // world stopped                                                 Replace match with if let
                Err(())
            }
        };
    }
}
*/
