use std::collections::HashMap;
pub use librasp::comm::Control;
use anyhow::Result as AnyhowResult;
use coarsetime::Clock;
use librasp::runtime::Runtime;
use serde_json::json;
use librasp::process::{ProcessInfo, TracingState};
use log::error;
use plugins::Record;

pub fn generate_seq_id() -> String {
    let timestamp = Clock::now_since_epoch().as_secs();
    format!("{}-{}", timestamp, "rand")
}

pub fn generate_heartbeat(watched_process: &ProcessInfo) -> HashMap<&'static str, String> {
    let mut message = HashMap::new();
    message.insert("pid", watched_process.pid.to_string());
    message.insert("cmdline", watched_process.cmdline.clone().unwrap_or("".to_string()));
    message.insert("exe_name", watched_process.exe_name.clone().unwrap_or("".to_string()));
    message.insert("current_config_hash", watched_process.current_config_hash.clone());
    let environ = watched_process.environ.clone().unwrap_or(HashMap::new());
    let mut environ_string = HashMap::new();
    for (k, v) in environ.iter() {
        let ks = k.to_str().unwrap_or("");
        let vs = v.to_str().unwrap_or("");
        environ_string.insert(ks, vs);
    }
    log::debug!("environ: {:?}", environ_string);
    message.insert("environ", json!(environ_string).to_string());
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
    message.insert("uptime", match count_uptime(watched_process.start_time.unwrap_or(0 as f32)) {
        Ok(t) => t.to_string(),
        Err(e) => {
            error!("count uptime failed: {}", e);
            0.to_string()
        }
    });


    message
}

pub fn count_uptime(start_time: f32) -> AnyhowResult<u64> {
    let ticks = procfs::ticks_per_second()? as f32;
    let boottime = procfs::boot_time_secs()?;
    let seconds_since_boot = ((start_time / ticks) as i64) as u64;
    let timestamp = Clock::now_since_epoch().as_secs();
    let uptime = timestamp - seconds_since_boot - boottime;
    if uptime <= 0 {
        error!(
            "uptime <=0: uptime: {} timestamp: {} seconds since boot: {} boot time: {}",
            uptime, timestamp, seconds_since_boot, boottime
        );
    }
    return Ok(uptime);
}

pub fn hashmap_to_record(hashmap: HashMap<&'static str, String>) -> Record {
    let mut rec = Record::new();

    let muted_rec = rec.mut_data().mut_fields();
    for (k, v) in hashmap.iter() {
        muted_rec.insert(k.to_string(), v.clone());
    }
    rec
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
