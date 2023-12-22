use librasp::process::ProcessInfo;
use serde_json::json;
use std::collections::HashMap;
use log::{error, debug};
use crate::utils;

pub fn make_report(
    process: &ProcessInfo,
    action: &str,
    reason: String,
) -> HashMap<&'static str, String> {
    let mut report = HashMap::new();
    report.insert("action", action.to_string());
    report.insert("reason", reason);
    report.insert("pid", process.pid.to_string());
    report.insert("exe_name", process.exe_name.as_ref().unwrap_or(&String::new()).to_string());
    report.insert(
        "cmdline",
        process
            .cmdline
            .as_ref()
            .unwrap_or(&String::new())
            .to_string(),
    );
    let environ = process.environ.clone().unwrap_or(HashMap::new());
    let mut environ_string = HashMap::new();
    for (k, v) in environ.iter() {
        let ks = k.to_str().unwrap_or("");
        let vs = v.to_str().unwrap_or("");
        environ_string.insert(ks, vs);
    }
    debug!("environ: {:?}", environ_string);
    report.insert("environ", json!(environ_string).to_string());
    report.insert(
        "trace_state",
        match process.tracing_state {
            Some(st) => st.to_string(),
            None => String::new(),
        },
    );
    report.insert(
        "runtime",
        match &process.runtime {
            Some(rt) => String::from(rt.name.clone()),
            None => String::new(),
        },
    );
    report.insert(
	"runtime_version",
	match &process.runtime {
	    Some(rt) => rt.version.clone(),
	    None => String::new(),
	}
    );
    report.insert(
        "runtime_size",
        match &process.runtime {
            Some(rt) => rt.size.to_string(),
            None => String::new(),
        }
        );
    report.insert(
        "attach_start_time",
        process
            .attach_start_time
            .as_ref()
            .unwrap_or(&String::new())
            .to_string(),
    );
    report.insert(
        "attach_end_time",
        process
            .attach_end_time
            .as_ref()
            .unwrap_or(&String::new())
            .to_string(),
    );
    report.insert(
        "failed_time",
        process
            .failed_time
            .as_ref()
            .unwrap_or(&String::new())
            .to_string(),
    );
    report.insert(
        "missing_time",
        process
            .missing_time
            .as_ref()
            .unwrap_or(&String::new())
            .to_string(),
    );
    report.insert("try_attach_count", process.try_attach_count.to_string());
    report.insert("attached_count", process.attached_count.to_string());
    report.insert("uptime", match utils::count_uptime(process.start_time.unwrap_or(0 as f32)){
        Ok(t) => t.to_string(),
        Err(e) => {
            error!("count uptime failed: {}", e);
            "0".to_string()
        },
    });
    report
}
