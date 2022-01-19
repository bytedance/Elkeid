use crate::process::ProcessInfo;
use serde::Serialize;
use serde_json::to_string;
use std::{collections::HashMap, ffi::OsString};

/* convert hashmap to json string */
#[derive(Serialize, Debug)]
struct H2J {
    h: HashMap<OsString, OsString>,
}

pub fn make_report(
    process: &ProcessInfo,
    action: &str,
    reason: String,
) -> HashMap<&'static str, String> {
    let mut report = HashMap::new();
    report.insert("action", action.to_string());
    report.insert("reason", reason);
    report.insert("pid", process.pid.to_string());
    report.insert(
        "cmdline",
        process
            .cmdline
            .as_ref()
            .unwrap_or(&String::new())
            .to_string(),
    );
    if let Some(envs) = process.environ.as_ref() {
        let h2j = H2J {
	    h: (envs.clone())
        };
        report.insert("envs", to_string(&h2j).unwrap_or(String::new()).to_string());
    }
    report.insert(
        "tracing_state",
        match process.tracing_state {
            Some(st) => st.to_string(),
            None => String::new(),
        },
    );
    report.insert(
        "runtime",
        match &process.runtime {
            Some(rt) => rt.to_string(),
            None => String::new(),
        },
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
    report
}
