use log::*;
use regex::Regex;
use std::process::Command;
use std::fs;
use std::time::Duration;
use crate::async_command::run_async_process;
use crate::process::ProcessInfo;
use crate::runtime::{ProbeCopy, ProbeState, ProbeStateInspect};
use crate::settings::{self, RASP_VERSION};
use lazy_static::lazy_static;
use anyhow::{anyhow, Result};

lazy_static! {
    static ref RASP_JAVA_CHECKSUMSTR: String = {
        match fs::read_to_string(settings::RASP_JAVA_CHECKSUM_PATH()) {
            Ok(content) => content,
            Err(e) => {
                error!("failed to get Java check sum, err: {}, path: {},java may not be attach success", e, settings::RASP_JAVA_CHECKSUM_PATH());
                String::new()
            }
        }
    };
}
pub struct JVMProbeState {}

impl ProbeStateInspect for JVMProbeState {
    fn inspect_process(process_info: &ProcessInfo) -> Result<ProbeState> {
        match  prop(process_info.pid) {
            Ok(state) => {
                Ok(state)
            }
            Err(_) => {
                Ok(ProbeState::NotAttach)
            }
        }
    }
}

pub struct JVMProbe {}

impl ProbeCopy for JVMProbe {
    fn names() -> (Vec<String>, Vec<String>) {
        (
            [
                settings::RASP_JAVA_JATTACH_BIN(),
                settings::RASP_JAVA_PROBE_BIN(),
                settings::RASP_JAVA_AGENT_BIN(),
            ]
            .to_vec(),
            [settings::RASP_JAVA_RULES_DIR()].to_vec(),
        )
    }
}

pub fn java_attach(pid: i32) -> Result<bool> {
    let java_attach = settings::RASP_JAVA_JATTACH_BIN();
    let agent = settings::RASP_JAVA_AGENT_BIN();
    let probe_param = format!("{}={};{};{};", agent, "attach", *RASP_JAVA_CHECKSUMSTR, settings::RASP_JAVA_PROBE_BIN());
    match run_async_process(Command::new(java_attach).args(&[
        pid.to_string().as_str(),
        "load",
        "instrument",
        "false",
        probe_param.as_str(),
    ])) {
        Ok((es, out, err)) => {
            if out.len() != 0 {
                info!("{}", &out);
            }
            if err.len() != 0 {
                info!("{}", &err);
            }
            let es_code = match es.code() {
                Some(ec) => ec,
                None => {
                    return Err(anyhow!("get status code failed: {}, output: {}, err: {}", pid, out, err));
                }
            };
            if es_code == 0 {
                std::thread::sleep(Duration::from_millis(500));
                match check_result(pid, "attach") {
                    Ok(_) => {
                        return Ok(true);
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(500));
                        match check_result(pid, "attach") {
                            Ok(_) => {
                                return Ok(true);
                            }
                            Err(e) => {
                                return Err(anyhow!(e.to_string()));
                            }
                        }
                    }
                }
            } else {
                let msg = format!(
                    "jvm attach exit code {} {} {}",
                    es_code, &out, &err
                );
                error!("pid: {}, {}", pid, msg);
                Err(anyhow!("{}", msg))
            }
        }
        Err(e) => {
            Err(anyhow!(e.to_string()))
        }
    }
}

pub fn jcmd(pid: i32, cmd: &'static str) -> Result<Vec<u8>> {
    let java_attach = settings::RASP_JAVA_JATTACH_BIN();
    match run_async_process(Command::new(java_attach).args(&[
        pid.to_string().as_str(),
        "jcmd",
       cmd,
    ])) {
        Ok((_, out, err)) => {
            // if out.len() != 0 {
            //     info!("{}", &out);
            // }
            if err.len() != 0 {
                info!("pid: {}, {}", pid, &err);
            }
            return Ok(out.into())
        }
        Err(e) => {
            Err(anyhow!(e.to_string()))
        }
    }
}

pub fn vm_version(pid: i32) -> Result<i32> {
    return match jcmd(pid, "VM.version") {
        Ok(stdout) => {
            let response = String::from_utf8(stdout).unwrap_or(String::new());
            let re = Regex::new(r"JDK (\d+)\.").unwrap();
            let version = match re.captures(&response) {
                Some(c) => c.get(1).map_or("", |m| m.as_str()),
                None => return Err(anyhow!(String::from("can not find version"))),
            };
            let version_number = match version.parse::<i32>() {
                Ok(vm) => vm,
                Err(e) => return Err(anyhow!(e.to_string())),
            };
            Ok(version_number)
        }
        Err(e) => Err(anyhow!(e)),
    };
}

pub fn check_java_version(ver: &String, pid:i32) -> Result<()> {
    let ver:u32 = match ver.parse::<u32>() {
        Ok(v) => {v}
        Err(_) => {0}
    };
    if ver < 8 {
        warn!("process {} Java version lower than 8: {}, so not inject", pid, ver);
        let msg = format!("Java version lower than 8: {}, so not inject", ver);
        return Err(anyhow!(msg));
    } else if ver == 13 || ver == 14 {
        // jdk bug https://bugs.openjdk.org/browse/JDK-8222005
        warn!("process {} Java version {} has attach bug, so not inject", pid, ver);
        let msg = format!("process {} Java version {} has attach bug, so not inject", pid, ver);
        return Err(anyhow!(msg));
    } else {
        return Ok(());
    }
}

pub fn prop(pid: i32) -> Result<ProbeState> {
    return match jcmd(pid, " VM.system_properties") {
        Ok(stdout) => {
            let response = String::from_utf8_lossy(&stdout);
            let re = Regex::new(r"rasp\.probe").unwrap();
            if re.is_match(&response) {
                info!("found rasp.probe");
                let re: Regex = Regex::new(r"smith\.rasp=(.*)").unwrap();

                if let Some(captures) = re.captures(&response) {
                    if let Some(value_match) = captures.get(1) {
                       let check_str = value_match.as_str().trim().to_string();
                       let unescaped_string = check_str.replace(r"\=", "=");
                       info!("found checkstr: {}", unescaped_string);
                       if unescaped_string != format!("{}-{}", RASP_VERSION, *RASP_JAVA_CHECKSUMSTR) {
                            return Ok(ProbeState::AttachedVersionNotMatch);
                       }
                    }
                }
                return Ok(ProbeState::Attached);
            }
            return Ok(ProbeState::NotAttach);
        }
        Err(e) => Err(anyhow!(e)),
    };
}

pub fn check_result(pid: i32, need_status: &str) -> Result<bool> {
    return match jcmd(pid, " VM.system_properties") {
        Ok(stdout) => {
            let response = String::from_utf8_lossy(&stdout);
            let re: Regex = Regex::new(r"smith\.status=(.*)").unwrap();
            if let Some(captures) = re.captures(&response) {
                if let Some(value_match) = captures.get(1) {
                    let check_status = value_match.as_str().trim().to_string();
                    info!("found smith.status: {}", check_status);
                    if check_status != need_status {
                        return Err(anyhow!(check_status));
                    }
                 }
            }
            Ok(true)
        }
        Err(e) => {Err(anyhow!(e))}
    }
}

pub fn java_detach(pid: i32) -> Result<bool> {
    let java_detach = settings::RASP_JAVA_JATTACH_BIN();
    let agent = settings::RASP_JAVA_AGENT_BIN();
    let probe_param = format!("{}={};", agent, "detach");
    match run_async_process(Command::new(java_detach).args(&[
        pid.to_string().as_str(),
        "load",
        "instrument",
        "false",
        probe_param.as_str(),
    ])) {
        Ok((es, out, err)) => {
            if out.len() != 0 {
                info!("{}", &out);
            }
            if err.len() != 0 {
                info!("{}", &err);
            }
            let es_code = match es.code() {
                Some(ec) => ec,
                None => {
                    return Err(anyhow!("get status code failed: {}", pid));
                }
            };
            if es_code == 0 {
                std::thread::sleep(Duration::from_millis(500));
                match check_result(pid, "detach") {
                    Ok(_) => {
                        return Ok(true);
                    }
                    Err(e) => {
                        return Err(anyhow!(e.to_string()));
                    }
                }
            } else {
                let msg = format!(
                    "jvm detach exit code {} {} {}",
                    es_code, &out, &err
                );
                error!("pid: {}, {}", pid, msg);
                Err(anyhow!("{}", msg))
            }      
        }
        Err(e) => {
            return Err(anyhow!(e.to_string()));
        }
    }
}