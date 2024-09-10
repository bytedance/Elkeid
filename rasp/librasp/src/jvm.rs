use log::*;
use regex::Regex;
use std::process::Command;
use std::fs;
use std::time::Duration;
use std::path::Path;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use anyhow::{anyhow, Result, Result as AnyhowResult};
use fs_extra::dir::create_all;
use fs_extra::file::{copy as file_copy, CopyOptions as FileCopyOptions};
use crate::async_command::run_async_process;
use crate::process::ProcessInfo;
use crate::runtime::{ProbeCopy, ProbeState, ProbeStateInspect};
use crate::settings::{self, RASP_VERSION};
use lazy_static::lazy_static;

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
    fn inspect_process(process_info: &mut ProcessInfo) -> Result<ProbeState> {
        if let Some(agent_jar) = extract_jar_path(process_info.pid) {
            let _ = process_info.update_attached_agent(&agent_jar);
        }
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

pub fn copy_file_from_to_dest(from: String, dest: String) -> AnyhowResult<()> {
    let target = dest;
    if Path::new(&target).exists() {
        return Ok(());
    }
    let dir = Path::new(&target).parent().unwrap();
    if Path::new(&target).exists() {
        return Ok(());
    }
    create_all(dir, true)?;
    let options = FileCopyOptions::new();
    return match file_copy(from.clone(), target.clone(), &options) {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!("can not copy: {}", e);
            Err(anyhow!(
                "copy failed: from {} to {}: {}",
                from,
                target,
                e
            ))
        }
    };
}

pub fn process_agent_path(attached_agent: Option<String>, pid: i32) -> String {
    let agent = settings::RASP_JAVA_AGENT_BIN();
    if attached_agent.is_none() {
        return agent;
    } else {
        let attached_agent = attached_agent.unwrap();
        info!("attached version: {}", attached_agent);
        if attached_agent != "" && attached_agent != settings::RASP_JAVA_AGENT_BIN() {
            let root_dir = format!("/proc/{}/root", pid);
            let agent_path = format!("{}{}", root_dir, attached_agent);
            let file_path = Path::new(&agent_path);

            if !file_path.exists() {
                info!("{} does not exist. start to copy", agent_path.clone());
                let _ = copy_file_from_to_dest(settings::RASP_JAVA_AGENT_BIN(), agent_path.clone());
            }
            return attached_agent;
        }
    }
    return agent;
}

pub fn java_attach(pid: i32, attached_agent: Option<String>) -> Result<bool> {
    let java_attach = settings::RASP_JAVA_JATTACH_BIN();
    let agent = process_agent_path(attached_agent, pid);
    
    let probe_param = format!("{}={};{};{};", agent, "attach", *RASP_JAVA_CHECKSUMSTR, settings::RASP_JAVA_PROBE_BIN());
    debug!("java attach: {}", probe_param.clone());
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

fn extract_jar_path(pid: i32) -> Option<String> {
    let maps_path = format!("/proc/{}/maps", pid);

    if let Ok(file) = File::open(maps_path) {
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(line) = line {
                if line.contains("SmithAgent.jar") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(path) = parts.get(5) {
                        return Some(path.to_string());
                    }
                }
            }
        }
    }

    None
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

pub fn java_detach(pid: i32, attached_agent: Option<String>) -> Result<bool> {
    let java_detach = settings::RASP_JAVA_JATTACH_BIN();
    let agent = process_agent_path(attached_agent, pid);
    let probe_param = format!("{}={};", agent, "detach");
    debug!("java detach param: {}", probe_param);
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