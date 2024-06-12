use anyhow::{anyhow, Result, Result as AnyhowResult};

use log::*;
use regex::Regex;
use std::process::Command;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use crate::async_command::run_async_process;
use crate::process::ProcessInfo;
use crate::runtime::{ProbeCopy, ProbeState, ProbeStateInspect};
use crate::settings::{self, RASP_VERSION};
use lazy_static::lazy_static;
use fs_extra::file::{copy as file_copy, remove as file_remove, CopyOptions as FileCopyOptions};

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
            [].to_vec(),
        )
    }
}

pub struct JVMProbeNativeLib {}

impl ProbeCopy for JVMProbeNativeLib {
    #[cfg(all(target_os = "linux"))]
    fn names() -> (Vec<String>, Vec<String>) {
        (
            [
                settings::RASP_JAVA_NETTY_EPOLL_SO(),
            ]
            .to_vec(),
            [].to_vec(),
        )
    }

    #[cfg(all(target_os = "macos"))]
    fn names() -> (Vec<String>, Vec<String>) {
        (
            [
                settings::RASP_JAVA_NETTY_KQUEUQ_SO_MAC(),
                settings::RASP_JAVA_NETTY_DNS_SO_MAC(),
            ]
            .to_vec(),
            [].to_vec(),
        )
    }
}

pub fn parse_java_library_path(input: &str) -> Result<Vec<PathBuf>, anyhow::Error> {
    let xinput = input.replace("\\:", ":");
    let paths: Vec<&str> = xinput.split(":").collect();
    let mut result = Vec::with_capacity(paths.len());

    for path in paths {
        let path_buf = {
            let path_str = path.to_string();
            PathBuf::from(path_str)
        };
        if path_buf.exists() {
            result.push(path_buf);
        } else {
            // Ignore non-existent paths
            continue;
        }
    }

    Ok(result)
}

fn copy_file_probe(from:String,to:String) -> AnyhowResult<()> {
    let options = FileCopyOptions::new();
    return match file_copy(from.clone(), to.clone(), &options) {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!("can not copy: {}", e);
            Err(anyhow!(
                "copy failed: from {} to {}: {}",
                from,
                to,
                e
            ))
        }
    }
}

fn get_last_filename(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
}

pub fn copy_probe_nativelib(pid:i32,dst_root:String) -> AnyhowResult<()> {
        let _ = jcmd(pid, " VM.system_properties").and_then(|output| {
        let output_str = String::from_utf8_lossy(&output);
        let lines: Vec<&str> = output_str.split("\n").collect();
        let java_library_path_line = lines.iter().find(|line| line.starts_with("java.library.path="));
        if let Some(line) = java_library_path_line {
            let path = line.trim_start_matches("java.library.path=");
            match parse_java_library_path(path) {
                Ok(parsed_paths) => {
                    println!("Java library paths:{:?}",parsed_paths);
                    for from in JVMProbeNativeLib::names().0.iter() {
                        let src_path = from.clone();
                        if let Some(soname) = get_last_filename(&src_path) {
                            let mut bIsExist = false;
                            println!("Last filename: {}", soname);
                            for path in parsed_paths.clone() {
                                let mut path_str = format!("{}{}",dst_root,path.display());
                                let path_buf: PathBuf = path_str.into();
                                println!("  {} exist", path_buf.display());
                                if path_buf.join(&soname).exists() {
                                    println!("{} exist",soname);
                                    bIsExist = true;
                                    break;
                                } 
                            }

                            if !bIsExist {
                                let path = parsed_paths[0].clone();

                                let dst_path = format!("{}{}/{}",dst_root,path.display(),soname);
                                println!("copy {} to {}",src_path,dst_path);
                                copy_file_probe(src_path,dst_path);
                            }
                        }
                    }
                }
                Err(e) => {
                    info!("parse java library path failed: {}", e);
                }
            }
           
            Ok(0)
        } else {
            Err(anyhow::anyhow!("java.library.path not found in output"))
        }
    });

    Ok(())
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
                    return Err(anyhow!("get status code failed: {}", pid));
                }
            };
            if es_code == 0 {
                std::thread::sleep(Duration::from_millis(500));
                match check_result(pid, "attach") {
                    Ok(_) => {
                        return Ok(true);
                    }
                    Err(e) => {
                        return Err(anyhow!(e.to_string()));
                    }
                }
            } else {
                let msg = format!(
                    "jvm attach exit code {} {} {} {}",
                    es_code, pid, &out, &err
                );
                error!("{}", msg);
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
                    "jvm detach exit code {} {} {} {}",
                    es_code, pid, &out, &err
                );
                error!("{}", msg);
                Err(anyhow!("{}", msg))
            }      
        }
        Err(e) => {
            return Err(anyhow!(e.to_string()));
        }
    }
}