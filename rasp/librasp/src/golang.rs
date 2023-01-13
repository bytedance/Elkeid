use log::*;
use std::fs::File;
use std::{fs, path::PathBuf, process::Command};

use anyhow::{anyhow, Result};
use goblin::elf::Elf;
use memmap::MmapOptions;

use crate::async_command::run_async_process;
use crate::process::ProcessInfo;
use crate::runtime::{ProbeCopy, ProbeState, ProbeStateInspect};
use crate::settings;

pub struct GolangProbeState {}

impl ProbeStateInspect for GolangProbeState {
    fn inspect_process(process_info: &ProcessInfo) -> Result<ProbeState> {
        match search_thread(process_info) {
            Ok(ProbeState::Attached) => {
                warn!("find golang probe client thread");
                return Ok(ProbeState::Attached);
            }
            _ => {}
        };
        search_proc_map(process_info)
    }
}

pub struct GolangProbe {}
impl ProbeCopy for GolangProbe {
    fn names() -> (Vec<String>, Vec<String>) {
        (
            [
                settings::RASP_GOLANG(),
                // RASP_PANGOLIN.to_string(),
            ]
            .to_vec(),
            [].to_vec(),
        )
    }
}

fn search_proc_map(process_info: &ProcessInfo) -> Result<ProbeState> {
    let maps = procfs::process::Process::new(process_info.pid)?.maps()?;
    for map in maps.iter() {
        if let procfs::process::MMapPath::Path(p) = map.pathname.clone() {
            let s = match p.into_os_string().into_string() {
                Ok(s) => s,
                Err(os) => {
                    warn!("convert osstr to string failed: {:?}", os);
                    continue;
                }
            };
            if s.contains("go_probe") {
                return Ok(ProbeState::Attached);
            }
        }
    }
    Ok(ProbeState::NotAttach)
}

#[allow(dead_code)]
fn search_thread(process_info: &ProcessInfo) -> Result<ProbeState> {
    let tasks = procfs::process::Process::new(process_info.pid)?.tasks()?;
    for task_result in tasks {
        if let Err(_e) = task_result {
            continue;
        }
        if let Ok(task) = task_result {
            let task_stat_result = task.stat();
            if let Ok(task_stat) = task_stat_result {
                if task_stat.comm == "go-probe" {
                    return Ok(ProbeState::Attached);
                }
            }
        }
    }
    Ok(ProbeState::NotAttach)
}

pub fn golang_attach(pid: i32) -> Result<bool> {
    debug!("golang attach: {}", pid);
    let golang_probe = settings::RASP_GOLANG();
    let pangolin = settings::RASP_PANGOLIN();
    let daemon = "--daemon";
    let deaf = "--deaf";
    let pid_string = pid.clone().to_string();
    let args = &[daemon, deaf, pid_string.as_str(), golang_probe.as_str()];
    debug!("golang attach: {:?}", args);
    return match run_async_process(Command::new(pangolin).args(args)) {
        Ok((es, stdout, stderr)) => {
            if stdout.len() != 0 {
                info!("return code: {}\n{}", es.to_string(), &stdout);
            }
            if stderr.len() != 0 {
                warn!("return code: {}\n{}", es.to_string(), &stderr);
            }
            let es_code = match es.code() {
                Some(ec) => ec,
                None => {
                    return Err(anyhow!("get status code failed: {}", pid));
                }
            };
            if es_code == 0 {
                Ok(true)
            } else if es_code == 255 {
                let msg = format!(
                    "golang attach exit code 255: {} {} {} {}",
                    es_code, pid, &stdout, &stderr
                );
                error!("{}", msg);
                Err(anyhow!("{}", msg))
            } else {
                let msg = format!(
                    "golang attach exit code {} {} {} {}",
                    es_code, pid, &stdout, &stderr
                );
                error!("{}", msg);
                Err(anyhow!("{}", msg))
            }
        }
        Err(e) => Err(anyhow!(e.to_string())),
    };
}

pub fn golang_bin_inspect(bin_file: PathBuf) -> Result<bool> {
    let metadata = match fs::metadata(bin_file.clone()) {
        Ok(md) => md,
        Err(e) => {
            return Err(anyhow!(e));
        }
    };
    let size = metadata.len();
    if size >= (500 * 1024 * 1024) {
        return Err(anyhow!("bin file oversize"));
    }
    let file = File::open(bin_file)?;
    let bin = unsafe { MmapOptions::new().map(&file)? };
    let elf = Elf::parse(&bin)?;
    let shstrtab = elf.shdr_strtab;
    for section in elf.section_headers.iter() {
        let offset = section.sh_name;
        if let Some(name) = shstrtab.get(offset) {
            if name.unwrap() == ".gopclntab" {
                return Ok(true);
            }
        }
    }
    return Ok(false);
}
