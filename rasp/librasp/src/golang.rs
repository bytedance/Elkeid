use anyhow::{anyhow, Result};
use goblin::elf::Elf;
use log::*;
use std::{fs, path::PathBuf, process::Command};

use memmap::MmapOptions;
use std::fs::File;

use crate::process::ProcessInfo;
use crate::runtime::{ProbeState, ProbeStateInspect, ProbeCopy};
use crate::settings::{RASP_GOLANG, RASP_PANGOLIN, RASP_GOLANG_BOE};

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
                RASP_GOLANG_BOE(),
                RASP_GOLANG(),
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
    let golang_probe = RASP_GOLANG();
    let pangolin = RASP_PANGOLIN();
    let daemon = "--daemon";
    let pid_string = pid.clone().to_string();
    let args = &[daemon, pid_string.as_str(), golang_probe.as_str()];
    debug!("golang attach: {:?}", args);
    return match Command::new(pangolin).args(args).status() {
        Ok(st) => Ok(st.success()),
        Err(e) => Err(anyhow!(e.to_string())),
    };
}

pub fn golang_bin_inspect(bin_file: PathBuf) -> Result<bool> {
    // file exist?
    let metadata = match fs::metadata(bin_file.clone()) {
        Ok(md) => md,
        Err(e) => {
            return Err(anyhow!(e));
        }
    };
    // file size <= 100M
    let size = metadata.len();
    if size >= (500 * 1024 * 1024) {
        return Err(anyhow!("bin file oversize"));
    }
    /*
    let bin = match std::fs::read(bin_file) {
        Ok(b) => b,
        Err(e) => {
            return Err(anyhow!(e));
        }
    };
     */
    let file = File::open(bin_file)?;
    let bin = unsafe { MmapOptions::new().map(&file)? };
    let elf = Elf::parse(&bin).unwrap();
    let shstrtab = elf.shdr_strtab;
    for section in elf.section_headers.iter() {
        let offset = section.sh_name;
        if let Some(name) = shstrtab.get(offset) {
            if name.unwrap() == ".gopclntab" {
                // drop(bin);
                return Ok(true);
            }
        }
    }
    // drop(bin);
    return Ok(false);
}
