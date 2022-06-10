use std::process;
use std::thread::sleep;
use std::time::Duration;

use clap::{App, Arg};
use crossbeam::channel::unbounded;
use env_logger;
use librasp::comm::Control;
use librasp::manager::RASPManager;
use librasp::process::ProcessInfo;
use log::*;

fn parse_arg() -> i32 {
    let matches = App::new("Elkeid rasp")
        .version("1.0")
        .about("Elkeid Runtime Application Self Protection Controller.")
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("config")
                .value_name("PID")
                .help("inspect process with process id PID"),
        )
        .get_matches();
    let pid = match matches.value_of("pid") {
        Some(p) => p,
        None => {
            println!("{}", matches.usage());
            process::exit(1);
        }
    };
    if pid == "" {
        println!("pid needed");
        process::exit(1);
    }
    let pid_i32 = pid.parse::<i32>().unwrap_or(-1);
    if pid_i32 == -1 {
        println!("pid must be a valid number");
        process::exit(1);
    }
    pid_i32
}


fn main() -> anyhow::Result<()> {
    env_logger::init();
    // grab process info
    let process_id = parse_arg();
    let mut rasp_manager = RASPManager::init()?;
    let mut process_info = ProcessInfo::from_pid(process_id)?;
    match rasp_manager.inspect(&mut process_info) {
        Ok(pi) => pi,
        Err(e) => {
            error!("rasp inspect failed: pid: {}, {}", process_id, e);
        }
    };
    match rasp_manager.runtime_inspect(&mut process_info) {
        Ok(_) => {}
        Err(e) => {
            error!("inspect runtime failed: {}", e);
            return Err(anyhow::anyhow!(""))
        }
    };
    let runtime = match process_info.runtime.clone() {
        Some(rt) => rt,
        None => {
            error!("can not inspect process runtime");
            return Err(anyhow::anyhow!(""));
        }
    };
    debug!(
        "try to inspect process: {} {}",
        process_info.cmdline.clone().unwrap(),
        runtime.clone()
    );
    debug!("start comm server");
    let ctrl = Control::new();
    let (result_sender, result_receiver) = unbounded();
    match rasp_manager
        .start_comm(
            &process_info.clone(),
            result_sender,
            String::from("DEBUG"),
            ctrl,
        ){
            Ok(_) => {},
            Err(e) => {
                error!("start comm failed: {}", e);
                return Err(anyhow::anyhow!(""));
            }
        };
    debug!("ready to attach");
    match rasp_manager.attach(&mut process_info) {
        Ok(_) => {
            info!("attach process success");
        },
        Err(e) => {
            error!("attach process failed: {}", e);
            return Err(anyhow::anyhow!(""))
        }
    };
    loop {
        let msg = match result_receiver.recv() {
            Ok(m) => m,
            Err(e) => {
                error!("recv msg failed: {}", e);
                return Err(anyhow::anyhow!(""))
            }
        };
        println!("{:?}", msg);
        sleep(Duration::from_millis(100));
    }
}
