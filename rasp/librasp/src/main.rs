use librasp::comm::{Control, RASPServerManager};
use librasp::manager::RASPManager;

use clap::{App, Arg};
use env_logger;
use log::*;

use std::process;
use std::thread::sleep;
use std::time::Duration;

fn parse_arg() -> i32 {
    let matches = App::new("Elkeid rasp")
        .version("0.2")
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

fn main() {
    env_logger::init();
    let process_id = parse_arg();
    let mut rasp_manager = match RASPManager::init() {
        Ok(r) => r,
        Err(e) => {
            error!("rasp manager init failed: {}", e);
            return;
        }
    };
    let mut process_info = match rasp_manager.inspect(process_id.clone()) {
        Ok(pi) => pi,
        Err(e) => {
            error!("rasp inpsect failed: pid: {}, {}", process_id, e);
            return;
        }
    };
    match rasp_manager.runtime_inspect(&mut process_info) {
        Ok(_) => {}
        Err(e) => {
            error!("inspect runtime failed: {}", e);
            return
        }
    };
    let runtime = match process_info.runtime_info.clone() {
        Some(rt) => rt,
        None => {
            error!("can not inspect process runtime");
            return;
        }
    };
    debug!(
        "try to inspect process: {} {}",
        process_info.cmdline().unwrap(),
        runtime.clone()
    );
    debug!("start comm server");
    let ctrl = Control::new();
    let (result_sender, result_receiver, _command_sender, command_receiver) =
        RASPServerManager::new_comm();
    match rasp_manager
        .start_comm(
            &process_info.clone(),
            (result_sender, command_receiver),
            String::from("DEBUG"),
            ctrl,
        ){
            Ok(_) => {},
            Err(e) => {
                error!("start comm failed: {}", e);
                return
            }
        };
    debug!("ready to attach");
    match rasp_manager.attach(&mut process_info) {
        Ok(_) => {
            info!("attach process success");
        },
        Err(e) => {
            error!("attach process failed: {}", e);
            return
        }
    };
    loop {
        let msg = match result_receiver.recv() {
            Ok(m) => m,
            Err(e) => {
                error!("recv msg failed: {}", e);
                return
            }
        };
        println!("{:?}", msg);
        sleep(Duration::from_secs(1));
    }
}
