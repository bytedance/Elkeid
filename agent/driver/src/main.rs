use config::*;
use log::*;
use plugin_builder::Builder;
use prepare::*;
use std::fs::*;
use std::io::{BufRead, BufReader};
use std::time::Duration;

mod cache;
mod config;
mod parser;
mod prepare;

const SLEEP_INTERVAL: Duration = Duration::from_millis(126);

fn safety_exit() {
    std::thread::sleep(SLEEP_INTERVAL);
    warn!("Safety exit");
    let _ = std::process::Command::new("rmmod")
        .arg("hids_driver")
        .env("PATH", "/sbin:/bin:/usr/bin:/usr/sbin")
        .spawn();
}

fn main() {
    let (sender, receiver) = Builder::new(SOCKET_PATH, "driver", VERSION).unwrap().build();
    if let Some(dmesg) = check_crash() {
        error!("Detect latest kernel panic, dmesg:{}", dmesg);
        std::thread::sleep(SLEEP_INTERVAL);
        return;
    } else {
        info!("Crash check passed");
    }

    if let Err(version) = check_kernel_version() {
        error!("Unsupported kernel version:{}", version);
        std::thread::sleep(SLEEP_INTERVAL);
        return;
    } else {
        info!("Kernel version check passed");
    }
    if let Err(e) = prepare_ko() {
        error!("{}", e);
        std::thread::sleep(SLEEP_INTERVAL);
        return;}

    let handle = std::thread::spawn(move || {
        let mut parser = parser::Parser::new(sender);
        loop {
            let pipe = match File::open(PIPE_PATH) {
                Ok(pipe) => pipe,
                Err(e) => {
                    error!("{}", e);
                    return;
                }
            };
            let pipe = BufReader::new(pipe);
            let lines = pipe.split(b'\x17');
            for line in lines {
                match line {
                    Ok(content) => {
                        let content = match String::from_utf8(content) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("{}", e);
                                continue;
                            }
                        };
                        let fields: Vec<&str> = content.split('\x1e').collect();
                        if parser.parse(fields).is_err() {
                            return;
                        };
                    }
                    Err(e) => {
                        error!("{}", e);
                        break;
                    }
                }
            }
            warn!("Pipe read end");
            std::thread::sleep(Duration::from_secs(10));
        }
    });
    loop {
        match receiver.receive() {
            Ok(t) => println!("{:?}", t),
            Err(e) => {
                error!("{}", e);
                break;
            }
        }
    }
    let _ = handle.join();
    safety_exit();
}
