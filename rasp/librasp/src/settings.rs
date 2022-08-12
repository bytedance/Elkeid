use std::env::current_dir;
// use anyhow::{Result as AnyhowResult, anyhow};

pub const RASP_VERSION: &'static str = "1.0.0.1";
// pub const RASP_SERVER_ADDR: &'static str = "/var/run/smith_agent.sock";

pub fn RASP_BASE_DIR() -> String {
    match current_dir() {
        Ok(p) => match p.to_str() {
            Some(p) => String::from(p),
            None =>  {
                panic!("can not fetch current dir from env");
            }
        }
        Err(e) => panic!("can not fetch current dir from env: {}", e),
    }
}

pub fn RASP_NS_ENTER_BIN() -> String {
    format!("{}{}", RASP_BASE_DIR(), "/nsenter")
}

pub fn RASP_LIB_DIR() -> String {
    format!("{}{}", RASP_BASE_DIR(), format!("/lib-{}", RASP_VERSION))
}

pub fn RASP_SERVER_BIN() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/rasp_server")
}

pub fn RASP_PANGOLIN() -> String { format!("{}{}", RASP_LIB_DIR(), "/pangolin") }

// Golang
pub fn RASP_GOLANG_BOE() -> String { format!("{}{}", RASP_LIB_DIR(), "/go_probe_boe") }

pub fn RASP_GOLANG() -> String { format!("{}{}", RASP_LIB_DIR(), "/go_probe") }

// Python
pub fn RASP_PYTHON_LOADER() -> String { format!("{}{}", RASP_LIB_DIR(), "/python_loader") }

pub fn RASP_PYTHON_DIR_BOE() -> String { format!("{}{}", RASP_LIB_DIR(), "/python-boe") }

pub fn RASP_PYTHON_DIR() -> String { format!("{}{}", RASP_LIB_DIR(), "/python") }

pub fn RASP_PYTHON_ENTRY_BOE() -> String { format!("{}{}", RASP_LIB_DIR(), "/python-boe/entry.py") }

pub fn RASP_PYTHON_ENTRY() -> String { format!("{}{}", RASP_LIB_DIR(), "/python/entry.py") }

// JAVA
pub fn RASP_JAVA_JATTACH_BIN() -> String { format!("{}{}", RASP_BASE_DIR(), "/jattach") }

pub fn RASP_JAVA_PROBE_BIN() -> String { format!("{}{}", RASP_LIB_DIR(), "/SmithAgent.jar") }

// NodeJS
pub fn RASP_NODEJS_DIR_BOE() -> String { format!("{}{}", RASP_LIB_DIR(), "/node-boe") }

pub fn RASP_NODEJS_DIR() -> String { format!("{}{}", RASP_LIB_DIR(), "/node") }

pub fn RASP_NODEJS_INJECTOR_BOE() -> String { format!("{}{}", RASP_NODEJS_DIR_BOE(), "/injector.js") }

pub fn RASP_NODEJS_INJECTOR() -> String { format!("{}{}", RASP_NODEJS_DIR(), "/injector.js") }

pub fn RASP_NODEJS_ENTRY_BOE() -> String { format!("{}{}", RASP_NODEJS_DIR_BOE(), "/smith") }

pub fn RASP_NODEJS_ENTRY() -> String { format!("{}{}", RASP_NODEJS_DIR_BOE(), "/smith") }

#[allow(non_snake_case)]
pub fn RASP_PHP_PROBE(major: &str, miner: &str) -> Option<String> {
    if match major {
        "5" => match miner {
            "3" => true,
            "4" => true,
            "5" => true,
            "6" => true,
            _ => false
        },
        "7" => match miner {
            "0" => true,
            "2" => true,
            "3" => true,
            "4" => true,
            _ => false
        },
        "8" => match miner {
            "0" => true,
            "1" => true,
            _ => false
        },
        _ => false
    } {
        Some(format!("{}/lib/libphp_probe-{}.{}.so", RASP_LIB_DIR(), major, miner))
    } else {
        None
    }
}
