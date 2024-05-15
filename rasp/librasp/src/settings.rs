use std::env::current_dir;
// use anyhow::{Result as AnyhowResult, anyhow};

pub const RASP_VERSION: &'static str = "1.0.0.1";

pub fn RASP_BASE_DIR() -> String {
    match current_dir() {
        Ok(p) => match p.to_str() {
            Some(p) => String::from(p),
            None => {
                panic!("can not fetch current dir from env");
            }
        },
        Err(e) => panic!("can not fetch current dir from env: {}", e),
    }
}

pub fn RASP_NS_ENTER_BIN() -> String {
    format!("{}{}", RASP_BASE_DIR(), "/nsenter")
}
pub fn RASP_MOUNT_SCRIPT_BIN() -> String {
    format!("{}{}", RASP_BASE_DIR(), "/NSMount")
}

pub fn RASP_LIB_DIR() -> String {
    format!("{}{}", RASP_BASE_DIR(), format!("/lib-{}", RASP_VERSION))
}

pub fn RASP_SERVER_BIN() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/rasp_server")
}

pub fn RASP_PANGOLIN() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/pangolin")
}

// Golang

pub fn RASP_GOLANG() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/golang/go_probe")
}
pub fn RASP_GOLANG_EBPF(version: &String) -> String {
    format!("{}/{}{}", RASP_LIB_DIR(), "/golang/go_probe_ebpf", version)
}

// Python
pub fn RASP_PYTHON_LOADER() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/python/python_loader")
}

pub fn RASP_PYTHON_DIR() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/python/rasp")
}

pub fn RASP_PYTHON_ENTRY() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/python/entry.py")
}

// JAVA
pub fn RASP_JAVA_JATTACH_BIN() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/java/jattach")
}

pub fn RASP_JAVA_PROBE_BIN() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/java/SmithProbe.jar")
}

pub fn RASP_JAVA_CHECKSUM_PATH() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/java/checksum.data")
}

pub fn RASP_JAVA_AGENT_BIN() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/java/SmithAgent.jar")
}

pub fn RASP_JAVA_DIR() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/java")
}
// NodeJS

pub fn RASP_NODEJS_DIR() -> String {
    format!("{}{}", RASP_LIB_DIR(), "/node")
}

pub fn RASP_NODEJS_INJECTOR() -> String {
    format!("{}{}", RASP_NODEJS_DIR(), "/injector.js")
}

pub fn RASP_NODEJS_ENTRY() -> String {
    format!("{}{}", RASP_NODEJS_DIR(), "/smith")
}

#[allow(non_snake_case)]
pub fn RASP_PHP_PROBE(major: &str, miner: &str, zts: bool) -> Option<(String, String)> {
    if match major {
        "5" => match miner {
            "3" => true,
            "4" => true,
            "5" => true,
            "6" => true,
            _ => false,
        },
        "7" => match miner {
            "0" => true,
            "2" => true,
            "3" => true,
            "4" => true,
            _ => false,
        },
        "8" => match miner {
            "0" => true,
            "1" => true,
            _ => false,
        },
        _ => false,
    } {
        if zts {
            Some((
                format!(
                    "{}/php/libphp_probe-{}.{}-zts.so",
                    RASP_LIB_DIR(),
                    major,
                    miner
                ),
                format!("libphp_probe-{}.{}-zts.so", major, miner),
            ))
        } else {
            Some((
                format!("{}/php/libphp_probe-{}.{}.so", RASP_LIB_DIR(), major, miner),
                format!("libphp_probe-{}.{}.so", major, miner),
            ))
        }
    } else {
        None
    }
}
