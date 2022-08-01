pub const RASP_SERVER_ADDR: &'static str = "/var/run/elkeid_rasp.sock";
pub const RASP_SERVER_BIN: &'static str = "lib/rasp_server";
pub const RASP_NS_ENTER_BIN: &'static str = "nsenter";
pub const RASP_JAVA_JATTACH_BIN: &'static str = "lib/java/jattach";
pub const RASP_JAVA_PROBE_BIN: &'static str = "lib/java/SmithAgent.jar";
pub const RASP_PANGOLIN_BIN: &'static str = "lib/pangolin";
pub const RASP_GOLANG_BIN: &'static str = "lib/go_probe";
pub const RASP_NODE_MODULE: &'static str = "lib/node/smith";
pub const RASP_NODE_INJECTOR: &'static str = "lib/node/injector.js";
pub const RASP_PYTHON_ENTRY: &'static str = "lib/python/entry.py";
pub const RASP_PYTHON_LOADER: &'static str = "lib/python_loader";

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
        Some(format!("lib/php_probe.{}.{}.so", major, miner))
    } else {
        None
    }
}
