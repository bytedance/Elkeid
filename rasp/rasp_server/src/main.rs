use anyhow::Result as AnyHowResult;
use crossbeam::channel::bounded;
use libraspserver::utils::Control;
use libraspserver::{RASPServer, RASPServerConfig, RASPServerRun, RASPSock};
use std::path::Path;

use clap;
use log::*;

fn args() -> AnyHowResult<RASPServerConfig> {
    let matches = clap::command!()
        .arg(
            clap::arg!(--pid <pid> "target pid")
                .validator(|s| s.parse::<i32>())
                .required(false),
        )
        .arg(
            clap::arg!(--max_thread <max_thread> "max thead spawn")
                .default_value("6")
                .validator(|s| s.parse::<usize>())
                .required(false),
        )
        .arg(
            clap::arg!(--path <PATH> "path for socket listen")
                .default_value("/var/run/smith_agent.sock")
                .required(false)
                .validator(|s| s.parse::<String>()),
        )
        .get_matches();
    let pid = match matches.value_of_t("pid") {
        Ok(p) => Some(p),
        Err(_) => None,
    };
    debug!("[arg] will switch namespace to target: {:?}", pid);
    let path: String = matches.value_of_t("path")?;
    debug!("[arg] will bind sock on: {:?}", path);
    let checking = Path::new(&path);
    // check path
    if checking.is_dir() {
        return Err(anyhow::anyhow!("<PATH> need to be file not dir"));
    }
    if checking.is_relative() {
        return Err(anyhow::anyhow!("<PATH> need to be absolute"));
    }
    let max_thread = matches.value_of_t("max_thread")?;
    debug!("[arg] max thread will be used: {}", max_thread);
    Ok(RASPServerConfig {
        target_pid: pid,
        sock_path: path,
        max_thread,
    })
}
fn main() -> AnyHowResult<()> {
    env_logger::init();
    let server_config = args().unwrap();
    debug!("starting rasp server with config: {:?}", server_config);
    // switch namespace
    if let Some(pid) = server_config.target_pid {
        libraspserver::ns::switch_namespace(pid).unwrap();
    }
    let server_config = args()?;

    // dual comm from rasp-plugin <-> probe
    let (probe_to_agent_sender, probe_to_agent_receiver) = bounded(100);
    let (agent_to_probe_sender, agent_to_probe_receiver) = bounded(100);
    let global_ctrl = Control::new();
    let mut rasp_server = RASPServer {
        config: server_config.clone(),
        global_signal: global_ctrl.clone(),
        probe_to_agent_rx: probe_to_agent_receiver,
        agent_to_probe_tx: agent_to_probe_sender,
    };
    let sock = RASPSock {
        server_addr: server_config.sock_path,
        tx_channel: probe_to_agent_sender,
        rx_channel: agent_to_probe_receiver,
        ctrl: global_ctrl.clone(),
    };
    rasp_server.start(sock);
    Ok(())
}
