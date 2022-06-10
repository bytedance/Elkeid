pub mod comm;
pub mod ns;
pub mod process_mode;
pub mod proto;
pub mod thread_mode;
pub mod utils;

use crate::utils::Control;
use crossbeam::channel::{Receiver, Sender};

#[derive(Debug, Clone)]
pub struct RASPServerConfig {
    pub sock_path: String,
    pub target_pid: Option<i32>,
    pub max_thread: usize,
}

#[derive(Clone)]
pub struct RASPSock {
    pub server_addr: String,
    pub tx_channel: Sender<String>,
    pub rx_channel: Receiver<(i32, String)>,
    pub ctrl: Control,
}

pub struct RASPPair {
    ctrl: Control,
    probe_message_sender: tokio::sync::mpsc::Sender<String>,
}

pub struct RASPServer {
    pub config: RASPServerConfig,
    pub global_signal: Control,
    pub probe_to_agent_rx: Receiver<String>,
    pub agent_to_probe_tx: Sender<(i32, String)>,
}

pub trait RASPServerRun {
    fn start(&mut self, sock: RASPSock);
}
