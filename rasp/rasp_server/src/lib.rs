pub mod comm;
pub mod ns;
pub mod process_mode;
pub mod proto;
pub mod thread_mode;
pub mod utils;

use crate::utils::Control;
use crossbeam::channel::{Receiver, Sender};
// use dashmap::DashMap;
// use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RASPServerConfig {
    pub sock_path: String,
    pub target_pid: Option<i32>,
    pub max_thread: usize,
}

#[derive(Clone)]
pub struct RASPSock {
    pub server_addr: String,
    pub tx_channel: Sender<plugins::Record>,
    pub rx_channel: Receiver<(i32, String)>,
    // pub patches: Arc<DashMap<i32, DashMap<String, String>>>,
    pub ctrl: Control,
}

pub struct RASPPair {
    ctrl: Control,
    probe_message_sender: tokio::sync::mpsc::Sender<String>,
}

pub struct RASPServer {
    pub config: RASPServerConfig,
    pub global_signal: Control,
    pub probe_to_agent_rx: Option<Receiver<plugins::Record>>,
    pub agent_to_probe_tx: Option<Sender<(i32, String)>>,
}

pub trait RASPServerRun {
    fn start(&mut self, sock: RASPSock);
}
