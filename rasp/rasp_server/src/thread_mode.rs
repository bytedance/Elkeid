// use crate::proto::{Message, ProbeConfig, PROBE_CONFIG, PROBE_CONFIG_FLAG};
use crate::{comm, Control, RASPSock};
use crossbeam::channel::{Receiver, Sender};
use log::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::Builder;

pub fn core_loop(sock: RASPSock, max_thread: usize) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(max_thread)
        .worker_threads(max_thread)
        .enable_all()
        .on_thread_stop(|| {
            log::debug!("tokio thread stopping");
        })
        .on_thread_start(|| {
            log::debug!("tokio thread starting");
        })
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("rasp_server-{}", id)
        })
        .build()
        .unwrap();
    debug!("rasp server config ready");
    let tokio_task = runtime.block_on(async { comm::start_bind(sock).await });
    tokio_task.unwrap();
}

pub fn start(
    path: String,
    max_thread: usize,
    ctrl: Control,
    probe_to_agent_sender: Sender<plugins::Record>,
    agent_to_probe_receiver: Receiver<(i32, String)>,
) {
    let sock = RASPSock {
        server_addr: path,
        tx_channel: probe_to_agent_sender,
        rx_channel: agent_to_probe_receiver,
        ctrl: ctrl.clone(),
    };
    Builder::new()
        .name("bind".to_string())
        .spawn(move || core_loop(sock, max_thread))
        .unwrap();
}
