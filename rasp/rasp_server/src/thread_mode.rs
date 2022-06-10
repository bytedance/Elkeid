// use crate::proto::{Message, ProbeConfig, PROBE_CONFIG, PROBE_CONFIG_FLAG};
use crate::{comm, RASPSock};
use log::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn core_loop(sock: RASPSock, max_thread: usize) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(max_thread)
        // .worker_threads(2)
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
    debug!("ready");
    let tokio_task = runtime.block_on(async { comm::start_bind(sock).await });
    tokio_task.unwrap();
}
