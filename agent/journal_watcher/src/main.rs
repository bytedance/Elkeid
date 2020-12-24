use log::{error, info};
use std::sync::{atomic, Arc};
use std::thread;
use std::time::Duration;

mod watcher;

const SENDER_SLEEP_INTERVAL: Duration = Duration::from_millis(126);
const AGENT_SOCK_PATH:&str = "/etc/hids/plugin.sock";
const PLUGIN_NAME:&str = "journal_watcher";
const PLUGIN_VERSION:&str = "1.0.0.0";

fn main() {
    let (sender, receiver) = plugin_builder::Builder::new(
        AGENT_SOCK_PATH,
        PLUGIN_NAME,
        PLUGIN_VERSION,
    )
    .unwrap()
    .build();

    let exit = Arc::new(atomic::AtomicBool::new(false));
    let sender_exit = exit.clone();
    let receiver_exit = sender_exit.clone();

    let sender_handler = thread::spawn(move || {
        let mut watcher = match watcher::JournalWatcher::new(sender) {
            Ok(w) => w,
            Err(e) => {
                error!("{}", e);
                thread::sleep(SENDER_SLEEP_INTERVAL);
                return;
            }
        };
        loop {
            if sender_exit.load(atomic::Ordering::Relaxed) {
                error!("Sender detect exit");
                return;
            }
            if let Err(e) = watcher.parse() {
                error!("{}", e);
                thread::sleep(SENDER_SLEEP_INTERVAL);
                break;
            }
        }
        sender_exit.store(true, atomic::Ordering::Relaxed);
    });
    let receiver_handler = thread::spawn(move || {
        loop {
            if receiver_exit.load(atomic::Ordering::Relaxed) {
                error!("Sender detect exit");
                return;
            }
            match receiver.receive() {
                Ok(t) => info!("{:?}", t),
                Err(e) => {
                    error!("{}", e);
                    break;
                }
            }
        }
        receiver_exit.store(true, atomic::Ordering::Relaxed);
    });
    if sender_handler.join().is_err() {
        error!("Sender panic");
        exit.store(true, atomic::Ordering::Relaxed);
    }
    if receiver_handler.join().is_err() {
        error!("Receiver panic");
        exit.store(true, atomic::Ordering::Relaxed);
    }
}
