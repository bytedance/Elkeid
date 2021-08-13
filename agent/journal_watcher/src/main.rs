use log::{error, info};
use serde_json;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use watcher::{JournalWatcher, Record};

mod watcher;

const SENDER_SLEEP_INTERVAL: Duration = Duration::from_millis(126);
const SOCK_PATH: &str = "../../plugin.sock";
const NAME: &str = "journal_watcher";
const VERSION: &str = "1.6.0.0";

fn main() {
    let (sender, receiver) = plugin_builder::Builder::new(SOCK_PATH, NAME, VERSION)
        .unwrap()
        .build();
    thread::spawn(move || {
        let mut watcher = JournalWatcher::new(sender);
        loop {
            let mut journal = match Command::new("journalctl")
                .args(&["-f", "_COMM=sshd", "-o", "json"])
                .stdout(Stdio::piped())
                .spawn()
            {
                Ok(j) => j,
                Err(e) => {
                    error!("{}", e);
                    return;
                }
            };
            for line in BufReader::new(journal.stdout.take().unwrap()).lines() {
                match line {
                    Ok(line) => {
                        if let Ok(r) = serde_json::from_str::<Record>(line.as_str()) {
                            if let Err(_) = watcher.parse(r) {
                                return;
                            };
                        };
                    }
                    Err(e) => {
                        error!("{}", e);
                        break;
                    }
                }
            }
            journal.kill();
            journal.wait();
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    });
    loop {
        match receiver.receive() {
            Ok(t) => info!("{:?}", t),
            Err(e) => {
                error!("{}", e);
                break;
            }
        }
    }
    std::thread::sleep(SENDER_SLEEP_INTERVAL);
}
