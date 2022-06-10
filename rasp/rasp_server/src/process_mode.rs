use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, ChildStdout, Stdio};
use std::sync::Arc;
use std::time::Duration;
use std::{process, thread};
use thread::{sleep, Builder};

use anyhow::anyhow;
use anyhow::Result as AnyhowResult;
use crossbeam::channel::{Receiver, Sender, TryRecvError};
use libc::{kill, killpg, SIGKILL};
use log::*;

use crate::proto::{Message, ProbeConfig};
use crate::thread_mode::core_loop;
use crate::RASPSock;
use crate::{Control, RASPServer, RASPServerRun};

impl RASPServerRun for RASPServer {
    fn start(&mut self, sock: RASPSock) {
        // stdout thread
        let rx = self.probe_to_agent_rx.clone();
        let mut rx_ctrl = self.global_signal.clone();
        let _rx_thread = Builder::new().name("global_rx".to_string()).spawn(move || {
            debug!("global_rx thread started, received message will print to stdout");
            loop {
                if !rx_ctrl.check() {
                    info!("global_rx thread receive quit signal, quiting.");
                    break;
                }
                match rx.try_recv() {
                    Ok(m) => {
                        println!("probe_report: {}", m);
                    }
                    Err(TryRecvError::Disconnected) => {
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        sleep(Duration::from_secs(1));
                        continue;
                    }
                }
            }
        });
        // stdin thread
        let tx = self.agent_to_probe_tx.clone();
        let _tx_thread = Builder::new().name("global_tx".to_string()).spawn(move || {
            debug!("global_tx thread started, listening message from stdin");
            listen_stdin(tx.clone());
            std::process::exit(1);
        });
        // core sock loop
        debug!("starting core loop");
        core_loop(sock, self.config.max_thread.clone());
    }
}
pub fn listen_stdin(sender: Sender<(i32, String)>) {
    let stdin = std::io::stdin();
    let handle = stdin.lock();
    for line in handle.lines() {
        match line {
            Ok(l) => {
                debug!("receive stdin: {}", l.clone());
                println!("receive stdin: {}", l.clone());
                let value: ProbeConfig = match serde_json::from_str(l.as_str()) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("parse stdin json failed: {}", e.to_string());
                        continue;
                    }
                };
                // println!("receiver ProbeConfig: {:?}", value);
                let pid = value.pid;
                let _ = sender.send((pid, l));
            }
            Err(e) => {
                error!("receive stdin failed: {}", e.to_string());
                return;
            }
        }
    }
}

pub fn spawn(
    rasp_server_bin_path: &str,
    pid: i32,
    log_level: String,
) -> AnyhowResult<process::Child> {
    let pid_string = pid.clone().to_string();
    let args = &["--pid", pid_string.as_str()];
    debug!("spawning rasp server: {} {:?}", rasp_server_bin_path, args);
    let child = match std::process::Command::new(rasp_server_bin_path)
        .env("RUST_LOG", log_level)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!(
                "spawn rasp server failed: {} {:?} {}",
                rasp_server_bin_path, args, e
            );
            error!("{}", msg);
            return Err(anyhow!("{}", msg));
        }
    };
    debug!("spawn success: {}", child.id());
    Ok(child)
}

pub struct RASPServerProcess {
    child_id: u32,
    patch_field: Arc<parking_lot::RwLock<HashMap<String, HashMap<&'static str, String>>>>, // child_ctrl: Control,
}

impl RASPServerProcess {
    pub fn new(
        pid: i32,
        message_sender: Sender<HashMap<&'static str, String>>,
        message_receiver: Receiver<String>,
        log_level: String,
        patch_field: HashMap<&'static str, String>,
        ctrl: Control,
    ) -> AnyhowResult<Self> {
        pub const RASP_SERVER_BIN: &'static str =
            "/etc/sysop/mongoosev3-agent/plugin/rasp/lib/rasp_server";

        let mut child = match spawn(RASP_SERVER_BIN, pid, log_level) {
            Ok(child) => child,
            Err(e) => {
                let msg = format!("spawn command failed: {}", e);
                error!("spawn rasp server failed: {}", msg);
                return Err(anyhow!("{}", msg));
            }
        };
        let child_id = child.id();
        let stdin = match child.stdin.take() {
            None => {
                let msg = format!("can not take child stdin, pid: {}", child_id);
                error!("{}", msg);
                return Err(anyhow!(msg));
            }
            Some(stdin) => stdin,
        };
        let stdout = match child.stdout.take() {
            None => {
                let msg = format!("can not take child stdin, pid: {}", child_id);
                error!("{}", msg);
                return Err(anyhow!(msg));
            }
            Some(stdout) => stdout,
        };
        let child_ctrl = Control::new();
        let mut wait_child_ctrl = child_ctrl.clone();
        // wait child in new thread
        thread::Builder::new()
            .name(format!("comm_wait_{}", child.id()))
            .spawn(move || loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        warn!("comm wait exited with: {}", status);
                        let _ = wait_child_ctrl.stop();
                        break;
                    }
                    Ok(None) => {
                        sleep(Duration::from_secs(3));
                    }
                    Err(e) => {
                        warn!("error attempting to wait: {}", e);
                        let _ = wait_child_ctrl.stop();
                        break;
                    }
                }
                sleep(Duration::from_secs(3));
            })
            .unwrap();
        let patch_rw = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let patch_r = patch_rw.clone();
        let mut server_process = Self {
            child_id,
            patch_field: patch_rw,
        };
        server_process.update_patch_field(patch_field);
        let _ = process_comm(
            child_id,
            message_sender.clone(),
            message_receiver.clone(),
            ctrl.clone(),
            child_ctrl.clone(),
            stdin,
            stdout,
            patch_r,
        );
        Ok(server_process)
    }
    pub fn update_patch_field(&mut self, patch_field: HashMap<&'static str, String>) {
        let nspid = if let Some(nspid) = patch_field.get("nspid") {
            nspid.clone()
        } else {
            return;
        };
        let mut patch = self.patch_field.write();
        debug!("update patch start: {:?}", *patch);
        (*patch).insert(nspid, patch_field);
        debug!("update patch done: {:?}", *patch);
        drop(patch)
    }
    pub fn kill(&mut self) {
        unsafe {
            killpg(self.child_id as i32, SIGKILL);
            kill(self.child_id as i32, SIGKILL);
        }
    }
}

pub fn process_comm(
    child_id: u32,
    sender: Sender<HashMap<&'static str, String>>,
    receiver: Receiver<String>,
    ctrl: Control,
    child_ctrl: Control,
    mut stdin: ChildStdin,
    stdout: ChildStdout,
    patch_field: Arc<parking_lot::RwLock<HashMap<String, HashMap<&'static str, String>>>>,
) {
    let receiver = receiver.clone();
    let sender = sender.clone();
    let mut recv_ctrl = ctrl.clone();
    let mut send_ctrl = ctrl.clone();
    let mut recv_child_ctrl = child_ctrl.clone();
    let mut send_child_ctrl = child_ctrl.clone();
    match thread::Builder::new()
        .name(format!("comm_recv_{}", child_id))
        .spawn(move || loop {
            // check global ctrl
            if !recv_ctrl.check() {
                debug!("comm recv thread: {} receive ctrl sig, quiting", child_id);
                break;
            }
            // check child ctrl
            if !recv_child_ctrl.check() {
                debug!(
                    "comm recv thread: {} receive child ctrl sig, quiting",
                    child_id
                );
                break;
            }
            match receiver.try_recv() {
                Ok(line) => {
                    debug!("comm recv thread: {} receive command: {}", child_id, line);
                    match stdin.write_all(format!("{}\n", line).as_bytes()) {
                        Ok(_) => {}
                        Err(e) => {
                            let msg = format!(
                                "comm recv thread: {}, can not write stdin: {}",
                                child_id,
                                e.to_string()
                            );
                            error!("{}", msg);
                            break;
                        }
                    }
                    match stdin.flush() {
                        Ok(_) => {}
                        Err(e) => {
                            let msg = format!(
                                "comm recv thread: {}, flush stdin failed: {}",
                                child_id,
                                e.to_string()
                            );
                            error!("{}", msg);
                            break;
                        }
                    }
                }
                Err(TryRecvError::Empty) => {
                    sleep(Duration::from_secs(20));
                    continue;
                }
                Err(TryRecvError::Disconnected) => {
                    warn!("comm recv thread: {} TryRecv error: disconnect", child_id);
                    break;
                }
            }
            sleep(Duration::from_secs(20))
        }) {
        Ok(_) => {}
        Err(e) => {
            error!("create new thread failed: {}", e);
            return;
        }
    }
    let mut stdout_buf_reader = BufReader::new(stdout);
    match thread::Builder::new()
        .name(format!("comm_send_{}", child_id))
        .spawn(move || loop {
            if !send_ctrl.check() {
                debug!("comm send thread: {} receive ctrl sig, quiting", child_id);
                break;
            }
            if !send_child_ctrl.check() {
                debug!("comm send thread: {} receive ctrl sig, quiting", child_id);
                break;
            }
            let mut buf = String::new();
            match stdout_buf_reader.read_line(&mut buf) {
                Ok(size) => {
                    if size == 0 {
                        warn!("stream EOF");
                        break;
                    }
                    // debug!("recv buf: {}", buf);
                    // parse message from probe
                    let mut message_from_probe = if let Some(msg) = parse_server_stdout(&buf) {
                        msg
                    } else {
                        continue;
                    };
                    // patch
                    let nspid = if let Some(nspid) = message_from_probe.get("pid") {
                        nspid.clone()
                    } else {
                        String::new()
                    };
                    let patch_r = patch_field.read();
                    debug!("patching nspid: {}", nspid);
                    if let Some(patch) = patch_r.get(&nspid) {
                        debug!("patching nspid patch: {:?}", patch);
                        for (k, v) in patch.iter() {
                            message_from_probe.insert(k, v.clone());
                        }
                    };
                    drop(patch_r);
                    // send to agent though queue
                    match sender.send(message_from_probe) {
                        Ok(_) => {}
                        Err(e) => {
                            let msg = format!("send failed: {}", e.to_string());
                            error!("comm send thread: {} send queue failed: {}", child_id, msg);
                            break;
                        }
                    }
                    continue;
                }
                Err(e) => {
                    let msg = format!("comm send thread: {} read line failed: {}", child_id, e);
                    error!("{}", msg);
                    break;
                }
            }
        }) {
        Ok(_) => {}
        Err(e) => {
            error!("create new thread failed: {}", e);
            return;
        }
    }
}

pub fn parse_server_stdout(buf: &String) -> Option<HashMap<&'static str, String>> {
    // strip fist `:`
    let splited: Vec<&str> = buf.splitn(2, ":").collect();
    if splited.len() != 2 {
        return None;
    }
    return match splited[0] {
        "probe_report" | "heart_beat" | "jar" => {
            let message: Message = match serde_json::from_str(splited[1]) {
                Ok(m) => m,
                Err(e) => {
                    error!("can not deserialize message: {} {}", buf, e.to_string());
                    return None;
                }
            };
            let message_hash_map = message.to_hashmap();
            Some(message_hash_map)
        }
        _ => None,
    };
}
