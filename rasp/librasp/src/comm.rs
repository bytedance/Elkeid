use super::process::ProcessInfo;
use super::settings;
use libraspserver::proto::Message;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::{collections::HashMap, thread::sleep, time::Duration};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    process::{ChildStdin, ChildStdout},
};

use crossbeam::channel::{bounded, Receiver, Sender, TryRecvError};
use libc::{kill, killpg, SIGKILL};
use serde_json;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread;

// use procfs::process::Process;

use log::*;

pub struct RASPServerManager {
    pub mnt_namespace_server_map: HashMap<String, RASPServerRunner>,
    pub mnt_namespace_comm_send_config_map: HashMap<String, Sender<String>>,
}

pub struct RASPServerRunner {
    child_id: u32,
    child_ctrl: Control,
}

#[allow(unused_must_use)]
#[allow(dead_code)]
fn no_ns_enter_spawn(log_level: String) -> Result<Child, String> {
    info!("spawn new rasp server");
    let cwd_path = std::env::current_dir().unwrap();
    let cwd = cwd_path.to_str().unwrap();
    let rasp_server = format!("{}/{}", cwd, settings::RASP_SERVER_BIN.to_string());
    let log_level = format!("RUST_LOG={}", log_level);
    let args = &[log_level.as_str(), rasp_server.as_str()];
    debug!("env {:?}", args.clone());
    let child = match Command::new("env")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("can tnot spawn command: {}", e.to_string());
            return Err(msg);
        }
    };
    info!("started process: {}", child.id());
    Ok(child)
}
fn ns_enter_spawn(pid: i32, log_level: String) -> Result<Child, String> {
    info!("spawn new rasp server");
    let cwd_path = std::env::current_dir().unwrap();
    let cwd = cwd_path.to_str().unwrap();
    let rasp_server = format!("{}/{}", cwd, settings::RASP_SERVER_BIN.to_string());
    let nsenter = format!("{}/{}", cwd, settings::RASP_NS_ENTER_BIN.to_string());
    let pid_string = pid.clone().to_string();
    let log_level = format!("RUST_LOG={}", log_level);
    let args = &[
        "-m",
        "-n",
        "-p",
        "-t",
        pid_string.as_str(),
        "env",
        log_level.as_str(),
        rasp_server.as_str(),
    ];
    debug!("{} {:?}", nsenter, args.clone());
    let child = match Command::new(nsenter)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("can tnot spawn command: {}", e.to_string());
            return Err(msg);
        }
    };
    info!("started process: {}", child.id());
    Ok(child)
}

// https://stackoverflow.com/questions/35883390/how-to-check-if-a-thread-has-finished-in-rust
// https://stackoverflow.com/a/39615208
#[derive(Clone)]
pub struct Control {
    pub working_atomic: Arc<AtomicBool>,
    pub control: Weak<AtomicBool>,
}

impl Control {
    pub fn new() -> Self {
        let working = Arc::new(AtomicBool::new(true));
        let control = Arc::downgrade(&working);
        Control {
            working_atomic: working,
            control,
        }
    }
    pub fn check(&mut self) -> bool {
        (*self.working_atomic).load(Ordering::Relaxed)
    }
    pub fn stop(&mut self) -> Result<(), ()> {
        return match self.control.upgrade() {
            Some(working) => {
                (*working).store(false, Ordering::Relaxed);
                Ok(())
            }
            None => {
                // world stopped
                Err(())
            }
        };
    }
}

impl RASPServerRunner {
    pub fn new(
        process_info: ProcessInfo,
        message_sender: Sender<HashMap<&'static str, String>>,
        message_receiver: Receiver<String>,
        log_level: String,
        ctrl: Control,
    ) -> Result<Self, String> {
        debug!("new RASP Server Runner");
        let mut child = match ns_enter_spawn(process_info.pid, log_level) {
            Err(e) => {
                let msg = format!("spawn command failed: {}", e);
                error!("spawn rasp server failed: {}", msg);
                return Err(msg);
            }
            Ok(child) => child,
        };
        let child_id = child.id();
        let stdin = match child.stdin.take() {
            None => {
                let msg = format!("can not take child stdin, pid: {}", child_id);
                error!("{}", msg);
                return Err(msg);
            }
            Some(stdin) => stdin,
        };
        let stdout = match child.stdout.take() {
            None => {
                let msg = format!("can not take child stdin, pid: {}", child_id);
                error!("{}", msg);
                return Err(msg);
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
        let _ = process_comm(
            child_id,
            message_sender.clone(),
            message_receiver.clone(),
            ctrl.clone(),
            child_ctrl.clone(),
            stdin,
            stdout,
        );
        let rasp_server_runner = RASPServerRunner {
            child_id,
            child_ctrl,
        };
        Ok(rasp_server_runner)
    }
    pub fn kill(&mut self) {
        // let id = self.child.id();
        // let _ = self.child.kill();
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
) -> Result<String, String> {
    debug!("try comm with child process, child pid: {}", child_id);
    // let mut stdin = &mut self.stdin;
    // let stdout = &self.stdout;
    let receiver = receiver.clone();
    let sender = sender.clone();
    let mut recv_ctrl = ctrl.clone();
    let mut send_ctrl = ctrl.clone();
    let mut recv_child_ctrl = child_ctrl.clone();
    let mut send_child_ctrl = child_ctrl.clone();
    thread::Builder::new()
        .name(format!("comm_recv_{}", child_id))
        .spawn(move || loop {
            if !recv_ctrl.check() {
                debug!("comm recv thread recive ctrl sig, quiting");
                break;
            }
            if !recv_child_ctrl.check() {
                debug!("comm recv thread recive child ctrl sig, quiting");
                break;
            }
            match receiver.try_recv() {
                Ok(line) => {
                    debug!("recv stdin: {}", line);
                    match stdin.write_all(line.as_bytes()) {
                        Ok(_) => {}
                        Err(e) => {
                            let msg = format!("can not write stdin: {}", e.to_string());
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
                    warn!("recv receive chan failed: recv channel disconnect");
                    break;
                }
            }
            sleep(Duration::from_secs(20))
        })
        .unwrap();
    let mut f = BufReader::new(stdout);
    thread::Builder::new()
        .name(format!("comm_send_{}", child_id))
        .spawn(move || {
            // let mut f = BufReader::new(stdout);
            loop {
                if !send_ctrl.check() {
                    break;
                }
                if !send_ctrl.check() {
                    debug!("comm recv thread recive ctrl sig, quiting");
                    break;
                }
                if !send_child_ctrl.check() {
                    debug!("comm recv thread recive child ctrl sig, quiting");
                    break;
                }
                let mut buf = String::new();
                match f.read_line(&mut buf) {
                    Ok(size) => {
                        if size == 0 {
                            warn!("sender steam EOF");
                            break;
                        }
                        let new_map: HashMap<&str, String> =
                            if let Some(new_map) = parse_server_stdout_buffer(&buf) {
                                new_map
                            } else {
                                continue;
                            };
                        match sender.send(new_map) {
                            Err(e) => {
                                let msg = format!("send failed: {}", e.to_string());
                                error!("{}", msg);
                                break;
                            }
                            Ok(_) => {}
                        };
                        continue;
                    }
                    Err(e) => {
                        let msg = format!("read line failed: {}", e);
                        error!("{}", msg);
                        break;
                    }
                }
            }
        })
        .unwrap();
    Ok(String::from("started"))
}

fn gen_probe_action(action_no: i32) -> String {
    format!("{{\"action\": {}}}\n", action_no)
}

fn gen_probe_config(config: String) -> String {
    format!("{{\"config\": {}}}\n", config)
}

pub enum ServerStatus {
    WORKING,
    // not exitst
    NULL,
    // exited
    DEAD,
    // alived, but can not `wait` on child process
    MISSING,
}

impl Display for ServerStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ServerStatus::WORKING => write!(f, "WORKING"),
            ServerStatus::NULL => write!(f, "NULL"),
            ServerStatus::DEAD => write!(f, "DEAD"),
            ServerStatus::MISSING => write!(f, "MISSING"),
        }
    }
}

impl RASPServerManager {
    pub fn new() -> Result<Self, String> {
        let new_manager = Self {
            mnt_namespace_server_map: HashMap::new(),
            mnt_namespace_comm_send_config_map: HashMap::<String, Sender<String>>::new(),
        };
        Ok(new_manager)
    }
    pub fn server_status(&mut self, mnt_ns: &String) -> ServerStatus {
        if let Some(server_runner) = self.mnt_namespace_server_map.get_mut(mnt_ns) {
            let status = server_runner.child_ctrl.check();
            if status {
                return ServerStatus::WORKING;
            } else {
                return ServerStatus::MISSING;
            }
        } else {
            return ServerStatus::NULL;
        }
    }
    pub fn stop_probe(&mut self, mnt_ns: &String) -> Result<(), String> {
        self.send_probe_action(mnt_ns, 0)
    }
    pub fn restart_probe(&mut self, mnt_ns: &String) -> Result<(), String> {
        self.send_probe_action(mnt_ns, 1)
    }
    pub fn send_probe_action(&mut self, mnt_ns: &String, action: i32) -> Result<(), String> {
        let server_status = self.server_status(mnt_ns);
        match server_status {
            ServerStatus::WORKING => {}
            _ => {
                return Err(format!("server not running, status: {}", server_status));
            }
        };

        let action_message = gen_probe_action(action);
        self.send_to_probe(mnt_ns, action_message)
    }
    pub fn send_to_probe(&self, mnt_namespace: &String, message: String) -> Result<(), String> {
        if let Some(send_channel) = self.mnt_namespace_comm_send_config_map.get(mnt_namespace) {
            if let Err(e) = send_channel.send(message) {
                return Err(format!("send probe config failed: {}", e.to_string()));
            }
        }
        Ok(())
    }
    pub fn send_probe_config(&mut self, mnt_ns: &String, config: String) -> Result<(), String> {
        let server_status = self.server_status(mnt_ns);
        match server_status {
            ServerStatus::WORKING => {}
            _ => {
                return Err(format!("server not running, status: {}", server_status));
            }
        }
        let config_message = gen_probe_config(config.clone());
        self.send_to_probe(mnt_ns, config_message)
    }
    pub fn send_jar_coll_sig(&self, _mnt_ns: &String) {}
    pub fn new_comm() -> (
        Sender<HashMap<&'static str, String>>,
        Receiver<HashMap<&'static str, String>>,
        Sender<String>,
        Receiver<String>,
    ) {
        let (result_sender, result_receiver) = bounded(1000);
        let (command_sender, command_receiver) = bounded(1000);
        (
            result_sender,
            result_receiver,
            command_sender,
            command_receiver,
        )
    }
    pub fn start_new_rasp_server(
        &mut self,
        process_info: &ProcessInfo,
        sender: Sender<HashMap<&'static str, String>>,
        receiver: Receiver<String>,
        log_level: String,
        ctrl: Control,
    ) -> Result<(), String> {
        let mnt_namespace = if let Some(ref ns) = process_info.namespace_info {
            match ns.mnt.clone() {
                Some(mnt_ns) => mnt_ns,
                None => {
                    return Err(format!("process mnt ns empty: {}", process_info.pid));
                }
            }
        } else {
            return Err(format!("fetch process ns failed: {}", process_info.pid));
        };
        let runner =
            match RASPServerRunner::new(process_info.clone(), sender, receiver, log_level, ctrl) {
                Err(e) => {
                    return Err(e);
                }
                Ok(runner) => runner,
            };
        self.mnt_namespace_server_map
            .insert(mnt_namespace.clone(), runner);
        Ok(())
    }
    pub fn stop_rasp_server(&mut self, mnt_ns: &String) -> Result<(), String> {
        info!("stop server: {}", mnt_ns.clone());
        if let Some(runner) = self.mnt_namespace_server_map.get_mut(mnt_ns) {
            runner.kill();
            return Ok(());
        } else {
            return Err(format!("didn't start server for pid: {}", mnt_ns.clone()));
        }
    }
}

pub fn parse_server_stdout_buffer(buf: &String) -> Option<HashMap<&'static str, String>> {
    // strip fist `:`
    let splited: Vec<&str> = buf.splitn(2, ":").collect();
    if splited.len() != 2 {
        return None;
    }
    match splited[0] {
        "probe_report" | "heart_beat" | "jar" => {
            let message: Message = match serde_json::from_str(splited[1]) {
                Ok(m) => m,
                Err(e) => {
                    error!("can not deserialize message: {} {}", buf, e.to_string());
                    return None;
                }
            };
            let message_hash_map = message.to_hashmap();
            return Some(message_hash_map);
        }
        _ => {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam::channel::TryRecvError;
    use env_logger;
    use std::thread::sleep;
    use std::time::Duration;
    #[test]
    fn raw_server() {
        env_logger::init();
        let pid = 123;
        let (tx1, rx1) = bounded(100);
        let (_, rx2) = bounded(100);
        let mut manager = RASPServerManager::new().unwrap();
        let process_info = ProcessInfo::new(pid).unwrap();
        let ctrl = Control::new();
        let _ = manager
            .start_new_rasp_server(&process_info, tx1, rx2, String::from("DEBUG"), ctrl)
            .unwrap();
        loop {
            match rx1.try_recv() {
                Ok(line) => {
                    info!("RECV: {:?}", line);
                }
                Err(TryRecvError::Empty) => {
                    sleep(Duration::from_secs(2));
                    continue;
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                }
            }
            sleep(Duration::from_secs(2));
        }
    }
}
