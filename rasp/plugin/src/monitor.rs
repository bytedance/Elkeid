use std::{
    collections::HashMap,
    sync::Arc,
    thread::{sleep, Builder},
    time::Duration,
};

use crate::{
    config::*,
    filter::load_local_filter,
    message::{make_record, parse_message, RASPCommand},
    process::{poll_pid_func, process_health},
    report::make_report,
    utils::Control,
};
use anyhow::{anyhow, Result as Anyhow};
use crossbeam::channel::{bounded, Receiver, Sender, TrySendError};
use librasp::{
    process::{ProcessInfo, TracingState},
    runtime::{Runtime, RuntimeInspect},
};
use log::*;
use parking_lot::RwLock;
use plugins::Client;
use crate::utils::{generate_heartbeat, generate_seq_id};

pub fn rasp_monitor_start() -> Anyhow<()> {
    let client = Client::new(false);
    let mut ctrl = Control::new();
    /* data collection thread */
    let (internal_message_sender, internal_message_receiver): (
        Sender<HashMap<&'static str, String>>,
        Receiver<HashMap<&'static str, String>>,
    ) = bounded(settings_int("internal", "internal_message_capability")? as usize);
    let mut collect_ctrl = ctrl.clone();
    let mut collect_client = client.clone();
    let collect_thread =
        Builder::new()
            .name("collect".to_string())
            .spawn(move || -> Anyhow<()> {
                loop {
                    debug!("collect thread looping");
                    if !collect_ctrl.check() {
                        warn!("collect thread receive stop signal, quiting");
                        break;
                    }
                    let mut internal_message = match internal_message_receiver.recv() {
                        Ok(m) => m,
                        Err(e) => {
                            let _ = collect_ctrl.stop();
                            debug!("internal message channel recv failed: {}", e);
                            return Err(anyhow!("recv internal channel failed: {}", e));
                        }
                    };
                    let record = make_record(&mut internal_message);
                    debug!("collect message: {:?}", record);
                    match collect_client.send_record(&record) {
                        Ok(_) => {}
                        Err(e) => {
                            let _ = collect_ctrl.stop();
                            return Err(anyhow!("send record failed: {}", e));
                        }
                    }
                }
                let _ = collect_ctrl.stop();
                Ok(())
            })?;
    let (external_message_sender, external_message_receiver): (
        Sender<RASPCommand>,
        Receiver<RASPCommand>,
    ) = bounded(settings_int("internal", "external_message_capablility")? as usize);
    let external_message_sender_clone = external_message_sender.clone();
    let mut external_ctrl = ctrl.clone();
    let mut external_client = client.clone();
    let external_thread =
        Builder::new()
            .name("external".to_string())
            .spawn(move || -> Anyhow<()> {
                loop {
                    debug!("external thread looping");
                    if !external_ctrl.check() {
                        warn!("external thread recv stop signal, quiting");
                        break;
                    }
                    let message = match external_client.receive() {
                        Ok(m) => m,
                        Err(e) => {
                            let _ = external_ctrl.stop();
                            return Err(anyhow!("recv failed client failed: {}", e));
                        }
                    };
                    let parsed_message = match parse_message(&message) {
                        Ok(pm) => pm,
                        Err(e) => {
                            warn!("parse message failed: {} {:?}", e.to_string(), &message);
                            continue;
                        }
                    };
                    if parsed_message.commands.is_none() {
                        continue;
                    }
                    for command in parsed_message.commands.unwrap() {
                        match external_message_sender_clone.try_send(command) {
                            Ok(_) => {}
                            Err(TrySendError::Full(e)) => {
                                warn!("command send channel full: {:?}", e);
                                sleep(Duration::from_secs(1));
                                continue;
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                warn!("command send chnnel disconnected");
                                let _ = external_ctrl.stop();
                                break;
                            }
                        };
                    }
                }
                Ok(())
            })?;
    let external_message_sender_for_internal_thread = external_message_sender.clone();
    let internal_ctrl = ctrl.clone();
    let internal_thread =
        Builder::new()
            .name("internal".to_string())
            .spawn(move || -> Anyhow<()> {
                info!("starting internal thread");
                match internal_main(
                    internal_message_sender,
                    external_message_receiver,
                    external_message_sender_for_internal_thread,
                    internal_ctrl,
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("internal error: {}", e);
                    }
                };
                info!("internal stopped");
                Ok(())
            })?;
    // WAIT until quit
    loop {
        if !ctrl.check() {
            let _ = collect_thread.join().unwrap();
            let _ = external_thread.join().unwrap();
            let _ = internal_thread.join().unwrap();
            break;
        }
        sleep(Duration::from_secs(20));
    }
    Ok(())
}

fn internal_main(
    internal_message_sender: Sender<HashMap<&'static str, String>>,
    external_message_receiver: Receiver<RASPCommand>,
    external_message_sender: Sender<RASPCommand>,
    mut ctrl: Control,
) -> Anyhow<()> {
    debug!("internal main starting");
    /* poll pid from `/proc` */
    let mut pid_recv_ctrl = ctrl.clone();
    let mut tracking_pids = Vec::<i32>::new();
    let (pid_sender, pid_receiver) =
        bounded(settings_int("internal", "pid_queue_length")? as usize);
    let pid_recv_thread = Builder::new()
        .name("pid_recv".to_string())
        .spawn(move || loop {
            debug!("pid_recv thread looping");
            if !pid_recv_ctrl.check() {
                warn!("pid_recv thread recv stop signal, quiting");
                break;
            }
            let pids = match poll_pid_func(&tracking_pids) {
                Ok((all_pids, need_inspect)) => {
                    tracking_pids = all_pids;
                    need_inspect
                }
                Err(_) => Vec::new(),
            };
            if pids.len() == 0 {
                sleep(Duration::from_secs(20));
                continue;
            }
            for pid in pids.iter() {
                if let Err(_) = pid_sender.send(*pid) {
                    error!("can not send pid to pid_sender channel, quiting");
                    let _ = pid_recv_ctrl.stop();
                    break;
                };
            }
            sleep(Duration::from_secs(60));
        })?;
    /* consume pid then inspect runtime */
    let mut inspect_ctrl = ctrl.clone();
    let local_filters = load_local_filter()?;
    let tracing_process_arcrw = Arc::new(RwLock::new(HashMap::new()));
    let inspected_process_rw = Arc::clone(&tracing_process_arcrw);
    let report_process_r = Arc::clone(&tracing_process_arcrw);
    let cleaning_process_rw = Arc::clone(&tracing_process_arcrw);
    let operation_process_rw = Arc::clone(&tracing_process_arcrw);
    let inspect_reportor = internal_message_sender.clone();
    let external_message_sender_for_inspected = external_message_sender.clone();
    let inspect_thread = Builder::new()
        .name("inspect".to_string())
        .spawn(move || loop {
            debug!("inspect thread looping");
            if !inspect_ctrl.check() {
                warn!("inspect thread recv stop signal, quiting")
            }
            let pid = match pid_receiver.try_recv() {
                Ok(p) => p,
                Err(crossbeam::channel::TryRecvError::Disconnected) => {
                    let _ = inspect_ctrl.stop();
                    break;
                }
                Err(crossbeam::channel::TryRecvError::Empty) => {
                    sleep(Duration::from_secs(10));
                    continue;
                }
            };
            let mut process = match crate::process::collect(pid, &local_filters) {
                Ok(p) => p,
                Err(e) => {
                    warn!("process filting failed: {} {}", pid, e);
                    sleep(Duration::from_millis(50));
                    continue;
                }
            };
            let runtime: Runtime = match ProcessInfo::inspect_from_process_info(&mut process) {
                Ok(opt) => match opt {
                    Some(r) => r,
                    None => {
                        sleep(Duration::from_millis(50));
                        continue;
                    }
                },
                Err(e) => {
                    debug!("inspect process: {} failed: {}", pid, e);
                    sleep(Duration::from_millis(50));
                    continue;
                }
            };
            info!("found process: {} runtime: {}", process.pid, runtime);
            process.tracing_state = Some(TracingState::INSPECTED);
            process.runtime = Some(runtime.clone());
            for rt in local_filters.auto_attach_runtime.iter() {
                if &runtime.name == rt {
                    let _ = external_message_sender_for_inspected.send(RASPCommand {
                        pid: process.pid.to_string(),
                        state: "WAIT_ATTACH".to_string(),
                        runtime: runtime.to_string(),
                        probe_message: None,
                    });
                    break;
                }
            }
            let mut ip = inspected_process_rw.write();
            let report = make_report(&process.clone(), "inspected", String::new());
            let _ = inspect_reportor.send(report);
            (*ip).insert(pid, process);
            drop(ip);
            sleep(Duration::from_millis(100));
        })?;
    let mut reporter_ctrl = ctrl.clone();
    let reporter_sender = internal_message_sender.clone();
    let reporter_thread = Builder::new()
        .name("reporter".to_string())
        .spawn(move || loop {
            debug!("reporter thread looping");
            if !reporter_ctrl.check() {
                break;
            }
            sleep(Duration::from_secs(settings_int("internal", "report_interval").unwrap_or(120) as u64));
            let watched_process = report_process_r.read();
            let watched_process_cloned = watched_process.clone();
            drop(watched_process);
            let seq_id = generate_seq_id();
            for (_pid, process) in watched_process_cloned.iter() {
                let mut message = generate_heartbeat(&process);
                message.insert("data_type", "2997".to_string());
                message.insert("package_seq", seq_id.clone());
                debug!("sending heartbeat: {:?}", &message);
                let _ = reporter_sender.send(message);
            }
        })?;
    /* clean missing process */
    let mut cleaner_ctrl = ctrl.clone();
    let cleaner_thread = Builder::new()
        .name("cleaner".to_string())
        .spawn(move || loop {
            debug!("cleaner thread looping");
            if !cleaner_ctrl.check() {
                break;
            }
            sleep(Duration::from_secs(60));
            let cleaning_process = cleaning_process_rw.read();
            let check_needed = (*cleaning_process).clone();
            drop(cleaning_process);
            let missing_process = process_health(&check_needed);
            info!(
                "current watching process: {}, missing: {}",
                check_needed.len(),
                missing_process.len()
            );
            for pid in missing_process.iter() {
                let _ = external_message_sender.send(RASPCommand {
                    pid: pid.to_string(),
                    state: "MISSING".to_string(),
                    runtime: "".to_string(),
                    probe_message: None,
                });
            }
        })?;
    let mut operation_ctrl = ctrl.clone();
    let operation_reporter = internal_message_sender.clone();
    let mut operator = crate::operation::Operator::new(internal_message_sender, ctrl.clone())?;
    operator.host_rasp_server()?;
    let operation_thread = Builder::new()
        .name("operation".to_string())
        .spawn(move || loop {
            debug!("operation thread looping");
            if !operation_ctrl.check() {
                warn!("operation recv stop signal, quiting.");
                break;
            }
            let operation_message = match external_message_receiver.try_recv() {
                Ok(p) => p,
                Err(crossbeam::channel::TryRecvError::Empty) => {
                    sleep(Duration::from_secs(3));
                    continue;
                }
                Err(crossbeam::channel::TryRecvError::Disconnected) => {
                    let _ = operation_ctrl.stop();
                    break;
                }
            };
            let state = operation_message.get_state();
            let probe_message = operation_message
                .get_probe_message()
                .unwrap_or("".to_string());
            let mut process = match operation_message.get_pid_i32() {
                Ok(pid) => {
                    let opp = operation_process_rw.read();
                    let process = match opp.get(&pid) {
                        Some(p) => p.clone(),
                        None => {
                            warn!("process not found: {:?}", operation_message);
                            continue;
                        }
                    };
                    drop(opp);
                    process
                }
                Err(_) => {
                    continue;
                }
            };
            // handle operation
            info!("starting operation: {:?}", operation_message);
            match operator.op(&mut process, state.clone(), probe_message.clone()) {
                Ok(_) => {
                    info!("operation success: {:?}", operation_message);
                    let report = make_report(&process.clone(), "attach_success", String::new());
                    let _ = operation_reporter.send(report);
                }
                Err(e) => {
                    warn!("operation failed: {:?} {}", operation_message, e);
                    let report = make_report(
                        &process.clone(),
                        format!("{}_failed", state.clone()).as_str(),
                        e.to_string(),
                    );
                    let _ = operation_reporter.send(report);
                    continue
                }
            };
            // update
            let mut opp = operation_process_rw.write();
            match state.as_str() {
                "WAIT_ATTACH" => {
                    process.tracing_state = Some(TracingState::ATTACHED);
                    // update config hash
                    let probe_config_hash = if !probe_message.clone().is_empty() {
                        // calc_hash
                        format!("{:x}", md5::compute(probe_message.clone()))
                    } else {
                        String::new()
                    };
                    process.current_config_hash = probe_config_hash;
                    (*opp).insert(process.pid, process);
                }
                "MISSING" => {
                    (*opp).remove(&process.pid);
                }
                _ => {}
            }
            drop(opp);
            sleep(Duration::from_millis(500));
        })?;

    loop {
        if !ctrl.check() {
            pid_recv_thread.join().unwrap();
            inspect_thread.join().unwrap();
            cleaner_thread.join().unwrap();
            operation_thread.join().unwrap();
            reporter_thread.join().unwrap();
            break;
        }
        sleep(Duration::from_secs(10));
    }
    Ok(())
}
