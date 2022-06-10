use log::*;

use bytes::Bytes;
use std::collections::HashMap;
use std::fs;
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::utils::Control;
use crate::{RASPPair, RASPSock};

use crossbeam::channel::{Sender, TryRecvError};
use futures_util::{SinkExt, TryStreamExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixListener;
use tokio::spawn;
use tokio::sync::mpsc::Receiver;
use tokio::sync::RwLock;
use tokio::time::sleep;

pub fn clean_bind_addr(addr: &str) -> Result<(), String> {
    if Path::new(addr.clone()).exists() {
        match fs::remove_file(addr.clone()) {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

pub fn listen(addr: &str) -> Result<UnixListener, String> {
    let listener: UnixListener = match UnixListener::bind(addr.clone()) {
        Ok(l) => {
            if let Err(e) = fs::set_permissions(addr, fs::Permissions::from_mode(0o777)) {
                return Err(format!("chmod failed: {}", e.to_string()));
            };
            l
        }
        Err(e) => {
            let msg = format!("bind socket failed: {}", e.to_string());
            log::error!("{}", msg);
            return Err(msg);
        }
    };
    Ok(listener)
}

pub async fn new_pair(
    pairs: &mut Arc<RwLock<HashMap<i32, RASPPair>>>,
    pid: i32,
) -> (tokio::sync::mpsc::Receiver<String>, Control) {
    // println!("new pair: {}", pid);
    let (probe_message_sender, probe_message_receiver) = tokio::sync::mpsc::channel(5);

    let ctrl = Control::new();
    let pair = RASPPair {
        ctrl: ctrl.clone(),
        probe_message_sender,
    };
    (*pairs.write().await).insert(pid, pair);
    (probe_message_receiver, ctrl)
}

pub async fn start_bind(sock: RASPSock) -> Result<(), String> {
    clean_bind_addr(&sock.server_addr.clone())?;
    info!("bind: {}", &sock.server_addr.clone());
    let listener = listen(&sock.server_addr.clone())?;
    let mut pairs: Arc<RwLock<HashMap<i32, RASPPair>>> = Arc::new(RwLock::new(HashMap::new()));
    let pairs_clean = Arc::clone(&pairs);
    let pairs_send_message = Arc::clone(&&pairs);
    let mut clean_ctrl = sock.ctrl.clone();
    spawn(async move {
        loop {
            debug!("pairs clean tokio thread looping");
            if !clean_ctrl.check() {
                info!("receive global quit signal, clean every paris then quit");
                let mut pairs_clone = pairs_clean.write().await;
                for (_, pair) in pairs_clone.iter_mut() {
                    let _ = (*pair).ctrl.stop();
                }
                return;
            }
            let mut pairs_clone = pairs_clean.write().await;
            let mut pids = Vec::new();
            for (pid, pair) in pairs_clone.iter_mut() {
                if !(*pair).ctrl.check() {
                    pids.push(pid.clone());
                }
            }
            drop(pairs_clone);
            debug!("cleaning pid pairs: {:?}", pids);
            let mut pw = pairs_clean.write().await;
            if pids.len() > 0 {
                for pid in pids {
                    (*pw).remove(&pid);
                }
            }
            sleep(Duration::from_secs(30)).await;
        }
    });
    let global_rx = sock.rx_channel.clone();
    let mut rx_ctrl = sock.ctrl.clone();
    spawn(async move {
        loop {
            debug!("pairs rx dispatcher tokio thread looping");
            if !rx_ctrl.check() {
                warn!("global rx recv quit signal");
                break;
            }
            let (pid, message) = match global_rx.try_recv() {
                Ok(m) => m,
                Err(TryRecvError::Disconnected) => {
                    let _ = rx_ctrl.stop();
                    break;
                }
                Err(TryRecvError::Empty) => {
                    sleep(Duration::from_secs(30)).await;
                    continue;
                }
            };
            // println!("dispatcher recv message: {} {}", message, pid,);
            let writable = pairs_send_message.write().await;
            // println!(
            //     "dispatcher paris: {} {} {:?}",
            //     message,
            //     pid,
            //     writable.keys()
            // );
            let pair = match writable.get(&pid) {
                Some(pair) => pair,
                None => {
                    warn!("pid not found: {}", pid);
                    continue;
                }
            };
            // println!("send to pair: {} {}", pid, message);
            pair.probe_message_sender.send(message).await.unwrap();
            sleep(Duration::from_secs(1)).await;
        }
    });
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let pid = match stream.peer_cred() {
                    Ok(cred) => match cred.pid() {
                        Some(p) => p,
                        None => 0,
                    },
                    Err(e) => {
                        log::warn!("can not get peer_cred: {}", e);
                        0
                    }
                };
                info!("recv new stream from: {}", pid);
                let (sock_tx, ctrl) = new_pair(&mut pairs, pid as i32).await;
                let sock_rx = sock.tx_channel.clone();
                let rx_ctrl = ctrl.clone();
                let tx_ctrl = ctrl.clone();
                spawn(async move {
                    let (rx, tx) = stream.into_split();
                    looping(rx, tx, sock_rx, sock_tx, rx_ctrl, tx_ctrl).await;
                });
            }
            Err(e) => {
                let msg = format!("connection failed: {}", e.to_string());
                error!("{}", msg);
            }
        }
    }
}

pub async fn looping(
    rx: OwnedReadHalf,
    tx: OwnedWriteHalf,
    sock_rx: Sender<String>,
    mut sock_tx: Receiver<String>,
    mut rx_ctrl: Control,
    mut tx_ctrl: Control,
) {
    let mut framed_rx = tokio_util::codec::LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_length(4)
        .length_adjustment(0)
        .num_skip(4)
        .new_read(rx);
    let mut framed_tx = tokio_util::codec::LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_length(4)
        .length_adjustment(0)
        .num_skip(0)
        .new_write(tx);
    loop {
        tokio::select! {
            x = sock_tx.recv() => {
                match x {
                    Some(s) => {
                        println!("send message to probe: {}", s);
                        let bytes = Bytes::copy_from_slice(s.as_bytes());
                        match framed_tx.send(bytes).await {
                           Ok(_) => {}
                            Err(e) => {
                                println!("send failed: {}", e);
                                return;
                            }
                        }
                    }
                    None => {
                        log::warn!("tx recv ctrl stop: ");
                        let _ = tx_ctrl.stop();
                    }

                }
            },
            x = framed_rx.try_next() => {
                match x {
                   Ok(Some(buf)) => {
                        let message = String::from_utf8_lossy(&*buf).to_string();
                        log::debug!("RECV: {}", &message.clone());
                        if let Err(e) = sock_rx.send(message) {
                            log::warn!("rx recv ctrl stop: {}", e);
                            let _ = rx_ctrl.stop();
                            return;
                        }
                    }
                    Ok(None) => {
                        warn!("frame_rx thread quiting");
                        let _ = rx_ctrl.stop();
                        return
                    }
                    Err(e) => {
                        error!("frame_rx got err: {}", e);
                    }
                }
            },
        }
    }
}
