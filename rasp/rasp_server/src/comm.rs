use super::utils::{four_bytes_to_num, num_to_four_bytes, ByteBuf};
use super::proto::*;
use super::*;

use std::fs;
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::stream::StreamExt;
use tokio::spawn;

pub struct Server {
    server_addr: &'static str,
}

impl Server {
    pub fn new(server_addr: &'static str) -> Self {
        Self { server_addr }
    }
    pub fn clean_bind_addr(&self) -> Option<String> {
        let path = self.server_addr.clone();
        if Path::new(path.clone()).exists() {
            match fs::remove_file(path.clone()) {
                Ok(_) => {}
                Err(e) => return Some(e.to_string()),
            }
        }
        None
    }
    pub async fn start_bind(&mut self) -> Result<(), String> {
        if let Some(e) = self.clean_bind_addr() {
            return Err(e);
        }
	info!("bind: {}", self.server_addr.clone());
        let mut listener: UnixListener = match UnixListener::bind(self.server_addr.clone()) {
            Ok(l) => {
                if let Err(e) = fs::set_permissions(self.server_addr.clone(), fs::Permissions::from_mode(0o777))
                {
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
        while let Some(stream) = listener.next().await {
            match stream {
                Ok(stream) => {
		    info!("incoming stream");
                    spawn(async move {
                        if let Err(e) = process(stream).await {
                            let msg =
                                format!("failed to process connection; error: {}", e.to_string());
                            error!("{}", msg);
                        }
                    });
                }
                Err(e) => {
                    let msg = format!("connection failed: {}", e.to_string());
                    error!("{}", msg);
                }
            }
        }
        Ok(())
    }
}

struct Stream {
    stream: UnixStream,
}

impl Stream {
    pub async fn recv(&mut self) -> Result<String, String> {
        let mut message_len_bytes: [u8; 4] = [0; 4];
        let message_len = match self.stream.read_exact(&mut message_len_bytes).await {
            Err(e) => {
                let msg = format!("recv `message_len` failed: {}", e.to_string());
                return Err(msg);
            }
            Ok(size) => {
                if size == 0 {
                    warn!("recv 0 len message");
                    return Err(String::from("socket EOF"));
                }
                four_bytes_to_num(message_len_bytes)
            }
        };
        log::debug!(
            "RECV: {:x}, len: {}",
            ByteBuf(&message_len_bytes),
            message_len
        );
        let mut message_bytes = vec![0; message_len];
        return match self.stream.read_exact(&mut message_bytes).await {
            Err(e) => Err(format!("recv message body failed: {}", e.to_string())),
            Ok(size) => {
                if size != message_len {
                    let msg = format!(
                        "recv message body length not equal: {} {}",
                        size, message_len
                    );
                    warn!("{}", msg);
                    return Err(msg);
                }
                // convert bytes to string
                let message = String::from_utf8_lossy(&message_bytes[0..message_len]).to_string();
                log::debug!(
                    "RECV: {:x}, {}",
                    ByteBuf(&message_bytes.clone()),
                    message.clone()
                );
                Ok(message)
            }
        };
    }
    pub async fn send(&mut self, message: String) -> Result<(), String> {
        let message_len = message.len();
        debug!("SEND: {} {}", message_len, message.clone());
        let message_len_bytes = num_to_four_bytes(message_len);
        let message_bytes: Vec<u8> = [&message_len_bytes, message.as_bytes()].concat();
        debug!("HEX: {:x}", ByteBuf(&message_bytes));
        return match self.stream.write_all(message_bytes.as_slice()).await {
            Err(e) => Err(e.to_string()),
            Ok(_) => Ok(()),
        };
    }
}

async fn process(stream: UnixStream) -> Result<(), String> {
    let mut st = Stream { stream };
    loop {
        let recv_message = match st.recv().await {
            Ok(m) => m,
            Err(e) => {
                error!("{}", e);
                return Err(e);
            }
        };
        if recv_message == "" {
	    warn!("recv empty message");
            continue;
        }

        // check probe config flag
        if let Some(flag) = get_probe_config_flag() {
            if flag {
                // gen probe config data
                let (config_message, action_message) = match parse_config() {
                    Ok(m) => m,
                    Err(e) => {
                        error!("parse config failed: {}", e);
                        (None, None)
                    }
                };
                // send to probe
                if let Some(config) = config_message {
                    if let Err(send_failed) = st.send(config.to_json()).await {
                        error!("send config failed: {}", send_failed);
                    }
                }
		if let Some(action) = action_message {
		    if let Err(send_failed) = st.send(action.to_json()).await {
			error!("send action failed: {}", send_failed);
		    }
		}
            }
	    if let Some(set_failed) = set_probe_config_flag(false) {
		error!("set probe config flag failed: {}", set_failed);
	    }
        }
       let send_message = match message_handle(&recv_message) {
            Ok(message) => message,
            Err(e) => {
                error!("handle request failed: {}", e);
		return Err(e);
            }
        };
	if send_message.is_empty() {
	    continue;
	}
        if let Err(e) = st.send(send_message).await {
            warn!("write failed: {}", e);
	    return Err(e);
	}
    }
}
