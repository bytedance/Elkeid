use std::io;
use std::io::prelude::*;
use log::*;

pub mod comm;
pub mod utils;
pub mod proto;


use proto::*;

pub fn listen_stdin() {
    let stdin = io::stdin();
    let handle = stdin.lock();
    for line in handle.lines() {
        match line {
            Ok(l) => {
                debug!("receive stdin: {}", l.clone());
                let value: ProbeConfig = match serde_json::from_str(l.as_str()) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("parse stdin json failed: {}", e.to_string());
                        continue;
                    }
                };
                debug!("receiver ProbeConfig: {:?}", value);
                let mut count = 0;
                loop {
                    count += 1;
                    if count >= 5 {
                        error!("set probe config failed: max try 5 times");
                        break;
                    }

                    if let Some(_) = set_probe_config_flag(true) {
                        continue;
                    }
                    if let Some(_) = set_probe_config(value.clone()) {
                        continue;
                    }
                    break;
                }
            }
            Err(e) => {
		error!("receive stdin failed: {}", e.to_string());
		return
	    }
        }
    }
}

// config Message action Message
pub fn parse_config() -> Result<(Option<Message>, Option<Message>), String> {
    let mut count = 0;
    loop {
        count += 1;
        if count >= 5 {
            return Err(String::from("get probe config failed"));
        }
        match get_probe_config() {
            Some(probe_config) => {
                let config_message = if let Some(config) = probe_config.config.clone() {
                    Some(Message::new_config(&config))
                } else {
		    None
                };
                let action_message = if let Some(action) = probe_config.action.clone() {
		    Some(Message::new_action(action))
		} else {
		    None
		};
                return Ok((config_message, action_message));
            }
            None => {
                continue;
            }
        }
    }
}

pub fn set_probe_config_flag(value: bool) -> Option<String> {
    let mut probe_flag = match PROBE_CONFIG_FLAG.lock() {
        Ok(pf) => pf,
        Err(e) => {
            warn!("probe flag lock failed: {}", e.to_string());
            return Some(format!("set probe flag lock failed: {}", e.to_string()));
        }
    };
    *probe_flag = value;
    None
}

pub fn get_probe_config_flag() -> Option<bool> {
    let probe_flag = match PROBE_CONFIG_FLAG.lock() {
        Ok(pf) => pf,
        Err(e) => {
            warn!("probe flag lock failed: {}", e.to_string());
            return None;
        }
    };
    Some((*probe_flag).clone())
}

pub fn set_probe_config(value: ProbeConfig) -> Option<String> {
    let mut probe_config = match PROBE_CONFIG.lock() {
        Ok(pc) => pc,
        Err(e) => {
            warn!("probe config lock failed: {}", e.to_string());
            return Some(format!("probe config lock failed: {}", e.to_string()));
        }
    };
    *probe_config = value;
    None
}

pub fn get_probe_config() -> Option<ProbeConfig> {
    let probe_config: std::sync::MutexGuard<ProbeConfig> = match PROBE_CONFIG.lock() {
        Ok(pc) => pc,
        Err(e) => {
            warn!("probe config lock failed: {}", e.to_string());
            return None;
        }
    };
    let probe_config_clone = probe_config.clone();
    Some(probe_config_clone)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    async fn server() {
        env_logger::init();
	thread::spawn(|| {
	    listen_stdin()
	});
        println!("new server");
	let mut server = comm::Server::new("/tmp/test.sock");
        println!("start listen");
	server.start_bind().await.unwrap();
    }
}
