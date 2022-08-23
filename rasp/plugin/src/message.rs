use anyhow::{anyhow, Result as Anyhow};
use plugins::Record;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use log::error;

pub fn make_record(message: &mut HashMap<&'static str, String>) -> Record {
    // conver hashmap to plugins::Record
    let mut rec = Record::new();
    if let Some(data_type) = message.remove("data_type") {
        rec.set_data_type(match data_type.parse() {
            Ok(dt) => dt,
            Err(_) => 2459,
        })
    } else {
        rec.set_data_type(2439);
    }
    if let Some(timestamp) = message.remove("rasp_timestamp") {
        rec.set_timestamp(match timestamp.parse() {
            Ok(ts) => ts,
            Err(_) => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        });
    } else {
        rec.set_timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
    }
    rec.mut_data().set_fields(
        message
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<_>(),
    );
    rec
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RASPMessage {
    pub name: String,
    pub commands: Option<Vec<RASPCommand>>,
}

impl RASPMessage {
    pub fn default() -> Self {
        RASPMessage {
            name: String::new(),
            commands: None,
        }
    }
    pub fn to_json(&self) -> Anyhow<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RASPCommand {
    pub pid: String,
    pub state: String,
    pub runtime: String,
    pub probe_message: Option<String>,
}

impl RASPCommand {
    pub fn to_json(&self) -> Anyhow<String> {
        Ok(serde_json::to_string(self)?)
    }
    pub fn get_pid_i32(&self) -> Anyhow<i32> {
        Ok(self.pid.parse::<i32>()?)
    }
    pub fn get_state(&self) -> String {
        self.state.to_string()
    }
    pub fn get_probe_message(&self) -> Option<String> {
        self.probe_message.clone()
    }
}

pub fn parse_message(task: &plugins::Task) -> Anyhow<RASPMessage> {
    let message_str = task.get_data();
    let rasp_message: RASPMessage = serde_json::from_str(message_str)?;
    if message_str.contains("file_download_url") || message_str.contains("file_content") {
        if let Some(commands) = rasp_message.commands.as_ref() {
            for command in commands.iter() {
                let pid = command.pid.clone();
                if let Some(probe_config_str) = command.probe_message.clone() {
                    let probe_config: libraspserver::proto::ProbeConfigData = match serde_json::from_str(&probe_config_str) {
                        Ok(probe_config) => probe_config,
                        Err(_) => {
                            continue;
                        }
                    };
                    if let Some(patches) = probe_config.patch {
                        match parse_patch_message(pid, patches) {
                            Ok(_) => {},
                            Err(e) => {
                                error!("download patches failed: {} {:?}", e, command);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(rasp_message)
}

pub fn parse_patch_message(pid: String, patches: Vec<libraspserver::proto::ProbeConfigPatch>) -> Anyhow<()> {
    for patch in patches.iter() {
        let patch_path = String::from(patch.path.clone());
        if let Some(download_urls) = patch.file_download_url.as_ref() {
            for download_url in download_urls.iter() {
                match download_patch_to_file(&patch_path, download_url) {
                    Ok(_) => {
                        break
                    },
                    Err(e) => {
                        error!("download patch file failed: `{}`, {} {}", e, patch_path, download_url);
                        continue;
                    }
                };
            }
        };
        let ipid = pid.parse::<i32>()?;
        let dest_dir = librasp::manager::RASPManager::root_dir(ipid);
        // TODO copy to dest dir
        let dest_path = format!("{}/{}", dest_dir, patch_path);
        let mut option = fs_extra::file::CopyOptions::new();
        option.skip_exist = true;
        fs_extra::file::copy(patch_path, dest_path, &option)?;
    }
    Ok(())
}

// pub fn write_patch_to_file(path: &String, content: &String) -> Anyhow<()> {
//     // base64::decode(content.as_bytes().to_vec());
//     let file = std::fs::File::create(path)?;
//     let mut base64_writer = base64::write::EncoderWriter::new(file, base64::STANDARD);
//     base64_writer.write_all(&content.as_bytes())?;
//     Ok(())
// }

pub fn download_patch_to_file(path: &String, download_url: &String) -> Anyhow<()> {
    let response = reqwest::blocking::get(download_url)?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(&*response.bytes()?)?;
    Ok(())
}

pub fn file_check_sum(file_path: &String, sum: &String) -> Anyhow<()> {
    let bytes = std::fs::read(file_path)?;  // Vec<u8>
    let hash = sha256::digest_bytes(&bytes);
    if sum == &hash {
        Ok(())
    } else {
        Err(anyhow!("check sum not match downloaded: {} sum: {}", hash, sum))
    }
}
