use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use log::*;
use serde::{Deserialize, Serialize};
use serde_json;
use anyhow::{Result as AnyhowResult, anyhow};

use super::utils::generate_timestamp_f64;

lazy_static! {
    pub static ref PROBE_CONFIG: Arc<Mutex<ProbeConfig>> =
        Arc::new(Mutex::new(ProbeConfig::default()));
    pub static ref PROBE_CONFIG_FLAG: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeData {
    args: Option<Vec<String>>,
    method_id: Option<u32>,
    class_id: Option<u32>,
    stack_trace: Option<Vec<String>>,
    pub async_stack_trace: Option<Vec<Vec<String>>>,
    pub action: Option<u32>,
    pub config: Option<String>,
    pub jars: Option<Vec<JarData>>,
    pub golang: Option<GolangDepData>,
    pub request: Option<String>,
    pub blocked: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GolangDepData {
    pub deps: Option<Vec<GolangDep>>,
    pub main: Option<Vec<GolangDep>>,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GolangDep {
    pub path: Option<String>,
    pub sum: Option<String>,
    pub version: Option<String>,
    pub replace: Option<GolangReplace>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GolangReplace {
    pub path: Option<String>,
    pub sum: Option<String>,
    pub version: Option<String>,
}

impl ProbeData {
    pub fn new_config(config_string: String) -> Self {
        let mut pd = ProbeData::default();
        pd.config = Some(config_string);
        pd
    }

    pub fn new_action(action: u32) -> Self {
        let mut pd = ProbeData::default();
        pd.action = Some(action);
        pd
    }
    pub fn to_hashmap(self) -> HashMap<&'static str, String> {
        let mut pdhm = HashMap::<&'static str, String>::new();
        if let Some(args) = self.args {
            pdhm.insert("args", serde_json::json!(args).to_string());
        }
        if let Some(method_id) = self.method_id {
            pdhm.insert("method_id", method_id.to_string());
        }
        if let Some(class_id) = self.class_id {
            pdhm.insert("class_id", class_id.to_string());
        }
        if let Some(async_stack_trace) = self.async_stack_trace {
            pdhm.insert(
                "async_stack_trace",
                serde_json::json!(async_stack_trace).to_string(),
            );
        }
        if let Some(req) = self.request {
            pdhm.insert("request", serde_json::json!(req).to_string());
        }
        if let Some(stack_trace) = self.stack_trace {
            pdhm.insert("stack_trace", serde_json::json!(stack_trace).to_string());
        }
        if let Some(jars) = self.jars {
            pdhm.insert("jars", serde_json::json!(jars).to_string());
        }
        if let Some(blocked) = self.blocked {
            pdhm.insert("blocked", blocked.to_string());
        }
        pdhm
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JarData {
    path: String,
    implementation_title: Option<String>,
    implementation_version: Option<String>,
    specification_tittle: Option<String>,
    specification_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeConfig {
    pub pid: i32,
    pub message_type: i32,
    pub data: ProbeConfigData,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PidMissingProbeConfig {
    pub message_type: i32,
    pub data: ProbeConfigData,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeConfigData {
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<ProbeConfigBlock>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<Vec<ProbeConfigFilter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Vec<ProbeConfigLimit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patches: Option<Vec<ProbeConfigPatch>>,
}

impl ProbeConfigData {
    pub fn empty(message_type: i32) -> AnyhowResult<Self> {
        /*
        6FILTER,
        7BLOCK,
        8LIMIT,
        9PATCH
         */
        let data = match message_type {
            6 => ProbeConfigData {
                uuid: "".to_string(),
                blocks: None,
                filters: Some(Vec::new()),
                limits: None,
                patches: None,
            },
            7 => ProbeConfigData {
                uuid: "".to_string(),
                blocks: Some(Vec::new()),
                filters: None,
                limits: None,
                patches: None,
            },
            8 => ProbeConfigData {
                uuid: "".to_string(),
                blocks: None,
                filters: None,
                limits: Some(Vec::new()),
                patches: None,
            },
            9 => ProbeConfigData {
                uuid: "".to_string(),
                blocks: None,
                filters: None,
                limits: None,
                patches: Some(Vec::new()),
            },
            _ => {
                return Err(anyhow!("message type not valid"));
            }
        };
        return Ok(data);
    }
}

// #[derive(Debug, Serialize, Deserialize, Clone, Default)]
// pub struct ProbeConfigBlocks {
//     uuid: String,
//     blocks: Vec<ProbeConfigBlock>
// }
//
// #[derive(Debug, Serialize, Deserialize, Clone, Default)]
// pub struct ProbeConfigFilters {
//     uuid: String,
//     filters: Vec<ProbeConfigFilter>,
// }
//
// #[derive(Debug, Serialize, Deserialize, Clone, Default)]
// pub struct ProbeConfigLimits {
//     uuid: String,
//     limits: Vec<ProbeConfigLimit>,
// }
//
// #[derive(Debug, Serialize, Deserialize, Clone, Default)]
// pub struct ProbeConfigPatches{
//     uuid: String,
//     pub patches: Vec<ProbeConfigPatch>
// }

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeConfigBlock {
    pub class_id: i32,
    pub method_id: i32,
    pub rules: Vec<ProbeConfigRules>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeConfigRules {
    pub index: i32,
    pub regex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeConfigFilter {
    pub class_id: i32,
    pub method_id: i32,
    pub include: Vec<ProbeConfigRules>,
    pub exclude: Vec<ProbeConfigRules>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeConfigLimit {
    pub class_id: i32,
    pub method_id: i32,
    pub quota: i32,
}


#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeConfigPatch {
    pub class_name: String,
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sum_hash: Option<String>,
}

pub fn message_handle(message: &String) -> Result<String, String> {
    // parse message
    let message = match Message::from(message) {
        Ok(m) => m,
        Err(e) => {
            return Err(e.to_string());
        }
    };
    debug!("Message: {}", message);
    let response = match message.message_type {
        1 => match heartbeat_handle(&message.clone()) {
            Ok(resp) => resp,
            Err(e) => {
                return Err(e);
            }
        },
        2 => match probe_report(&message.clone()) {
            Some(e) => {
                return Err(e);
            }
            None => String::new(),
        },
        5 => match jar_report(&message.clone()) {
            Ok(_) => String::new(),
            Err(e) => return Err(e),
        },
        _ => return Err(String::from("bad message type")),
    };
    Ok(response)
}

pub fn jar_report(message: &Message) -> Result<String, String> {
    let msg = message.clone();
    let response = serde_json::json!(msg).to_string();
    println!("jar:{}", response);
    Ok(String::new())
}

pub fn heartbeat_handle(message: &Message) -> Result<String, String> {
    let msg = message.clone();
    let response = serde_json::json!(msg).to_string();
    println!("heart_beat:{}", response);
    Ok(response)
}

pub fn probe_report(message: &Message) -> Option<String> {
    let msg = message.clone();
    let response = serde_json::json!(msg).to_string();
    println!("probe_report:{}", response);
    None
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pid: i32,
    runtime: String,
    runtime_version: String,
    probe_version: String,
    message_type: u32,
    time: f64,
    data: Option<ProbeData>,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {}, {}, {}, {}, ProbeData: {:?})",
            self.pid,
            self.message_type,
            self.runtime,
            self.runtime_version,
            self.probe_version,
            self.data,
        )
    }
}

impl fmt::Display for ProbeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?})", self.args)
    }
}

impl Message {
    pub fn from(message_string: &String) -> Result<Self, String> {
        info!("new mesage from: {}", message_string);
        let message_struct = match serde_json::from_str(message_string.as_str()) {
            Ok(m) => m,
            Err(e) => {
                return Err(e.to_string());
            }
        };
        Ok(message_struct)
    }
    pub fn default() -> Self {
        Message {
            pid: 0,
            runtime: String::new(),
            runtime_version: String::new(),
            probe_version: String::new(),
            message_type: 0,
            time: generate_timestamp_f64(),
            data: None,
        }
    }
    pub fn new_config(config_string: &String) -> Self {
        let probe_data = ProbeData::new_config(config_string.clone());
        let mut new_message = Message::default();
        new_message.data = Some(probe_data);
        new_message.message_type = 3;
        new_message
    }

    pub fn new_action(action: u32) -> Self {
        let probe_data = ProbeData::new_action(action);
        let mut new_message = Message::default();
        new_message.data = Some(probe_data);
        new_message.message_type = 4;
        new_message
    }
    pub fn to_json(&self) -> String {
        serde_json::json!(&self).to_string()
    }
    pub fn to_hashmap(self) -> HashMap<&'static str, String> {
        let mut mhm = HashMap::<&'static str, String>::new();
        mhm.insert("pid", self.pid.to_string());
        mhm.insert("runtime", self.runtime);
        mhm.insert("runtime_version", self.runtime_version);
        mhm.insert("message_type", self.message_type.to_string());
        mhm.insert("rasp_timestamp", self.time.to_string());
        mhm.insert("probe_version", self.probe_version.to_string());
        if let Some(data) = self.data {
            let probe_data_map = data.to_hashmap();
            mhm.extend(probe_data_map);
        }
        mhm
    }
}
