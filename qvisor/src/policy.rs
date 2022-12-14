
extern crate serde_json;
//use serde_json::{Value, Map}
use super::runc::oci::*;


#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default)]
pub enum CriEndPointDedaultAction {
    #[default]
    CRI_ACT_RETUREN_ERRNO,  // define a white list
    CRI_ACT_RETUREN_SECCESS,  // define a black list
}

#[derive(Clone, Copy,Serialize, Deserialize, Debug, Default)]
pub enum Role {
    #[default]
    Host,  // define a white list
    Guest,  // define a black list
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default)]
pub enum CriEndpoitsName {
    #[default]
    ATTACH, 
    CREATE, 
    EXEC,     // "allowed_binary": ["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/touch"]
    INSPECT,
    INSPECTP,
    PORT_FORWARD,   //            "allowed_remote_ports": [1200, 1500]
    PS,
    RUN,
    RUNP,
    RM,
    RMP,
    PODS,
    START,
    STOP,
    STOPP,
    UPDATE,
    STATS,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub enum Action {
    CRI_ACT_ALLOW,   // define a white list
    CRI_ACT_REJECT,  // define a black list
}


#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CriEndPoint {
    pub name: CriEndpoitsName,
    pub action: Action,
    pub opts: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub auxiliary_array: Vec<serde_json::Value>,
}



#[derive(Clone,Default, Serialize, Deserialize, Debug)]
pub struct Policy {
    pub default_action: CriEndPointDedaultAction,
    pub role: Role,
    pub CriEndpoits: Vec<CriEndPoint>,
}


impl Policy {
    pub const POLICY_FILE: &'static str = "/etc/quark/policy.json";

    // if the config file exist, load file and return true; otherwise return false
    pub fn Load(&mut self) -> bool {
        let config = serialize::deserialize(Self::POLICY_FILE).unwrap();
        *self = config;
        return true;
    }

    pub fn Print(&self) {
        let c = serde_json::to_string(self).unwrap();
        error!("policy is {}", c);
    }
}