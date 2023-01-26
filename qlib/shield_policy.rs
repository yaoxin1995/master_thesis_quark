
use alloc::string::String;
use alloc::vec::Vec;
use super::control_msg::*;



#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum TrackInodeType {
    Stdin,
    Stdout, 
    Stderro,
    TTY,
    #[default]
    Normal,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum Role {
    DataOwner,  // define a white list
    CodeOwner,  // define a black list
    #[default]
    Host,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DebugModeOpt {
    pub enable_terminal: bool,
    pub single_shot_command_line_mode: bool,
    pub disable_container_logs_encryption: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SingleShotCommandLineModeConfig {
    pub role: Role,
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Secret {
    pub file_encryption_key: String,
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
    pub secret_file_path: Vec<String>,
}



#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Policy {
    pub debug_mode_opt: DebugModeOpt,
    pub single_shot_command_line_mode_configs: Vec<SingleShotCommandLineModeConfig>,
    pub secret: Secret,
}

#[derive(Debug, Default)]
pub enum RequestType {
    #[default]
    Terminal,  // define a white list
    SingleShotCmdMode(OneShotCmdArgs),  // define a black list
}




    