
use alloc::string::{String};
use alloc::vec::Vec;
use crate::shielding_layer::*;



#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum StdioType {
    #[default]
    SandboxStdio, // the stdio of root conainer, i.e., "pause" container
    ContaienrStdio,  // the stio of subcontainers
    ExecProcessStdio,   // the stdio of exec process
    SessionAllocationStdio (ExecSession), // tue stdio of session allocation req
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct StdioArgs {
    pub exec_id: Option<String>,
    pub exec_user_type: Option<UserType>,
    pub stdio_type : StdioType
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct TtyArgs {
    pub exec_id: Option<String>,
    pub exec_user_type: Option<UserType>,
    pub tty_slave : i32,
    pub stdio_type : StdioType
}



#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum TrackInodeType {
    Stdin(StdioArgs),
    Stdout(StdioArgs), 
    Stderro(StdioArgs),
    TTY(TtyArgs),
    #[default]
    Normal,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum Role {
    #[default]
    Privileged,  // define a white list
    Unprivileged,  // define a black list
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PrivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
    pub exec_result_encryption: bool,
    pub enable_container_logs_encryption:bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct UnprivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SingleShotCommandLineModeConfig {
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Secret {
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
    pub secret_file_path: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Policy {
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub hmac_key_slice: String,
    pub log_encryption_key: String,
    pub secret: Secret,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub enum ExecRequestType {
    #[default]
    Terminal,  // define a white list
    SingleShotCmdMode,  // define a black list
    SessionAllocationReq(ExecSession), 
}




    