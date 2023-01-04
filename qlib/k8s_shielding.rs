
use alloc::string::String;
use alloc::vec::Vec;
use spin::mutex::Mutex;

lazy_static! {
    pub static ref POLICY_CHEKCER : Mutex<PolicyChecher> = Mutex::new(PolicyChecher::default());
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
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

#[derive(Debug, Default, PartialEq)]
pub enum RequestType {
    Terminal,  // define a white list
    #[default]
    SingleShotCmdMode,  // define a black list
}

#[derive(Debug, Default)]
pub struct PolicyChecher {
    policy: Policy,
}


impl PolicyChecher {

    pub fn init(&mut self, policy: Option<&Policy>) -> () {

        self.policy = policy.unwrap().clone();
    }

    pub fn print_policy(&self) -> () {

        info!("default policy:{:?}" ,self.policy);
    }

    pub fn terminal_endpointer_check (&self) -> bool {

        self.policy.debug_mode_opt.enable_terminal

    }

    pub fn single_shot_command_line_mode_check (&self) -> bool {

        if self.policy.debug_mode_opt.single_shot_command_line_mode == false {
            return false;
        }


        return true;
            

    }


}

