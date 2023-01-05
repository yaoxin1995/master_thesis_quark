
use alloc::string::String;
use alloc::vec::Vec;
use spin::mutex::Mutex;
use super::control_msg::*;
lazy_static! {
    pub static ref POLICY_CHEKCER : Mutex<PolicyChecher> = Mutex::new(PolicyChecher::default());
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

    pub fn single_shot_command_line_mode_check (&self, oneShotCmdArgs: OneShotCmdArgs) -> bool {


        info!("oneShotCmdArgs is {:?}", oneShotCmdArgs);
        if self.policy.debug_mode_opt.single_shot_command_line_mode == false {
            return false;
        }



        return self.is_cmd_allowed(&Role::DataOwner, &oneShotCmdArgs.args);
    }

    fn is_cmd_allowed (&self, role: &Role, reqArgs: &Vec<String>) ->bool {
        info!("is_cmd_allowed role {:?}, reqArgs: {:?}", role, reqArgs);
        if reqArgs.len() <= 0 {
            return false;
        }
        
        let req_cmd = reqArgs.get(0).unwrap();

        for conf in &self.policy.single_shot_command_line_mode_configs {

            if &conf.role == role {
                for cmd in &conf.allowed_cmd {
                    if req_cmd.eq(cmd) {
                        return true;
                    }

                }
                return false;
            }
        }

        false
   
    }

    fn is_path_allowed () -> bool {
        true
    }


}

