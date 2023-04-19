use qlib::shield_policy::*;
use shield::Vec;
use shield::String;


#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct EnvCmdBasedSecrets {
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct KbsSecrets {
    pub env_cmd_secrets: Option<EnvCmdBasedSecrets>,
    pub config_fils: Option<Vec<ConfigFile>>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct KbsPolicy {
    pub enable_policy_updata: bool,
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub privileged_user_key_slice: String,
}


