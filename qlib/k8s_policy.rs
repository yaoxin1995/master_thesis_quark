// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


use alloc::string::String;
use alloc::vec::Vec;

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



