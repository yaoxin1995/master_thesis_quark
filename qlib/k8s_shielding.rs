
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use spin::mutex::Mutex;
use super::control_msg::*;
use super::path::*;

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

    pub fn printPolicy(&self) -> () {

        info!("default policy:{:?}" ,self.policy);
    }

    pub fn terminalEndpointerCheck (&self) -> bool {

        self.policy.debug_mode_opt.enable_terminal

    }


    /*
    TODO: 
        1. Pass credential of role to quark
        2. Encrypt the args on client side and decrypt them here
        3. Validate the credential with the help of KBS
        4. Chose the policy based on Role
     */
    pub fn singleShotCommandLineModeCheck (&self, oneShotCmdArgs: OneShotCmdArgs) -> bool {


        info!("oneShotCmdArgs is {:?}", oneShotCmdArgs);

        if self.policy.debug_mode_opt.single_shot_command_line_mode == false ||  oneShotCmdArgs.args.len() == 0 {
            return false;
        }

        let isCmdAllowed = self.isCmdAllowed(&Role::Host, &oneShotCmdArgs.args);

        info!("singleShotCommandLineModeCheck: role {:?}, cmd {:?}, isCmdAllowed: {:?}", Role::Host, oneShotCmdArgs.args[0], isCmdAllowed);

        // For now the path can only identify 3 type of path : abs path, relative path including "/" or "."
        // isPathAllowed can't identify the path such as "usr", "var" etc.
        // therefore,  ls usr, ls var will be allowd even though "var" and "usr" are not in the allowd dir
        // Todo: identify more dir type from args
        let isPathAllowd = self.isPathAllowed(&Role::Host, &oneShotCmdArgs.args, &oneShotCmdArgs.cwd);

        info!("singleShotCommandLineModeCheck: role {:?}, paths {:?}, isPathAllowd: {:?}", Role::Host, oneShotCmdArgs.args, isPathAllowd);

        return isCmdAllowed & isPathAllowd;
    }

    fn isCmdAllowed (&self, role: &Role, reqArgs: &Vec<String>) ->bool {
        info!("isCmdAllowed role {:?}, reqArgs: {:?}", role, reqArgs);
        if reqArgs.len() <= 0 {
            return false;
        }
        
        let reqCmd = reqArgs.get(0).unwrap();

        for conf in &self.policy.single_shot_command_line_mode_configs {

            if &conf.role == role {
                for cmd in &conf.allowed_cmd {
                    if reqCmd.eq(cmd) {
                        return true;
                    }

                }
                return false;
            }
        }
        false
    }

    fn isPathAllowed (&self, role: &Role, reqArgs: &Vec<String>, cwd: &str) -> bool {

        if reqArgs.len() == 1 {

            let subpaths = vec![cwd.to_string()];
            let allowedPaths= self.findAllowedPath(role);

            let isAllowed = self.IsSubpathCheck (subpaths, allowedPaths);

            info!("isPathAllowed: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}, isAllowed: {:?}", role, reqArgs, cwd, isAllowed);

            return isAllowed;


        }
        info!("isPathAllowed000: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}", role, reqArgs, cwd);
        let mut absPaths = Vec::new();
        let mut relPaths = Vec::new();
        //collect all path like structure including abs path, relative path, files (a.s)

        for e in reqArgs[1..].iter() {
            if e.len() > 0 && e.as_bytes()[0] == '-' as u8 {
                continue;
            }
            if IsPath(e) {
                let str = Clean(e);
                if IsAbs(&str) {
                    absPaths.push(str);
                    continue;
                }

                if IsRel(e) {
                    let str = Clean(e);
                    relPaths.push(str);
                    continue;
                }
            }


        }

        info!("relPaths {:?}, absPaths {:?}", relPaths, absPaths);

        // convert rel path to abs path
        for relPath in relPaths {
            let absPath = Join(cwd, &relPath);
            info!("absPath {:?}", absPath);
            absPaths.push(absPath);
        }

        let allowedPaths= self.findAllowedPath(role);

        if allowedPaths.len() <= 0 {
            return false;
        }

        let isAllowed = self.IsSubpathCheck (absPaths, allowedPaths);

        info!("isPathAllowed111: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}, isAllowed: {:?}", role, reqArgs, cwd, isAllowed);

        return isAllowed;
            

    }


    fn findAllowedPath (&self,  role: &Role) -> Vec<String> {

        let mut allowedPaths= &Vec::new();
        for conf in &self.policy.single_shot_command_line_mode_configs {

            if &conf.role == role {
                allowedPaths = &conf.allowed_dir;
            }
        }

        return allowedPaths.clone();
    }

    fn IsSubpathCheck (&self, subPaths: Vec<String>, paths: Vec<String>) -> bool {

        info!("IsSubpathCheck:  subPaths: {:?}, paths: {:?}", subPaths, paths);
        for absPath in subPaths {
            
            let mut isAllowd = false;
            for  allowedPath in &paths {
                if Clean(&absPath) == Clean(allowedPath) {
                    isAllowd = true;
                    break;
                }

                let (_, isSub) = IsSubpath(&absPath, &allowedPath);
                if  isSub {
                    isAllowd = true;
                    break;
                }
            }
            if !isAllowd {
                return false;
            }
        }
        true

    }

}

