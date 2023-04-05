
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use crate::aes_gcm::{
    aead::{OsRng, generic_array::{GenericArray, typenum::U32}, rand_core::RngCore},
};
use spin::rwlock::RwLock;
use crate::qlib::control_msg::*;
use crate::qlib::path::*;
use crate::qlib::common::*;
use crate::qlib::shield_policy::*;
use crate::qlib::linux_def::*;
use base64ct::{Base64, Encoding};
use super::cryptographic_utilities::{decrypt};

const PRIVILEGE_KEYWORD_INDEX: usize = 0;
const HMAC_INDEX: usize = 1;
const ENCRYPTED_MESSAGE_INDEX: usize = 2;
const NONCE_INDEX: usize = 3;
const PRIVILEGE_KEYWORD: &str = "Privileged ";
const SESSION_ALLOCATION_REQUEST: &str = "Login";

lazy_static! {
    pub static ref EXEC_AUTH_AC:  RwLock<ExecAthentityAcChekcer> = RwLock::new(ExecAthentityAcChekcer::default());
    pub static ref STDOUT_EXEC_RESULT_SHIELD:  RwLock<StdoutExecResultShiled> = RwLock::new(StdoutExecResultShiled::default());
}



#[derive(Debug, Default)]
pub struct StdoutExecResultShiled {
    policy: Policy,
    key: GenericArray<u8, U32>,
}


impl StdoutExecResultShiled{

    pub fn init(&mut self, policy: &Policy, key: &GenericArray<u8, U32>) -> () {
    
        self.policy = policy.clone();
       // self.key = policy.unwrap().secret.file_encryption_key.as_bytes().to_vec();
        self.key = key.clone();
    }


    pub fn encryptContainerStdouterr (&self, _src: DataBuff, _user_type: Option<UserType>, _stdio_type: StdioType) -> DataBuff {


        let  res = DataBuff::New(1);

        res

    }

}


/***********************************************Exec Authentication and Access Control************************************************* */



#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct ExecSession {
    session_id: u32,
    counter: u32,
}


pub fn verify_hmac (_key_slice : &[u8], _message: &String, _base64_encoded_code: &String) -> bool {
    true
}

/**
 * Privilege request format:                  
 * *********************** * *********************** ************************
 *         Privileged / hmac(Privileged|Session_id|Conter|cmd|args, privilegd_user_key) /  (Session_id + Conter + cmd + args) / nonce
 * ************************ ************************************************
 */
pub fn verify_privileged_exec_cmd(privileged_cmd: &mut Vec<String>, key_slice: &[u8], key: &GenericArray<u8, U32>) -> Result<Vec<String>>  {

    assert!(privileged_cmd.len() > 2);

    if privileged_cmd.len() != 4 {
        return  Err(Error::Common(format!("the privileged_cmd len is 4, len  {:?}, privileged_cmd verification failed", privileged_cmd.len())));
    }

    info!("verify_privileged_exec_cmd {:?}", privileged_cmd);

    let base64_encrypted_cmd = privileged_cmd.get(ENCRYPTED_MESSAGE_INDEX).unwrap();
    let base64_nonce = privileged_cmd.get(NONCE_INDEX).unwrap();

    let nonce_bytes = Base64::decode_vec(base64_nonce)
    .map_err(|e| Error::Common(format!("failed to decode the nonce, the error is {:?}, privileged_cmd verification failed", e)))?;

    let encrypted_cmd_bytes = Base64::decode_vec(base64_encrypted_cmd)
    .map_err(|e| Error::Common(format!("failed to decode the nonce, the error is {:?}, privileged_cmd verification failed", e)))?;

    let decrypted_cmd = decrypt(encrypted_cmd_bytes.as_slice(), nonce_bytes.as_slice(), key)
    .map_err(|e| Error::Common(format!("failed to decrypted the cmd message, the error is {:?}, privileged_cmd verification failed", e)))?;

    let cmd_string = String::from_utf8(decrypted_cmd)
    .map_err(|e| Error::Common(format!("failed to turn the cmd from bytes to string, the error is {:?}, privileged_cmd verification failed", e)))?;

    let mut hmac_message = privileged_cmd.get(PRIVILEGE_KEYWORD_INDEX).unwrap().clone();
    hmac_message.push_str(&cmd_string);

    let base64_hmac = privileged_cmd.get(HMAC_INDEX).unwrap();

    let hmac_verify_res = verify_hmac(key_slice, &hmac_message, base64_hmac);
    if hmac_verify_res == false {
        return Err(Error::Common(format!("hmac verification failed, privileged_cmd verification failed")));
    }

    let split = cmd_string.split_whitespace();
    let cmd_list = split.collect::<Vec<&str>>().iter().map(|&s| s.to_string()).collect::<Vec<String>>();

    info!("verification result  {:?}", cmd_list);
    return Ok(cmd_list);
}

#[derive(Debug, Default)]
pub struct ExecAthentityAcChekcer {
    policy: Policy,
    pub hmac_key_slice: Vec<u8>,
    pub decryption_key: GenericArray<u8, U32>,
    pub authenticated_reqs: BTreeMap<String, AuthenticatedExecReq>,
    pub auth_session: BTreeMap<u32, ExecSession>,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum UserType {
    Privileged,  // define a white list
    #[default]
    Unprivileged,  // define a black list
}


#[derive(Debug, Default)]
pub struct AuthenticatedExecReq {
    pub exec_id: String,
    pub args: Vec<String>,  // args in plaintext
    pub env: Vec<String>,
    pub cwd: String,
    pub exec_type: ExecRequestType,
    pub user_type: UserType,
}

impl ExecAthentityAcChekcer{
    pub fn init(&mut self, hmac_key_slice: &Vec<u8>, decryption_key: &GenericArray<u8, U32>, policy: &Policy) -> () {
        self.authenticated_reqs= BTreeMap::new();
        self.hmac_key_slice = hmac_key_slice.clone();
        self.decryption_key = decryption_key.clone();
        self.policy = policy.clone();
        self.auth_session = BTreeMap::new();
    }

    pub fn exec_req_authentication (&mut self, exec_req: ExecAuthenAcCheckArgs) -> bool {

        if exec_req.args.len() < 1 {
            return false;
        }

        match exec_req.args.get(PRIVILEGE_KEYWORD_INDEX).unwrap().as_str() {
            PRIVILEGE_KEYWORD => return self.verify_privileged_req(exec_req),
            _ => return self.verify_unprivileged_req(exec_req),
        }
    }


    fn verify_privileged_req (&mut self, exec_req_args: ExecAuthenAcCheckArgs) -> bool {

        info!("verify_privileged_req, exec_req_args {:?}", exec_req_args);
        // Hmac authentication
        let mut privileged_cmd = exec_req_args.args.clone();
        let mut cmd_in_plain_text = match verify_privileged_exec_cmd(&mut privileged_cmd, &self.hmac_key_slice, &self.decryption_key) {
            Ok(args) => args,
            Err(e) => {
                info!("privileged req authentication failed {:?}", e);
                return false;
            }
        };

        // Session allocation request:
        let cmd = cmd_in_plain_text.get(0).unwrap();
        info!("verify_privileged_req cmd {:?} SESSION_ALLOCATION_REQUEST {:?}  cmd.eq(SESSION_ALLOCATION_REQUEST):{:?}", 
                                cmd, SESSION_ALLOCATION_REQUEST, cmd.eq(SESSION_ALLOCATION_REQUEST));
        let mut exec_req_args = exec_req_args.clone();
        if cmd.eq(SESSION_ALLOCATION_REQUEST) {
            let mut rng = OsRng;
            let s = ExecSession {
                session_id: rng.next_u32(),
                counter: rng.next_u32(),
            };
            self.auth_session.insert(s.session_id, s.clone());
            exec_req_args.req_type = ExecRequestType::SessionAllocationReq(s);
            cmd_in_plain_text = vec!["ls".to_string(), "/".to_string()];

        } else {
            // Reqeust resource request:

            // check if counter and session id are valid
            const SESSION_ID_INDEX: usize = 0;
            const SESSION_COUNTER_INDEX: usize = 1;

            let session_id = cmd_in_plain_text.get(SESSION_ID_INDEX).unwrap().parse::<u32>().unwrap();
            let counter = cmd_in_plain_text.get(SESSION_COUNTER_INDEX).unwrap().parse::<u32>().unwrap();

            // replay case 1: attacker send a request that belongs to a old session (Sessions that existed before the vm was restarted)
            if !self.auth_session.contains_key(&session_id) {
                info!("verify_privileged_req,  replay case 1: attacker send a request that belongs to a old session (Sessions that existed before the vm was restarted");
                return false;
            }

            let mut session = self.auth_session.remove(&session_id).unwrap();

            // replay case 2: attacker send a old request that belongs to the current session
           if counter < session.counter {
                info!("verify_privileged_req, replay case 2: attacker send a old request that belongs to the current session , counter {:?}. session.counter {:?}",counter,  session.counter);
                return false;
            }

            session.counter = session.counter + 1;

            self.auth_session.insert(session.session_id, session.clone());

            
            cmd_in_plain_text.remove(0);
            cmd_in_plain_text.remove(0);

            info!("verify_privileged_req, cmd_in_plain_text {:?}", cmd_in_plain_text);
        }

        match exec_req_args.req_type {
            ExecRequestType::Terminal => {
                info!("verify_privileged_req, exec_req_args.req_type {:?}", exec_req_args.req_type);
                let res = self.check_terminal_access_control (UserType::Privileged);

                if res == false {
                    return false;
                }

            },
            ExecRequestType::SingleShotCmdMode =>{
                info!("verify_privileged_req, exec_req_args.req_type {:?}", exec_req_args.req_type);
                let allowed_cmd = &self.policy.privileged_user_config.single_shot_command_line_mode_configs.allowed_cmd;
                let allowed_path = &self.policy.privileged_user_config.single_shot_command_line_mode_configs.allowed_dir;
                let res = self.check_oneshot_cmd_mode_access_control(UserType::Privileged, &cmd_in_plain_text, allowed_cmd, allowed_path, &exec_req_args.cwd);
                if res == false {
                    return false;
                }
            },
            ExecRequestType::SessionAllocationReq(ref _s) => {
                info!("verify_privileged_req, exec_req_args.req_type {:?}", exec_req_args.req_type);

            }
            
        }

        let exec_req = AuthenticatedExecReq {
            exec_id : exec_req_args.exec_id.clone(),
            args: cmd_in_plain_text,
            env: exec_req_args.env.clone(),
            cwd: exec_req_args.cwd.clone(),
            user_type: UserType::Privileged,
            exec_type:exec_req_args.req_type.clone()
        };

        self.authenticated_reqs.insert(exec_req_args.exec_id, exec_req);

        return true;
    }

    fn verify_unprivileged_req (&mut self, exec_req_args: ExecAuthenAcCheckArgs) -> bool {

        info!("verify_unprivileged_req, exec_req_args {:?}", exec_req_args);

        let cmd_in_plain_text = &exec_req_args.args;
        //TODO Access Control
        match exec_req_args.req_type {
            ExecRequestType::Terminal => {
                let res = self.check_terminal_access_control (UserType::Unprivileged);

                if res == false {
                    return false;
                }

            },
            ExecRequestType::SingleShotCmdMode =>{
                let allowed_cmd = &self.policy.unprivileged_user_config.single_shot_command_line_mode_configs.allowed_cmd;
                let allowed_path = &self.policy.unprivileged_user_config.single_shot_command_line_mode_configs.allowed_dir;
                let res = self.check_oneshot_cmd_mode_access_control(UserType::Unprivileged, &cmd_in_plain_text, allowed_cmd, allowed_path, &exec_req_args.cwd);
                if res == false {
                    return false;
                }
            },
            _ => return false,            
        }

        let exec_req = AuthenticatedExecReq {
            exec_id : exec_req_args.exec_id.clone(),
            args: cmd_in_plain_text.clone(),
            env: exec_req_args.env.clone(),
            cwd: exec_req_args.cwd.clone(),
            user_type: UserType::Unprivileged,
            exec_type:exec_req_args.req_type.clone()
        };

        self.authenticated_reqs.insert(exec_req_args.exec_id, exec_req);

        return true;
    }


    fn check_terminal_access_control (&self, user_type: UserType) -> bool {

        match user_type {
            UserType::Privileged => {
                return self.policy.privileged_user_config.enable_terminal;
            },
            UserType::Unprivileged => {
                return self.policy.unprivileged_user_config.enable_terminal;
            }
        }
    }


    fn check_oneshot_cmd_mode_access_control (&self, user_type: UserType, cmd : &Vec<String>, allowed_cmds: &Vec<String>, allowed_pathes: &Vec<String>, cwd: &String) -> bool {

        let is_sigle_shot_cmd_enabled = match user_type {
            UserType::Privileged => {
                info!("check_oneshot_cmd_mode_access_control UserType::Privileged, cmd {:?}, allowed_cmds {:?}, allowed_pathes {:?} cwd {:?}", cmd, allowed_cmds, allowed_pathes, cwd);
                self.policy.privileged_user_config.enable_single_shot_command_line_mode
            },
            UserType::Unprivileged => {
                info!("check_oneshot_cmd_mode_access_control UserType::Unprivileged, cmd {:?}, allowed_cmds {:?}, allowed_pathes {:?} cwd {:?}", cmd, allowed_cmds, allowed_pathes, cwd);
                self.policy.unprivileged_user_config.enable_single_shot_command_line_mode
            }
        };
        if is_sigle_shot_cmd_enabled == false {
            return false;
        }
       
        let is_cmd_path_allowed = single_shot_cmd_check(cmd, allowed_cmds, allowed_pathes, cwd);

        return is_cmd_path_allowed;
    }

}




pub fn single_shot_cmd_check (cmd_args: &Vec<String>,  allowed_cmds: &Vec<String>, allowed_dir: &Vec<String>, cwd: &String) -> bool {

    if cmd_args.len() == 0 {
        return false;
    }

    let cmd = cmd_args.get(0).unwrap();

    let is_cmd_allowed = is_cmd_allowed(cmd, allowed_cmds);
    if is_cmd_allowed == false {
        return false;
    }

    // For now the path can only identify 3 type of path : abs path, relative path including "/" or "."
    // isPathAllowed can't identify the path such as "usr", "var" etc.
    // therefore,  ls usr, ls var will be allowd even though "var" and "usr" are not in the allowd dir
    // Todo: identify more dir type from args
    let isPathAllowd = is_path_allowed(cmd_args, &allowed_dir, cwd);

    info!("singleShotCommandLineModeCheck isPathAllowd: {:?}", isPathAllowd);

    return isPathAllowd;
}

fn is_cmd_allowed (cmd: &String, allowed_cmd_list: &Vec<String>) ->bool {
    info!("is_cmd_allowed cmd {:?}, allowed_cmd_list: {:?}", cmd, allowed_cmd_list);

    if allowed_cmd_list.len() == 0 {
        return false;
    }


    for cmd_in_allowed_list in allowed_cmd_list {

        if cmd_in_allowed_list.eq(cmd) {
            return true;
        }
    }
    return false;
}

fn is_path_allowed (cmd: &Vec<String>, allowed_paths: &Vec<String>, cwd: &str) -> bool {

    if cmd.len() == 1 {

        let sub_paths = vec![cwd.to_string()];

        let is_allowed = is_subpaht_check(&sub_paths, allowed_paths);

        info!("is_path_allowed: cmd {:?} cwd: {:?}, allowed_path: {:?} isAllowed: {:?}", cmd, cwd, allowed_paths, is_allowed);

        return is_allowed;
    }

    info!("is_path_allowed: cmd {:?} cwd: {:?}, allowed_path: {:?}", cmd, cwd, allowed_paths);
    let mut abs_paths = Vec::new();
    let mut rel_paths = Vec::new();
    //collect all path like structure including abs path, relative path, files (a.s)

    for e in cmd[1..].iter() {
        if e.len() > 0 && e.as_bytes()[0] == '-' as u8 {
            continue;
        }
        if IsPath(e) {
            let str = Clean(e);
            if IsAbs(&str) {
                abs_paths.push(str);
                continue;
            }

            if IsRel(e) {
                let str = Clean(e);
                rel_paths.push(str);
                continue;
            }
        }


    }

    info!("relPaths {:?}, absPaths {:?}", rel_paths, abs_paths);
    // convert rel path to abs path
    for relPath in rel_paths {
        let absPath = Join(cwd, &relPath);
        info!("absPath {:?}", absPath);
        abs_paths.push(absPath);
    }

    if allowed_paths.len() <= 0 {
        return false;
    }

    let isAllowed = is_subpaht_check (&abs_paths, allowed_paths);

    info!("isPathAllowed111: isAllowed cwd: {:?}, isAllowed: {:?}",cwd, isAllowed);

    return isAllowed;
        

}


fn is_subpaht_check (abs_paths_in_cmd: &Vec<String>, allowed_pathes: &Vec<String>) -> bool {

    info!("IsSubpathCheck:  subPaths: {:?}, paths: {:?}", abs_paths_in_cmd, allowed_pathes);
    for absPath in abs_paths_in_cmd {
            
        let mut is_allowd = false;
        for  allowed_path in allowed_pathes {
            if Clean(&absPath) == Clean(allowed_path) {
                is_allowd = true;
                break;
            }

            let (_, isSub) = is_subpath(&absPath, &allowed_path);
            info!("IsSubpathCheck22123:  path_in_cmd: {:?}, allowed_path: {:?}, is_sub {:?}", absPath, allowed_path, isSub);
            if  isSub {
                is_allowd = true;
                break;
            }
        }
        if !is_allowd {
            return false;
        }
    }
    true

}

// IsSubpath checks whether the first path is a (strict) descendent of the
// second. If it is a subpath, then true is returned along with a clean
// relative path from the second path to the first. Otherwise false is
// returned.
pub fn is_subpath(subpath: &str, path: &str) -> (String, bool) {

    let mut cleanPath = Clean(path);
    let cleanSubpath = Clean(subpath);

    if cleanPath.len() == 0 {
        cleanPath += "/";
    }

    if cleanPath == cleanSubpath {
        return ("".to_string(), false);
    }
    info!("cleanSubpath11111 {:?}, cleanPath {:?}", cleanSubpath, cleanPath);

    if has_prefix(&cleanSubpath, &cleanPath) {
        return (TrimPrefix(&cleanSubpath, &cleanPath), true);
    }

    return ("".to_string(), false);
}

pub fn has_prefix(s: &str, prefix: &str) -> bool {
    info!("s.len {:?}, prefix.len() {:?}, s[..prefix.len()] :{:?}, prefix[..] {:?}", s.len(),  prefix.len(), s,  prefix);
    return s.len() >= prefix.len() && s[..prefix.len()] == prefix[..];
}
