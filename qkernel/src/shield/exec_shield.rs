
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use spin::RwLockWriteGuard;
use crate::aes_gcm::{
    aead::{OsRng, generic_array::{GenericArray, typenum::U32}, rand_core::RngCore},
};
use spin::rwlock::RwLock;
use qlib::control_msg::*;
use qlib::path::*;
use qlib::common::*;
use qlib::shield_policy::*;
use qlib::linux_def::*;
use sha2::{Sha256};
use hmac::{Hmac, Mac};
use base64ct::{Base64, Encoding};
use super::cryptographic_utilities::{prepareEncodedIoFrame, decrypt};
use shield::INODE_TRACKER;

const PRIVILEGE_KEYWORD_INDEX: usize = 0;
const HMAC_INDEX: usize = 1;
const ENCRYPTED_MESSAGE_INDEX: usize = 2;
const NONCE_INDEX: usize = 3;
const PRIVILEGE_KEYWORD: &str = "Privileged ";
const SESSION_ALLOCATION_REQUEST: &str = "Login";
const POLICYUPDATE_REQUEST: &str = "PolicyUpdate";

lazy_static! {
    pub static ref EXEC_AUTH_AC:  RwLock<ExecAthentityAcChekcer> = RwLock::new(ExecAthentityAcChekcer::default());
    pub static ref STDOUT_EXEC_RESULT_SHIELD:  RwLock<StdoutExecResultShiled> = RwLock::new(StdoutExecResultShiled::default());
}



#[derive(Debug, Default)]
pub struct StdoutExecResultShiled {
    policy: KbsPolicy,
    key: GenericArray<u8, U32>,
}


impl StdoutExecResultShiled{

    pub fn init(&mut self, policy: &KbsPolicy, key: &GenericArray<u8, U32>) -> () {
    
        self.policy = policy.clone();
       // self.key = policy.unwrap().secret.file_encryption_key.as_bytes().to_vec();
        self.key = key.clone();
    }


    pub fn encrypNormalIOStdouterr (&self, src: DataBuff, inode_id: u64) -> Result<DataBuff> {

        let inode_checker_locked =  INODE_TRACKER.read();
        inode_checker_locked.isInodeExist(&inode_id);
        let trackedInodeType = inode_checker_locked.getInodeType(&inode_id);

        let arg;
        match trackedInodeType {
            TrackInodeType::Stdout(args) => {
                arg = args;
            },
            TrackInodeType::Stderro (args) => {
                arg = args;
            },
            _ => {
                return Ok(src);
            },
        };



        let user_type = arg.exec_user_type;
        let stdio_type = arg.stdio_type;
    

        debug!("encryptContainerStdouterr 00000000, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
        // case 0: if this is a unprivileged exec req in single cmd mode
        if user_type.is_some() && user_type.as_ref().unwrap().eq(&UserType::Unprivileged) && stdio_type ==  StdioType::ExecProcessStdio {
            info!("case 0: if this is a unprivileged exec req in single cmd mode, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
            return Ok(src);
        }

        match stdio_type {
            // case 1: if this is subcontainer stdout / stderr
            StdioType::ContaienrStdio => {
                debug!("case 1:if this is subcontainer stdout / stderr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
                if self.policy.privileged_user_config.no_interactive_process_stdout_err_encryption == false {
                    return Ok(src);
                }
            },
            // case 2: if this is a privileged exec req in single cmd mode
            StdioType::ExecProcessStdio => {
                debug!("case 2:if this is subcontainer stdout / stderr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
                if self.policy.privileged_user_config.no_interactive_process_stdout_err_encryption == false {
                    return Ok(src);
                }
            },
            // case 3: if this is root container stdout / stderr
            StdioType::SandboxStdio => {
                debug!("case 3:if this is root container stdout / stderr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
                return Ok(src);
            },
            StdioType::SessionAllocationStdio(ref s) => {
                debug!("case 4:if this is session allocation request, user_type:{:?}, stdio_type {:?}, session {:?}", user_type, stdio_type, s);

                let encoded_session: Vec<u8> = postcard::to_allocvec(s).unwrap();
                let encrypted_session = prepareEncodedIoFrame(&encoded_session[..], &self.key).unwrap();
                // write session to stdout
                let mut buf= DataBuff::New(encrypted_session.len());
                buf.buf = encrypted_session;
                return Ok(buf);
            },
            StdioType::PolicyUpdate(ref update_res) => {


                let exit;
                {
                    exit = EXEC_AUTH_AC.read().auth_session.contains_key(&update_res.session_id);
                }
                debug!("case 5:if this is PolicyUpdate request, user_type:{:?}, stdio_type {:?}, session exist {:?}", user_type, stdio_type, exit);


                let result = if update_res.result {
                    "policy update is succeed".to_string()

                } else {
                    "qkernel doesn't allow policy update".to_string()
                };

                let encodedOutBoundDate = prepareEncodedIoFrame(result.as_bytes(), &self.key).unwrap();
                let mut buf = DataBuff::New(encodedOutBoundDate.len());
                buf.buf = encodedOutBoundDate.clone();            
                return Ok(buf);
            }
        }
        debug!("case5 encryptContainerStdouterr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
        let rawData= src.buf.clone();

        let str = String::from_utf8_lossy(&rawData).to_string();

        debug!("stdout is : {:?}", str);

        let encodedOutBoundDate = prepareEncodedIoFrame(rawData.as_slice(), &self.key).unwrap();
        assert!(encodedOutBoundDate.len() != 0);

        let mut res = DataBuff::New(encodedOutBoundDate.len());


        res.buf = encodedOutBoundDate.clone();

        // for (i, el) in encodedOutBoundDate.iter().enumerate(){
        //     assert!(res.buf[i] == *el);
        // }
        
        Ok(res)
    }

}


/***********************************************Exec Authentication and Access Control************************************************* */



#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct ExecSession {
    session_id: u32,
    counter: u32,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct PolicyUpdate {
    pub new_policy: KbsPolicy,
    pub is_updated: bool,
    pub session_id: u32
}

pub fn verify_hmac (key_slice : &[u8], message: &String, base64_encoded_code: &String) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac : HmacSha256 = hmac::Mac::new_from_slice(key_slice).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());


    let code_bytes = Base64::decode_vec(base64_encoded_code).unwrap();

    let res = mac.verify_slice(&code_bytes[..]);

    if res.is_ok() {
        return true;
    } else {
        return false;
    }
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
    policy: KbsPolicy,
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
    pub fn init(&mut self, hmac_key_slice: &Vec<u8>, decryption_key: &GenericArray<u8, U32>, policy: &KbsPolicy) -> () {
        self.authenticated_reqs= BTreeMap::new();
        self.hmac_key_slice = hmac_key_slice.clone();
        self.decryption_key = decryption_key.clone();
        self.policy = policy.clone();
        self.auth_session = BTreeMap::new();
    }


    pub fn update(&mut self, hmac_key_slice: &Vec<u8>, decryption_key: &GenericArray<u8, U32>, policy: &KbsPolicy) -> () {
        self.hmac_key_slice = hmac_key_slice.clone();
        self.decryption_key = decryption_key.clone();
        self.policy = policy.clone();
    }
}

pub fn exec_req_authentication (exec_req: ExecAuthenAcCheckArgs) -> bool {

    if exec_req.args.len() < 1 {
        return false;
    }

    let mut exec_ac = EXEC_AUTH_AC.write();

    match exec_req.args.get(PRIVILEGE_KEYWORD_INDEX).unwrap().as_str() {
        PRIVILEGE_KEYWORD => return verify_privileged_req(exec_req, &mut exec_ac),
        _ => return verify_unprivileged_req(exec_req, &mut exec_ac),
    }
}


fn verify_privileged_req (exec_req_args: ExecAuthenAcCheckArgs, exec_ac: &mut RwLockWriteGuard<ExecAthentityAcChekcer>) -> bool {

    info!("verify_privileged_req, exec_req_args {:?}", exec_req_args);
    // Hmac authentication
    let mut privileged_cmd = exec_req_args.args.clone();
    let mut cmd_in_plain_text = match verify_privileged_exec_cmd(&mut privileged_cmd, &exec_ac.hmac_key_slice, &exec_ac.decryption_key) {
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

    
        exec_ac.auth_session.insert(s.session_id, s.clone());

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
        if !exec_ac.auth_session.contains_key(&session_id) {
            info!("verify_privileged_req,  replay case 1: attacker send a request that belongs to a old session (Sessions that existed before the vm was restarted");
            return false;
        }

        let mut session = exec_ac.auth_session.remove(&session_id).unwrap();

        // replay case 2: attacker send a old request that belongs to the current session
        if counter < session.counter {
            info!("verify_privileged_req, replay case 2: attacker send a old request that belongs to the current session , counter {:?}. session.counter {:?}",counter,  session.counter);
            return false;
        }

        session.counter = session.counter + 1;

        exec_ac.auth_session.insert(session.session_id, session.clone());

        
        cmd_in_plain_text.remove(0);
        cmd_in_plain_text.remove(0);

        let cmd = cmd_in_plain_text[0].clone();

        if cmd.eq(POLICYUPDATE_REQUEST) {
            info!("verify_privileged_req, cmd.eq(POLICYUPDATE_REQUEST) cmd_in_plain_text {:?}", cmd_in_plain_text[1]);

            let policy_in_base64_string = &cmd_in_plain_text[1];
            let policy_in_json_slice = Base64::decode_vec(policy_in_base64_string).unwrap();

            let policy = serde_json::from_slice(&policy_in_json_slice).unwrap();

            let policy_update = PolicyUpdate {
                new_policy: policy,
                is_updated: false,
                session_id: session_id,
            };

            exec_req_args.req_type = ExecRequestType::PolicyUpdate(policy_update);
            cmd_in_plain_text = vec!["ls".to_string(), "/".to_string()];

            info!("verify_privileged_req, cmd.eq(POLICYUPDATE_REQUEST) cmd_in_plain_text {:?}, session id exist {:?}", cmd_in_plain_text[1], exec_ac.auth_session.contains_key(&session_id));

        } 
        info!("verify_privileged_req, cmd_in_plain_text {:?}", cmd_in_plain_text);
    }

    match exec_req_args.req_type {
        ExecRequestType::Terminal => {
            info!("verify_privileged_req, exec_req_args.req_type {:?}", exec_req_args.req_type);
            let policy = &exec_ac.policy;
            let res = check_oneshot_cmd_mode_access_control(UserType::Privileged, &cmd_in_plain_text, policy, &exec_req_args.cwd);
            if res == false {
                return false;
            }

        },
        ExecRequestType::SingleShotCmdMode =>{
            info!("verify_privileged_req, exec_req_args.req_type {:?}", exec_req_args.req_type);
            let policy = &exec_ac.policy;
            let res = check_oneshot_cmd_mode_access_control(UserType::Privileged, &cmd_in_plain_text, policy, &exec_req_args.cwd);
            if res == false {
                return false;
            }
        },
        ExecRequestType::SessionAllocationReq(ref _s) => {
            info!("verify_privileged_req, exec_req_args.req_type {:?}", exec_req_args.req_type);

        },
        ExecRequestType::PolicyUpdate(ref arg) => {
            info!("verify_privileged_req, exec_req_args.req_type {:?}, policy {:?}", exec_req_args.req_type, arg);

            let policy_update;
            if exec_ac.policy.enable_policy_updata {
                super::policy_update(&arg.new_policy, exec_ac).unwrap();
                policy_update = PolicyUpdate {
                    new_policy: arg.new_policy.clone(),
                    is_updated: true,
                    session_id: arg.session_id
                };

                info!("verify_privileged_req session id exist {:?}", exec_ac.auth_session.contains_key(&arg.session_id));
                exec_req_args.req_type = ExecRequestType::PolicyUpdate(policy_update);
            }



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

    exec_ac.authenticated_reqs.insert(exec_req_args.exec_id, exec_req);
    return true;
}

fn verify_unprivileged_req (exec_req_args: ExecAuthenAcCheckArgs, exec_ac: &mut RwLockWriteGuard<ExecAthentityAcChekcer>) -> bool {

    info!("verify_unprivileged_req, exec_req_args {:?}", exec_req_args);

    let cmd_in_plain_text = &exec_req_args.args;
    let policy = &exec_ac.policy;
    //TODO Access Control
    match exec_req_args.req_type {
        ExecRequestType::Terminal => {
            let res = check_oneshot_cmd_mode_access_control(UserType::Unprivileged, &cmd_in_plain_text, policy, &exec_req_args.cwd);
            if res == false {
                return false;
            }

        },
        ExecRequestType::SingleShotCmdMode =>{
            let res = check_oneshot_cmd_mode_access_control(UserType::Unprivileged, &cmd_in_plain_text, policy, &exec_req_args.cwd);
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

    exec_ac.authenticated_reqs.insert(exec_req_args.exec_id, exec_req);

    return true;
}

fn check_oneshot_cmd_mode_access_control (user_type: UserType, cmd : &Vec<String>, policy: &KbsPolicy, cwd: &String) -> bool {


    let allowed_cmds;
    let allowed_pathes;
    let is_sigle_shot_cmd_enabled = match user_type {
        UserType::Privileged => {
            allowed_cmds = &policy.privileged_user_config.allowed_cmd;
            allowed_pathes = &policy.privileged_user_config.allowed_dir;

            info!("check_oneshot_cmd_mode_access_control UserType::Privileged, cmd {:?}, allowed_cmds {:?}, allowed_pathes {:?} cwd {:?}", cmd, allowed_cmds, allowed_pathes, cwd);
            if allowed_cmds.is_empty() {
                false
            } else {
                true
            }
        },
        UserType::Unprivileged => {
            allowed_cmds = &policy.unprivileged_user_config.allowed_cmd;
            allowed_pathes = &policy.unprivileged_user_config.allowed_dir;
            info!("check_oneshot_cmd_mode_access_control UserType::Unprivileged, cmd {:?}, allowed_cmds {:?}, allowed_pathes {:?} cwd {:?}", cmd, allowed_cmds, allowed_pathes, cwd);

            if allowed_cmds.is_empty() {
                false
            } else {
                true
            }

        }
    };
    if is_sigle_shot_cmd_enabled == false {
        return false;
    }
    
    let is_cmd_path_allowed = single_shot_cmd_check(cmd, allowed_cmds, allowed_pathes, cwd);

    return is_cmd_path_allowed;
}

fn single_shot_cmd_check (cmd_args: &Vec<String>,  allowed_cmds: &Vec<String>, allowed_dir: &Vec<String>, cwd: &String) -> bool {

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

        if cmd[0] == "/bin/sh" || cmd[0] == "/bin/bash" || cmd[0] == "sh" {
            return true
        }

        let sub_paths = vec![cwd.to_string()];

        let is_allowed = is_subpaht_check(&sub_paths, allowed_paths);

        info!("is_path_allowed: cmd {:?} cwd: {:?}, allowed_path: {:?} isAllowed: {:?}", cmd, cwd, allowed_paths, is_allowed);

        return true;
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
fn is_subpath(subpath: &str, path: &str) -> (String, bool) {

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
