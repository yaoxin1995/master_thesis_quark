use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use spin::rwlock::RwLock;
use crate::aes_gcm::{
    aead::{Aead, KeyInit, OsRng, generic_array::{GenericArray, typenum::U32}, rand_core::RngCore},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
    Key,
};

use qlib::control_msg::*;
use qlib::path::*;
use qlib::common::*;
use qlib::shield_policy::*;


use super::qlib::linux_def::*;
use super::qlib::kernel::task::*;
use super::qlib::kernel::{SHARESPACE, IOURING, fd::*, boot::controller::HandleSignal};
use sha2::{Sha256};
use hmac::{Hmac, Mac};
use base64ct::{Base64, Encoding};
use crate::qlib::kernel::sev_guest::*;

lazy_static! {
    pub static ref TERMINAL_SHIELD:  RwLock<TerminalShield> = RwLock::new(TerminalShield::default());
    pub static ref INODE_TRACKER:  RwLock<InodeTracker> = RwLock::new(InodeTracker::default());
    pub static ref EXEC_AUTH_AC:  RwLock<ExecAthentityAcChekcer> = RwLock::new(ExecAthentityAcChekcer::default());
    pub static ref STDOUT_EXEC_RESULT_SHIELD:  RwLock<StdoutExecResultShiled> = RwLock::new(StdoutExecResultShiled::default());
}


#[derive(Debug, Default)]
pub struct TerminalShield {
    key: GenericArray<u8, U32>,
}

    
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct IoFrame {
    pub nonce: Vec<u8>,
    // length: usize,
     // encrypted payload structure using aes-gcm
    pub pay_load: Vec<u8>,
}
    
#[derive(Serialize, Deserialize, Debug, Default,Clone)]
pub struct PayLoad {
    pub counter: i64,
    pub data: Vec<u8>,
}


pub fn init_shielding_layer (policy: Option<&Policy>) ->() {

    // TODO: Use KEY_SLICE and DEDAULT_VMPK sent from secure client
    const KEY_SLICE: &[u8; 32] = b"a very simple secret key to use!";
    const DEDAULT_VMPK: u32 = 0;


    info!("init_shielding_layer default policy:{:?}" ,policy);


    let encryption_key = Key::<Aes256Gcm>::from_slice(KEY_SLICE).clone();
    let policy = policy.unwrap();

    let mut termianl_shield = TERMINAL_SHIELD.write();
    termianl_shield.init(policy, &encryption_key);


    let mut inode_tracker = INODE_TRACKER.write();
    inode_tracker.init();

    let mut exec_access_control = EXEC_AUTH_AC.write();
    exec_access_control.init(&KEY_SLICE.to_vec(), &encryption_key, policy);

    let mut stdout_exec_result_shield = STDOUT_EXEC_RESULT_SHIELD.write();
    stdout_exec_result_shield.init(policy, &encryption_key);


    // init sev guest driver
    GUEST_SEV_DEV.write().init(0);

    
}

/************************************Encryption, Decryption, Encoding, Decoding Untilities****************************/
    
    /// Nonce: unique per message.
    /// 96-bits (12 bytes)
const NONCE_LENGTH: usize = 12;

fn encrypt(plain_txt: &[u8], key: &GenericArray<u8, U32>) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(key);

    let mut nonce_rnd = vec![0; NONCE_LENGTH];
    random_bytes(&mut nonce_rnd);
    let nonce = Nonce::from_slice(&nonce_rnd);

    let encrypt_msg = cipher.encrypt(nonce, plain_txt).map_err(|e| Error::Common(format!("failed to encryp the data error {:?}", e)))?;

    let mut cipher_txt = Vec::new();
    // cipher_txt.extend_from_slice(&nonce_rnd);
    cipher_txt.extend(encrypt_msg);
    Ok((cipher_txt, nonce_rnd.to_vec()))
}

fn decrypt(cipher_txt: &[u8], nouce: &[u8], key: &GenericArray<u8, U32>) -> Result<Vec<u8>> {
    // if cipher_txt.len() <= NONCE_LENGTH {
    //     bail!("cipher text is invalid");
    // }
    // let key = GenericArray::from_slice(self.key.as_slice());
    let cipher = Aes256Gcm::new(key);
    // let nonce_rnd = &cipher_txt[..NONCE_LENGTH];
    let nonce = Nonce::from_slice(nouce);
    let plain_txt = cipher
        .decrypt(nonce, &cipher_txt[..])
        .map_err(|e| Error::Common(format!("failed to dencryp the data error {:?}", e)))?;
    Ok(plain_txt)
}
    
fn random_bytes(slice: &mut [u8]) -> (){
    // let mut rmd_nonce= Vec::with_capacity(NONCE_LENGTH);
    // getrandom(&mut rmd_nonce).unwrap();
    assert!(slice.len() == NONCE_LENGTH);
    let mut rng = OsRng;
    rng.fill_bytes(slice);
    info!("generate nounce {:?}", slice);
    // rmd_nonce
    // thread_rng().gen::<[u8; NONCE_LENGTH]>()
}

fn prepareEncodedIoFrame(plainText :&[u8], key: &GenericArray<u8, U32>) -> Result<Vec<u8>> {
    
    let mut payload = PayLoad::default();
    payload.counter = 1;
    payload.data = plainText.to_vec();
    assert!(payload.data.len() == plainText.len());

    let encoded_payload: Vec<u8> = postcard::to_allocvec(&payload).unwrap();

    let mut io_frame = IoFrame::default();

    (io_frame.pay_load, io_frame.nonce)= encrypt(encoded_payload.as_ref(), key).unwrap();

    let encoded_frame = postcard::to_allocvec_cobs(&io_frame).unwrap();

    Ok(encoded_frame)
}


fn getDecodedPayloads(encoded_payload :&Vec<u8>, key: &GenericArray<u8, U32>) -> Result<Vec<PayLoad>> {

    let mut payloads = Vec::new();
    let mut frame;
    let mut payloads_slice= encoded_payload.as_slice();

    while payloads_slice.len() > 0 {
         (frame , payloads_slice) =  postcard::take_from_bytes::<IoFrame>(payloads_slice.as_ref()).unwrap();
        // let frame2:IoFrame = bincode::deserialize(encoded12[]).unwrap();
        // print!("frame111111111111 : {:?}\n", frame1);
        
    
        let decrypted = decrypt(&frame.pay_load, &frame.nonce, key).unwrap();
        let payload:PayLoad = postcard::from_bytes(decrypted.as_ref()).unwrap();

        payloads.push(payload);
    
    
        // print!("decrypted22222222222 {:?}, PLAIN_TEXT{:?}\n", payload, PLAIN_TEXT1.as_ref());

        // print!("payload111 :{:?}\n", &payload);
        if payloads_slice.len() == 0 {
            break;
        }
    }
    // print!("payloads22222 :{:?}\n", payloads);
    Ok(payloads)

}

/****************************Inode Traker ******************************************* */

#[derive(Debug, Default)]
pub struct InodeTracker {
    inode_track: BTreeMap<u64, TrackInodeType>,
}

impl InodeTracker {

    pub fn init(&mut self) -> () {
        self.inode_track= BTreeMap::new();
    }

    
    pub fn addInoteToTrack(&mut self, key: u64, value: TrackInodeType) -> (){

        info!("add inode id {:?}, type:{:?}", key, value);
        self.inode_track.insert(key, value);
    }

    pub fn rmInoteToTrack(&mut self, key: u64) -> (){

        let res = self.inode_track.remove_entry(&key);
        let (_k, _v) = res.unwrap();
        info!("removed inode id {:?}, type:{:?}", _k, _v);
    }

    pub fn isInodeExist(&self, key: &u64) -> bool {
        info!("isInodeExist, key{:?} , exist{:?}", key ,self.inode_track.contains_key(key));
        self.inode_track.contains_key(key)
    }


    pub fn getInodeType (&self, key: &u64) -> TrackInodeType{
        
        let res =  self.inode_track.get(key).unwrap().clone();
        res
    }


    
}


/********************************Container STDOUT/ Exec RESULT Shield / Policy Encforcement Point ************************************ */
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


    pub fn encryptContainerStdouterr (&self, src: DataBuff, user_type: Option<UserType>, stdio_type: StdioType) -> DataBuff {

        info!("encryptContainerStdouterr 00000000, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
        // case 0: if this is a unprivileged exec req in single cmd mode
        if user_type.is_some() && user_type.as_ref().unwrap().eq(&UserType::Unprivileged) && stdio_type ==  StdioType::ExecProcessStdio {
            info!("case 0: if this is a unprivileged exec req in single cmd mode, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
            return src;
        }

        match stdio_type {
            // case 1: if this is subcontainer stdout / stderr
            StdioType::ContaienrStdio => {
                info!("case 1:if this is subcontainer stdout / stderr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
                if self.policy.privileged_user_config.enable_container_logs_encryption == false {
                    return src;
                }
            },
            // case 2: if this is a privileged exec req in single cmd mode
            StdioType::ExecProcessStdio => {
                info!("case 2:if this is subcontainer stdout / stderr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
                if self.policy.privileged_user_config.exec_result_encryption == false {
                    return src;
                }
            },
            // case 3: if this is root container stdout / stderr
            StdioType::SandboxStdio => {
                info!("case 3:if this is root container stdout / stderr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
                return src;
            },
            StdioType::SessionAllocationStdio(ref s) => {
                info!("case 4:if this is session allocation request, user_type:{:?}, stdio_type {:?}, session {:?}", user_type, stdio_type, s);

                let encoded_session: Vec<u8> = postcard::to_allocvec(s).unwrap();
                let encrypted_session = prepareEncodedIoFrame(&encoded_session[..], &self.key).unwrap();
                // write session to stdout
                let mut buf= DataBuff::New(encrypted_session.len());
                buf.buf = encrypted_session;
                return buf;
            }
        }
        info!("case5 encryptContainerStdouterr, user_type:{:?}, stdio_type {:?}", user_type, stdio_type);
        let rawData= src.buf.clone();

        let str = String::from_utf8_lossy(&rawData).to_string();

        info!("stdout is : {:?}", str);

        let encodedOutBoundDate = prepareEncodedIoFrame(rawData.as_slice(), &self.key).unwrap();
        assert!(encodedOutBoundDate.len() != 0);

        let mut res = DataBuff::New(encodedOutBoundDate.len());


        res.buf = encodedOutBoundDate.clone();

        // for (i, el) in encodedOutBoundDate.iter().enumerate(){
        //     assert!(res.buf[i] == *el);
        // }
        
        res

    }

}


/***********************************************Exec Authentication and Access Control************************************************* */

const PRIVILEGE_KEYWORD_INDEX: usize = 0;
const HMAC_INDEX: usize = 1;
const ENCRYPTED_MESSAGE_INDEX: usize = 2;
const NONCE_INDEX: usize = 3;
const PRIVILEGE_KEYWORD: &str = "Privileged ";
const SESSION_ALLOCATION_REQUEST: &str = "Login";

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct ExecSession {
    session_id: u32,
    counter: u32,
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


/******************************************Privileged User Terminal Shield****************************************************************** */

/*
1. Redirect the FIFO stdin from shim to qkernel (Done)    
2. Emulate TTY in qkernel
    - add qkernel buffer for fifo stdin
    - filter the signal from the client and notify the qkernel foreground process
    - send the data from the FIFO stdin to the FIFO stdout so that the client can view the character he typed
    - notify qkernel to read the buffer once the character '/r' coming
    - preprocessing the outbound data of qkernel (add /n after '/r' etc.)
    - write the output data to FIFO stdout
3. End-to-end encryption and decryption
    - Enrypte the outboud and decrypt the inbound in qkernel
    - Encrypte the outboud and decyrpt the inbound in secure client
*/
pub trait TermianlIoShiled{
    fn console_copy_from_fifo_to_tty(&self, fifo_fd: i32, tty_fd: i32, cid: &str, pid: i32, filter_sig: bool, task: &Task) -> Result<i64>;
    fn filter_signal_and_write(&self, task: &Task, to_fd: i32, s: &[u8], cid: &str, pid: i32) -> Result<()>;
    fn get_signal(&self, c: u8) -> Option<i32>;
    fn write_buf(&self, task: &Task, to: i32, buf: &[u8]) -> Result<i64>;
    fn read_from_fifo(&self, fd:i32, task: &Task, buf: &mut DataBuff, count: usize) -> Result<i64>;
    fn write_to_tty (&self, host_fd: i32, task: &Task, src_buf: &mut DataBuff, count: usize) -> Result<i64>;
    fn termianlIoEncryption(&self, src: &[IoVec], task: &Task) -> Result<(usize, Option<Vec::<IoVec>>)>;
}


pub const ENABLE_RINGBUF: bool = true;


impl TerminalShield {

    pub fn init(&mut self, _policy: &Policy, key: &GenericArray<u8, U32>) -> () {
    
       // self.key = policy.unwrap().secret.file_encryption_key.as_bytes().to_vec();
        self.key = key.clone();
    }

}




impl TermianlIoShiled for TerminalShield {

    fn termianlIoEncryption(&self, src: &[IoVec], task: &Task) -> Result<(usize, Option<Vec::<IoVec>>)>{
        let size = IoVec::NumBytes(src);
        if size == 0 {
            return Ok((0, None));
        }

        let mut vec = Vec::<IoVec>::new();
        let mut src_buf = DataBuff::New(size);
        let _ = task.CopyDataInFromIovs(&mut src_buf.buf, src, true)?;

        let rawData= src_buf.buf.clone();

        let str = String::from_utf8_lossy(&rawData).to_string();

        info!("terminal output is : {:?}", str);

        //let encodedOutBoundDate = self.prepareEncodedIoFrame(rawData.as_slice()).unwrap();
        let encodedOutBoundDate = rawData;
        let mut encrypted_iov = DataBuff::New(encodedOutBoundDate.len());
        encrypted_iov.buf = encodedOutBoundDate.clone();
        vec.push(encrypted_iov.IoVec(encodedOutBoundDate.len()));
        return Ok((encodedOutBoundDate.len(), Some(vec)));


        // let mut new_len : usize = 0;
        // let mut vec = Vec::<IoVec>::new();

        // for iov in src {
        //     let mut buf= DataBuff::New(iov.len);
        //     let _ = task.CopyDataInFromIovs(&mut buf.buf, &[iov.clone()], true)?;
        //     let rawData= buf.buf.clone();
        //     let encodedOutBoundDate = self.prepareEncodedIoFrame(rawData.as_slice()).unwrap();
        //     //let encodedOutBoundDate = rawData;
        //     let mut encrypted_iov = DataBuff::New(encodedOutBoundDate.len());
        //     encrypted_iov.buf = encodedOutBoundDate.clone();
        //     vec.push(encrypted_iov.IoVec(encodedOutBoundDate.len()));
        //     new_len = new_len + encodedOutBoundDate.len();
        // }

        // return Ok((new_len, Some(vec)));
    
    }

    fn console_copy_from_fifo_to_tty(&self, fifo_fd: i32, tty_fd: i32, cid: &str, pid: i32, _filter_sig: bool, task: &Task) -> Result<i64> {

        //TODO: Now let's assume the max input len is 512
        // Add while loop or use bigger buffer to address this issue

        info!("console_copy_from_fifo_to_tty fifo_fd {:?}, tty {:?}, cid {:?}, pid {:?}", fifo_fd, tty_fd, cid, pid);
        let mut src_buf = DataBuff::New(512);
        let len = src_buf.Len();

        let ret = self.read_from_fifo(fifo_fd, task, &mut src_buf, len);

        if ret.is_err() {
            info!("read from stdin pipr got error, {:?}", ret);
            return ret;
        }
        
        let cnt = ret.unwrap();
        if cnt == 0 {
            info!("read from stdin pipr got 0 byte");
            return Ok(cnt);
        }
        assert!(cnt > 0);

        let buf_slice = src_buf.buf.as_slice();

        self.filter_signal_and_write(task, tty_fd, &buf_slice[..cnt as usize], cid, pid)?;

        Ok(cnt)
    }

    fn filter_signal_and_write(&self, task: &Task, to_fd: i32, s: &[u8], cid: &str, pid: i32) -> Result<()> {
        let len = s.len();
        let mut offset = 0;
        let rawData= s.clone();
        for i in 0..len {
            if let Some(sig) = self.get_signal(s[i]) {
                let sigArgs = SignalArgs {
                    CID: cid.to_string(),
                    Signo: sig,
                    PID: pid,
                    Mode: SignalDeliveryMode::DeliverToProcess,
                };
    
                let str = String::from_utf8_lossy(&rawData[offset..i]).to_string();
                info!("filter_signal_and_write, signal exist tty input {:?}", str);
                self.write_buf(task, to_fd, &s[offset..i])?;
                HandleSignal(&sigArgs);
                offset = i + 1;
            }
        }
        if offset < len {
            let str = String::from_utf8_lossy(&rawData[offset..len]).to_string();
            info!("filter_signal_and_write, offset < len, tty input {:?}", str);
            self.write_buf(task, to_fd, &s[offset..len])?;
        }
        return Ok(());
    }
    

    
    fn write_buf(&self, task: &Task, to: i32, buf: &[u8]) -> Result<i64> {
        let len = buf.len() as usize;
        let mut offset = 0;
        while offset < len {
            let count = len - offset;
            let but_to_write = &buf[offset..count];

            let mut src_buf = DataBuff::New(count);
            src_buf.buf = but_to_write.to_vec().clone();
            let len = src_buf.Len();

            let writeCnt = self.write_to_tty(to, task, &mut src_buf, len);
            if writeCnt.is_err() {
                info! ("qkernel write_buf got error {:?}", writeCnt);
                return writeCnt;
            }

    
            offset += writeCnt.unwrap() as usize;
        }
        return Ok(offset as i64);
    }

    fn get_signal(&self, c: u8) -> Option<i32> {
        // signal characters for x86
        const INTR_CHAR: u8 = 3;
        const QUIT_CHAR: u8 = 28;
        const SUSP_CHAR: u8 = 26;
        return match c {
            INTR_CHAR => Some(Signal::SIGINT),
            QUIT_CHAR => Some(Signal::SIGQUIT),
            SUSP_CHAR => Some(Signal::SIGTSTP),
            _ => None,
        };
    }


    fn read_from_fifo(&self, host_fd: i32, task: &Task, buf: &mut DataBuff, _count: usize) -> Result<i64> {
        if SHARESPACE.config.read().UringIO {

                let ret = IOURING.Read(
                    task,
                    host_fd,
                    buf.Ptr(),
                    buf.Len() as u32,
                    0 as i64,
                );

                if ret < 0 {
                    info!("read_from_fifo IOURING.READ got error {:?}", ret);
                    if ret as i32 != -SysErr::EINVAL {
                        return Err(Error::SysError(-ret as i32));
                    }
                } else if ret >= 0 {
                    info!("read_from_fifo IOURING.READ read {:?} bytes data from pipe", ret);
                    return Ok(ret as i64);
                }

                // if ret == SysErr::EINVAL, the file might be tmpfs file, io_uring can't handle this
                // fallback to normal case
                // todo: handle tmp file elegant
        }

        match IOReadAt(host_fd, &buf.Iovs(buf.Len()), 0 as u64) {
            Err(e) => {
                info!("read_from_fifo IOReadAt  got error {:?}", e);
                return Err(e)
            },
            Ok(ret) => {
                info!("read_from_fifo IOReadAt  read {:?} bytes data from pipe", ret);
                return Ok(ret);
        }
    }

    }


    
    fn write_to_tty (&self, host_fd: i32, task: &Task, src_buf: &mut DataBuff, _count: usize) -> Result<i64> {


        let ret;
        let offset:i64 = -1;
        if SHARESPACE.config.read().UringIO {

            /*
            IORING_OP_WRITE:
            Issue the equivalent of a pread(2) or pwrite(2) system call. fd is the file descriptor to be operated on, addr contains the buffer in question, len contains the length of the 
            IO operation, and offs contains the read or write offset. If fd does not refer to a seekable file, off must be set to zero or -1. If offs is set to -1 , the offset will use
            (and advance) the file position, like the read(2) and write(2) system calls. These are non-vectored versions of the IORING_OP_READV and IORING_OP_WRITEV opcodes. See also read(2) 
            and write(2) for the general description of the related system call. Available since 5.6.
             */
            ret = IOURING.Write(task, host_fd, src_buf.Ptr(), src_buf.Len() as u32, offset);

            if ret < 0 {
                info!("write_to_tty ucall got error {:?}", ret);
                if ret as i32 != -SysErr::EINVAL {
                   
                    return Err(Error::SysError(-ret as i32));
                }
            } else if ret >= 0 {
                info!("write_to_tty ucall wirte {:?} bytes data to tty", ret);
                return Ok(ret as i64);
            }
        }

        match IOWriteAt(host_fd, &src_buf.Iovs(src_buf.Len()), offset as u64) {
            Err(e) => {
                info!("write_to_tty IOWriteAt  got error {:?}", e);
                return Err(e)
            },
            Ok(ret) => {
                info!("write_to_tty IOWriteAt  irte {:?} bytes data to tty", ret);
                return Ok(ret);
            }
        }

    }


}







/******************************************Provisioning HTTPS Client****************************************************************** */
use alloc::sync::Arc;

use qlib::kernel::socket::socket::Provider;
use qlib::kernel::socket::hostinet::hostsocket::newHostSocketFile;
use qlib::kernel::fs::flags::SettableFileFlags;
use qlib::kernel::Kernel;
use super::qlib::kernel::fs::file::*;
use qlib::kernel::tcpip::tcpip::*;
use crate::httparse;
use qlib::kernel::kernel::timer::MonotonicNow;
use qlib::kernel::kernel::time::Time;
use qlib::linux_def::SysErr;
use embedded_tls::blocking::*;

const SECRET_MANAGER_IP:  [u8;4] = [10, 206, 133, 76];
const SECRET_MANAGER_PORT: u16 = 8000;

pub struct ShieldSocketProvider {
    pub family: i32,
}

pub struct ShieldProvisioningHttpSClient {
    pub socket_file: Arc<File>,
    pub read_buf : Vec<u8>,
    pub read_from_buf_len: usize,
    pub total_loop_times_of_try_to_read_from_server: usize,
}


impl ShieldProvisioningHttpSClient {

    fn init (scoket: Arc<File>, read_buf_len: usize, total_loop_times: usize) -> Self{

        ShieldProvisioningHttpSClient { 
            socket_file: scoket, 
            read_buf: Vec::new(),  
            read_from_buf_len: read_buf_len,
            total_loop_times_of_try_to_read_from_server: total_loop_times,
        }
    }
    
}

impl Provider for ShieldSocketProvider {
    fn Socket(&self, task: &Task, stype: i32, protocol: i32) -> Result<Option<Arc<File>>> {
        let nonblocking = stype & SocketFlags::SOCK_NONBLOCK != 0;
        let stype = stype & SocketType::SOCK_TYPE_MASK;

        let res =
            Kernel::HostSpace::Socket(self.family, stype | SocketFlags::SOCK_CLOEXEC, protocol);
        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        let fd = res as i32;

        let file = newHostSocketFile(
                task,
                self.family,
                fd,
                stype & SocketType::SOCK_TYPE_MASK,
                nonblocking,
                None,
            )?;

        return Ok(Some(Arc::new(file)));
    }

    fn Pair(
        &self,
        _task: &Task,
        _stype: i32,
        _protocol: i32,
    ) -> Result<Option<(Arc<File>, Arc<File>)>> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP));
    }
}

fn try_get_data_from_server (task: &Task, socket_op: FileOps, read_to: &mut [u8], total_loop_times: usize) -> Result<i64> {


    let mut pMsg = MsgHdr::default();

    // The msg_name and msg_namelen fields contain the address and address length to which the message is sent. 
    // For further information about the structure of socket addresses, see the Sockets programming topic collection. 
    // If the msg_name field is set to a NULL pointer, the address information is not returned.
    pMsg.msgName = 0;
    pMsg.nameLen = 0;


    let flags = crate::qlib::linux_def::MsgType::MSG_DONTWAIT;
    let mut deadline = None;

    let dl = socket_op.SendTimeout();
    if dl > 0 {
        let now = MonotonicNow();
        deadline = Some(Time(now + dl));
    }

    let resp_buf =  DataBuff::New(read_to.len());
    let mut dst = resp_buf.Iovs(resp_buf.Len());
    let mut bytes: i64 = 0;

    let mut loop_time = 0;

    loop {
        if loop_time > total_loop_times {
            log::trace!("try_get_data_from_server: we have tried {:?} times to get the http resps, receive {:?} bytes, default RecvMsg flag {:?}", loop_time,  bytes, flags);
            break;
        }
        // info!("try_get_data_from_server get http get resp, bytes {:?} before recvmsg, flags {:?}", bytes, flags);
        match socket_op.RecvMsg(task, &mut dst, flags, deadline, false, 0) {
            Ok(res) => {
                let (n, mut _mflags, _, _) = res;
                assert!(n >= 0);
                bytes = bytes + n;
                // info!("try_get_data_from_server get http get resp, ok bytes {:?} after recvmsg, flags {:?},RecvMsg return {:?} bytes", bytes, flags, n);

                if bytes as usize == read_to.len() {
                    break;
                }
                assert!(bytes >= 0);
                // rust pointer arthmitic
                let new_start_pointer;
                unsafe {
                    new_start_pointer = resp_buf.buf.as_ptr().offset(bytes as isize);
                }

                let io_vec = IoVec {
                start: new_start_pointer as u64,
                len: resp_buf.Len() - bytes as usize,
                };

                dst = [io_vec];},
            Err(e) => match  e {
                Error::SysError(SysErr::EWOULDBLOCK) =>  {
                    log::trace!("try_get_data_from_server RecvMsg get error SysErr::EWOULDBLOCK, try again");
                }
                _ => {
                    log::trace!("try_get_data_from_server RecvMsg get error {:?} exit from loop", e);
                    break;
                }
            },
        };
        loop_time = loop_time + 1;
    }

    assert!(bytes >= 0);
    let http_get_resp = String::from_utf8_lossy(&resp_buf.buf.as_slice()[..bytes as usize]).to_string();

    log::trace!("try_get_data_from_server http get resp: {}", http_get_resp);

    read_to[0..(bytes as usize)].clone_from_slice(&resp_buf.buf[0..(bytes as usize)]);

    //log::trace!("try_get_data_from_server read_to {:?}, resp_buf.buf {:?}",read_to, resp_buf.buf);
    return Ok(bytes);
}



impl embedded_io::Io for ShieldProvisioningHttpSClient {
    type Error = embedded_tls::TlsError;
}

impl embedded_io::blocking::Read for ShieldProvisioningHttpSClient {
    fn read<'m>(&'m mut self, read_to: &'m mut [u8]) -> core::result::Result<usize, Self::Error> {

        log::trace!("embedded_io::blocking::read start, read_to len {:?}, ShieldProvisioningHttpSClient buffer {:?}, len {:?}", read_to.len(), self.read_buf, self.read_buf.len());
        let socket_op = self.socket_file.FileOp.clone();
        let read_to_len = read_to.len();
        let current_task = Task::Current();

        if read_to_len <= self.read_buf.len() {
            read_to.clone_from_slice(&self.read_buf[..read_to_len]);
            self.read_buf.drain(0..read_to_len);
            log::trace!("embedded_io::blocking::Read return {:?} byte from the buffer, read_to {:?}, ShieldProvisioningHttpSClient len {:?} buffer {:?} ", read_to_len, read_to, self.read_buf.len(), self.read_buf);


            // try get more data from server side before return
            let mut buf: [u8; 30000] = [0; 30000];
            let res = try_get_data_from_server(current_task, socket_op, &mut buf, self.total_loop_times_of_try_to_read_from_server);
            if res.is_err() {
                info!("try_get_data_from_server get error : {:?}", res);
            } else {
                let buf_len = res.unwrap();
                let buf_slice = buf.as_slice();
                let mut buf_vec = buf_slice[..(buf_len as usize)].to_vec();
                self.read_buf.append(&mut buf_vec);
                log::trace!("get data with len {:?} from server, put it into buffer, ShieldProvisioningHttpSClient len {:?} buffer {:?}", buf_len, self.read_buf.len(), self.read_buf);
            }
            return Ok(read_to_len as usize);
        }

        let current_task = Task::Current();
        let mut deadline = None;
        let mut flags = 0 as i32;
        let dl = socket_op.SendTimeout();
        if dl > 0 {
            let now = MonotonicNow();
            deadline = Some(Time(now + dl));
        } else if dl < 0 {
            flags |= crate::qlib::linux_def::MsgType::MSG_DONTWAIT
        }

        let buffer =  DataBuff::New(self.read_from_buf_len);
        let mut buffer_iovec = buffer.Iovs(buffer.Len());
    
        log::trace!("embedded_io::blocking::Read get package from intenet, before recvmsg, flags {:?}", flags);
        match socket_op.RecvMsg(current_task, &mut buffer_iovec, flags, deadline, false, 0) {
            Ok(res) => {
                let (n, mut _mflags, _, _) = res;
                let http_get_resp = String::from_utf8_lossy(&buffer.buf[..(n as usize)]).to_string();
                log::trace!("embedded_io::blocking::Read get package from intenet get resp, ok, bytes {:?} after recvmsg, flags {:?}, reverive: {:?}", n, flags, http_get_resp);
                
                // assert!(n >= read_to_len as i64);
                // return the data with read_to_len, store the rest in the read buffer
                let buf_slice = buffer.buf.as_slice();
                let mut buf_vec = buf_slice[..(n as usize)].to_vec();
                self.read_buf.append(&mut buf_vec);

                assert!(self.read_buf.len() >= read_to_len);
                let read_buf_slice = self.read_buf.as_slice();
                read_to.clone_from_slice(&read_buf_slice[..read_to_len]);
                self.read_buf.drain(0..read_to_len);
                log::trace!("embedded_io::blocking::Read return {:?} byte after RecvMsg, read_to {:?}, ShieldProvisioningHttpSClient len {:?} buffer {:?}", read_to_len, read_to,  self.read_buf.len(), self.read_buf);
                return Ok(read_to_len as usize);
            
            },
            Err(e) => {
                log::trace!("embedded_io::blocking::Read get package from intenet get resp, error {:?}  flags {:?}", e, flags);
                // TODO: return the exact error we got
                return Err(embedded_tls::TlsError::Io(embedded_io::ErrorKind::Other));
            },
        }
    }
}

impl embedded_io::blocking::Write for ShieldProvisioningHttpSClient {
    fn write<'m>(&'m mut self, write_from: &'m [u8]) -> core::result::Result<usize, Self::Error> {
        let socket_op = self.socket_file.FileOp.clone();

        let current_task = Task::Current();

        let mut pMsg = MsgHdr::default();

        // The msg_name and msg_namelen fields contain the address and address length to which the message is sent. 
        // For further information about the structure of socket addresses, see the Sockets programming topic collection. 
        // If the msg_name field is set to a NULL pointer, the address information is not returned.
        pMsg.msgName = 0;
        pMsg.nameLen = 0;
    
        let mut deadline = None;
        let mut flags = 0 as i32;
    
        let dl = socket_op.SendTimeout();
        if dl > 0 {
            let now = MonotonicNow();
            deadline = Some(Time(now + dl));
        } else if dl < 0 {
            flags |= crate::qlib::linux_def::MsgType::MSG_DONTWAIT
        }
        
        let mut req_buf = DataBuff::New(write_from.len());
        let write_buf = write_from.to_vec();
        req_buf.buf = write_buf;
        let src = req_buf.Iovs(write_from.len());

        log::trace!("call_send send SendMsg start");
        let res = socket_op.SendMsg(current_task, &src, flags, &mut pMsg, deadline);
        if res.is_err() {
            info!("call_send SendMsg get error  irte {:?} bytes data to tty", res);
            return Err(embedded_tls::TlsError::Io(embedded_io::ErrorKind::Other));
        }
        
        let res = res.unwrap();

        let http_get_resp = String::from_utf8_lossy(write_from).to_string();

        log::trace!("call_send send req finished, get {:?} bytes, data: {:?}", res, http_get_resp);

        Ok(res as usize)
    }

    fn flush<'m>(&'m mut self) -> core::result::Result<(), Self::Error> {
        Ok(())
    }
}


/**
 * ip: the ip of secret manager
 * port: on which port the secret manager is listening on
 * TODO: Get the ip and port of the secrect manager from container deployment yaml
*/
pub fn get_socket(task: &Task, ip: [u8;4], port: u16) -> Result<Arc<File>> {


    // get a qkernel socket file object, 
    log::trace!("socket_connect start");

    let family = AFType::AF_INET;  // ipv4
    let socket_type = LibcConst::SOCK_STREAM as i32;
    let protocol = 0;   
    let ipv4_provider = ShieldSocketProvider { family: family};

    log::trace!("socket_connect get a socekt from host");
    let socket_file = ipv4_provider.Socket(task, socket_type, protocol).unwrap().unwrap();

    let flags = SettableFileFlags {
        NonBlocking: socket_type & Flags::O_NONBLOCK != 0,
        ..Default::default()
    };

    socket_file.SetFlags(task, flags);

    // connect to target ip:port, blocking is true
    let blocking = !socket_file.Flags().NonBlocking;
    assert!(blocking == true);
    let socket_op = socket_file.FileOp.clone();

    let sock_addr = SockAddr::Inet(SockAddrInet {
        Family: AFType::AF_INET as u16,
        Port: htons(SECRET_MANAGER_PORT),
        Addr: SECRET_MANAGER_IP,
        Zero: [0; 8],
    });

    let socket_addr_vec = sock_addr.ToVec().unwrap();

    socket_op.Connect(task, socket_addr_vec.as_slice(), blocking)?;
    log::trace!("socket_connect connect to secret manager done");

    return Ok(socket_file);


}



pub fn provisioning_http_client(task: &Task) -> core::result::Result<usize, embedded_tls::TlsError> {

    const DEFAULT_GET_REQUEST: &[u8; 30] = b"GET /kbs/v0/hello HTTP/1.1\r\n\r\n";

    log::trace!("provisioning_http_client start");

    let socket_to_sm = get_socket(task, SECRET_MANAGER_IP, SECRET_MANAGER_PORT);
    if socket_to_sm.is_err() {
        info!("get_socket get error");
        return Err(embedded_tls::TlsError::ConnectionClosed);
    }

    let client = ShieldProvisioningHttpSClient::init(socket_to_sm.unwrap(), 30000, 10000);   // ~30 Mib

    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let mut rng = OsRng;

    // TODO: figur out the server name
    let config = TlsConfig::new().enable_rsa_signatures();

    let mut tls: TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256> = TlsConnection::new(client, &mut read_record_buffer, &mut write_record_buffer);


    // TODO: add verrifyer to verify the server certificate
    let res = tls.open::<OsRng, NoVerify>(TlsContext::new(&config, &mut rng,));
    if res.is_err() {
        info!("tls.open get error : {:?}", res);
        return Err(res.err().unwrap());
    }

    let res = tls.write(DEFAULT_GET_REQUEST);
    if res.is_err() {
        info!(" tls.write get error : {:?}", res);
        return res;
    }

    //all number literals except the byte literal allow a type suffix, such as 57u8
   // So 0u8 is the number 0 as an unsigned 8-bit integer.
    let mut rx_buf = [0; 4096];
    let resp_len = tls.read(&mut rx_buf);
    if resp_len.is_err() {
        info!("tls.read get error : {:?}", resp_len);
        return resp_len;
    }

    let resp_len = resp_len.unwrap();
    assert!(resp_len > 0);

    let http_get_resp = String::from_utf8_lossy(&rx_buf[..resp_len as usize]).to_string();

    info!("provisioning_https_client http get resp: {}", http_get_resp);
    Ok(resp_len)
}