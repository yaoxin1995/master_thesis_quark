use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use spin::rwlock::RwLock;


use super::qlib::control_msg::*;
use super::qlib::path::*;
use super::qlib::common::*;
use super::qlib::shield_policy::*;
use super::qlib::kernel::boot::controller::{WriteControlMsgResp, WriteWaitAllResponse};
use crate::aes_gcm::{
    aead::{Aead, KeyInit, generic_array::{GenericArray, typenum::U32}},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
    Key,
};

use alloc::collections::btree_map::BTreeMap;
use super::qlib::linux_def::*;
use super::qlib::kernel::task::*;
use super::qlib::kernel::{SHARESPACE, IOURING, fd::*, boot::controller::HandleSignal};
use super::qlib::vcpu_mgr::*;
use super::qlib::kernel::taskMgr::SwitchToNewTask;

use sha2::{Sha256};
use hmac::{Hmac, Mac};
use base64ct::{Base64, Encoding};




/*********************************************************************************************************************************************************
    The functions in this file will never be called, we keep this file just to make the qvisor binary file compile successfully. 
    For the shielding layer implementation, please view the the file in dir qkernel/src/shiedling_layer_rs
**********************************************************************************************************************************************************/

lazy_static! {
    pub static ref TERMINAL_SHIELD:  RwLock<TerminalShield> = RwLock::new(TerminalShield::default());
    pub static ref INODE_TRACKER:  RwLock<InodeTracker> = RwLock::new(InodeTracker::default());
    pub static ref EXEC_AUTH_AC:  RwLock<ExecAthentityAcChekcer> = RwLock::new(ExecAthentityAcChekcer::default());
    pub static ref STDOUT_EXEC_RESULT_SHIELD:  RwLock<StdoutExecResultShiled> = RwLock::new(StdoutExecResultShiled::default());
}



pub fn init_shielding_layer (policy: Option<&Policy>) ->() {

    const KEY_SLICE: &[u8; 32] = b"a very simple secret key to use!";

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

}


/************************************Encryption, Decryption, Encoding, Decoding Untilities****************************************************************/
    
    /// Nonce: unique per message.
    /// 96-bits (12 bytes)
const NONCE_LENGTH: usize = 12;

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
    
fn random_bytes(_slice: &mut [u8]) -> (){
    // let mut rmd_nonce= Vec::with_capacity(NONCE_LENGTH);
    // getrandom(&mut rmd_nonce).unwrap();
    // assert!(slice.len() == NONCE_LENGTH);
    // let mut rng = OsRng;
    // rng.fill_bytes(slice);
    // rmd_nonce
    // thread_rng().gen::<[u8; NONCE_LENGTH]>()
}

fn prepareEncodedIoFrame(plainText :&[u8], _key: &GenericArray<u8, U32>) -> Result<Vec<u8>> {
    
    let mut payload = PayLoad::default();
    payload.counter = 1;
    payload.data = plainText.to_vec();
    assert!(payload.data.len() == plainText.len());

    // let encoded_payload: Vec<u8> = postcard::to_allocvec(&payload).unwrap();

    // let mut io_frame = IoFrame::default();

    // (io_frame.pay_load, io_frame.nonce)= encrypt(encoded_payload.as_ref(), key).unwrap();

    let encoded_frame = Vec::new();

    Ok(encoded_frame)
}


fn getDecodedPayloads(encoded_payload :&Vec<u8>, _key: &GenericArray<u8, U32>) -> Result<Vec<PayLoad>> {

    let payloads = Vec::new();
    // let mut frame;
    let payloads_slice= encoded_payload.as_slice();

    while payloads_slice.len() > 0 {
        //  (frame , payloads_slice) =  postcard::take_from_bytes::<IoFrame>(payloads_slice.as_ref()).unwrap();
        // let frame2:IoFrame = bincode::deserialize(encoded12[]).unwrap();
        // print!("frame111111111111 : {:?}\n", frame1);
        
    
        // let decrypted = decrypt(&frame.pay_load, &frame.nonce, key).unwrap();
        // let payload:PayLoad = postcard::from_bytes(decrypted.as_ref()).unwrap();

        // payloads.push(payload);
    
    
        // print!("decrypted22222222222 {:?}, PLAIN_TEXT{:?}\n", payload, PLAIN_TEXT1.as_ref());

        // print!("payload111 :{:?}\n", &payload);
        if payloads_slice.len() == 0 {
            break;
        }
    }
    // print!("payloads22222 :{:?}\n", payloads);
    Ok(payloads)

}

/**********************************************Inode Traker *************************************************************** */

#[derive(Debug, Default)]
pub struct InodeTracker {

    inode_track: BTreeMap<u64, TrackInodeType>,
}

impl InodeTracker {
    pub fn init(&mut self) -> () {
        self.inode_track= BTreeMap::new();
    }

    
    pub fn addInoteToTrack(&mut self, key: u64, value: TrackInodeType) -> (){

        self.inode_track.insert(key, value);
    }

    pub fn rmInoteToTrack(&mut self, key: u64) -> (){

        let res = self.inode_track.remove_entry(&key);
        let (_k, _v) = res.unwrap();
    }

    pub fn isInodeExist(&self, key: &u64) -> bool {
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

        // case 0: if this is a unprivileged exec req in single cmd mode
        if user_type.is_some() && user_type.as_ref().unwrap().eq(&UserType::Unprivileged) && stdio_type ==  StdioType::ExecProcessStdio {
            return src;
        }

        match stdio_type {
            // case 1: if this is subcontainer stdout / stderr
            StdioType::ContaienrStdio => {
                if self.policy.privileged_user_config.enable_container_logs_encryption == false {
                    return src;
                }
            },
            // case 2: if this is a privileged exec req in single cmd mode
            StdioType::ExecProcessStdio => {
                if self.policy.privileged_user_config.exec_result_encryption == false {
                    return src;
                }
            },
            // case 1: if this is root container stdout / stderr
            StdioType::SandboxStdio => {
                return src;
            }
            StdioType::SessionAllocationStdio(ref s) => {
                return src;
            }
        }

        let rawData= src.buf.clone();
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
 *         Privileged     /    hmac(Privileged|cmd|args)     /  encrypted cmd + args / tag
 * ************************ ************************************************                    
 */
pub fn verify_privileged_exec_cmd(privileged_cmd: &mut Vec<String>, key_slice: &[u8], key: &GenericArray<u8, U32>) -> Result<Vec<String>>  {

    assert!(privileged_cmd.len() > 2);

    if privileged_cmd.len() != 4 {
        return  Err(Error::Common(format!("the privileged_cmd len is 4, len  {:?}, privileged_cmd verification failed", privileged_cmd.len())));
    }


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

    return Ok(cmd_list);
}

#[derive(Debug, Default)]
pub struct ExecAthentityAcChekcer {
    policy: Policy,
    pub hmac_key_slice: Vec<u8>,
    pub decryption_key: GenericArray<u8, U32>,
    pub authenticated_reqs: BTreeMap<String, AuthenticatedExecReq>
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

        // Hmac authentication
        let mut privileged_cmd = exec_req_args.args.clone();
        let mut cmd_in_plain_text = match verify_privileged_exec_cmd(&mut privileged_cmd, &self.hmac_key_slice, &self.decryption_key) {
            Ok(args) => args,
            Err(e) => {
                return false;
            }
        };

        // Session allocation request
        let mut exec_req_args = exec_req_args.clone();

        //TODO Access Control
        match exec_req_args.req_type {
            ExecRequestType::Terminal => {
                let res = self.check_terminal_access_control (UserType::Privileged);

                if res == false {
                    return false;
                }

            },
            ExecRequestType::SingleShotCmdMode =>{
                let allowed_cmd = &self.policy.privileged_user_config.single_shot_command_line_mode_configs.allowed_cmd;
                let allowed_path = &self.policy.privileged_user_config.single_shot_command_line_mode_configs.allowed_dir;
                let res = self.check_oneshot_cmd_mode_access_control(UserType::Privileged, &cmd_in_plain_text, allowed_cmd, allowed_path, &exec_req_args.cwd);
                if res == false {
                    return false;
                }
            },
            ExecRequestType::SessionAllocationReq(ref _s) => {

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
                self.policy.privileged_user_config.enable_single_shot_command_line_mode
            },
            UserType::Unprivileged => {
                self.policy.unprivileged_user_config.enable_single_shot_command_line_mode
            }
        };
        if is_sigle_shot_cmd_enabled == false {
            return false;
        }
       
        let is_cmd_path_allowed = single_shot_cmd_check(cmd, allowed_cmds, allowed_pathes, cwd);

        return is_cmd_path_allowed;
    }


    // pub fn session_request_handler (&self, _exec_stdfds: &[i32], resp_fd : i32, container_id : String, _session: ExecSession, exec_id : String) -> () {

    //     // return tid to tell the shim the exec req is launched
    //     WriteControlMsgResp(resp_fd, &UCallResp::ExecProcessResp(1 as i32), true);
        
    //     // notify the shim that the session allocation exec request is finished 
    //     WriteWaitAllResponse(container_id, exec_id, 0);

    //     // free curent task in the waitfn context
    //     CPULocal::SetPendingFreeStack(Task::Current().taskId);
    //     SwitchToNewTask();
    // }
    
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

    return isPathAllowd;
}

fn is_cmd_allowed (cmd: &String, allowed_cmd_list: &Vec<String>) ->bool {

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

        let is_allowed = IsSubpathCheck(&sub_paths, allowed_paths);

        return is_allowed;
    }

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

    // convert rel path to abs path
    for relPath in rel_paths {
        let absPath = Join(cwd, &relPath);
        abs_paths.push(absPath);
    }

    if allowed_paths.len() <= 0 {
        return false;
    }

    let isAllowed = IsSubpathCheck (&abs_paths, allowed_paths);


    return isAllowed;
        

}


fn IsSubpathCheck (abs_paths_in_cmd: &Vec<String>, allowed_pathes: &Vec<String>) -> bool {

    for absPath in abs_paths_in_cmd {
            
        let mut is_allowd = false;
        for  allowed_path in allowed_pathes {
            if Clean(&absPath) == Clean(allowed_path) {
                is_allowd = true;
                break;
            }

            let (_, isSub) = IsSubpath(&absPath, &allowed_path);
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



#[derive(Debug, Default)]
pub struct TerminalShield {
    key: GenericArray<u8, U32>,
}
    

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

        let mut src_buf = DataBuff::New(512);
        let len = src_buf.Len();

        let ret = self.read_from_fifo(fifo_fd, task, &mut src_buf, len);

        if ret.is_err() {
            return ret;
        }
        
        let cnt = ret.unwrap();
        if cnt == 0 {

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
    
                let _str = String::from_utf8_lossy(&rawData[offset..i]).to_string();
                self.write_buf(task, to_fd, &s[offset..i])?;
                HandleSignal(&sigArgs);
                offset = i + 1;
            }
        }
        if offset < len {
            let _str = String::from_utf8_lossy(&rawData[offset..len]).to_string();
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
                    if ret as i32 != -SysErr::EINVAL {
                        return Err(Error::SysError(-ret as i32));
                    }
                } else if ret >= 0 {
                    return Ok(ret as i64);
                }

                // if ret == SysErr::EINVAL, the file might be tmpfs file, io_uring can't handle this
                // fallback to normal case
                // todo: handle tmp file elegant
        }

        match IOReadAt(host_fd, &buf.Iovs(buf.Len()), 0 as u64) {
            Err(e) => {
                return Err(e)
            },
            Ok(ret) => {
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
                if ret as i32 != -SysErr::EINVAL {
                   
                    return Err(Error::SysError(-ret as i32));
                }
            } else if ret >= 0 {
                return Ok(ret as i64);
            }
        }

        match IOWriteAt(host_fd, &src_buf.Iovs(src_buf.Len()), offset as u64) {
            Err(e) => {
                return Err(e)
            },
            Ok(ret) => {
                return Ok(ret);
            }
        }

    }


}

    