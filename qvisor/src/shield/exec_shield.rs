
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use crate::aes_gcm::{
    aead::{generic_array::{GenericArray, typenum::U32}},
};
use spin::rwlock::RwLock;
use crate::qlib::control_msg::*;
use crate::qlib::common::*;
use crate::qlib::shield_policy::*;
use crate::qlib::linux_def::*;

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
    pub fn init(&mut self, _policy: &Policy, _key: &GenericArray<u8, U32>) -> () {
    }

    pub fn encrypNormalIOStdouterr (&self, _src: DataBuff, _: u64) -> Result<DataBuff> {
        Err(Error::NotSupport)
    }
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct ExecSession {
    session_id: u32,
    counter: u32,
}


/**
 * Privilege request format:                  
 * *********************** * *********************** ************************
 *         Privileged / hmac(Privileged|Session_id|Conter|cmd|args, privilegd_user_key) /  (Session_id + Conter + cmd + args) / nonce
 * ************************ ************************************************
 */
pub fn verify_privileged_exec_cmd(_privileged_cmd: &mut Vec<String>, _key_slice: &[u8], _key: &GenericArray<u8, U32>) -> Result<Vec<String>>  {
    Err(Error::NotSupport)
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

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct PolicyUpdate {
    pub new_policy: KbsPolicy,
    pub is_updated: bool,
    pub session_id: u32
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
    pub fn init(&mut self, _hmac_key_slice: &Vec<u8>, _decryption_key: &GenericArray<u8, U32>, _policy: &Policy) -> () {
    }

}

pub fn exec_req_authentication (_exec_req: ExecAuthenAcCheckArgs) -> bool {
    false
}
