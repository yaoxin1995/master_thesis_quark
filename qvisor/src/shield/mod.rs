pub mod terminal_shield;
pub mod https_attestation_provisioning_cli;
pub mod cryptographic_utilities;
pub mod exec_shield;
pub mod inode_tracker;
pub mod sev_guest;
pub mod secret_injection;
pub mod software_measurement_manager;

use spin::rwlock::RwLock;
use self::exec_shield::*;
use self::terminal_shield::*;
use self::inode_tracker::*;
use crate::qlib::shield_policy::*;
use crate::aes_gcm::{ Aes256Gcm, Key};
use self::sev_guest::GUEST_SEV_DEV;
use crate::qlib::common::*;

lazy_static! {
    pub static ref APPLICATION_INFO_KEEPER:  RwLock<ApplicationInfoKeeper> = RwLock::new(ApplicationInfoKeeper::default());
}

#[derive(Default)]
pub struct ApplicationInfoKeeper {
    app_name: String,
    is_launched: bool,
    kbs_ip:  [u8;4],  // key: file name, value: secret
    kbs_port: u16,
}


impl ApplicationInfoKeeper {
    // ip pattern: ip:port, i.e., 10.206.133.76:8080"
    fn parse_ip(&self, _ip_port : &str) -> Result<(Vec<u8>, u16)> {
        Err(Error::NotSupport)
    }

    pub fn init(&mut self, _envs : &Vec<String>, _cid: String) -> Result<()>{
        Err(Error::NotSupport)
    }

    pub fn get_kbs_ip(&self) -> Result<[u8;4]> {
        Err(Error::NotSupport)
    }

    pub fn get_kbs_port(&self) -> Result<u16> {
        Err(Error::NotSupport)
    }

    pub fn is_application_loaded (&self) -> Result<bool> {
        Err(Error::NotSupport)
    }

    pub fn set_application_loaded (&mut self) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn get_application_name (&self) -> Result<&str> {
        Err(Error::NotSupport)
    }
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
    // init sev guest driver
    GUEST_SEV_DEV.write().init(0);

    
}
pub fn hash_chunks(_chunks: Vec<Vec<u8>>) -> String {
	return "".to_string();
} 

pub fn policy_provisioning (_policy: &Policy) -> Result<()> {
    Err(Error::NotSupport)
}