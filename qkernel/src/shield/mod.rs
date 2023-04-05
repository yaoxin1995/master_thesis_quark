pub mod terminal_shield;
pub mod https_attestation_provisioning_cli;
pub mod cryptographic_utilities;
pub mod exec_shield;
pub mod inode_tracker;
pub mod sev_guest;


use self::exec_shield::*;
use self::terminal_shield::*;
use self::inode_tracker::*;
use qlib::shield_policy::*;
use crate::aes_gcm::{ Aes256Gcm, Key};
use self::sev_guest::GUEST_SEV_DEV;



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
