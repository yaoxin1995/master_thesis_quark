pub mod terminal_shield;
pub mod https_attestation_provisioning_cli;
pub mod exec_shield;
pub mod inode_tracker;
pub mod sev_guest;
pub mod secret_injection;
pub mod software_measurement_manager;
pub mod guest_syscall_interceptor;
use crate::qlib::kernel::task::Task;
use spin::rwlock::RwLock;
use crate::qlib::shield_policy::*;
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



pub fn policy_provisioning (_policy: &KbsPolicy) -> Result<()> {
    Err(Error::NotSupport)
}


pub fn shiled_clock_get_time(_task: &mut Task) -> i64 {
    return -1;
}
