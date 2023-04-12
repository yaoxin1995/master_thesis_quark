use spin::rwlock::RwLock;
use crate::qlib::kernel::boot::{oci, config};
use crate::qlib::shield_policy::Secret;
use alloc::vec::Vec;
use alloc::string::ToString;
use crate::qlib::kernel::task::Task;
use crate::qlib::kernel::fs::dirent::Dirent;
use  crate::qlib::kernel::fs::mount::MountNs;
use crate::qlib::common::*;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;

lazy_static! {
    pub static ref SECRET_KEEPER:  RwLock<SecretKeeper> = RwLock::new(SecretKeeper::default());
}

const SECRETFS: &str = "secret";

#[derive(Default)]
pub struct SecretKeeper {
    initialized: bool,
    secrets_mount_info: FileSystemMount,
    pub file_secrets:  BTreeMap<String, Vec<u8>>,  // key: file name, value: secret
}


impl SecretKeeper {
    pub fn set_secrets_mount_info (&mut self, _info: FileSystemMount) -> Result<()> {

        Err(Error::NotSupport)
    }



    pub fn bookkeep_file_based_secret (&mut self, _secrets: Secret) -> Result<()> {

        info!("file_based_secret_injection");

        
        Err(Error::NotSupport)

    }


    pub fn inject_file_based_secret_to_secret_file_system (&self, _task: &Task) -> Result<()> {

        info!("inject_file_based_secret_to_secret_file_system");
        Err(Error::NotSupport)

    }
}



#[derive(Default)]
pub struct FileSystemMount {
    mount_config: config::Config,
    root: Dirent,
    mount_namespace: MountNs,
}

impl FileSystemMount {

    pub fn init(mount_config: config::Config,root: Dirent, mount_namespace: MountNs) -> Self {

        Self { 
            mount_config: mount_config,  
            root: root, 
            mount_namespace: mount_namespace 
        }

    }
    fn mount_secret_mount(&self, _task: &Task) -> Result<()> {


        Err(Error::NotSupport)
    }

    fn prepare_secrets_mounts(&self) -> Vec<oci::Mount> {
        let mut _procMounted = false;
        let mut _sysMounted = false;
        let mut mounts = Vec::new();
    
        mounts.push(oci::Mount {
            destination: "/secret".to_string(),
            typ: SECRETFS.to_string(),
            source: "".to_string(),
            options: Vec::new(),
        });
        let mut mandatoryMounts = Vec::new();
    
    
        mandatoryMounts.append(&mut mounts);
    
        return mandatoryMounts;
    }
}



