use spin::rwlock::RwLock;
use crate::qlib::kernel::boot::config;
use crate::qlib::shield_policy::{KbsSecrets};
use alloc::vec::Vec;
use crate::qlib::kernel::task::Task;
use crate::qlib::kernel::fs::dirent::Dirent;
use  crate::qlib::kernel::fs::mount::MountNs;
use crate::qlib::common::*;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use crate::EnvCmdBasedSecrets;

lazy_static! {
    pub static ref SECRET_KEEPER:  RwLock<SecretKeeper> = RwLock::new(SecretKeeper::default());
}

const SECRETFS: &str = "secret";

#[derive(Default)]
pub struct SecretKeeper {
    initialized: bool,
    secrets_mount_info: FileSystemMount,
    pub file_secrets:  BTreeMap<String, Vec<u8>>,  // key: file name, value: secret
    pub arg_env_based_secrets: Option<EnvCmdBasedSecrets>,
}


impl SecretKeeper {
    pub fn set_secrets_mount_info (&mut self, _info: FileSystemMount) -> Result<()> {
        Err(Error::NotSupport)
    }



    pub fn bookkeep_secrets (&mut self, _secrets: KbsSecrets) -> Result<()> {
        Err(Error::NotSupport)
    }


    pub fn inject_file_based_secret_to_secret_file_system (&self, _task: &Task) -> Result<()> {
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
}



