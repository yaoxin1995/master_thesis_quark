use spin::rwlock::RwLock;
use crate::qlib::kernel::boot::{oci, config};
use crate::qlib::shield_policy::{KbsSecrets};
use alloc::vec::Vec;
use alloc::string::ToString;
use crate::qlib::kernel::task::Task;
use crate::qlib::kernel::fs::dirent::Dirent;
use  crate::qlib::kernel::fs::mount::MountNs;
use crate::qlib::kernel::boot::fs::MountSubmounts;
use qlib::common::*;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;

lazy_static! {
    pub static ref SECRET_KEEPER:  RwLock<SecretKeeper> = RwLock::new(SecretKeeper::default());
}

const SECRETFS: &str = "secret";

#[derive(Default)]
pub struct SecretKeeper {
    initialized: bool,
    pub secrets_mount_info: FileSystemMount,
    pub file_secrets:  BTreeMap<String, Vec<u8>>,  // key: file name, value: secret
}


impl SecretKeeper {
    pub fn set_secrets_mount_info (&mut self, info: FileSystemMount) -> Result<()> {
        info!("set_secrets_mount_info");

        self.initialized = true;
        self.secrets_mount_info = info;
        Ok(())
    }

    pub fn bookkeep_file_based_secret (&mut self, secrets: KbsSecrets) -> Result<()> {

        info!("file_based_secret_injection");

        if secrets.config_fils.is_none() {
            return Ok(());
        }

        let config_file = secrets.config_fils.unwrap();


        for file_based_secret in config_file {

            let content = file_based_secret.base64_file_content;
            let bytes = base64::decode(content)
            .map_err(|e| Error::Common(format!("file_based_secret_injection base64::decode failed to decoded file based secret {:?}", e)))?;

            let content = String::from_utf8_lossy(&bytes).to_string();
            info!("file_based_secret_injection file based secret content: {:?}", content);

            self.file_secrets.insert(file_based_secret.file_path, bytes);

        }        
        
        Ok(())

    }


    pub fn inject_file_based_secret_to_secret_file_system (&self, task: &Task) -> Result<()> {

        info!("inject_file_based_secret_to_secret_file_system");


        let res = self.secrets_mount_info.mount_secret_mount(task);
        
        res
    }




}

#[derive(Default)]
pub struct FileSystemMount {
    pub mount_config: config::Config,
    pub root: Dirent,
    pub mount_namespace: MountNs,
}

impl FileSystemMount {

    pub fn init(mount_config: config::Config,root: Dirent, mount_namespace: MountNs) -> Self {
        info!("init");

        Self { 
            mount_config: mount_config,  
            root: root, 
            mount_namespace: mount_namespace 
        }

    }
    fn mount_secret_mount(&self, task: &Task) -> Result<()> {

        info!("mount_secret_mount");
        let mounts = self.prepare_secrets_mounts();

        let res = MountSubmounts(task, &self.mount_config, &self.mount_namespace, &self.root, &mounts);
        if res.is_err() {
            info!("mount_secret_mount got error");
        }

        Ok(())
    }

    fn prepare_secrets_mounts(&self) -> Vec<oci::Mount> {

        info!("prepare_secrets_mounts");
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



