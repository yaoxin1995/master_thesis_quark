use alloc::vec::Vec;
use spin::rwlock::RwLock;
use alloc::string::String;
use crate::qlib::common::*;
use crate::qlib::kernel::task::Task;
use crate::qlib::loader::Process;


use crate::Config;
const APP_NMAE: &str = "APPLICATION_NAME"; 

lazy_static! {
    pub static ref SOFTMEASUREMENTMANAGER:  RwLock<SoftwareMeasurementManager> = RwLock::new(SoftwareMeasurementManager::default());
}

#[derive(Debug, Default, Serialize)]
struct QKernelArgs {
    heapStart: u64, 
    shareSpaceAddr: u64, 
    id: u64, 
    svdsoParamAddr: u64, 
    vcpuCnt: u64, 
    autoStart: bool
}


#[derive(Debug, Default)]
pub struct SoftwareMeasurementManager {
    containerlized_app_name: String,
    is_app_loaded: bool,
    //  a base64 of the sha512
    measurement : String,
}

impl SoftwareMeasurementManager {

    fn updata_measurement(&mut self, _new_data: Vec<u8>) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn start_track_app_creation(&mut self, _proc_spec: &Process, _is_root: bool) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn set_application_name(&mut self, _envs: &Vec<String>) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn measure_qkernel_argument (&mut self, _config: Config) ->  Result<()> {
        Err(Error::NotSupport)
    }

    /**
     *  Only measure the auxv we got from elf file is enough,
     *  Other data like, envv, argv, are measuared by `start_track_app_creation`
     */
    pub fn check_before_app_starts(&mut self, _is_app: bool, _binary: &str) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn measure_elf_loadable_segment(&mut self, _load_segment_virtual_addr: u64, _load_segment_size: u64, _offset: u64, _task: &Task, _: &str) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn measure_shared_lib_loadable_segment(&mut self) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn get_measurement(&self) -> Result<String> {
        Err(Error::NotSupport)
    }

    
    pub fn init_binary_hash (&mut self, _binary_name: &str) -> Result<()> {

        Ok(())
    }

    
    pub fn get_sm_certificate(&self) -> Result<Vec<u8>> {

        Err(Error::NotSupport)
    }



    pub fn check_binary_hash (&mut self, _binary_name: &str) -> Result<()> {

        Ok(())
    }

}



