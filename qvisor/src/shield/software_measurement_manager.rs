use alloc::vec::Vec;
use spin::rwlock::RwLock;
use alloc::string::String;
use crate::qlib::common::*;
use crate::qlib::kernel::task::Task;
use crate::qlib::loader::Process;
use crate::qlib::auxv::AuxEntry;


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
    pub measured_executable_memory_mapping_in_bytes_before_app_launch: u64,
    pub measured_shared_lib_memory_mapping_in_bytes_before_app_launch: u64,

    pub measured_process_spec_before_app_launch:u64,

    pub measured_qkernel_args_in_bytes_before_app_launch:u64,

    pub measured_stack_in_bytes_before_app_launch:u64,


    pub measured_executable_memory_mapping_in_bytes_after_app_launch: u64,
    pub measured_shared_lib_memory_mapping_in_bytes_after_app_launch: u64,
    pub measured_stack_in_bytes_after_app_launch:u64,
}

impl SoftwareMeasurementManager {

    fn updata_measurement(&mut self, _new_data: Vec<u8>) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn measure_process_spec(&mut self, _proc_spec: &Process, _is_root: bool) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn set_application_name(&mut self, _envs: &Vec<String>) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn measure_qkernel_argument (&mut self, _heapStart: u64, _shareSpaceAddr: u64, _id: u64, _svdsoParamAddr: u64, _vcpuCnt: u64, _autoStart: bool) ->  Result<()> {
        Err(Error::NotSupport)
    }

    /**
     *  Only measure the auxv we got from elf file is enough,
     *  Other data like, envv, argv, are measuared by `measure_process_spec`
     */
    pub fn measure_stack(&mut self, _auxv: Vec<AuxEntry>, _is_app: bool, _task: &mut Task, binary: &str) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn measure_elf_loadable_segment(&mut self, _load_segment_virtual_addr: u64, _load_segment_size: u64, _offset: u64, _task: &Task, file_name: &str) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn measure_shared_lib(&mut self) -> Result<()> {
        Err(Error::NotSupport)
    }

    pub fn get_measurement(&self) -> Result<String> {
        Err(Error::NotSupport)
    }

    
    pub fn init_runtime_binary_hash (&mut self, binary_name: &str) -> Result<()> {

        Ok(())
    }



    pub fn check_runtime_binary_hash (&mut self, binary_name: &str) -> Result<()> {

        Ok(())
    }

}



