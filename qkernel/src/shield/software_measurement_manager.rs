use alloc::vec::Vec;
use spin::rwlock::RwLock;
use alloc::string::{String, ToString};
use crate::qlib::common::*;
use qlib::addr::Addr;
use crate::qlib::kernel::task::Task;
use crate::qlib::loader::Process;
use qlib::auxv::AuxEntry;
use qlib::path::*;
use qlib::linux_def::*;
use fs::file::File;

const APP_NMAE: &str = "APPLICATION_NAME"; 
const SHARED_LIB_PATTERN: &str = ".so"; 

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

enum MeasurementType{
    AppRef,
    Global,
    Tmp
}


#[derive(Debug, Default)]
pub struct SoftwareMeasurementManager {
    containerlized_app_name: String,
    is_app_loaded: bool,
    load_app_start: bool,
    load_app_end: bool,
    //  a base64 of the sha512
    // measurement that tracking the qkernel behavier after launch
    global_measurement : String,
    // measurement that tracks the appllication building process
    app_ref_measurement : String,
    // measurement that tracks the application rebuilding process (app exit, k8s tries to restart the app)
    // if the tmp_measurement doesn't match the  app_ref_measurement, panic!!! 
    tmp_measurement : String,
}



fn get_application_name(envs : Vec<String>) -> Option<String>{

    if envs.len() == 0 {
        return  None;
    }

    for env in envs {

        let key_value:  Vec<&str> = env.split('=').collect();

        assert!(key_value.len() == 2);
        if key_value[0].eq(APP_NMAE) {
            return Some(key_value[1].to_string());
        }
    }

    None
}

pub fn is_shared_lib(file_name: &str) -> Result<bool> {

    let base_name = Base(&file_name).to_string();

    let is_shared_lib = base_name.contains(SHARED_LIB_PATTERN);

    info!("is_shared_lib file_name {:?}, is_shared_lib {:?}", file_name, is_shared_lib);

    Ok(is_shared_lib)
}

impl SoftwareMeasurementManager {

    fn updata_measurement(&mut self, new_data: Vec<u8>, m_type: MeasurementType) -> Result<()> {

        let measurement = match m_type {
            MeasurementType::Global => self.global_measurement.clone(),
            MeasurementType::AppRef => self.app_ref_measurement.clone(),
            MeasurementType::Tmp => self.tmp_measurement.clone(),   
        };

        let chunks = vec![
            measurement.as_bytes().to_vec(),
            new_data,  
        ];

        let hash_res = super::hash_chunks(chunks);

        self.global_measurement = hash_res;

        Ok(())
    }

    pub fn measure_process_spec(&mut self, proc_spec: &Process) -> Result<()> {

        self.load_app_end = false;
        self.tmp_measurement = String::default();

        let proccess_spec_vec = serde_json::to_vec(proc_spec);
        if proccess_spec_vec.is_err() {
            info!("measure_process_spec serde_json::to_vec(proc_spec) get error");
            return Err(Error::Common("measure_process_spec serde_json::to_vec(proc_spec) get error".to_string()));
        }

        let proccess_spec_vec_in_bytes = proccess_spec_vec.unwrap();

        if self.is_app_loaded {
            self.updata_measurement(proccess_spec_vec_in_bytes, MeasurementType::Tmp).unwrap();
        } else {
            self.updata_measurement(proccess_spec_vec_in_bytes.clone(), MeasurementType::Global).unwrap();
            self.updata_measurement(proccess_spec_vec_in_bytes, MeasurementType::AppRef).unwrap();
        }
        Ok(())
    }

    pub fn set_application_name(&mut self, envs: &Vec<String>) -> Result<()> {

        let app_name = get_application_name(envs.clone());
        if app_name.is_none() {
            info!("set_application_name get_application_name return none");
            return Err(Error::Common("set_application_name get_application_name return none".to_string()));
        }

        self.containerlized_app_name = app_name.unwrap();

        Ok(())
    }

    pub fn measure_qkernel_argument (&mut self, heapStart: u64, shareSpaceAddr: u64, id: u64, svdsoParamAddr: u64, vcpuCnt: u64, autoStart: bool) ->  Result<()> {

        let qkernel_args = QKernelArgs {
            heapStart: heapStart,
            shareSpaceAddr: shareSpaceAddr,
            id: id,
            svdsoParamAddr: svdsoParamAddr,
            vcpuCnt: vcpuCnt,
            autoStart: autoStart,
        };

        let kernel_args_in_bytes = serde_json::to_vec(&qkernel_args)
            .map_err(|e| Error::Common(format!("measure_qkernel_argument, serde_json::to_vec(&qkernel_args) get error {:?}", e)))?;

        self.updata_measurement(kernel_args_in_bytes, MeasurementType::Global).unwrap();

        Ok(())
    }

    /**
     *  Only measure the auxv we got from elf file is enough,
     *  Other data like, envv, argv, are measuared by `measure_process_spec`
     */
    pub fn measure_stack(&mut self, auxv: Vec<AuxEntry>, is_app: bool) -> Result<()> {

        let mut aux_entries_in_byte = Vec::new();
        for entry in auxv {
            let mut entry_in_byte = serde_json::to_vec(&entry)
                .map_err(|e| Error::Common(format!("measure_stack, serde_json::to_vec(&entry) get error {:?}", e)))?;
            aux_entries_in_byte.append(&mut entry_in_byte);
        }

        // app retart
        if self.is_app_loaded && !self.load_app_end && !is_app {
            self.updata_measurement(aux_entries_in_byte, MeasurementType::Tmp).unwrap();
        // app restart, app binary loading is finished
        } else if self.is_app_loaded && !self.load_app_end && is_app{
            self.updata_measurement(aux_entries_in_byte, MeasurementType::Tmp).unwrap();

            let app_ref_measurement = self.app_ref_measurement.clone();
            let tmp_measurement = self.tmp_measurement.clone();

            if app_ref_measurement.eq(&tmp_measurement) {
                self.load_app_end = true;
                info!("app restart successfully");
                return Ok(());
            }

            panic!("tmp_measurement doesn't match the app_ref_measurement, k8s tries to restart application using bad bainary")
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && !is_app {
            self.updata_measurement(aux_entries_in_byte.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(aux_entries_in_byte, MeasurementType::Global).unwrap();
        // app first time loading us finished
        } else if !self.is_app_loaded && !self.load_app_end && is_app{
            self.updata_measurement(aux_entries_in_byte.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(aux_entries_in_byte, MeasurementType::Global).unwrap();
            self.is_app_loaded = true;
            self.load_app_end = true
        } else {
            self.updata_measurement(aux_entries_in_byte, MeasurementType::Global).unwrap();
        }

        Ok(())
    }

    pub fn measure_elf_loadable_segment(&mut self, load_segment_virtual_addr: u64, load_segment_size: u64, offset: u64, task: &Task) -> Result<()> {

        let startMem = Addr(load_segment_virtual_addr).RoundDown().unwrap();
        let endMem = Addr(load_segment_virtual_addr)
                .AddLen(load_segment_size).unwrap()
                .RoundUp().unwrap();
        let len = endMem.0 - startMem.0;
        
        let vma_start = startMem.0 + offset;
        let data: Result<Vec<u8>> =  task.CopyInVec(vma_start, len as usize);
        if data.is_err() {
            info!("After MapSegment copy elf loadable segment got error {:?}", data);
            return Err(data.err().unwrap());
        }

        let loadable = data.unwrap();

        // app retart
        if self.is_app_loaded && !self.load_app_end{
            self.updata_measurement(loadable, MeasurementType::Tmp).unwrap();
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end {
            self.updata_measurement(loadable.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(loadable, MeasurementType::Global).unwrap();
        } else {
            self.updata_measurement(loadable, MeasurementType::Global).unwrap();
        }
    
        Ok(())
    }

    pub fn measure_shared_lib(&mut self, start_addr: u64, file: &File, task: &Task, fixed: bool, mmmap_len: u64) -> Result<()> {

        let uattr = file.UnstableAttr(task)?;
        let real_mmap_size = if uattr.Size as u64 > mmmap_len {
            mmmap_len
        } else {
            uattr.Size as u64
        };

        // let length = match Addr(shared_lib_size).RoundDown() {
        //     Err(_) => return Err(Error::SysError(SysErr::ENOMEM)),
        //     Ok(l) => l.0,
        // };
        debug!("measure_shared_lib, addr {:x}, shared_lib_size {:x}, fixed {:?}, mmmap_len {:x}", start_addr, real_mmap_size, fixed, mmmap_len);
        
        let data: Result<Vec<u8>>;
        if fixed {
            let length = match Addr(mmmap_len).RoundDown() {
                Err(_) => return Err(Error::SysError(SysErr::ENOMEM)),
                Ok(l) => l.0,
            };

            data = task.CopyInVec(start_addr, length as usize);
        } else {
            data = task.CopyInVec(start_addr, real_mmap_size as usize);
        }

        if data.is_err() {
            info!("measure_shared_lib After task.CopyInVec got error {:?}", data);
            return Err(data.err().unwrap());
        }

        let loadable = data.unwrap();

        // app retart
        if self.is_app_loaded && !self.load_app_end{
            self.updata_measurement(loadable, MeasurementType::Tmp).unwrap();            
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end {
            self.updata_measurement(loadable.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(loadable, MeasurementType::Global).unwrap();
        // app first time loading is finished, 
        } else {
            self.updata_measurement(loadable, MeasurementType::Global).unwrap();
            // compare the loadable with the hash in policy file
        }

        Ok(())
    }

    pub fn get_measurement(&self) -> Result<String> {

        Ok(self.global_measurement.clone())
    }

}



