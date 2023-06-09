use core::clone;
use core::intrinsics::offset;

use alloc::string;
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
use alloc::collections::btree_map::BTreeMap;
use shield::EnclaveMode;
use shield::RuntimeReferenceMeasurement;


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
    autoStart: bool,
}

enum MeasurementType{
    AppRef,
    Global,
    Tmp
}


#[derive(Debug, Default)]
pub struct SoftwareMeasurementManager {
    enclave_mode: EnclaveMode,
    containerlized_app_name: String,
    is_app_loaded: bool,
    load_app_start: bool,
    load_app_end: bool,
    //  a base64 of the sha512
    // measurement that tracking the qkernel behavier after launch
    global_measurement : String,
    // measurement that tracks the appllication building process
    app_ref_measurement : String,
    enclave_ref_measurement: String,
    // measurement that tracks the application rebuilding process (app exit, k8s tries to restart the app)
    // if the tmp_measurement doesn't match the  app_ref_measurement, panic!!! 
    tmp_measurement : String,
    shared_lib_measurements: BTreeMap<String, String>,
    runtime_binary_measurement:  BTreeMap<String, String>,
    runtime_binary_reference_measurement:  BTreeMap<String, String>,
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


    pub fn init(&mut self, enclave_mode: &EnclaveMode, runtime_reference_measurement: &Vec<RuntimeReferenceMeasurement> ) -> Result<()>{


        self.enclave_mode = enclave_mode.clone();
        

        for item in runtime_reference_measurement {
            self.runtime_binary_reference_measurement.insert(item.binary_name.clone(), item.reference_measurement.clone());
        }
        Ok(())
    }



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

        
        match m_type {
            MeasurementType::Global => self.global_measurement = hash_res,
            MeasurementType::AppRef => self.app_ref_measurement = hash_res,
            MeasurementType::Tmp => self.tmp_measurement = hash_res,   
        };

        Ok(())
    }

    pub fn measure_process_spec(&mut self, proc_spec: &Process, is_root: bool) -> Result<()> {

        self.load_app_end = false;
        self.tmp_measurement = String::default();


        let mut process = Process::default();
        process.Terminal = proc_spec.Terminal;
        

        // info!("measure_process_spec {:?}", process_spec);

        if is_root == false {
            self.load_app_start = true;
            self.load_app_end = false;
        }


        let proccess_spec_vec = serde_json::to_vec(&process);
        if proccess_spec_vec.is_err() {
            info!("measure_process_spec serde_json::to_vec(proc_spec) get error");
            return Err(Error::Common("measure_process_spec serde_json::to_vec(proc_spec) get error".to_string()));
        }

        let proccess_spec_vec_in_bytes = proccess_spec_vec.unwrap();
        // app restart
        if self.is_app_loaded && !self.load_app_end && self.load_app_start{
            info!("measure_process_spec app restart");
            self.updata_measurement(proccess_spec_vec_in_bytes, MeasurementType::Tmp).unwrap();            
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start {
            info!("measure_process_spec app load");
            self.updata_measurement(proccess_spec_vec_in_bytes.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(proccess_spec_vec_in_bytes, MeasurementType::Global).unwrap();
            // app runtime 
        } else  if self.is_app_loaded && self.load_app_end && !self.load_app_start {
        
        } else {
            // qkernel launch
                // self.updata_measurement(proccess_spec_vec_in_bytes, MeasurementType::Global).unwrap();
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

    pub fn measure_qkernel_argument (&mut self, _heapStart: u64, _shareSpaceAddr: u64, _id: u64, _svdsoParamAddr: u64, __vcpuCnt: u64, _autoStart: bool) ->  Result<()> {


        // let qkernel_args = QKernelArgs {
        //     heapStart: heapStart,
        //     shareSpaceAddr: shareSpaceAddr,
        //     id: id,
        //     svdsoParamAddr: svdsoParamAddr,
        //     vcpuCnt: vcpuCnt,
        //     autoStart: autoStart,
        // };

        let config = crate::SHARESPACE.config.read().clone();

        let kernel_args_in_bytes = serde_json::to_vec(&config)
            .map_err(|e| Error::Common(format!("measure_qkernel_argument, serde_json::to_vec(&qkernel_args) get error {:?}", e)))?;

        self.updata_measurement(kernel_args_in_bytes, MeasurementType::Global).unwrap();

        Ok(())
    }

    /**
     *  Only measure the auxv we got from elf file is enough,
     *  Other data like, envv, argv, are measuared by `measure_process_spec`
     */
    pub fn measure_stack(&mut self, auxv: Vec<AuxEntry>, is_app: bool, binary_name: &str) -> Result<()> {

        info!("measure_stack binary_name {:?}, auxv {:?}",binary_name, auxv);

        let mut aux_entries_in_byte = Vec::new();
        for entry in auxv {
            let mut entry_in_byte = serde_json::to_vec(&entry)
                .map_err(|e| Error::Common(format!("measure_stack, serde_json::to_vec(&entry) get error {:?}", e)))?;
            aux_entries_in_byte.append(&mut entry_in_byte);
        }

        // app retart
        if self.is_app_loaded && !self.load_app_end && !is_app {
            // self.updata_measurement(aux_entries_in_byte, MeasurementType::Tmp).unwrap();
        // app restart, app binary loading is finished
        } else if self.is_app_loaded && !self.load_app_end && self.load_app_start && is_app{
            // self.updata_measurement(aux_entries_in_byte, MeasurementType::Tmp).unwrap();

            let app_ref_measurement = self.app_ref_measurement.clone();
            let tmp_measurement = self.tmp_measurement.clone();

            if app_ref_measurement.eq(&tmp_measurement) {
                self.load_app_end = true;
                self.load_app_start = false;
                info!("app restart successfully, app_ref_measurement {:?}, tmp_measurement {:?}",app_ref_measurement, tmp_measurement);
                self.tmp_measurement = String::new();
                return Ok(());
            }

            panic!("tmp_measurement doesn't match the app_ref_measurement {:?}, k8s tries to restart application using bad bainary {:?}", app_ref_measurement, tmp_measurement);
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start && !is_app {
            // self.updata_measurement(aux_entries_in_byte.clone(), MeasurementType::AppRef).unwrap();
           // self.updata_measurement(aux_entries_in_byte, MeasurementType::Global).unwrap();
        // app first time loading us finished
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start && is_app{
            // self.updata_measurement(aux_entries_in_byte.clone(), MeasurementType::AppRef).unwrap();
            //self.updata_measurement(aux_entries_in_byte, MeasurementType::Global).unwrap();
            self.is_app_loaded = true;
            self.load_app_end = true;
            self.load_app_start = false;

            match self.enclave_mode {
                EnclaveMode::Development => error!("app_ref_measurement {:?}, app ref {:?}", self.global_measurement, self.app_ref_measurement),
                EnclaveMode::Production =>  {
                    //nothing need to be compared here
                }
            }
            self.enclave_ref_measurement = self.global_measurement.clone();

        } else {

            // self.updata_measurement(aux_entries_in_byte, MeasurementType::Global).unwrap();
        }


        Ok(())
    }

    pub fn measure_elf_loadable_segment(&mut self, load_segment_virtual_addr: u64, load_segment_size: u64, offset: u64, task: &Task, file_name: &str) -> Result<()> {

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
        if self.is_app_loaded && !self.load_app_end && self.load_app_start{
            info!("measure_elf_loadable_segment app restart time loading load_segment_virtual_addr {:?}, file name {:?}", load_segment_virtual_addr, file_name);
            self.updata_measurement(loadable, MeasurementType::Tmp).unwrap();
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start{
            info!("measure_elf_loadable_segment app load   load_segment_virtual_addr {:?} file name {:?}", load_segment_virtual_addr, file_name);
            self.updata_measurement(loadable.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(loadable, MeasurementType::Global).unwrap();
           // app runtime 
        } else  if self.is_app_loaded && self.load_app_end && !self.load_app_start {
            let current_hash = self.runtime_binary_measurement.remove(file_name).unwrap();
            let chunks = vec![
                current_hash.as_bytes().to_vec(),
                loadable.clone()
            ];
            let hash_res = super::hash_chunks(chunks);
            self.runtime_binary_measurement.insert(file_name.to_string(), hash_res);
        
        // qkernel launch measurement
        }  else {
            info!("measure_elf_loadable_segment launch measurement  load_segment_virtual_addr {:?} file name {:?}", load_segment_virtual_addr, file_name);
            self.updata_measurement(loadable, MeasurementType::Global).unwrap();
        }
    
        Ok(())
    }

    pub fn measure_shared_lib(&mut self, start_addr: u64, file: &File, task: &Task, fixed: bool, mmmap_len: u64, offset: u64, file_name: String) -> Result<()> {

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
        debug!("measure_shared_lib, addr {:x}, shared_lib_size {:x}, fixed {:?}, mmmap_len {:x} file_name {:?}", start_addr, real_mmap_size, fixed, mmmap_len, file_name);
        
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
        if self.is_app_loaded && !self.load_app_end && self.load_app_start{
            info!("measure_shared_lib app restart time loading offset {:?}, mmmap_len {:?} file name {:?}", offset, mmmap_len, file_name);
            self.updata_measurement(loadable, MeasurementType::Tmp).unwrap();            
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start {
            info!("measure_shared_lib app load   offset {:?}  mmmap_len {:?}  file name {:?}", offset, mmmap_len, file_name);
            self.updata_measurement(loadable.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(loadable, MeasurementType::Global).unwrap();
        // app runtime measurement 
        } else  if self.is_app_loaded && self.load_app_end && !self.load_app_start {
         

            let current_hash = self.shared_lib_measurements.remove(&file_name).unwrap();
            let chunks = vec![
                current_hash.as_bytes().to_vec(),
                loadable
            ];
            let hash_res = super::hash_chunks(chunks);
            self.shared_lib_measurements.insert(file_name, hash_res);
        } else {
            // qkernel lauch measurement
            info!("measure_shared_lib launch measurement  offset {:?}  mmmap_len {:?}  file name {:?}", offset, mmmap_len, file_name);
            self.updata_measurement(loadable.clone(), MeasurementType::Global).unwrap();
        }

        Ok(())
    }

    pub fn get_measurement(&self) -> Result<String> {

        Ok(self.enclave_ref_measurement.clone())
    }



    pub fn init_shared_lib_hash (&mut self, shared_lib_name: &str) -> Result<()> {
        if self.is_app_loaded && self.load_app_end{ 
            info!("init_shared_lib_hash {:?}", shared_lib_name);
            self.shared_lib_measurements.insert(shared_lib_name.to_string(), String::default());
        }
        Ok(())
    }



    pub fn check_runtime_hash (&mut self, shared_lib_name: &str) -> Result<()> {

        
        if self.is_app_loaded && self.load_app_end{ 
            let hash = self.shared_lib_measurements.remove(shared_lib_name).unwrap();

            match self.enclave_mode {
                EnclaveMode::Development => {
                    error!("lib_name {:?}, measurement {:?}",shared_lib_name, hash)
                }
                EnclaveMode::Production =>  {
                    // compare the loadable with the hash in policy file
    
                    let reference = self.runtime_binary_reference_measurement.get(shared_lib_name).clone();
    
                    if reference.is_none() {
                        panic!("check_runtime_binary_hash missing reference value binary_name {}, hashed value {}", shared_lib_name, hash);
                    }
    
                    let ref_value = reference.unwrap();
    
                    if ref_value.eq(&hash) == false {
                        panic!("check_runtime_binary_hash hash not match  binary_name {}, refernce {} hashed value {}", shared_lib_name, ref_value, hash);
                    }
    
                }
            }
        }

        Ok(())
    }



    pub fn init_runtime_binary_hash (&mut self, binary_name: &str) -> Result<()> {

        //runtime
        if self.is_app_loaded && self.load_app_end{
            info!("init_runtime_binary_hash {:?}", binary_name);
            self.runtime_binary_measurement.insert(binary_name.to_string(), String::default());
        }

        Ok(())
    }



    pub fn check_runtime_binary_hash (&mut self, binary_name: &str) -> Result<()> {

        if self.is_app_loaded && self.load_app_end{
            info!("check_runtime_binary_hash {:?}", binary_name);

            let hash = self.runtime_binary_measurement.remove(binary_name).unwrap();

            match self.enclave_mode {
                EnclaveMode::Development => {
                    error!("runtime binary_name {:?}, measurement {:?}",binary_name, hash)
                }
                EnclaveMode::Production =>  {
                    // compare the loadable with the hash in policy file

                    let reference = self.runtime_binary_reference_measurement.get(binary_name).clone();

                    if reference.is_none() {
                        panic!("check_runtime_binary_hash missing reference value binary_name {}, hashed value {}", binary_name, hash);
                    }

                    let ref_value = reference.unwrap();

                    if ref_value.eq(&hash) == false {
                        panic!("check_runtime_binary_hash hash not match  binary_name {}, refernce {} hashed value {}", binary_name, ref_value, hash);
                    }
                }
            }

        }

        Ok(())
    }

}



