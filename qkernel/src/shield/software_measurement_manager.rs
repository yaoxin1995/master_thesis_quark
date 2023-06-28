use alloc::vec::Vec;
use spin::rwlock::RwLock;
use alloc::string::{String, ToString};
use crate::qlib::common::*;
use qlib::addr::Addr;
use crate::qlib::kernel::task::Task;
use crate::qlib::loader::Process;
use qlib::path::*;
use fs::file::File;
use alloc::collections::btree_map::BTreeMap;
use shield::EnclaveMode;
use shield::RuntimeReferenceMeasurement;
use crate::qlib::config::Config;
use syscalls::sys_file::openAt;
use syscalls::sys_read::readv;
use qlib::linux_def::*;

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
    Restart
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
    restart_bianry_measurement : String,

    //记录lib测量过程中的值 
    shared_lib_measurements: BTreeMap<String, String>,
    binary_measurement:  BTreeMap<String, String>,

    
    runtime_binary_reference_measurement:  BTreeMap<String, String>,

    //记录lib测量的结果
    startup_shared_lib_measurement_results:  BTreeMap<String, String>,
    restart_shared_lib_measurement_results:  BTreeMap<String, String>,

    sm_certiface: Vec<u8>
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

        let task = Task::Current();
        self.sm_certiface = get_sm_public_key(task).unwrap();

        self.updata_measurement(self.sm_certiface.clone(), MeasurementType::Global).unwrap();

        Ok(())
    }



    fn updata_measurement(&mut self, new_data: Vec<u8>, m_type: MeasurementType) -> Result<()> {

        let measurement = match m_type {
            MeasurementType::Global => self.global_measurement.clone(),
            MeasurementType::AppRef => self.app_ref_measurement.clone(),
            MeasurementType::Restart => self.restart_bianry_measurement.clone(),   
        };

        let chunks = vec![
            measurement.as_bytes().to_vec(),
            new_data,  
        ];

        let hash_res = super::hash_chunks(chunks);
        match m_type {
            MeasurementType::Global => self.global_measurement = hash_res,
            MeasurementType::AppRef => self.app_ref_measurement = hash_res,
            MeasurementType::Restart => self.restart_bianry_measurement = hash_res,   
        };

        Ok(())
    }

    pub fn start_track_app_creation(&mut self, proc_spec: &Process, is_root: bool) -> Result<()> {

        self.load_app_end = false;
        self.restart_bianry_measurement = String::default();
        self.restart_shared_lib_measurement_results = BTreeMap::default();


        let mut process = Process::default();
        process.Terminal = proc_spec.Terminal;
        

        // info!("start_track_app_creation {:?}", process_spec);

        if is_root == false {
            self.load_app_start = true;
            self.load_app_end = false;
        }


        let proccess_spec_vec = serde_json::to_vec(&process);
        if proccess_spec_vec.is_err() {
            info!("start_track_app_creation serde_json::to_vec(proc_spec) get error");
            return Err(Error::Common("start_track_app_creation serde_json::to_vec(proc_spec) get error".to_string()));
        }

        let proccess_spec_vec_in_bytes = proccess_spec_vec.unwrap();
        // app restart
        if self.is_app_loaded && !self.load_app_end && self.load_app_start{
            info!("start_track_app_creation app restart");
            self.updata_measurement(proccess_spec_vec_in_bytes, MeasurementType::Restart).unwrap();            
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start {
            info!("start_track_app_creation app load");
            self.updata_measurement(proccess_spec_vec_in_bytes.clone(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(proccess_spec_vec_in_bytes, MeasurementType::Global).unwrap();
            // app runtime 
        } else  if self.is_app_loaded && self.load_app_end && !self.load_app_start {
        
        } else {
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



    pub fn measure_qkernel_argument (&mut self, config: Config) ->  Result<()> {


        let kernel_args_in_bytes = serde_json::to_vec(&config)
            .map_err(|e| Error::Common(format!("measure_qkernel_argument, serde_json::to_vec(&qkernel_args) get error {:?}", e)))?;

        self.updata_measurement(kernel_args_in_bytes, MeasurementType::Global).unwrap();

        Ok(())
    }

    /**
     *  Only measure the auxv we got from elf file is enough,
     *  Other data like, envv, argv, are measuared by `start_track_app_creation`
     */
    pub fn check_before_app_starts(&mut self, is_app: bool, binary_name: &str) -> Result<()> {

        info!("measure_stack binary_name {:?}",binary_name);

        // app retart
        if self.is_app_loaded && !self.load_app_end && !is_app {
        // app restart, app binary loading is finished
        } else if self.is_app_loaded && !self.load_app_end && self.load_app_start && is_app{
            let app_ref_measurement = self.app_ref_measurement.clone();
            let restart_bianry_measurement = self.restart_bianry_measurement.clone();

            if app_ref_measurement.eq(&restart_bianry_measurement) {
                self.load_app_end = true;
                self.load_app_start = false;
                for (k, v) in &self.restart_shared_lib_measurement_results {
                    let ref_hash = self.startup_shared_lib_measurement_results.get(k);
                    if ref_hash.is_none() {
                        panic!("restart failed, during restart  app load unknow shared lib   shared lib name {:?}, reference shared lib values {:?}", k, self.startup_shared_lib_measurement_results);
                    }
                    let ref_hash = ref_hash.unwrap();

                    if ref_hash.eq(v) == false {
                        panic!("restart failed, during restart  app load buggy shared lib   shared lib name {:?}, reference hash {:?}, measured_hahs {:?}", k, ref_hash, v);
                    }
                }
                info!("app restart successfully, binary_ref_measurement {:?}, tmp_binary_measurement {:?}",app_ref_measurement, restart_bianry_measurement);
                self.restart_shared_lib_measurement_results = BTreeMap::new();
                self.restart_bianry_measurement = String::new();
                return Ok(());
            }

            panic!("tmp_measurement doesn't match the app_ref_measurement {:?}, k8s tries to restart application using bad bainary {:?}", app_ref_measurement, restart_bianry_measurement);
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start && !is_app {
        // app first time loading us finished
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start && is_app{
            self.is_app_loaded = true;
            self.load_app_end = true;
            self.load_app_start = false;


            let mut lib_hashes = String::default();
            for (_key, value) in &self.startup_shared_lib_measurement_results {

                let chunks = vec![
                    lib_hashes.as_bytes().to_vec(),
                    value.as_bytes().to_vec()
                ];

                lib_hashes = super::hash_chunks(chunks);
            }

            let chunks = vec![
                self.global_measurement.clone().as_bytes().to_vec(),
                lib_hashes.as_bytes().to_vec()
            ];

            let enclave_start_hash  = super::hash_chunks(chunks);

            match self.enclave_mode {
                EnclaveMode::Development => error!("enclave_start_hash {:?}, app ref {:?}", enclave_start_hash, self.app_ref_measurement),
                EnclaveMode::Production =>  {
                    //nothing need to be compared here
                }
            }
            self.enclave_ref_measurement = enclave_start_hash;

        } else {
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

        let current_hash = self.binary_measurement.remove(file_name);
        if current_hash.is_none() {
            panic!("measure_elf_loadable_segment  binary_name {:?}, hashmap {:?}", file_name, self.binary_measurement);
        }
        let current_hash = current_hash.unwrap();

        let chunks = vec![
            current_hash.as_bytes().to_vec(),
            loadable.clone()
        ];
        let hash_res = super::hash_chunks(chunks);
        self.binary_measurement.insert(file_name.to_string(), hash_res);
        
    
        Ok(())
    }

    pub fn measure_shared_lib_loadable_segment(&mut self, start_addr: u64, file: &File, task: &Task, fixed: bool, mmmap_len: u64, _offset: u64, file_name: String) -> Result<()> {

        let uattr = file.UnstableAttr(task)?;
        let real_mmap_size = if uattr.Size as u64 > mmmap_len {
            mmmap_len
        } else {
            uattr.Size as u64
        };

        debug!("measure_shared_lib, addr {:x}, shared_lib_size {:x}, fixed {:?}, mmmap_len {:x} file_name {:?}", start_addr, real_mmap_size, fixed, mmmap_len, file_name);
        
        let data: Result<Vec<u8>> = task.CopyInVec(start_addr, real_mmap_size as usize);
        if data.is_err() {
            info!("measure_shared_lib After task.CopyInVec got error {:?}", data);
            return Err(data.err().unwrap());
        }

        let loadable = data.unwrap();

        let current_hash = self.shared_lib_measurements.remove(&file_name);
        if current_hash.is_none() {
            panic!("measure_shared_lib check_runtime_hash shared_lib_name {:?}, hashmap {:?}", file_name, self.shared_lib_measurements);
        }
        let current_hash = current_hash.unwrap();

        let chunks = vec![
            current_hash.as_bytes().to_vec(),
            loadable
        ];
        let hash_res = super::hash_chunks(chunks);
        self.shared_lib_measurements.insert(file_name, hash_res);


        Ok(())
    }

    pub fn get_measurement(&self) -> Result<String> {

        Ok(self.enclave_ref_measurement.clone())
    }

    pub fn get_sm_certificate(&self) -> Result<Vec<u8>> {

        Ok(self.sm_certiface.clone())
    }

    
    pub fn init_shared_lib_hash (&mut self, shared_lib_name: &str) -> Result<()> {
        info!("init_shared_lib_hash {:?}", shared_lib_name);
        self.shared_lib_measurements.insert(shared_lib_name.to_string(), String::default());
        Ok(())
    }



    pub fn check_shared_lib_hash (&mut self, shared_lib_name: &str) -> Result<()> {

        let hash = self.shared_lib_measurements.remove(shared_lib_name);
        if hash.is_none() {
            panic!("check_runtime_hash shared_lib_name {:?}, hashmap {:?}", shared_lib_name, self.shared_lib_measurements);
        }

        let hash = hash.unwrap();
        let strs : Vec<&str> = shared_lib_name.split_whitespace().collect();
        let lib_name = strs[1];
        // app retart
        if self.is_app_loaded && !self.load_app_end && self.load_app_start{

            let hash_value = self.restart_shared_lib_measurement_results.get(lib_name);
            if hash_value.is_none() {
                self.restart_shared_lib_measurement_results.insert(lib_name.to_string(), hash);
            } else {
                let ref_hash = hash_value.unwrap();
                if ref_hash.eq(&hash) == false {
                    panic!("chech restart time hash the libs with the same name doesn't match, libname {}, first hashed value {} secent hash value {:?}", lib_name, ref_hash, hash);
                }
            }   
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start {
            info!("runtime hash file nmae {:?}, hash {:?}", shared_lib_name, hash);


            let hash_value = self.startup_shared_lib_measurement_results.get(lib_name);
            if hash_value.is_none() {
                self.startup_shared_lib_measurement_results.insert(lib_name.to_string(), hash);
            } else {
                let ref_hash = hash_value.unwrap();
                if ref_hash.eq(&hash) == false {
                    panic!("chech startup time hash the libs with the same name doesn't match libname {}, first hashed value {} secent hash value {:?}", lib_name, ref_hash, hash);
                }
            }
        // app runtime measurement 
        } else  if self.is_app_loaded && self.load_app_end && !self.load_app_start {

            let strs : Vec<&str> = shared_lib_name.split_whitespace().collect();
            let lib_name = strs[1];
            match self.enclave_mode {
                EnclaveMode::Development => {
                    error!("lib_name {:?}, measurement {:?}",lib_name, hash)
                }
                EnclaveMode::Production =>  {
                    // compare the loadable with the hash in policy file
    
                    let reference = self.runtime_binary_reference_measurement.get(lib_name).clone();
    
                    if reference.is_none() {
                        panic!("check_runtime_binary_hash missing reference value binary_name {}, hashed value {}", lib_name, hash);
                    }
    
                    let ref_value = reference.unwrap();
    
                    if ref_value.eq(&hash) == false {
                        panic!("check_runtime_binary_hash hash not match  binary_name {}, refernce {} hashed value {}", lib_name, ref_value, hash);
                    }
    
                }
            }
        } else {

        }

        Ok(())
    }



    pub fn init_binary_hash (&mut self, binary_name: &str) -> Result<()> {
        //runtime
        info!("init_runtime_binary_hash {:?}", binary_name);
        self.binary_measurement.insert(binary_name.to_string(), String::default());
        Ok(())
    }



    pub fn check_binary_hash (&mut self, binary_name: &str) -> Result<()> {


        let hash = self.binary_measurement.remove(binary_name);
        if hash.is_none() {
            panic!("check_runtime_binary_hash  binary_name {:?}, hashmap {:?}", binary_name, self.binary_measurement);
        }
        let hash = hash.unwrap();

        // app retart
        if self.is_app_loaded && !self.load_app_end && self.load_app_start{
            self.updata_measurement(hash.into_bytes().to_vec(), MeasurementType::Restart).unwrap();
        // during app first time loading
        } else if !self.is_app_loaded && !self.load_app_end && self.load_app_start{
            // info!("measure_elf_loadable_segment during app first time loading global_measurement {:?}  app_reference_measurement {:?}", self.global_measurement, self.app_ref_measurement);
            
            self.updata_measurement(hash.as_bytes().to_vec(), MeasurementType::AppRef).unwrap();
            self.updata_measurement(hash.as_bytes().to_vec(), MeasurementType::Global).unwrap();
            // app runtime 
        } else  if self.is_app_loaded && self.load_app_end && !self.load_app_start {

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
        }  else {
            
        }

        Ok(())
    }

}


fn get_sm_public_key(task: &Task)-> Result<Vec<u8>> {

    let path = "/usr/local/secret_manager_cert.pem";

    let fd = openAt(task, -1, path.to_string(), false, Flags::O_RDWR as u32)?;
    assert!(fd > 1);

    let file = task.GetFile(fd)?;

    let uattr = file.UnstableAttr(task)?;

    let mut buf = Vec::with_capacity(uattr.Size as usize);

    info!("secret_manager_cert.pem size {:?}  len {:?}", uattr, buf.len());
    buf.resize(uattr.Size as usize, 0);

    let iov = IoVec::New(&buf);


    let mut iovs: [IoVec; 1] = [iov];

    let n = readv(task, &file, &mut iovs)?;
    assert!(n == uattr.Size);


    return Ok(buf)
}




