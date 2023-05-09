
use alloc::{vec::Vec, string::String};
use crate::qlib::common::*;
use spin::rwlock::RwLock;
use alloc::string::ToString;
use core::convert::TryInto;
use Task;
lazy_static! {
    pub static ref APPLICATION_INFO_KEEPER:  RwLock<ApplicationInfoKeeper> = RwLock::new(ApplicationInfoKeeper::default());
}

const APP_NMAE: &str = "APPLICATION_NAME";
const SECRET_MANAGER_IP: &str = "SECRET_MANAGER_IP"; 
const CMD_ENV_BASED_SECRETS_PATH: &str = "CMD_ENV_BASED_SECRETS_PATH"; 
const FILE_BASED_SECRETS_PATH: &str = "FILE_BASED_SECRETS_PATH"; 
const SHILED_POLICY_PATH: &str = "SHILED_POLICY_PATH"; 


#[derive(Default)]
pub struct ApplicationInfoKeeper {
    pub app_name: String,
    pub is_launched: bool,
    pub cid: String,
    pub pid: i32,
}

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}


impl ApplicationInfoKeeper {
    pub fn init(&mut self, envs : &Vec<String>, cid: String) -> Result<()>{

        if envs.len() == 0 {
            return  Err(Error::Common("parse_envs, envs.len() == 0".to_string()));
        }

        self.cid = cid;

        let mut found_app_name = false;
        for env in envs {

            let key_value:  Vec<&str> = env.split('=').collect();

            assert!(key_value.len() == 2);
            if key_value[0].eq(APP_NMAE) {
                self.app_name =  key_value[1].to_string();
                found_app_name = true;
            }
        }
        assert!(found_app_name == true);
        Ok(())
    }

    pub fn is_application_loaded (&self) -> Result<bool> {
        return Ok(self.is_launched);
    }

    pub fn set_application_loaded (&mut self) -> Result<()> {
        self.is_launched = true;
        return Ok(());
    }

    pub fn get_application_name (&self) -> Result<&str> {
        return Ok(&self.app_name);
    }
}


pub fn shiled_clock_get_time(task: &mut Task) -> i64 {

    let clockID = crate::qlib::linux::time::CLOCK_MONOTONIC;

    let clock = crate::syscalls::sys_time::GetClock(task, clockID).unwrap();


    let ns = clock.Now().Nanoseconds();


    return ns;
}