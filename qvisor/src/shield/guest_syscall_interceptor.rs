use crate::qlib::shield_policy::*;
use spin::lock_api::RwLock;
use crate::qlib::common::*;

lazy_static! {
    static ref SYSCALLINTERCEPTOR:  RwLock<GuestSyscallInterceptor> = RwLock::new(GuestSyscallInterceptor::default());
}

#[derive(Debug, Default)]
pub struct GuestSyscallInterceptor {
    policy: BackEndSyscallInterceptorConfig,
    application_pid: i32,
    is_init: bool,
}


pub fn syscall_interceptor_init(_policy: BackEndSyscallInterceptorConfig) -> Result<()>{
    Err(Error::NotSupport)
}


// TODO: ENABLE CONTEXT BASED SYSTEM CALL INTERCEPTOR
pub fn is_guest_syscall_allowed(_current_pid: i32, _syscall_id: u64) -> bool {
    false
}


pub fn syscall_interceptor_set_app_pid(_application_pid: i32) -> Result<()> {
    Err(Error::NotSupport)
}














