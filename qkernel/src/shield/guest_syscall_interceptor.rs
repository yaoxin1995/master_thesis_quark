use qlib::shield_policy::*;
use spin::lock_api::RwLock;
use qlib::common::*;



lazy_static! {
    static ref SYSCALLINTERCEPTOR:  RwLock<GuestSyscallInterceptor> = RwLock::new(GuestSyscallInterceptor::default());
}



#[derive(Debug, Default)]
pub struct GuestSyscallInterceptor {
    policy: BackEndSyscallInterceptorConfig,
    application_pid: u64,
    is_init: bool,
}


pub fn syscall_interceptor_policy_update(policy: &BackEndSyscallInterceptorConfig) -> Result<()> {

    let mut syscall_info_keeper = SYSCALLINTERCEPTOR.write();

    debug!("syscall_interceptor_policy_update policy {:?}", policy);
    syscall_info_keeper.policy.enable = policy.enable;
    Ok(())
}


pub fn syscall_interceptor_init(policy: BackEndSyscallInterceptorConfig, application_pid: u64) -> Result<()> {

    let mut syscall_info_keeper = SYSCALLINTERCEPTOR.write();

    debug!("syscall_interceptor_init policy {:?}", policy);
    syscall_info_keeper.policy = policy;
    syscall_info_keeper.application_pid = application_pid;
    syscall_info_keeper.is_init = true;

    Ok(())
}


// TODO: ENABLE CONTEXT BASED SYSTEM CALL INTERCEPTOR
pub fn is_guest_syscall_allowed(current_pid: u64, syscall_id: u64) -> bool {
    let syscall_info_keeper = SYSCALLINTERCEPTOR.read();
    if !syscall_info_keeper.is_init {

        info!("syscall_info_keeper is not init");
        return true;
    }

    if !syscall_info_keeper.policy.enable {
        info!("syscall_info_keeper is not enabel");
        return true;
    }

    let res = syscall_info_keeper.policy.syscalls.contains(&syscall_id);
    debug!("is_guest_syscall_allowed syscall id {:?}, is allowed {:?}", syscall_id, res);
    return res;
}














