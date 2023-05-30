use qlib::shield_policy::*;
use spin::lock_api::RwLock;
use qlib::common::*;



lazy_static! {
    static ref SYSCALLINTERCEPTOR:  RwLock<GuestSyscallInterceptor> = RwLock::new(GuestSyscallInterceptor::default());
}



#[derive(Debug, Default)]
pub struct GuestSyscallInterceptor {
    policy: BackEndSyscallInterceptorConfig,
    application_pid: i32,
    is_init: bool,
}


pub fn syscall_interceptor_policy_update(policy: &BackEndSyscallInterceptorConfig) -> Result<()> {

    let mut syscall_info_keeper = SYSCALLINTERCEPTOR.write();

    debug!("syscall_interceptor_policy_update policy {:?}", policy);
    syscall_info_keeper.policy.enable = policy.enable;
    syscall_info_keeper.policy.mode = policy.mode.clone();
    syscall_info_keeper.policy.syscalls = policy.syscalls;
    Ok(())
}


pub fn syscall_interceptor_init(policy: BackEndSyscallInterceptorConfig) -> Result<()> {

    let mut syscall_info_keeper = SYSCALLINTERCEPTOR.write();

    debug!("syscall_interceptor_init policy {:?}", policy);
    syscall_info_keeper.policy = policy;
    syscall_info_keeper.is_init = true;

    Ok(())
}

pub fn syscall_interceptor_set_app_pid(application_pid: i32) -> Result<()> {

    let mut syscall_info_keeper = SYSCALLINTERCEPTOR.write();

    debug!("syscall_interceptor_set_app_pid pid {:?}", application_pid);
    syscall_info_keeper.application_pid = application_pid;

    Ok(())
}


// TODO: ENABLE CONTEXT BASED SYSTEM CALL INTERCEPTOR
pub fn is_guest_syscall_allowed(current_pid: i32, syscall_id: u64) -> bool {
    let syscall_info_keeper = SYSCALLINTERCEPTOR.read();
    if !syscall_info_keeper.is_init {
        info!("syscall_info_keeper is not init");
        return true;
    }

    if !syscall_info_keeper.policy.enable {
        info!("syscall_info_keeper is not enabel");
        return true;
    }

    info!("is_guest_syscall_allowed enter");
    debug!("is_guest_syscall_allowed enter");
    error!("is_guest_syscall_allowed enter");
    warn!("is_guest_syscall_allowed enter");


    match syscall_info_keeper.policy.mode {
        SystemCallInterceptorMode::ContextBased => {
            if current_pid != syscall_info_keeper.application_pid {
                debug!("is_guest_syscall_allowed syscall id {:?}, ContextBased, not app process task id {:?}", syscall_id, current_pid);
                return true;
            }
            let allowed_list = syscall_info_keeper.policy.syscalls;
            let res = is_syscall_allowed(allowed_list, syscall_id);
            debug!("is_guest_syscall_allowed syscall id {:?}, is allowed {:?}, ContextBased", syscall_id, res);
            return res;
        },
        SystemCallInterceptorMode::Global => {


            let allowed_list = syscall_info_keeper.policy.syscalls;
            let res = is_syscall_allowed(allowed_list, syscall_id);

            debug!("is_guest_syscall_allowed syscall id {:?}, is allowed {:?} Global", syscall_id, res);
            return res;

        }
    }
}


fn is_syscall_allowed(allowed_list: [u64; 8], syscall_num: u64)-> bool {
    debug!("allowed_list {:?}, isyscall_num {:?}", allowed_list, syscall_num);
    let position_in_u64 = syscall_num % 64;
    let index = syscall_num / 64;
    let is_allowed = allowed_list[index as usize] & (1 << position_in_u64);


    debug!("allowed_list {:?}, isyscall_num {:?}, is_allowed {:?} allowed_list[index as usize] {:b}, (1 << position_in_u64) {:?}, position_in_u64 {:?} index {:?}", allowed_list, syscall_num, is_allowed, allowed_list[index as usize], (1 << position_in_u64), position_in_u64, index);
    return is_allowed > 0;
}

















