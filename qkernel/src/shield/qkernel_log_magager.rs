
use qlib::shield_policy::*;
use spin::lock_api::RwLock;
use qlib::common::*;


lazy_static! {
    static ref QLOGMANAGER:  RwLock<QlogManager> = RwLock::new(QlogManager::default());
}


#[derive(Debug, Default)]
pub struct QlogManager {
    policy: QlogPolicy,
}

/**
 * Please don't use any print in this file to prevent dead lock
*/
pub fn qlog_magager_update(policy: &QlogPolicy) -> Result<()> {

    let mut qloger = QLOGMANAGER.write();
    qloger.policy = policy.clone();
    Ok(())
}


pub fn qlog_magager_init() -> Result<()> {

    let mut qloger = QLOGMANAGER.write();
    // qloger.policy = QlogPolicy::default();

    qloger.policy.allowed_max_log_level = QkernelDebugLevel::Off;
    qloger.policy.enable = true;
    Ok(())
}


pub fn is_log_level_allowed(current_log_level: QkernelDebugLevel) -> bool {
    let qloger = QLOGMANAGER.read();
    if !qloger.policy.enable {
        return true;
    }
    if current_log_level > qloger.policy.allowed_max_log_level {
        return false;
    }

    return true;
}

