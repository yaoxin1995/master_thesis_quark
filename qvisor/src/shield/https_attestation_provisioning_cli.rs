
use crate::qlib::common::*;
use crate::qlib::kernel::task::Task;
use crate::qlib::shield_policy::*;


/// The supported TEE types:
/// - Tdx: TDX TEE.
/// - Sgx: SGX TEE.
/// - Sevsnp: SEV-SNP TEE.
/// - Sample: A dummy TEE that used to test/demo the KBC functionalities.
#[derive(Debug, Clone)]
pub enum Tee {
    Sev,
    Sgx,
    Snp,
    Tdx,

    // This value is only used for testing an attestation server, and should not
    // be used in an actual attestation scenario.
    Sample,
}



pub fn provisioning_http_client(_task: &Task, _software_maasurement: &str, _: Vec<u8>) -> Result<(KbsPolicy, KbsSecrets)> {
    Err(Error::NotSupport)
}