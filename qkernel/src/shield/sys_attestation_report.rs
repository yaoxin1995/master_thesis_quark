// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use core::fmt::Debug;
use super::super::qlib::common::*;
use super::super::task::*;
use super::super::syscalls::syscalls::*;
use crate::shield::{sev_guest, https_attestation_provisioning_cli};
use crate::qlib::kernel::util::cstring::CString;
use crate::qlib::linux_def::*;
use alloc::string::String;
use ssh_key;
use spin::rwlock::RwLock;
use shield::Vec;
use base64ct::{Base64, Encoding};

lazy_static! {
    pub static ref KBS_SIGNING_KEY_KEEPER:  RwLock<SoftwareBasedReportSigner> = RwLock::new(SoftwareBasedReportSigner::default());
}

#[derive(Debug, Clone, Default)]
pub struct SoftwareBasedReportSigner {
    kbs_signing_key: Vec<u8>,
    kbs_signing_key_installed: bool,
}

impl SoftwareBasedReportSigner{
    pub fn set_kbs_signing_key(&mut self,  key: Vec<u8>) -> Result<()> {

        if self.kbs_signing_key_installed {
            return Err(Error::Common(format!("Error, the kbs_signing_key is installed")));
        }

        self.kbs_signing_key = key;
        self.kbs_signing_key_installed = true;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[repr(C)]
pub struct SoftwareBasedAttestationReport {
    signature: Vec<u8>,
    software_measurement: Vec<u8>,
    user_data_hash: Vec<u8>,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Requst {
    //  AMD SNP: 2, TDX: 3, See https_attestation_provisioning_cli::Tee
    pub software_based_report_requered: bool,
    pub use_user_provided_signing_key: bool,
    pub signing_key_length: usize,
    //  AMD SNP REPORT has 1183 bytes, INTEL TDX report has 1024 bytes, so 4kb array should be enough to  hold the  Base64 encoded attestation tdx/snp report 
    pub signing_Key: [u8; 4096],  
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Report {
    //  AMD SNP: 2, TDX: 3, Software based: 4, See https_attestation_provisioning_cli::Tee
    pub tee_type: u64,
    pub report_length: u64,
    //  AMD SNP REPORT has 1183 bytes, INTEL TDX report has 1024 bytes, so 4kb array should be enough to  hold the  Base64 encoded attestation tdx/snp report 
    pub report: [u8; 4096],  
}

impl Default for Report {
    fn default() -> Self {
        let default_type = https_attestation_provisioning_cli::Tee::Snp;
        Self { tee_type: default_type as u64,
            report_length: 0,
            report: [0; 4096] 
        }
    }
}

//return (path, whether it is dir)
fn copy_user_data_from_container(task: &Task, addr: u64) -> Result<String> {
    let str = CString::ToString(task, addr)?;

    if &str == ""{
        debug!("copy_user_data_from_container got null str");
        return Err(Error::SysError(SysErr::EINVAL));
    }

    return Ok(str);
}

fn copy_attesation_report_to_container(task: &Task, tee_type: https_attestation_provisioning_cli::Tee, report_adr: u64, attestation_report: String) -> Result<()> {
    //let mut s: &mut LibcStat = task.GetTypeMut(statAddr)?;
    debug!("copy_attesation_report_to_container: start");
    let mut report_info: Report = Report::default();
    //*s = LibcStat::default();

    report_info.tee_type = tee_type as u64;

    let report_bytes = attestation_report.as_bytes();
    
    report_info.report_length = report_bytes.len() as u64;

    report_info.report[..report_bytes.len()].clone_from_slice(report_bytes);

    task.CopyOutObj(&report_info, report_adr)?;
    //info!("copyOutStat stat is {:x?}", s);
    return Ok(());
}

fn get_software_based_attestation_report(user_requset: Requst, user_data: Vec<u8>) -> Result<String> {

    let software_measurement;
    {
        software_measurement = super::software_measurement_manager::SOFTMEASUREMENTMANAGER.read().get_measurement()
        .map_err(|e| Error::Common(format!("sign_software_based_attestation_report, get measuerement failed:{:?}", e)))?;
    }

    let raw_software_measurement  = Base64::decode_vec(&software_measurement)
        .map_err(|e| Error::Common(format!("sign_software_based_attestation_report, Base64::decode_vec(&software_measurement) got error {:?}", e)))?;
    
    let chunks = vec![
        user_data,
    ];
    let hash_of_user_data: String = super::hash_chunks(chunks);
    let raw_hash_of_user_data = Base64::decode_vec(&hash_of_user_data)
        .map_err(|e| Error::Common(format!("sign_software_based_attestation_report, Base64::decode_vec(&hash_of_user_data) got error {:?}", e)))?;

    let signing_key = if user_requset.use_user_provided_signing_key {

        let user_provided_key_slice = &user_requset.signing_Key[..user_requset.signing_key_length];

        ssh_key::PrivateKey::from_bytes(user_provided_key_slice)
        .map_err(|e| Error::Common(format!("sign_software_based_attestation_report, build private key from user provided data failed {:?}", e)))?
    } else {

        let kbs_key;
        {   
            let kbs_signing_key_keeper = KBS_SIGNING_KEY_KEEPER.read();

            if !kbs_signing_key_keeper.kbs_signing_key_installed {
                return Err(Error::Common(format!("sign_software_based_attestation_report, kbs signing key is not installed")));
            }
            kbs_key = kbs_signing_key_keeper.kbs_signing_key.clone();
        }

        ssh_key::PrivateKey::from_bytes(&kbs_key)
        .map_err(|e| Error::Common(format!("sign_software_based_attestation_report, build private key from kbs_signing_key failed {:?}", e)))?
    };


    let app_name;
    let container_id;
    {   
        let app_info_keeper = super::APPLICATION_INFO_KEEPER.read();
        app_name = app_info_keeper.app_name.clone();
        container_id = app_info_keeper.cid.clone();
    }

    let signature_namespace = format!("QUARK-{}-{}", container_id, app_name);

    let mut signed_value =  raw_hash_of_user_data.clone();
    signed_value.copy_from_slice(&raw_software_measurement);

    let sig = signing_key.sign(&signature_namespace, ssh_key::HashAlg::Sha256, &signed_value)
        .map_err(|e| Error::Common(format!("sign_software_based_attestation_report, signing_key.sign(&signature_namespace, ssh_key::HashAlg::Sha256, &user_data) failed {:?}", e)))?;

    let soft_report = SoftwareBasedAttestationReport {
        signature: sig.signature_bytes().to_vec(),
        software_measurement: raw_software_measurement,
        user_data_hash : raw_hash_of_user_data,
    };


    serde_json::to_string(&soft_report)
        .map_err(|e| Error::Common(format!("Serialize SEV SNP evidence/report failed: {:?}", e)))

}


fn get_haredware_based_report (user_data: Vec<u8>) -> Result<String> {
    let software_measurement;
    {
        software_measurement = super::software_measurement_manager::SOFTMEASUREMENTMANAGER.read().get_measurement()
        .map_err(|e| Error::Common(format!("get_haredware_based_report, get measuerement failed:{:?}", e)))?;
    }

    let raw_software_measurement  = Base64::decode_vec(&software_measurement)
        .map_err(|e| Error::Common(format!("get_haredware_based_report, Base64::decode_vec(&software_measurement) got error {:?}", e)))?;
    
    let user_data_chunks = vec![
        user_data,
        raw_software_measurement,
    ];
    let encode64_user_data = crate::shield::hash_chunks(user_data_chunks);

    match sev_guest::detect_tee_type() {
        https_attestation_provisioning_cli::Tee::Snp => {

            debug!("get_haredware_based_report: Snp report");
            let mut attester = sev_guest::GUEST_SEV_DEV.try_write();
            while !attester.is_some() {
                attester = sev_guest::GUEST_SEV_DEV.try_write();
            }
            let mut attester = attester.unwrap();

            attester.get_report(encode64_user_data)
                .map_err(|e| Error::Common(format!("get_haredware_based_report, attester.get_report failed {:?}", e)))

        },
        https_attestation_provisioning_cli::Tee::Tdx => {
            debug!("get_haredware_based_report: Tdx report");
            return Err(Error::Common(format!("Tdx attestation is not supported yet, kbs signing key is not installed")));
        }
        _ => {
            debug!("get_haredware_based_report: other report");
            return Err(Error::Common(format!("the attestation type is not supported yet,")));
        }
    }
}

/**
 * arg0:  u8 array of user data, which will be embedded to attestation report
 * arg1:  lengh of the user data array
 * arg2:  `Requst` the requrement from user
 * arg3:  returned attestation report and it's info  
 */

pub fn SysAttestationReport(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
    let user_data_addr = args.arg0 as u64;
    let size = args.arg1 as u64;
    let request_adr = args.arg2;
    let report_info_adr = args.arg3 as u64;

    debug!("SysAttestationReport: start, user_data_addr {:?}, user_data_len {:?}, request_adr {:?} report_info_adr {:?}", user_data_addr, size, request_adr, report_info_adr);

    let user_data = task.CopyInVec(user_data_addr, size as usize);
    if user_data.is_err() {
        debug!("SysAttestationReport: task.CopyInVec(user_data_addr, size as usize) failed");
        return  Err(Error::SysError(SysErr::EINVAL));
    }

    let request: Result<Requst> = task.CopyInObj(request_adr);
    if request.is_err() {
        debug!("SysAttestationReport task.CopyInObj(request_adr) failed, error {:?}", request);
        return  Err(Error::SysError(SysErr::EINVAL));
    }

    let user_data_unwrap = user_data.unwrap();
    let request_unwrap = request.unwrap();

    let report = if request_unwrap.software_based_report_requered {

        get_software_based_attestation_report(request_unwrap, user_data_unwrap)

    } else {
        get_haredware_based_report(user_data_unwrap)
    };

    if report.is_err() {
        debug!("SysAttestationReport get attestation report failed, error {:?}", report);
        return  Err(Error::SysError(SysErr::EINVAL));
    }

    let res = copy_attesation_report_to_container(&task, https_attestation_provisioning_cli::Tee::Snp, report_info_adr, report.unwrap());
    if res.is_err() {
        debug!("SysAttestationReport: copy_attesation_report_to_container failed");
        return  Err(Error::SysError(SysErr::EIO));
    }

    Ok(0)
}
