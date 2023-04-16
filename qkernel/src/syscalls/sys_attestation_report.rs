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

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Report {
    //  AMD SNP: 2, TDX: 3, See https_attestation_provisioning_cli::Tee
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

/**
 * arg0:  u8 array of user data, which will be embedded to attestation report
 * arg1:  lengh of the user data array
 * arg1:  returned attestation report and it's info  
 */

pub fn SysAttestationReport(task: &mut Task, args: &SyscallArguments) -> Result<i64> {
    let user_data_addr = args.arg0 as u64;
    let size = args.arg1 as u64;
    let report_info_adr = args.arg2 as u64;

    debug!("SysAttestationReport: start, user_data_addr {:?}, user_data_len {:?}, report_info_adr {:?}", user_data_addr, size, report_info_adr);

    let user_data = task.CopyInVec(user_data_addr, size as usize);
    if user_data.is_err() {
        debug!("SysAttestationReport: Base64::decode_vec failed");
        return  Err(Error::SysError(SysErr::EINVAL));
    }

    let user_data_unwrap = user_data.unwrap();

    let report;

    // TODO: add the hash of image binary loaded to guest 
    let user_data_chunks = vec![
        user_data_unwrap
    ];

    let encode64_user_data = crate::shield::hash_chunks(user_data_chunks);
    match sev_guest::detect_tee_type() {
        https_attestation_provisioning_cli::Tee::Snp => {

            debug!("SysAttestationReport: Snp report");
            let mut attester = sev_guest::GUEST_SEV_DEV.try_write();
            while !attester.is_some() {
                attester = sev_guest::GUEST_SEV_DEV.try_write();
            }
            let mut attester = attester.unwrap();

            report = attester.get_report(encode64_user_data);

        },
        https_attestation_provisioning_cli::Tee::Tdx => {
            debug!("SysAttestationReport: Tdx report");
            return Ok(-1);
        }
        _ => {
            debug!("SysAttestationReport: other report");
            return Ok(-1);
        }
        
    }

    if report.is_err() {
        debug!("SysAttestationReport: attester.get_report failed");
        return  Err(Error::SysError(SysErr::EIO));
    }

    let res = copy_attesation_report_to_container(&task, https_attestation_provisioning_cli::Tee::Snp, report_info_adr, report.unwrap());

    if res.is_err() {
        debug!("SysAttestationReport: copy_attesation_report_to_container failed");
        return  Err(Error::SysError(SysErr::EIO));
    }

    Ok(0)
}
