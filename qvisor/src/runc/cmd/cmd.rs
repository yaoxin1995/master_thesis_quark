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

use alloc::string::String;
use alloc::vec::Vec;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use kvm_ioctls::Kvm;
use std::fs;

use super::super::super::qlib::common::*;
use super::super::super::qlib::config::*;
use super::super::cmd::config::*;
use super::super::runtime::loader::*;
use super::super::runtime::vm::*;
use super::command::*;

use super::super::super::qlib::shield_policy::*;
use crate::shield::sev_guest;

use sev_snp_utils;

#[derive(Debug)]
pub struct CmdCmd {
    pub cmd: Vec<String>,
}

impl CmdCmd {
    pub fn Init(cmd_matches: &ArgMatches) -> Result<Self> {
        return Ok(Self {
            cmd: match cmd_matches.values_of("cmd") {
                None => Vec::new(),
                Some(iter) => iter.map(|s| s.to_string()).collect(),
            },
        });
    }

    pub fn SubCommand<'a, 'b>(_common: &CommonArgs<'a, 'b>) -> App<'a, 'b> {
        return SubCommand::with_name("cmd")
            .setting(AppSettings::ColoredHelp)
            .setting(AppSettings::TrailingVarArg)
            .arg(
                Arg::with_name("cmd")
                    .help("Compatibility (ignored)")
                    .multiple(true),
            )
            .about("Signal a (previously created) container");
    }

    pub fn Run(&self, _gCfg: &GlobalConfig) -> Result<()> {
        let kvmfd = Kvm::open_with_cloexec(false).expect("can't open kvm");

        let mut args = Args::default();
        args.KvmFd = kvmfd;
        args.AutoStart = true;

        for a in &self.cmd {
            args.Spec.process.args.push(a.to_string());
        }

        match VirtualMachine::Init(args) {
            Ok(mut vm) => {
                vm.run().expect("vm.run() fail");
            }
            Err(e) => info!("error is {:?}", e),
        }

        return Ok(());
    }
}

impl Config {
    pub const CONFIG_FILE: &'static str = "/etc/quark/config.json";

    // if the config file exist, load file and return true; otherwise return false
    pub fn Load(&mut self) -> bool {
        let contents = match fs::read_to_string(Self::CONFIG_FILE) {
            Ok(c) => c,
            _ => return false,
        };

        let config = serde_json::from_str(&contents).expect("configuration wrong format");
        *self = config;
        return true;
    }

    pub fn Print(&self) {
        let c = serde_json::to_string(self).unwrap();
        error!("config is {}", c);
    }
}


impl sev_guest::AttestationReport {
    pub const REPORT_FILE: &'static str = "/etc/quark/sev_snp_guest_attestation_report.bin";

    // if the config file exist, load file and return true; otherwise return false
    pub fn Load() -> Result::<sev_guest::AttestationReport> {
        
        let sample_report = match  sev_snp_utils::AttestationReport::from_file(Self::REPORT_FILE) {
            Ok(reprot) => reprot,
            e => return Err(Error::IOError(format!("can't load the AttestationReport report error {:?}", e))),
        };

        let report = Self::prepare_guest_attestation_report(sample_report);
        
        return Ok(report);
    }


    fn prepare_guest_attestation_report (sample_report: sev_snp_utils::AttestationReport) -> sev_guest::AttestationReport {

        info!("prepare_guest_attestation_report get report from host  {:?}", sample_report);
    
        let platform_version = sev_guest::TcbVersion {
            boot_loader: sample_report.platform_version.boot_loader,
            tee: sample_report.platform_version.tee,
            reserved: vec![0;4],
            snp:sample_report.platform_version.snp,
            microcode: sample_report.platform_version.microcode,
            raw: vec![0;8],
        };
    
        let reported_tcb = sev_guest::TcbVersion {
            boot_loader: sample_report.reported_tcb.boot_loader,
            tee: sample_report.reported_tcb.tee,
            reserved: vec![0;4],
            snp:sample_report.reported_tcb.snp,
            microcode: sample_report.reported_tcb.microcode,
            raw: vec![0;8],
        };
        
        let mut reserverd = Vec::new();
        reserverd.resize(368, 0);
        let signature = sev_guest::SnpAttestationReportSignature {
            r: sample_report.signature.r.clone(),
            s: sample_report.signature.s.clone(),
            reserved: reserverd, //[0; 368],
        };

        let mut reserverd1 = Vec::new();
        reserverd1.resize(24, 0);

        let mut reserverd2 = Vec::new();
        reserverd2.resize(192, 0);
    
        let snp_report = sev_guest::AttestationReport {
            version : sample_report.version,
            guest_svn: sample_report.guest_svn,
            policy: sample_report.policy,
            family_id: sample_report.family_id.to_vec(),
            image_id: sample_report.image_id.to_vec(),
            vmpl: sample_report.vmpl,
            signature_algo: sample_report.signature_algo,
            platform_version: platform_version,
            flags:sample_report.flags,
            platform_info: sample_report.platform_info,
            reserved0: 0,
            report_data: sample_report.report_data.clone(),
            measurement: sample_report.measurement.to_vec(),
            host_data: sample_report.host_data.to_vec(),
            id_key_digest: sample_report.id_key_digest.to_vec(),
            author_key_digest: sample_report.author_key_digest.to_vec(),
            report_id: sample_report.report_id.to_vec(),
            report_id_ma: sample_report.report_id_ma.to_vec(),
            reported_tcb: reported_tcb,
            reserved1: reserverd1,
            chip_id: sample_report.chip_id.to_vec(),
            reserved2: reserverd2,
            signature: signature,
        };
    
        info!("prepare_guest_attestation_report snp_report {:?}", snp_report);
    
        snp_report
    }
    
}


impl Policy {
    pub const POLICY_FILE: &'static str = "/etc/quark/policy.json";

    // if the config file exist, load file and return true; otherwise return false
    pub fn Load(&mut self) -> bool {

        let contents = match fs::read_to_string(Self::POLICY_FILE) {
            Ok(c) => c,
            _ => return false,
        };

        let config = serde_json::from_str(&contents).expect("policy wrong format");
        *self = config;
        return true;
    }

    pub fn Print(&self) {
        let c = serde_json::to_string(self).unwrap();
        error!("policy is {}", c);
    }
}