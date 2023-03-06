use kvm_bindings::*;
use kvm_ioctls::{VmFd};
use super::super::super::qlib::common::*;
use super::super::super::qlib::kernel::sev_guest::*;
use crate::{aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
    Key,
}};

use crate::qlib::kernel::sev_guest;
//use p384::ecdsa::{signature::Signer, Signature, SigningKey};

use crate::MOCK_ATTESTAION_REPORT;
use crate::SHARE_SPACE_STRUCT;

const MAX_AUTHTAG_LEN: usize = 32;
const VMPCK_KEY_LEN: usize = 32;
const SEV_FW_BLOB_MAX_SIZE: usize = 0x4000; /* 16KB */
const MSG_HDR_VER: u8 = 1;
const MSG_VERSION: u8 = 1;
/* 
 * Nonce: unique per message. 
 * 96-bits (12 bytes)
 */
const NONCE_LENGTH: usize = 12;

/* 
 * Size of authentication tags The calculated tag will always be 16 bytes long, 
 * but the leftmost bytes can be used. GCM is defined for the tag sizes 128, 120, 
 * 112, 104, or 96, 64 and 32. 
 */
const MAX_TAG_LENGTH: usize = 16;


/*
 * vm_fd: the fd of the vm
 * sev_fd: the fd of sev dev
 * cmd: sev cmd, such as 
 * data_addr: the cmd-related data structure address
 * 
 * possible cmd are: 
 * pub const sev_cmd_id_KVM_SEV_INIT: sev_cmd_id = 0;
 * pub const sev_cmd_id_KVM_SEV_ES_INIT: sev_cmd_id = 1;
 * pub const sev_cmd_id_KVM_SEV_LAUNCH_START: sev_cmd_id = 2;
 * pub const sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA: sev_cmd_id = 3;
 * pub const sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_VMSA: sev_cmd_id = 4;
 * pub const sev_cmd_id_KVM_SEV_LAUNCH_SECRET: sev_cmd_id = 5;
 * pub const sev_cmd_id_KVM_SEV_LAUNCH_MEASURE: sev_cmd_id = 6;
 * pub const sev_cmd_id_KVM_SEV_LAUNCH_FINISH: sev_cmd_id = 7;
 * pub const sev_cmd_id_KVM_SEV_SEND_START: sev_cmd_id = 8;
 * pub const sev_cmd_id_KVM_SEV_SEND_UPDATE_DATA: sev_cmd_id = 9;
 * pub const sev_cmd_id_KVM_SEV_SEND_UPDATE_VMSA: sev_cmd_id = 10;
 * pub const sev_cmd_id_KVM_SEV_SEND_FINISH: sev_cmd_id = 11;
 * pub const sev_cmd_id_KVM_SEV_RECEIVE_START: sev_cmd_id = 12;
 * pub const sev_cmd_id_KVM_SEV_RECEIVE_UPDATE_DATA: sev_cmd_id = 13;
 * pub const sev_cmd_id_KVM_SEV_RECEIVE_UPDATE_VMSA: sev_cmd_id = 14;
 * pub const sev_cmd_id_KVM_SEV_RECEIVE_FINISH: sev_cmd_id = 15;
 * pub const sev_cmd_id_KVM_SEV_GUEST_STATUS: sev_cmd_id = 16;
 * pub const sev_cmd_id_KVM_SEV_DBG_DECRYPT: sev_cmd_id = 17;
 * pub const sev_cmd_id_KVM_SEV_DBG_ENCRYPT: sev_cmd_id = 18;
 * pub const sev_cmd_id_KVM_SEV_CERT_EXPORT: sev_cmd_id = 19;
 * pub const sev_cmd_id_KVM_SEV_GET_ATTESTATION_REPORT: sev_cmd_id = 20;
 * pub const sev_cmd_id_KVM_SEV_SEND_CANCEL: sev_cmd_id = 21;
 * pub const sev_cmd_id_KVM_SEV_NR_MAX: sev_cmd_id = 22; 
 * 
 * example of cmd-related data structure 
 * pub struct kvm_sev_launch_secret {
 *   pub hdr_uaddr: __u64,
 * 	 pub hdr_len: __u32,
 *   pub guest_uaddr: __u64,
 *   pub guest_len: __u32,
 *   pub trans_uaddr: __u64,
 *   pub trans_len: __u32,
 * }
 */
fn sev_ioctl(vm_fd : &VmFd ,sev_fd: u32, cmd: u32, data_addr: u64) -> Result<()>
{


	let mut op = kvm_sev_cmd {
		id: cmd,
		data: data_addr,
		error: 0,
		sev_fd: sev_fd,
	};

	let r = vm_fd.encrypt_op_sev(&mut op)
	.map_err(|e| Error::IOError(format!("io::error is {:?}", e)));

	return r;
}


/*
 * The hypervisor starts an SNP guest by launching the guest. The hypervisor uses the commands
 * SNP_LAUNCH_START, SNP_LAUNCH_UPDATE, and SNP_LAUNCH_FINISH to launch the guest.
 * 
 * KVM_SEV_SNP_LAUNCH_START begins the launch process. 
 *  
 * KVM_SEV_SNP_LAUNCH_UPDATE inserts data into the guest’s memory, the secrets page and the CPUID page. 
 * KVM_SEV_SNP_LAUNCH_FINISH finalizes the cryptographic digest and stores it as the measurement of the guest at launch
 * 
 * Ref: SEV Secure Nested Paging Firmware ABI Specification 4.5 Launching a Guest
 * 
 *  SEV VM INIT FLOW
 * 	ret = sev_platform_ioctl(sev->sev_fd, SEV_PLATFORM_STATUS, &status, &fw_error);
 *  ret = sev_ioctl(sev->sev_fd, KVM_SEV_SNP_INIT, NULL, &fw_error);
 *  rc = sev_ioctl(sev->sev_fd, KVM_SEV_SNP_LAUNCH_START, &start, &fw_error);
 *  ret = sev_ioctl(sev_guest->sev_fd, KVM_SEV_SNP_LAUNCH_UPDATE,&input, &error);
 *  ret = sev_ioctl(sev->sev_fd, KVM_SEV_SNP_LAUNCH_FINISH, 0, &error);
 * 
 * Ref: QEMU https://patchwork.kernel.org/project/qemu-devel/patch/20210709215550.32496-5-brijesh.singh@amd.com/
 */


/*
 * Quark doesn't support amd sev yet. Thus we let qvisor to inject the secret page to shared space btw 
 * qvisor and qkernel so that qkernel sev driver can work properly. 
 * Once quark support amd sev, qvisor should call sev_ioctl(.., .., KVM_SEV_LAUNCH_SECRET, ..) to notify the AMD PSP to insert the secret page
 */
pub fn qivsor_sev_inject_lauch_secret () -> SnpSecretsPageLayout {
 	
	SnpSecretsPageLayout::default()

}

pub fn prepare_guest_attestation_report (_user_data: &[u8; 64] ) -> sev_guest::AttestationReport {


	// TODO: add user_data to attesstation report
	let sample_report = MOCK_ATTESTAION_REPORT.lock();

	let report: sev_guest::AttestationReport = sample_report.clone();

	info!("prepare_guest_attestation_report snp_report {:?}", report);

	report
}



fn get_vmpck(id: u32) -> [u8; VMPCK_KEY_LEN] {
	let key : [u8; VMPCK_KEY_LEN];

	match  id {
	0 =>
		key = SHARE_SPACE_STRUCT.lock().sev_snp_secret_page.read().vmpck0.clone(),
	1 =>
		key = SHARE_SPACE_STRUCT.lock().sev_snp_secret_page.read().vmpck1.clone(),
	2 => 
		key = SHARE_SPACE_STRUCT.lock().sev_snp_secret_page.read().vmpck2.clone(),
	3 => 
		key = SHARE_SPACE_STRUCT.lock().sev_snp_secret_page.read().vmpck3.clone(),
    _ => panic!("key doesn't exist"),
	}

	return key;
}

fn snp_get_msg_seqno() -> u64 {
	/* Read the current message sequence counter from secrets pages */
	let count : u64= SHARE_SPACE_STRUCT.lock().sev_snp_secret_page.read().os_area.msg_seqno_0 as u64 + 1;

	/*
	 * The message sequence counter for the SNP guest request is a  64-bit
	 * value but the version 2 of GHCB specification defines a 32-bit storage
	 * for it. If the counter exceeds the 32-bit value then return zero.
	 * The caller should check the return value, but if the caller happens to
	 * not check the value and use it, then the firmware treats zero as an
	 * invalid number and will fail the  message request.
	 */
	if count  >= u32::MAX as u64 {
		error!("request message sequence counter overflow\n");
		return 0;
	}

	return count;
}


fn snp_increase_msg_seqno() {
	info!("snp_increase_msg_seqno");
	let share_space = SHARE_SPACE_STRUCT.lock();
	let mut sev_snp_secret_page = share_space.sev_snp_secret_page.write();
	sev_snp_secret_page.os_area.msg_seqno_0 = sev_snp_secret_page.os_area.msg_seqno_0 + 1;
}


fn prepare_guest_resp_msg(guest_resp: &mut SnpGuestMsg, guest_msg: &mut SnpGuestMsg, sev_report_req: &SnpReportReq, vmpck: &[u8]) -> Result<()> {

	info!("prepare_guest_resp_msg, guest_resp {:?}, guest_msg {:?} sev_report_req {:?}, vmpck {:?}", guest_resp, guest_msg, sev_report_req, vmpck);

	let report = prepare_guest_attestation_report(&sev_report_req.user_data);

	let req_size = core::mem::size_of::<sev_guest::AttestationReport>();
	let mut  req_buf: Vec<u8> = Vec::new();
	req_buf.resize(req_size, 0);
	unsafe {
		core::ptr::write(req_buf.as_ptr() as *mut sev_guest::AttestationReport, report);
		// target_req = core::ptr::read(req_buf.Ptr() as *const snp_report_req);
	}

	let seqno_bytes_slice = (guest_msg.hdr.msg_seqno + 1).to_le_bytes();
	let mut nonce_src:[u8; NONCE_LENGTH] = [0; NONCE_LENGTH];
	nonce_src[..seqno_bytes_slice.len()].copy_from_slice(&seqno_bytes_slice);
	let nonce = Nonce::from_slice(nonce_src.as_slice());


	let encryption_key = Key::<Aes256Gcm>::from_slice(&vmpck).clone();
	let cipher = Aes256Gcm::new(&encryption_key);
	let encrypted_report = cipher.encrypt(nonce, req_buf.as_slice()).map_err(|e| Error::Common(format!("failed to encryp the data error {:?}", e)))?;

	let (ct, tag) = encrypted_report.split_at(encrypted_report.len() - 16);

		
	let mut authtag:[u8; MAX_AUTHTAG_LEN] = [0; MAX_AUTHTAG_LEN];
	authtag[..tag.len()].copy_from_slice(tag);

	let mut cipher_text :[u8; 4000]= [0; 4000];
	cipher_text[..ct.len()].copy_from_slice(ct);

	assert!(ct.len() == req_buf.len());

	guest_resp.hdr.algo = AeadAlgo::SnpAeadAes256Gcm as u8;
	guest_resp.hdr.hdr_version = MSG_HDR_VER;
	guest_resp.hdr.hdr_sz = core::mem::size_of::<SnpGuestMsgHdr>() as u16;
	guest_resp.hdr.msg_type =  MsgType::SnpMsgReportRsp as u8;
	guest_resp.hdr.msg_version =   guest_msg.hdr.msg_version; // Default message version is 1
	guest_resp.hdr.msg_seqno =    guest_msg.hdr.msg_seqno + 1; 
	guest_resp.hdr.msg_vmpck =   guest_msg.hdr.msg_vmpck; 
	guest_resp.hdr.msg_sz =    req_buf.len() as u16; 
	guest_resp.hdr.authtag =   authtag; 
	guest_resp.payload = cipher_text;

	Ok(())
}


pub fn amd_firmware_emulation (input: &SnpReqData) -> u64 {

	info!("amd_firmware_emulation, input {:?}", input);
	let sev_guest_req_addr = input.req_gpa as *mut SnpGuestMsg; // as &mut qlib::Event;
	let guest_msg = unsafe { &mut (*sev_guest_req_addr) };


	let guest_tag = guest_msg.hdr.authtag[..16].to_vec();
	let cipher_len= guest_msg.hdr.msg_sz;
	let mut guest_cipher_txt = guest_msg.payload[..cipher_len as usize].to_vec();
	guest_cipher_txt.extend_from_slice(guest_tag.as_slice());


	let vmpck = get_vmpck(guest_msg.hdr.msg_vmpck);
	let decryption_key = Key::<Aes256Gcm>::from_slice(&vmpck).clone();
	let cipher = Aes256Gcm::new(&decryption_key);

	// For the emulation, we always use seqno 0 as nonce
	// Todo: snp firmware checks sequece number against replay attack
	let seqno = snp_get_msg_seqno();
	let seqno_bytes_slice = seqno.to_le_bytes();
	let mut nonce_src:[u8; NONCE_LENGTH] = [0; NONCE_LENGTH];
	nonce_src[..seqno_bytes_slice.len()].copy_from_slice(&seqno_bytes_slice);
	let nonce = Nonce::from_slice(nonce_src.as_slice());

	
	let plain_txt = cipher.decrypt(nonce, &guest_cipher_txt[..]).unwrap();
	let sev_report_req_addr = plain_txt.as_ptr() as *mut SnpReportReq; // as &mut qlib::Event;
	let sev_report_req = unsafe { &mut (*sev_report_req_addr) };


	let sev_guest_resp_addr = input.resp_gpa as *mut SnpGuestMsg; // as &mut qlib::Event;
	let resp_msg = unsafe { &mut (*sev_guest_resp_addr) };


	info!("amd_firmware_emulation, resp_msg {:?}", resp_msg);

	prepare_guest_resp_msg (resp_msg, guest_msg, &sev_report_req, &vmpck).unwrap();

	snp_increase_msg_seqno();

	0
}



