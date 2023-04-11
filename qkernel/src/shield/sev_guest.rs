// use core::slice::SlicePattern;

use crate::modular_bitfield::{bitfield, specifiers::{B1, B31}};
use crate::aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
    Key,
};
use crate::qlib::linux_def::*;
use crate::qlib::common::*;
use alloc::vec::Vec;
use alloc::string::ToString;
use spin::rwlock::RwLock;
use qlib::kernel::SHARESPACE;
use qlib::kernel::Kernel::HostSpace;
use sha2::{Sha512, Digest};
use base64ct::{Base64, Encoding};
use alloc::string::String;
use super::https_attestation_provisioning_cli::Tee;
use core::convert::TryInto;


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
 * The secrets page contains 96-bytes of reserved field that can be used by
 * the guest OS. The guest OS uses the area to save the message sequence
 * number for each VMPCK.
 *
 * See the GHCB spec section Secret page layout for the format for this area.
 */


lazy_static! {
    pub static ref GUEST_SEV_DEV:  RwLock<SnpGuestDev> = RwLock::new(SnpGuestDev::default());
}


#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct SecretsOsArea {
	pub msg_seqno_0: u32,
	pub msg_seqno_1: u32,
	pub msg_seqno_2: u32,
	pub msg_seqno_3: u32,
	ap_jump_table_pa: u64,
	rsvd: [u8; 40],
	guest_usage: [u8; 32],
}

impl Default for SecretsOsArea {
    fn default() -> SecretsOsArea {
        SecretsOsArea {
			msg_seqno_0: 0,
			msg_seqno_1: 0,
			msg_seqno_2: 0,
			msg_seqno_3: 0,
			ap_jump_table_pa: 0,
			rsvd: [0; 40],
			guest_usage: [0; 32]
        }
    }
}

#[bitfield(bits = 32)]
#[repr(C)]
#[derive(Copy, Default, Clone, Debug)]
pub struct gctx_imien_rsvd1 {
	imien: B1,
	rsvd1: B31,
}

/* See the SNP spec version 0.9 for secrets page format */
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct SnpSecretsPageLayout {
	version: u32,
	imien_rsvda:gctx_imien_rsvd1,
	fms: u32,
	rsvd: u32,
	gosvw: [u8; 16],
	pub vmpck0: [u8; VMPCK_KEY_LEN],
	pub vmpck1: [u8; VMPCK_KEY_LEN],
	pub vmpck2: [u8; VMPCK_KEY_LEN],
	pub vmpck3: [u8; VMPCK_KEY_LEN],
	pub os_area: SecretsOsArea,
	rsvd3: [u8; 3840],
}

impl Default for SnpSecretsPageLayout {
    fn default() -> SnpSecretsPageLayout {
		let mut arr = [0; VMPCK_KEY_LEN];
		let mut rng = OsRng;
		rng.fill_bytes(&mut arr);

		let os_area = SecretsOsArea::default();
		let imien_rsvda = gctx_imien_rsvd1::default();

        SnpSecretsPageLayout {
			version: 0,
			imien_rsvda:imien_rsvda,
			fms:0,
			rsvd:0,
			gosvw: [0; 16],
			vmpck0: arr.clone(),
			vmpck1: arr.clone(),
			vmpck2: arr.clone(),
			vmpck3: arr.clone(),
			rsvd3: [0; 3840],
			os_area:os_area,
        }
    }
}

/*
 * SEV API specification is available at: https://developer.amd.com/sev/
 */
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportReq {
	/* user data that should be included in the report */
	pub user_data: [u8; 64],

	/* The vmpl level to be included in the report */
	pub vmpl: u32,

	/* Must be zero filled */
    pub rsvd: [u8; 28],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportResp {
	/* response data, see SEV-SNP spec for the format */
    data: [u8; 4000]
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpDerivedKeyReq {
	root_key_select: u32,
	rsvd: u32,
	guest_field_select: u64,
	vmpl: u32,
	guest_svn: u32,
	tcb_version: u64
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct SnpDerivedKeyResp {
	/* response data, see SEV-SNP spec for the format */
	data: [u8; 64]
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpExtReportReq {
	data : SnpReportReq,

	/* where to copy the certificate blob */
	certs_address: u64,

	/* length of the certificate blob */
	certs_len: u32,
}

/* See SNP spec SNP_GUEST_REQUEST section for the structure */
pub enum MsgType {
	SnpMsgTypeInvalid = 0,
	SnpMsgCpuidReq,
	SnpMsgCpuidRsp,
	SnpMsgKeyReq,
	SnpMsgKeyRsp,
	SnpMsgReportReq,
	SnpMsgReportRsp,
	SnpMsgExportReq,
	SnpMsgExportRsp,
	SnpMsgImportReq,
	SnpMsgImportRsp,
	SnpMsgAbsorbReq,
	SnpMsgAbsorbRsp,
	SnpMsgVmrkReq,
	SnpMsgVmrkRsp,
	SnpMsgTypeMax
}

pub enum AeadAlgo {
	SnpAeadInvalid,
	SnpAeadAes256Gcm,
}

#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcbVersion {
    pub boot_loader: u8,
    pub tee: u8,
    pub reserved: Vec<u8>,
    pub snp: u8,
    pub microcode: u8,
    pub raw: Vec<u8>,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SnpAttestationReportSignature {
	pub r: Vec<u8>, // 72 bytes,
	pub s: Vec<u8>, //72 bytes,
	pub reserved: Vec<u8>,  // 368 bytes,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AttestationReport {
	pub version: u32,		/* 0x000 */
	pub guest_svn: u32,	/* 0x004 */
	pub policy: u64,			/* 0x008 */
	pub family_id: Vec<u8>, /* 16 bytes, 0x010 */
	pub image_id: Vec<u8>, /*16 bytes, 0x020 */
	pub vmpl: u32,				/* 0x030 */
	pub signature_algo: u32,		/* 0x034 */
	pub platform_version: TcbVersion,  /* 0x038 */
	pub platform_info: u64,		/* 0x040 */
	pub flags: u32,			/* 0x048 */
	pub reserved0: u32,		/* 0x04C */
	pub report_data: Vec<u8>, /*64 bytes, 0x050 */
	pub measurement: Vec<u8>, 	/*48 bytes, 0x090 */
	pub host_data: Vec<u8>, /*32 bytes, 0x0C0 */
	pub id_key_digest: Vec<u8>, /*48 bytes, 0x0E0 */
	pub author_key_digest: Vec<u8>, /*48 bytes, 0x110 */
	pub report_id: Vec<u8>, /*32 bytes, 0x140 */
	pub report_id_ma: Vec<u8>, 	/*32 bytes, 0x160 */
	pub reported_tcb: TcbVersion,	/* 0x180 */
	pub reserved1: Vec<u8>, /*24 bytes, 0x188 */
	pub chip_id: Vec<u8>, /*64 bytes, 0x1A0 */
	pub reserved2: Vec<u8>, /*192 bytes, 0x1E0 */
	pub signature: SnpAttestationReportSignature  /* 0x2A0 */
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpGuestMsgHdr {
	pub authtag: [u8; MAX_AUTHTAG_LEN],
	pub msg_seqno: u64,
	pub rsvd1: [u64; 8],
	pub algo: u8,
	pub hdr_version: u8,
	pub hdr_sz: u16,
	pub msg_type: u8,
	pub msg_version: u8,
	pub msg_sz: u16,
	pub rsvd2: u32,
	pub msg_vmpck: u32,
	pub rsvd3: [u8; 35],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SnpGuestMsg {
	pub hdr: SnpGuestMsgHdr,
	pub payload: [u8; 4000]
}

#[derive(Debug)]
#[derive(Copy, Default, Clone)]
struct SnpGuestCrypto {
    iv_len: usize,   // nonce len in bytes
    tag_len: usize   // tag len in bytes
}

/* SNP Guest message request */
#[derive(Debug, Default, Clone, Copy)]
pub struct SnpReqData {
	pub req_gpa: u64,
	pub resp_gpa: u64,
	pub data_gpa: u64,
	pub data_npages: u32,
}

#[derive(Debug)]
pub enum SevSnpReqType {
    GetReport,
    GetReportWithCertifacteChain,
    GetDerivedKey
}

#[derive(Debug)]
pub struct SnpGuestDev {
	default_vmpck_id: u32,
	crypto: SnpGuestCrypto,
	// request, response, certs_data should be on the shared pages!!!, For now we use DataBuff to emulate share guest pages
	request: DataBuff, 	// SnpGuestMsg
	response: DataBuff, //SnpGuestMsg,
	certs_data : DataBuff,  // buffer for certificates chain used for attestation report verification by guest owner
	input: SnpReqData,
	os_area_msg_seqno : u32,
	vmpck: [u8; VMPCK_KEY_LEN],
}

impl Default for SnpGuestDev {
    fn default() -> SnpGuestDev {
        SnpGuestDev {
			default_vmpck_id: 0,
			crypto: SnpGuestCrypto::default(),
			request: DataBuff::New(0),
			response: DataBuff::New(0),
			certs_data: DataBuff::New(0),
			input: SnpReqData::default(),
			os_area_msg_seqno: 0,
			vmpck : [0; VMPCK_KEY_LEN],
        }
    }
}


impl SnpGuestDev {

    pub fn init(&mut self, vmpck_id : u32) -> () {
        
		let vm_pck : [u8; VMPCK_KEY_LEN] = get_vmpck(vmpck_id);

    	// SNP use aec-gcm 256 for guest-psp message encryption
    	let snp_crypto = SnpGuestCrypto{
        	iv_len: NONCE_LENGTH,
        	tag_len: MAX_AUTHTAG_LEN
    	};

		let req_size = core::mem::size_of::<SnpGuestMsg>();

		self.default_vmpck_id = vmpck_id;
		self.crypto = snp_crypto;
		self.vmpck = vm_pck;
		
		/*
		 * TODO: we should allocat the shared pages for request
		 * response and certs_data, once the sev snp is able to run qkernel 
		 * as guest kernel
		 */	
		self.request = DataBuff::New(req_size);
		self.response = DataBuff::New(req_size);
		self.certs_data = DataBuff::New(SEV_FW_BLOB_MAX_SIZE); 

		self.input.req_gpa = self.request.Ptr();
		self.input.resp_gpa = self.response.Ptr();
		self.input.data_gpa = self.certs_data.Ptr();
    }
	

	fn enc_payload(&mut self, seqno: u64, version: u8, msg_type : MsgType, payload: &mut DataBuff) -> Result::<()> {

		let encryption_key = Key::<Aes256Gcm>::from_slice(&self.vmpck).clone();
		let cipher = Aes256Gcm::new(&encryption_key);


		//sev-snp use seqno as nonce
		let seqno_bytes_slice = seqno.to_le_bytes();
		let mut nonce_src:[u8; NONCE_LENGTH] = [0; NONCE_LENGTH];
		nonce_src[..seqno_bytes_slice.len()].copy_from_slice(&seqno_bytes_slice);
		let nonce = Nonce::from_slice(nonce_src.as_slice());


		let encrypt_payload = cipher.encrypt(nonce, payload.buf.as_slice()).map_err(|e| Error::Common(format!("failed to encryp the data error {:?}", e)))?;
		let (ct, tag) = encrypt_payload.split_at(encrypt_payload.len() - 16);

		
		let mut authtag:[u8; MAX_AUTHTAG_LEN] = [0; MAX_AUTHTAG_LEN];
		authtag[..tag.len()].copy_from_slice(tag);

		let mut cipher_text :[u8; 4000]= [0; 4000];
		cipher_text[..ct.len()].copy_from_slice(ct);

		assert!(ct.len() == payload.Len());
		// info!("enc_payload 2, ct len {:?}, payload len {:?}, payload.Len() as u16 {:?}", ct.len(), payload.Len(), payload.Len() as u16);

		let guest_msg_hdr = SnpGuestMsgHdr{
			algo: AeadAlgo::SnpAeadAes256Gcm as u8,
			hdr_version: MSG_HDR_VER,
			hdr_sz : core::mem::size_of::<SnpGuestMsgHdr>() as u16,
			msg_type : msg_type as u8,
			msg_version : version,  // for now the message version is 1
			msg_seqno : seqno,
			msg_vmpck : self.default_vmpck_id,
			msg_sz : payload.Len() as u16,
			rsvd1: [0; 8],
			rsvd2: 0,
			rsvd3: [0; 35],
			authtag: authtag,
		};

		let guest_msg = SnpGuestMsg {
			hdr: guest_msg_hdr,
			payload: cipher_text,
		};

		unsafe {
			core::ptr::write(self.request.Ptr() as *mut SnpGuestMsg, guest_msg.clone());
		}

		Ok(())

	}


	fn verify_decryption(&mut self) -> Result::<AttestationReport> {

		let sev_guest_resp_addr = self.input.resp_gpa as *mut SnpGuestMsg; // as &mut qlib::Event;
		let resp_mesg = unsafe { &mut (*sev_guest_resp_addr) };

		let sev_guest_req_addr = self.input.req_gpa as *mut SnpGuestMsg; // as &mut qlib::Event;
		let req_mesg = unsafe { &mut (*sev_guest_req_addr) };


		info!("sev-guest verify_decryption req_mesg {:?}, resp_mesg {:?}", req_mesg, resp_mesg);

		/* Verify that the sequence counter is incremented by 1 */
		if resp_mesg.hdr.msg_seqno != (req_mesg.hdr.msg_seqno + 1) {
			return Err(Error::IOError("sev-guest verify_decryption the sequence counter is not incremented by 1 ".to_string())); 
		}

		/* Verify response message type and version number. */
		if resp_mesg.hdr.msg_version != req_mesg.hdr.msg_version {
			return Err(Error::IOError("sev-guest verify_decryption, response message version number not match".to_string())); 
		}

		if  resp_mesg.hdr.msg_type != (req_mesg.hdr.msg_type + 1) {
			return Err(Error::IOError("sev-guest verify_decryption, response message type not match".to_string())); 
		}

	
		let guest_tag = resp_mesg.hdr.authtag[..16].to_vec();
		let cipher_len= resp_mesg.hdr.msg_sz;
		let mut guest_cipher_txt = resp_mesg.payload[..cipher_len as usize].to_vec();
		guest_cipher_txt.extend_from_slice(guest_tag.as_slice());
	
	
		let vmpck = get_vmpck(resp_mesg.hdr.msg_vmpck);
		let decryption_key = Key::<Aes256Gcm>::from_slice(&vmpck).clone();
		let cipher = Aes256Gcm::new(&decryption_key);
	
		// For the emulation, we always use seqno 0 as nonce
		// Todo: snp firmware checks sequece number against replay attack
		let seqno = resp_mesg.hdr.msg_seqno;
		let seqno_bytes_slice = seqno.to_le_bytes();
		let mut nonce_src:[u8; NONCE_LENGTH] = [0; NONCE_LENGTH];
		nonce_src[..seqno_bytes_slice.len()].copy_from_slice(&seqno_bytes_slice);
		let nonce = Nonce::from_slice(nonce_src.as_slice());
	
		
		let plain_txt = cipher.decrypt(nonce, &guest_cipher_txt[..]).unwrap();

		let sev_report_addr = plain_txt.as_ptr() as *mut AttestationReport; // as &mut qlib::Event;
		let sev_report_req = unsafe { &mut (*sev_report_addr) };

		info!("sev-guest verify_decryption sev_report_req {:?}", sev_report_req);



		Ok(sev_report_req.clone())

	}


	fn handle_guest_request(&mut self, msg_version: u8, message_type: MsgType, req_buf: &mut DataBuff, _fw_err: &mut u64) -> Result::<AttestationReport>  {

		info!("handle_guest_request");
		let seqno = snp_get_msg_seqno();
		if seqno == 0 {
			return Err(Error::IOError("failed to get a seqno from secret page".to_string()));
		}

		self.enc_payload(seqno, msg_version, message_type, req_buf).unwrap();

		/*
	 	 * Call firmware to process the request. In this function the encrypted
	 	 * message enters shared memory with the host. So after this call the
	 	 * sequence number must be incremented or the VMPCK must be deleted to
	 	 * prevent reuse of the IV.
	 	*/
		 HostSpace::SevSnpGuestReq(&self.input);


		let report = self.verify_decryption().unwrap();

		Ok(report)
 	}

	pub fn get_report(&mut self, report_data: String) -> Result<String> {

		info!("get_report, report data: {:?}", report_data);

		let report_data_bin = Base64::decode_vec(&report_data)
														.map_err(|e| Error::Common(format!("get_report, Base64::decode_vec failed: {:?}", e)))?;
        if report_data_bin.len() != 64 {
            return Err(Error::Common(format!(
                "SEV SNP Attester: Report data should be SHA512 base64 String"
            )));
        }

		let mut fw_err = 0;
		
		let user_data = vec_to_array(report_data_bin);
	
		let req = SnpReportReq {
			user_data: user_data,
			vmpl: 0,
			rsvd: [0; 28],
		};
	
		info!("req: {:?}", req);
	
		let req_size = core::mem::size_of::<SnpReportReq>();
		let mut req_buf = DataBuff::New(req_size);
	
	
		unsafe {
			core::ptr::write(req_buf.Ptr() as *mut SnpReportReq, req);
			// target_req = core::ptr::read(req_buf.Ptr() as *const snp_report_req);
		}
		// info!("target_req : {:?}", target_req);
		
		let report = self.handle_guest_request(MSG_VERSION, MsgType::SnpMsgReportReq, &mut req_buf, &mut fw_err).unwrap();

		serde_json::to_string(&report)
			.map_err(|e| Error::Common(format!("Serialize SEV SNP evidence/report failed: {:?}", e)))
	}


}

// Returns a base64 of the sha512 of all chunks.
pub fn hash_chunks(chunks: Vec<Vec<u8>>) -> String {
	let mut hasher = Sha512::new();

	for chunk in chunks.iter() {
		hasher.update(chunk);
	}

	let res = hasher.finalize();

	let base64 = Base64::encode_string(&res);

	base64
} 

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}


fn get_vmpck(id: u32) -> [u8; VMPCK_KEY_LEN] {

	let key : [u8; VMPCK_KEY_LEN];

	match  id {
	0 =>
		key = SHARESPACE.sev_snp_secret_page.read().vmpck0.clone(),
	1 =>
		key = SHARESPACE.sev_snp_secret_page.read().vmpck1.clone(),
	2 => 
		key = SHARESPACE.sev_snp_secret_page.read().vmpck2.clone(),
	3 => 
		key = SHARESPACE.sev_snp_secret_page.read().vmpck3.clone(),
    _ => panic!("key doesn't exist"),
	}

	return key;
}



/* Return a non-zero on success */
fn snp_get_msg_seqno() -> u64 {


	/* Read the current message sequence counter from secrets pages */
	let count : u64= SHARESPACE.sev_snp_secret_page.read().os_area.msg_seqno_0 as u64 + 1;

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

// Detect which TEE platform the KBC running environment is.
pub fn detect_tee_type() -> Tee {
	// Now assume we are running on amd sev snp
	Tee::Snp
}
