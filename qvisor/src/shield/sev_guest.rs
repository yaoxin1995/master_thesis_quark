// use core::slice::SlicePattern;

use crate::modular_bitfield::{bitfield, specifiers::{B1, B31}};
use crate::aes_gcm::aead::{OsRng, rand_core::RngCore};
use crate::qlib::linux_def::*;
use crate::qlib::common::*;
use alloc::vec::Vec;
use spin::rwlock::RwLock;
use alloc::string::String;


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

    pub fn init(&mut self, _vmpck_id : u32) -> () {
    }

	pub fn get_report(&mut self, _report_data: String) -> Result<String> {
		Err(Error::NotSupport)
	}
}
