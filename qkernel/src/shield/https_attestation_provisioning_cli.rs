use alloc::sync::Arc;
use qlib::kernel::socket::socket::Provider;
use qlib::kernel::socket::hostinet::hostsocket::newHostSocketFile;
use qlib::kernel::fs::flags::SettableFileFlags;
use qlib::kernel::Kernel;
use qlib::kernel::fs::file::*;
use qlib::kernel::tcpip::tcpip::*;
use qlib::kernel::kernel::timer::MonotonicNow;
use qlib::kernel::kernel::time::Time;
use qlib::linux_def::SysErr;
use embedded_tls::blocking::*;
use rsa::pkcs8::EncodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use zeroize::Zeroizing;
use alloc::string::String;
use qlib::common::*;
use alloc::vec::Vec;
use crate::aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
    Key,
};
use crate::shield::sev_guest::{detect_tee_type, GUEST_SEV_DEV};
use alloc::string::ToString;
use qlib::kernel::task::*;
use qlib::linux_def::*;
use qlib::shield_policy::*;
use super::APPLICATION_INFO_KEEPER;
use ssh_key;


const SECRET_MANAGER_IP:  [u8;4] = [10, 206, 133, 76];
const SECRET_MANAGER_PORT: u16 = 8000;
const KBS_PROTOCOL_VERSION: &str = "0.1.0";
const HTTP_HEADER_COOKIE: &str = "set-cookie";
const HTTP_HEADER_CONTENT_LENTH: &str = "content-length";
const RSA_KEY_TYPE: &str = "RSA";
const RSA_ALGORITHM: &str = "RSA1_5";
const RSA_PUBKEY_LENGTH: usize = 2048;
const NEW_PADDING: fn() -> PaddingScheme = PaddingScheme::new_pkcs1v15_encrypt;
const AES_256_GCM_ALGORITHM: &str = "A256GCM";
const URI_TO_GET_KBS_SIGNING_KEY: &str = "default/signing_key/test";

/// The supported TEE types:
/// - Tdx: TDX TEE.
/// - Sgx: SGX TEE.
/// - Sevsnp: SEV-SNP TEE.
/// - Sample: A dummy TEE that used to test/demo the KBC functionalities.
#[derive(Debug, Clone, Copy)]
pub enum Tee {
    Sev,
    Sgx,
    Snp,
    Tdx,

    // This value is only used for testing an attestation server, and should not
    // be used in an actual attestation scenario.
    Sample,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Request {
    version: String,
    tee: String,

    // Reserved field.
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

impl Request {
    pub fn new(tee: String) -> Request {
        Request {
            version: KBS_PROTOCOL_VERSION.to_string(),
            tee,
            extra_params: "".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Challenge {
    // Nonce from KBS to prevent replay attack.
    pub nonce: String,

    // Reserved field.
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Attestation {
    // The public key of TEE.
    // Its hash is included in `tee-evidence`.
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeePubKey,

    // TEE quote, different TEE type has different format of the content.
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

#[derive(Serialize, Deserialize)]
struct ProtectedHeader {
    // enryption algorithm for encrypted key
    alg: String,
    // encryption algorithm for payload
    enc: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    pub protected: String,
    pub encrypted_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

impl Response {
    // Use TEE's private key to decrypt output of Response.
    pub fn decrypt_output(&self, tee_key: TeeKey) -> Result<Vec<u8>> {
        self.decrypt_response(self, tee_key)
    }

    fn decrypt_response(&self, response: &Response, tee_key: TeeKey) -> Result<Vec<u8>> {
        // deserialize the jose header and check that the key type matches
        let protected: ProtectedHeader = serde_json::from_str(&response.protected)
            .map_err(|e| Error::Common(format!("decrypt_response: Deserialize response.protected as ProtectedHeader falied {:?}", e)))?;
        if protected.alg != RSA_ALGORITHM {
            return Err(Error::Common("decrypt_response: Algorithm mismatch for wrapped key.".to_string()));
        }
    
        // unwrap the wrapped key
        let wrapped_symkey: Vec<u8> =
            base64::decode_config(&response.encrypted_key, base64::URL_SAFE_NO_PAD)
            .map_err(|e| Error::Common(format!("decrypt_response: unwrap the wrapped key failed: {:?}", e)))?;
        let symkey: Vec<u8> = tee_key.decrypt(wrapped_symkey)?;
    
        let iv = base64::decode_config(&response.iv, base64::URL_SAFE_NO_PAD)
            .map_err(|e| Error::Common(format!("decrypt_responseL decode iv failed {:?}", e)))?;
        let ciphertext = base64::decode_config(&response.ciphertext, base64::URL_SAFE_NO_PAD)
            .map_err(|e| Error::Common(format!("decrypt_responseL decode ciphertext failed {:?}", e)))?;
    
        let plaintext = match protected.enc.as_str() {
            AES_256_GCM_ALGORITHM => self.decrypt(
                Zeroizing::new(symkey),
                ciphertext,
                iv,
            )?,
            _ => {
                return Err(Error::Common(format!("Unsupported algorithm: {}", protected.enc.clone())));
            }
        };
    
        Ok(plaintext)
    }

    fn decrypt(
        &self,
        key: Zeroizing<Vec<u8>>,
        ciphertext: Vec<u8>,
        iv: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let plaintext = self.aes256gcm_decrypt(&ciphertext, &key, &iv)?;
        Ok(plaintext)
    }

    fn aes256gcm_decrypt(&self, encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let decrypting_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(decrypting_key);
        let nonce = Nonce::from_slice(iv);
        let plain_text = cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| Error::Common(format!("aes-256-gcm decrypt failed: {:?}", e)))?;
    
        Ok(plain_text)
    }
}


// The key inside TEE to decrypt confidential data.
#[derive(Debug, Clone)]
pub struct TeeKey {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

// The struct that used to export the public key of TEE.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TeePubKey {
    kty: String,
    alg: String,
    pub k: String,
}

impl TeeKey {
    pub fn new() -> Result<TeeKey> {
        let mut rng = OsRng;

        let private_key = RsaPrivateKey::new(&mut rng, RSA_PUBKEY_LENGTH)
                                                .map_err(|e| Error::Common(format!("TEE RSA RsaPrivateKey generation failed: {:?}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(TeeKey {
            private_key,
            public_key,
        })
    }

    // Export TEE public key as specific structure.
    pub fn export_pubkey(&self) -> Result<TeePubKey> {
        let pem_line_ending = rsa::pkcs1::LineEnding::default();
        let pubkey_pem_string = self.public_key
                                            .to_public_key_pem(pem_line_ending)
                                            .map_err(|e| Error::Common(format!("Serialize this public key as PEM-encoded SPKI with the given LineEnding: {:?}", e)))?;

        Ok(TeePubKey {
            kty: RSA_KEY_TYPE.to_string(),
            alg: RSA_ALGORITHM.to_string(),
            k: pubkey_pem_string,
        })
    }

    // Use TEE private key to decrypt cipher text.
    pub fn decrypt(&self, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let padding = NEW_PADDING();

        self.private_key
            .decrypt(padding, &cipher_text)
            .map_err(|e| Error::Common(format!("TEE RSA key decrypt failed: {:?}", e)))
    }
}

#[derive(Clone)]
pub struct ShieldProvisioningHttpSClient {
    pub socket_file: Arc<File>,
    pub read_buf : Vec<u8>,
    pub read_from_buf_len: usize,
    pub total_loop_times_of_try_to_read_from_server: usize,
    cookie: String,
    tee_key: Option<TeeKey>,
    nonce: String,
    pub tee_type: Tee,
}

impl ShieldProvisioningHttpSClient {
    fn init (scoket: Arc<File>, read_buf_len: usize, total_loop_times: usize) -> Self{
        
        let tee_type = detect_tee_type();

        ShieldProvisioningHttpSClient { 
            socket_file: scoket, 
            read_buf: Vec::new(),  
            read_from_buf_len: read_buf_len,
            total_loop_times_of_try_to_read_from_server: total_loop_times,
            cookie: String::default(),
            tee_key: TeeKey::new().ok(),
            nonce: String::default(),
            tee_type: tee_type,
        }
    }
    
    /**
     * Request
     * {
     *   /* Attestation protocol version number used by KBC */
     *   "version": "0.1.0",
     *   /*
     *    * Type of HW-TEE platforms where KBC is located,
     *    * e.g. "intel-tdx", "amd-sev-snp", etc.
     *    */
     *   "tee": "$tee",
     *   /* Reserved fields to support some special requests sent by HW-TEE. 
     *    * In the run-time attestation scenario (Intel TDX and SGX, AMD SEV-SNP), 
     *    * the extra-params field is not used, so is set to the empty string
     *    */
     *   "extra-params": {}
     * }
     */
    fn prepair_post_auth_http_req(&self) -> String {

        let tee = match self.tee_type {
            Tee::Sample => "sample",
            Tee::Sev => "sev",
            Tee::Sgx => "sgx",
            Tee::Tdx => "tdx",
            Tee::Snp => "snp" 
        };
    
        let req = Request::new(tee.to_string());
        let serialized_req = serde_json::to_string(&req).unwrap();
        let post_string = format!("POST /kbs/v0/auth HTTP/1.1\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", serialized_req.as_bytes().len(), serialized_req);

        log::info!("post_auth_http_req creat post str {:?}", post_string);    
        post_string
    }
    
    /*
     * Challenge:
     * {
     *   /* The freshness number passed to KBC. KBC needs to place it in the evidence sent to the KBS in the next step to prevent replay attacks.*/
     *    "nonce": "$nonce",
     *    /* Extra parameters to support some special HW-TEE attestation.  In the run-time attestation scenario (Intel TDX and SGX, AMD SEV-SNP), the extra-params field is not used, so is set to the empty string*/
     *    "extra-params": {}
     * }
     * 
     * Sample auth_http_resp:
     * http post resp: HTTP/1.1 200 OK
     * content-length: 74
     * set-cookie: kbs-session-id=6147e2bcf0ab42058bcea8bb5ab4b7b5; Expires=Wed, 29 Mar 2023 12:20:54 GMT
     * content-type: application/json
     * date: Wed, 29 Mar 2023 12:15:54 GMT
     * {"nonce":"NYITD4rvGoNH6EiwW7vX3tKQkY3DtwgGu3zsX4nO5V4=","extra-params":""}
     */
    fn parse_auth_http_resp(&mut self, resp_buf: &[u8]) -> Result<()> {

        log::debug!("parse_auth_http_resp response  start");
    
        let mut resp_headers = [httparse::EMPTY_HEADER; 4];
        let mut http_resp = httparse::Response::new(&mut resp_headers);
    
        let res = http_resp.parse(resp_buf).unwrap();
        if res.is_partial() {
            info!("parse_auth_http_resp response is partial");
            return Err(Error::Common("parse_auth_http_resp response is partial".to_string()));
        }

        if http_resp.code.unwrap() != 200 {
            let http_get_resp = String::from_utf8_lossy(resp_buf).to_string();
            info!("parse_auth_http_resp response: we get error response {}", http_get_resp);
            return Err(Error::Common("parse_auth_http_resp response: we get error response".to_string()));
        }

        // let mut content_lenght;
        for h in http_resp.headers {
            info!("parse_auth_http_resp get header name: {}", h.name);
            if h.name == HTTP_HEADER_COOKIE {

                let cookie = String::from_utf8_lossy(h.value).to_string();

                info!("parse_auth_http_resp get cookie {}", cookie);
                self.cookie = cookie;
            }
        }

        let resp_payload_start = res.unwrap();
        assert!(resp_payload_start > 0);

        let resp_payload = &resp_buf[resp_payload_start..];

        let challenge: Result<Challenge> = serde_json::from_slice(resp_payload).map_err(|x| {Error::Common(format!("parse_auth_http_resp serde_json::from_slice failed error code: {x}"))});
        if challenge.is_err() {
            info!("{:?}", challenge.as_ref().err().unwrap());
            return Err(challenge.err().unwrap());
        }

        self.nonce = challenge.unwrap().nonce.clone();

        info!("parse_auth_http_resp response finished, cookie {}， nonce: {:?}", self.cookie, self.nonce);

        return Ok(());
    
    }

    /**
     * Payload format of the request:
     * {
     *   /*
     *   * A JWK-formatted public key, generated by the KBC running in the HW-TEE.
     *   * It is valid until the next time an attestation is required. Its hash must
     *   * be included in the HW-TEE evidence and signed by the HW-TEE hardware.
     *   */
     *    "tee-pubkey": $pubkey
     *
     *   /* The attestation evidence. Its format is specified by Attestation-Service. */
     *    "tee-evidence": {}
     * }
     * To prevent relay attack, we put the hash of the nonce we got from http auth to the user data field of attestation report
     */
    fn prepair_post_attest_http_req(&self, software_maasurement: &str) -> Result<String> {
        

        let tee_evidence = self.generate_evidence(software_maasurement)?;
    
        let serialized_req = serde_json::to_string(&tee_evidence).unwrap();

        let post_string = format!("POST /kbs/v0/attest HTTP/1.1\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nCookie: {}\r\nContent-Length: {}\r\n\r\n{}", self.cookie, serialized_req.as_bytes().len(), serialized_req);
    
        log::info!("prepair_post_attest_http_req creat post str {:?}", post_string);
        Ok(post_string)
    }

    /**
     * The KBS replies to the post_attest request with an empty HTTP response (no content), which HTTP status indicates if the attestation was successful or not.
     * 
     * Check if resp status is 200!!!
     */
    fn parse_attest_http_resp(&mut self, resp_buf: &[u8]) -> Result<()> {
        
        let resp = String::from_utf8_lossy(resp_buf).to_string();

        info!("parse_attest_http_resp {}", resp);

        let mut resp_headers = [httparse::EMPTY_HEADER; 4];
        let mut http_resp = httparse::Response::new(&mut resp_headers);
    
        let res = http_resp.parse(resp_buf).unwrap();
        if res.is_partial() {
            info!("parse_attest_http_resp response is partial");
            return Err(Error::Common("parse_attest_http_resp response is partial".to_string()));
        }

        if http_resp.code.unwrap() != 200 {
            let http_get_resp = String::from_utf8_lossy(resp_buf).to_string();
            info!("parse_attest_http_resp response: we get error response {} authentication failed, we are not allowed to get secret from kbs", http_get_resp);
            return Err(Error::Common(format!("parse_attest_http_resp response: we get error response {} authentication failed, we are not allowed to get secret from kbs", http_get_resp)));
        }

        info!("parse_attest_http_resp response: we pass theauthentication phase");
        Ok(())
    }


    fn generate_evidence(&self, software_maasurement: &str) -> Result<Attestation> {
        let key = self
            .tee_key
            .as_ref()
            .ok_or_else(|| Error::Common("Generate TEE key failed".to_string()))?;


        let tee_pubkey = key
            .export_pubkey()
            .map_err(|e| Error::Common(format!("Export TEE pubkey failed: {:?}", e)))?;


        let ehd_chunks = vec![
            software_maasurement.to_string().into_bytes(),
            self.nonce.clone().into_bytes(),   // agains replay attack
            tee_pubkey.k.clone().into_bytes(),  
        ];

        let ehd = super::hash_chunks(ehd_chunks);
        let tee_evidence;

        {
            let mut attester = GUEST_SEV_DEV.write();

            tee_evidence = attester
                .get_report(ehd)
                .map_err(|e| Error::Common(format!("generate_evidence get report failed: {:?}", e)))?;
        }
        
        Ok(Attestation {
            tee_pubkey,
            tee_evidence,
        })
    }


    fn prepair_get_resource_http_req(&self, resource_url: String) -> String {
        
        let http_get_string = format!("GET /kbs/v0/resource/{} HTTP/1.1\r\nCookie: {}\r\n\r\n", resource_url, self.cookie);
    
        log::info!("prepair_post_attest_http_req creat post str {:?}", http_get_string);
        http_get_string
    }

   /*
    * Upon successful attestation, the KBC can request resources from the KBS, by sending HTTP GET requests to it. 
    * If the KBS approves the request, it responds to the KBC by sending a Response payload that follows the JSON 
    * Web Encryption flattened serialization format:
    * {
    *    "protected": "$jose_header",
    *    "encrypted_key": "$encrypted_key",
    *    "iv": "$iv",
    *    "ciphertext": "$ciphertext",
    *    "tag": "$tag"
    * }   
    */
    fn parse_http_get_resource_resp(&mut self, resp_buf: &[u8]) -> Result<Vec<u8>> {

        debug!("parse_http_get_resource_resp response  start");
    
        let mut resp_headers = [httparse::EMPTY_HEADER; 4];
        let mut http_resp = httparse::Response::new(&mut resp_headers);
    
        let res = http_resp.parse(resp_buf).unwrap();
        if res.is_partial() {
            info!("parse_http_get_resource_resp response is partial");
            return Err(Error::Common("parse_http_get_resource_resp response is partial".to_string()));
        }

        match http_resp.code.unwrap() {
            200 => info!("parse_auth_http_resp response: we get resource successful"),
            401 => {   
                info!("parse_http_get_resource_resp response: we get 401 error response, The requester is not authenticated");
                return Err(Error::Common("parse_http_get_resource_resp response: we get 401 error response, the requester is not authenticated".to_string()));
            },
            403 => {
                info!("parse_http_get_resource_resp response: we get 403 error response, The attester is authenticated but requests a resource that it's not allowed to receive.");
                return Err(Error::Common("parse_http_get_resource_resp response: we get 403 error response, The attester is authenticated but requests a resource that it's not allowed to receive.".to_string()));
            },
            404 => {
                info!("parse_http_get_resource_resp response: we get 404 error response, The requested resource does not exist. ");
                return Err(Error::Common("parse_http_get_resource_resp response: we get 404 error response, The requested resource does not exist".to_string()));
            },
            n => {
                info!("parse_http_get_resource_resp response: we get unexpected error response: {}", n);
                return Err(Error::Common(format!("parse_http_get_resource_resp response: we get unexpected error response: {}", n)));
            }    
        }

        let resp_payload_start = res.unwrap();
        assert!(resp_payload_start > 0);

        let resp_payload = &resp_buf[resp_payload_start..];
        debug!("parse_http_get_resource_resp resp_payload len {:?}", resp_payload.len());
        let response: Result<Response> = serde_json::from_slice(resp_payload).map_err(|x| {Error::Common(format!("parse_http_get_resource_resp serde_json::from_slice failed error code: {x}"))});
        if response.is_err() {
            debug!("{:?}", response.as_ref().err().unwrap());
            return Err(response.err().unwrap());
        }

        let secret = self.decrypt_response_output(response.unwrap());

        debug!("parse_http_get_resource_resp response finished, secret {:?}", secret);
        return secret;
    
    }

    fn decrypt_response_output(&self, response: Response) -> Result<Vec<u8>> {
        let key = self
            .tee_key
            .clone()
            .ok_or_else(|| Error::Common("TEE rsa key missing".to_string()))?;
        response.decrypt_output(key)
    }
}


pub struct ShieldSocketProvider {
    pub family: i32,
}

impl Provider for ShieldSocketProvider {
    fn Socket(&self, task: &Task, stype: i32, protocol: i32) -> Result<Option<Arc<File>>> {
        let nonblocking = stype & SocketFlags::SOCK_NONBLOCK != 0;
        let stype = stype & SocketType::SOCK_TYPE_MASK;

        let res =
            Kernel::HostSpace::Socket(self.family, stype | SocketFlags::SOCK_CLOEXEC, protocol);
        if res < 0 {
            return Err(Error::SysError(-res as i32));
        }

        let fd = res as i32;

        let file = newHostSocketFile(
                task,
                self.family,
                fd,
                stype & SocketType::SOCK_TYPE_MASK,
                nonblocking,
                None,
            )?;

        return Ok(Some(Arc::new(file)));
    }

    fn Pair(
        &self,
        _task: &Task,
        _stype: i32,
        _protocol: i32,
    ) -> Result<Option<(Arc<File>, Arc<File>)>> {
        return Err(Error::SysError(SysErr::EOPNOTSUPP));
    }
}

fn try_get_data_from_server (task: &Task, socket_op: FileOps, read_to: &mut [u8], total_loop_times: usize) -> Result<i64> {


    let mut pMsg = MsgHdr::default();

    // The msg_name and msg_namelen fields contain the address and address length to which the message is sent. 
    // For further information about the structure of socket addresses, see the Sockets programming topic collection. 
    // If the msg_name field is set to a NULL pointer, the address information is not returned.
    pMsg.msgName = 0;
    pMsg.nameLen = 0;


    let flags = crate::qlib::linux_def::MsgType::MSG_DONTWAIT;
    let mut deadline = None;

    let dl = socket_op.SendTimeout();
    if dl > 0 {
        let now = MonotonicNow();
        deadline = Some(Time(now + dl));
    }

    let resp_buf =  DataBuff::New(read_to.len());
    let mut dst = resp_buf.Iovs(resp_buf.Len());
    let mut bytes: i64 = 0;

    let mut loop_time = 0;

    loop {
        if loop_time > total_loop_times {
            log::trace!("try_get_data_from_server: we have tried {:?} times to get the http resps, receive {:?} bytes, default RecvMsg flag {:?}", loop_time,  bytes, flags);
            break;
        }
        // info!("try_get_data_from_server get http get resp, bytes {:?} before recvmsg, flags {:?}", bytes, flags);
        match socket_op.RecvMsg(task, &mut dst, flags, deadline, false, 0) {
            Ok(res) => {
                let (n, mut _mflags, _, _) = res;
                assert!(n >= 0);
                bytes = bytes + n;
                // info!("try_get_data_from_server get http get resp, ok bytes {:?} after recvmsg, flags {:?},RecvMsg return {:?} bytes", bytes, flags, n);

                if bytes as usize == read_to.len() {
                    break;
                }
                assert!(bytes >= 0);
                // rust pointer arthmitic
                let new_start_pointer;
                unsafe {
                    new_start_pointer = resp_buf.buf.as_ptr().offset(bytes as isize);
                }

                let io_vec = IoVec {
                start: new_start_pointer as u64,
                len: resp_buf.Len() - bytes as usize,
                };

                dst = [io_vec];},
            Err(e) => match  e {
                Error::SysError(SysErr::EWOULDBLOCK) =>  {
                    log::trace!("try_get_data_from_server RecvMsg get error SysErr::EWOULDBLOCK, try again");
                }
                _ => {
                    log::trace!("try_get_data_from_server RecvMsg get error {:?} exit from loop", e);
                    break;
                }
            },
        };
        loop_time = loop_time + 1;
    }

    assert!(bytes >= 0);
    let http_get_resp = String::from_utf8_lossy(&resp_buf.buf.as_slice()[..bytes as usize]).to_string();

    log::trace!("try_get_data_from_server http get resp: {}", http_get_resp);

    read_to[0..(bytes as usize)].clone_from_slice(&resp_buf.buf[0..(bytes as usize)]);

    //log::trace!("try_get_data_from_server read_to {:?}, resp_buf.buf {:?}",read_to, resp_buf.buf);
    return Ok(bytes);
}



impl embedded_io::Io for ShieldProvisioningHttpSClient {
    type Error = embedded_tls::TlsError;
}

impl embedded_io::blocking::Read for ShieldProvisioningHttpSClient {
    fn read<'m>(&'m mut self, read_to: &'m mut [u8]) -> core::result::Result<usize, Self::Error> {

        log::trace!("embedded_io::blocking::read start, read_to len {:?}, ShieldProvisioningHttpSClient buffer {:?}, len {:?}", read_to.len(), self.read_buf, self.read_buf.len());
        let socket_op = self.socket_file.FileOp.clone();
        let read_to_len = read_to.len();
        let current_task = Task::Current();

        if read_to_len <= self.read_buf.len() {
            read_to.clone_from_slice(&self.read_buf[..read_to_len]);
            self.read_buf.drain(0..read_to_len);
            log::trace!("embedded_io::blocking::Read return {:?} byte from the buffer, read_to {:?}, ShieldProvisioningHttpSClient len {:?} buffer {:?} ", read_to_len, read_to, self.read_buf.len(), self.read_buf);


            // try get more data from server side before return
            let mut buf: [u8; 30000] = [0; 30000];
            let res = try_get_data_from_server(current_task, socket_op, &mut buf, self.total_loop_times_of_try_to_read_from_server);
            if res.is_err() {
                info!("try_get_data_from_server get error : {:?}", res);
            } else {
                let buf_len = res.unwrap();
                let buf_slice = buf.as_slice();
                let mut buf_vec = buf_slice[..(buf_len as usize)].to_vec();
                self.read_buf.append(&mut buf_vec);
                log::trace!("get data with len {:?} from server, put it into buffer, ShieldProvisioningHttpSClient len {:?} buffer {:?}", buf_len, self.read_buf.len(), self.read_buf);
            }
            return Ok(read_to_len as usize);
        }

        let current_task = Task::Current();
        let mut deadline = None;
        let mut flags = 0 as i32;
        let dl = socket_op.SendTimeout();
        if dl > 0 {
            let now = MonotonicNow();
            deadline = Some(Time(now + dl));
        } else if dl < 0 {
            flags |= crate::qlib::linux_def::MsgType::MSG_DONTWAIT
        }

        let buffer =  DataBuff::New(self.read_from_buf_len);
        let mut buffer_iovec = buffer.Iovs(buffer.Len());
    
        log::trace!("embedded_io::blocking::Read get package from intenet, before recvmsg, flags {:?}", flags);
        match socket_op.RecvMsg(current_task, &mut buffer_iovec, flags, deadline, false, 0) {
            Ok(res) => {
                let (n, mut _mflags, _, _) = res;
                let http_get_resp = String::from_utf8_lossy(&buffer.buf[..(n as usize)]).to_string();
                log::trace!("embedded_io::blocking::Read get package from intenet get resp, ok, bytes {:?} after recvmsg, flags {:?}, reverive: {:?}", n, flags, http_get_resp);
                
                // assert!(n >= read_to_len as i64);
                // return the data with read_to_len, store the rest in the read buffer
                let buf_slice = buffer.buf.as_slice();
                let mut buf_vec = buf_slice[..(n as usize)].to_vec();
                self.read_buf.append(&mut buf_vec);

                // assert!(self.read_buf.len() >= read_to_len);

                if self.read_buf.len() < read_to.len() {
                    let read_buf_slice_len = self.read_buf.len();
                    let read_to_slice = &mut read_to[..read_buf_slice_len];
                    read_to_slice.clone_from_slice(&self.read_buf.as_slice());
                    self.read_buf.drain(0..read_buf_slice_len);

                    log::trace!("embedded_io::blocking::Read return {:?} byte after RecvMsg, read_to {:?}, ShieldProvisioningHttpSClient len {:?} buffer {:?}", read_to_len, read_to,  self.read_buf.len(), self.read_buf);
                    return Ok(read_buf_slice_len);
                } else {
                    let read_buf_slice = &self.read_buf[..read_to.len()];
                    read_to.clone_from_slice(read_buf_slice);
                    self.read_buf.drain(0..read_to.len());

                    log::trace!("embedded_io::blocking::Read return {:?} byte after RecvMsg, read_to {:?}, ShieldProvisioningHttpSClient len {:?} buffer {:?}", read_to_len, read_to,  self.read_buf.len(), self.read_buf);
                    return Ok(read_to.len());
                }            
            },
            Err(e) => {
                log::trace!("embedded_io::blocking::Read get package from intenet get resp, error {:?}  flags {:?}", e, flags);
                // TODO: return the exact error we got
                return Err(embedded_tls::TlsError::Io(embedded_io::ErrorKind::Other));
            },
        }
    }
}

impl embedded_io::blocking::Write for ShieldProvisioningHttpSClient {
    fn write<'m>(&'m mut self, write_from: &'m [u8]) -> core::result::Result<usize, Self::Error> {
        let socket_op = self.socket_file.FileOp.clone();

        let current_task = Task::Current();

        let mut pMsg = MsgHdr::default();

        // The msg_name and msg_namelen fields contain the address and address length to which the message is sent. 
        // For further information about the structure of socket addresses, see the Sockets programming topic collection. 
        // If the msg_name field is set to a NULL pointer, the address information is not returned.
        pMsg.msgName = 0;
        pMsg.nameLen = 0;
    
        let mut deadline = None;
        let mut flags = 0 as i32;
    
        let dl = socket_op.SendTimeout();
        if dl > 0 {
            let now = MonotonicNow();
            deadline = Some(Time(now + dl));
        } else if dl < 0 {
            flags |= crate::qlib::linux_def::MsgType::MSG_DONTWAIT
        }
        
        let mut req_buf = DataBuff::New(write_from.len());
        let write_buf = write_from.to_vec();
        req_buf.buf = write_buf;
        let src = req_buf.Iovs(write_from.len());

        log::trace!("call_send send SendMsg start");
        let res = socket_op.SendMsg(current_task, &src, flags, &mut pMsg, deadline);
        if res.is_err() {
            info!("call_send SendMsg get error  irte {:?} bytes data to tty", res);
            return Err(embedded_tls::TlsError::Io(embedded_io::ErrorKind::Other));
        }
        
        let res = res.unwrap();

        let http_get_resp = String::from_utf8_lossy(write_from).to_string();

        log::trace!("call_send send req finished, get {:?} bytes, data: {:?}", res, http_get_resp);

        Ok(res as usize)
    }

    fn flush<'m>(&'m mut self) -> core::result::Result<(), Self::Error> {
        Ok(())
    }
}


/**
 * ip: the ip of secret manager
 * port: on which port the secret manager is listening on
 * TODO: Get the ip and port of the secrect manager from container deployment yaml
*/
pub fn get_socket(task: &Task, _ip: [u8;4], _port: u16) -> Result<Arc<File>> {

    // get a qkernel socket file object, 
    debug!("socket_connect start");

    let family = AFType::AF_INET;  // ipv4
    let socket_type = LibcConst::SOCK_STREAM as i32;
    let protocol = 0;   
    let ipv4_provider = ShieldSocketProvider { family: family};

    debug!("socket_connect get a socekt from host");
    let socket_file = ipv4_provider.Socket(task, socket_type, protocol).unwrap().unwrap();

    let flags = SettableFileFlags {
        NonBlocking: socket_type & Flags::O_NONBLOCK != 0,
        ..Default::default()
    };

    socket_file.SetFlags(task, flags);

    // connect to target ip:port, blocking is true
    let blocking = !socket_file.Flags().NonBlocking;
    assert!(blocking == true);
    let socket_op = socket_file.FileOp.clone();

    let kbs_ip;
    let kbs_port;

    {

        let app_info_keeper = APPLICATION_INFO_KEEPER.read();
        
        kbs_ip = app_info_keeper.get_kbs_ip().unwrap();
        kbs_port = app_info_keeper.get_kbs_port().unwrap();

    }

    let sock_addr = SockAddr::Inet(SockAddrInet {
        Family: AFType::AF_INET as u16,
        Port: htons(kbs_port),
        Addr: kbs_ip,
        Zero: [0; 8],
    });

    let socket_addr_vec = sock_addr.ToVec().unwrap();

    socket_op.Connect(task, socket_addr_vec.as_slice(), blocking)?;
    debug!("socket_connect connect to secret manager done");

    return Ok(socket_file);
}



fn send_http_request_to_sm (tls: &mut TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256>, http_req: String, rx_buf: &mut [u8]) ->  core::result::Result<usize, embedded_tls::TlsError>{

    let sx_buf = http_req.as_bytes();
    let res = tls.write(sx_buf);
    if res.is_err() {
        info!("send_http_request_to_sm tls.write get error : {:?}", res);
        return res;
    }

    //all number literals except the byte literal allow a type suffix, such as 57u8
   // So 0u8 is the number 0 as an unsigned 8-bit integer.
    let resp_len = tls.read(rx_buf);
    if resp_len.is_err() {
        info!("send_http_request_to_sm tls.read get error : {:?}", resp_len);
        return resp_len;
    }
    resp_len
}

fn set_up_tls<'a>(client: &'a ShieldProvisioningHttpSClient, read_record_buffer: &'a mut [u8], write_record_buffer: &'a mut [u8], rng: &mut OsRng) -> core::result::Result<TlsConnection<'a, ShieldProvisioningHttpSClient, Aes128GcmSha256>, embedded_tls::TlsError> {

    // TODO: figur out the server name
    let config = TlsConfig::new().enable_rsa_signatures();

    let mut tls: TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256> = TlsConnection::new(client.clone(), read_record_buffer, write_record_buffer);

    // TODO: add verrifyer to verify the server certificate
    let res = tls.open::<OsRng, NoVerify>(TlsContext::new(&config, rng));
    if res.is_err() {
        info!("tls.open get error : {:?}", res);
        return Err(res.err().unwrap());
    }

    Ok(tls)
}



fn get_policy(tls: &mut TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256>, client: &mut ShieldProvisioningHttpSClient) -> Result<KbsPolicy> {


    let policy_url;
    {
        let application_info_keeper = super::APPLICATION_INFO_KEEPER.read();
        policy_url = application_info_keeper.kbs_policy_path.clone();
    }

    if policy_url.is_none() {
        info!("user didn't provide policy, enclave will use default one");
        return Err(Error::Common(format!("get_policy user didn't provide policy, enclave will use default one")));
    }

    debug!("get_policy policy_url {:?}", policy_url);

    let get_resource_http = client.prepair_get_resource_http_req(policy_url.unwrap());
    let mut rx_buf_get_secret = [0; 4096];
    let resp_len = send_http_request_to_sm(tls, get_resource_http, &mut rx_buf_get_secret)
        .map_err(|e| Error::Common(format!("get_policy provisioning_http_client, attestation phase 2: get resource get error: {:?}", e)))?;

    let secret = client.parse_http_get_resource_resp(&rx_buf_get_secret[..resp_len as usize])
        .map_err(|e| Error::Common(format!("get_policy provisioning_http_client, attestation phase 2: parse resp get error: {:?}", e)))?;

    let http_get_resp = String::from_utf8_lossy(&secret).to_string();
    log::debug!("get_policy provisioning_https_client  attestation phase 2 resp: {}, resp_len {}", http_get_resp, resp_len);

    let bytes = base64::decode(secret)
        .map_err(|e| Error::Common(format!("get_policy base64::decode failed to get secret {:?}", e)))?;
    let policy: KbsPolicy = serde_json::from_slice(&bytes).map_err(|e| Error::Common(format!("get_policy serde_json::from_slice failed to get secret {:?}", e)))?;

    log::info!("get_policy policy from kbs {:?}", policy);


    Ok(policy)
    
}


fn get_env_based_secret(env_url_in_kbs: String, tls: &mut TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256>, client: &mut ShieldProvisioningHttpSClient) -> Result<Vec<String>> {
    
    let env_get_resource_http = client.prepair_get_resource_http_req(env_url_in_kbs.to_string());
    let mut rx_buf_for_env = [0; 4096];
    let env_resp_len = send_http_request_to_sm(tls, env_get_resource_http, &mut rx_buf_for_env)
        .map_err(|e| Error::Common(format!("get_env_based_secret provisioning_http_client, attestation phase 2: get resource get error: {:?}", e)))?;

    let cmd_based_secret = client.parse_http_get_resource_resp(&rx_buf_for_env[..env_resp_len as usize])
        .map_err(|e| Error::Common(format!("get_env_based_secret provisioning_http_client, attestation phase 2: parse resp get error: {:?}", e)))?;

    let http_get_resp = String::from_utf8_lossy(&cmd_based_secret).to_string();
    log::debug!("get_env_based_secret provisioning_https_client  attestation phase 2 resp: {}, resp_len {}", http_get_resp, env_resp_len);

    let cmd_in_bytes = base64::decode(cmd_based_secret)
        .map_err(|e| Error::Common(format!("get_env_based_secret base64::decode failed to get secret {:?}", e)))?;
    let env: Vec<String> = serde_json::from_slice(&cmd_in_bytes).map_err(|e| Error::Common(format!("get_env_based_secret serde_json::from_slice failed to get secret {:?}", e)))?;

    Ok(env)
}


fn get_cmd_env_based_secret(cmd_url_in_kbs: String, tls: &mut TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256>, client: &mut ShieldProvisioningHttpSClient) -> Result<EnvCmdBasedSecrets> {

    let get_resource_http = client.prepair_get_resource_http_req(cmd_url_in_kbs.to_string());
    let mut rx_buf_for_cmd = [0; 4096];
    let resp_len = send_http_request_to_sm(tls, get_resource_http, &mut rx_buf_for_cmd)
        .map_err(|e| Error::Common(format!("get_cmd_env_based_secret provisioning_http_client, attestation phase 2: get resource get error: {:?}", e)))?;

    let secret = client.parse_http_get_resource_resp(&rx_buf_for_cmd[..resp_len as usize])
        .map_err(|e| Error::Common(format!("get_cmd_env_based_secret provisioning_http_client, attestation phase 2: parse resp get error: {:?}", e)))?;

    let http_get_resp = String::from_utf8_lossy(&secret).to_string();
    log::info!("get_cmd_env_based_secret provisioning_https_client  attestation phase 2 resp: {}, resp_len {}", http_get_resp, resp_len);

    let bytes = base64::decode(secret)
        .map_err(|e| Error::Common(format!("get_cmd_env_based_secret base64::decode failed to get secret {:?}", e)))?;
    let cmd_env: EnvCmdBasedSecrets = serde_json::from_slice(&bytes).map_err(|e| Error::Common(format!("get_cmd_based_secret serde_json::from_slice failed to get secret {:?}", e)))?;

    Ok(cmd_env)

}



fn get_file_based_secret(file_based_secret_url_in_kbs: Vec<String>, tls: &mut TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256>, client: &mut ShieldProvisioningHttpSClient) -> Result<Vec<ConfigFile>> {


    let mut configs = Vec::new();
    for file_url in file_based_secret_url_in_kbs {

        let get_resource_http = client.prepair_get_resource_http_req(file_url);
        let mut rx_buf = [0; 8192];
        let resp_len = send_http_request_to_sm(tls, get_resource_http, &mut rx_buf)
            .map_err(|e| Error::Common(format!("get_file_based_secret provisioning_http_client, attestation phase 2: get resource get error: {:?}", e)))?;
    
        let file_based_secret = client.parse_http_get_resource_resp(&rx_buf[..resp_len as usize])
            .map_err(|e| Error::Common(format!("get_file_based_secret provisioning_http_client, attestation phase 2: parse resp get error: {:?}", e)))?;
    
        let http_get_resp = String::from_utf8_lossy(&file_based_secret).to_string();
        log::info!("get_file_based_secret provisioning_https_client  attestation phase 2 resp: {}, resp_len {}", http_get_resp, resp_len);
    
        let file_based_secret_in_bytes = base64::decode(file_based_secret)
            .map_err(|e| Error::Common(format!("get_file_based_secret base64::decode failed to get secret {:?}", e)))?;
        let config: ConfigFile = serde_json::from_slice(&file_based_secret_in_bytes).map_err(|e| Error::Common(format!("serde_json::from_slice failed to get secret {:?}", e)))?;
    
        configs.push(config);
    }


    Ok(configs)

}


fn get_secret(tls: &mut TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256>, client: &mut ShieldProvisioningHttpSClient) -> Result<KbsSecrets> {

    let cmd_env_url;
    let file_urls;


    let mut kbs_secret = KbsSecrets::default();

    {
        let application_info_keeper = super::APPLICATION_INFO_KEEPER.read();
        cmd_env_url = application_info_keeper.kbs_cmd_env_based_secret_path.clone();
        file_urls = application_info_keeper.kbs_file_based_secret_paths.clone();
    }

    debug!("get_secret cmd_url {:?}, file_urls {:?}", cmd_env_url, file_urls);


    if cmd_env_url.is_some() {
        let cmd = get_cmd_env_based_secret(cmd_env_url.unwrap(), tls, client)?;
        kbs_secret.env_cmd_secrets = Some(cmd);
    }

    if file_urls.len() > 0 {
        let config_files = get_file_based_secret(file_urls, tls, client)?;
        kbs_secret.config_fils = Some(config_files);
    }

    log::debug!("get_secret from kbs {:?}", kbs_secret);
    Ok(kbs_secret)

}


fn get_kbs_signing_key(tls: &mut TlsConnection<ShieldProvisioningHttpSClient, Aes128GcmSha256>, client: &mut ShieldProvisioningHttpSClient) -> Result<ssh_key::PrivateKey> {


    let get_resource_http = client.prepair_get_resource_http_req(URI_TO_GET_KBS_SIGNING_KEY.to_string());
    let mut rx_buf_for_cmd = [0; 4096];
    let resp_len = send_http_request_to_sm(tls, get_resource_http, &mut rx_buf_for_cmd)
        .map_err(|e| Error::Common(format!("get_kbs_signing_key provisioning_http_client, attestation phase 2: get resource get error: {:?}", e)))?;

    let secret = client.parse_http_get_resource_resp(&rx_buf_for_cmd[..resp_len as usize])
        .map_err(|e| Error::Common(format!("get_kbs_signing_key provisioning_http_client, attestation phase 2: parse resp get error: {:?}", e)))?;
    let to_private_key = ssh_key::PrivateKey::from_bytes(&secret)
        .map_err(|e| Error::Common(format!("get_kbs_signing_key ssh_key::PrivateKey::from_bytes get error: {:?}", e)))?;


    log::debug!("get_kbs_signing_key from kbs {}", &*to_private_key.to_openssh(ssh_key::LineEnding::LF).unwrap());

    {
        let mut kbs_signing_key_keeper = super::sys_attestation_report::KBS_SIGNING_KEY_KEEPER.write();
        kbs_signing_key_keeper.set_kbs_signing_key(secret).unwrap();
    }

    Ok(to_private_key)
}




pub fn provisioning_http_client(task: &Task, software_maasurement: &str) -> Result<(KbsPolicy, KbsSecrets)> {

    log::debug!("provisioning_http_client start");

    let socket_to_sm = get_socket(task, SECRET_MANAGER_IP, SECRET_MANAGER_PORT)
        .map_err(|e| Error::Common(format!("provisioning_http_client get_socket get error {:?}", e)))?;


    let mut client = ShieldProvisioningHttpSClient::init(socket_to_sm, 30000, 10000);   // ~30 Mib

    let mut read_record_buffer : [u8; 16384]= [0; 16384];
    let mut write_record_buffer  :[u8; 16384]= [0; 16384];

    let mut rng = OsRng;

    let client_clone = client.clone();
    let mut tls = set_up_tls(&client_clone, &mut read_record_buffer, &mut write_record_buffer, &mut rng)
        .map_err(|e| Error::Common(format!("provisioning_http_client set_up_tls get error {:?}", e)))?;

    {
            // attestation phase 1.1a: auth
        let auth_http_req = client.prepair_post_auth_http_req();
        let mut rx_buf = [0; 4096];
        let resp_len = send_http_request_to_sm(&mut tls, auth_http_req, &mut rx_buf)
            .map_err(|e| Error::Common(format!("provisioning_http_client send_http_request_to_sm get error {:?}", e)))?;
        let http_get_resp = String::from_utf8_lossy(&rx_buf[..resp_len as usize]).to_string();
        log::debug!("provisioning_https_client auth resp: {}, resp_len {}", http_get_resp, resp_len);

            // attestation phase 1.1b: parse auth response
        client.parse_auth_http_resp(&rx_buf[..resp_len as usize])
        .map_err(|e| Error::Common(format!("provisioning_http_client, attestation phase 1: parse auth response get error {:?}", e)))?;
    }


    {
            // attestation phase 1.2a: sent attest req
        let post_http_attest_req = client.prepair_post_attest_http_req(software_maasurement)
            .map_err(|e| Error::Common(format!("provisioning_http_client, attestation phase 1.2a: sent attest req to sm get error {:?}", e)))?;

        let mut rx_buf = [0; 4096];
        let resp_len = send_http_request_to_sm(&mut tls, post_http_attest_req, &mut rx_buf)
            .map_err(|e| Error::Common(format!("provisioning_http_client, attestation phase 1.2a: sent attest req to sm get error:{:?}", e)))?;

        let http_get_resp = String::from_utf8_lossy(&rx_buf[..resp_len as usize]).to_string();
        log::debug!("provisioning_https_client attest resp: {}, resp_len {}", http_get_resp, resp_len);

        // attestation phase 1.2b: parse attest response
        client.parse_attest_http_resp(&rx_buf[..resp_len as usize])
            .map_err(|e| Error::Common(format!("provisioning_http_client, attestation phase 1: parse auth response get error {:?}", e)))?;

    }

    let kbs_secret = get_secret(&mut tls, &mut client);
    if kbs_secret.is_err() {
        info!("provisioning_http_client  get_secret(&mut tls, &mut client) got erorr {:?}", kbs_secret);
        return Err(kbs_secret.err().unwrap());
    }

    let kbs_policy = get_policy(&mut tls, &mut client);
    if kbs_policy.is_err() {
        info!("provisioning_http_client  gget_policy(&mut tls, &mut client); got erorr {:?}", kbs_policy);
        return Err(kbs_policy.err().unwrap());
    }

    let kbs_signing_Key = get_kbs_signing_key(&mut tls, &mut client);
    if kbs_signing_Key.is_err() {
        info!("provisioning_http_client   get_kbs_signing_key(&mut tls, &mut client); got erorr {:?}", kbs_signing_Key);
    }

    let kbs_secret = kbs_secret.unwrap();
    let kbs_policy = kbs_policy.unwrap();


    // let mut shield_policy = Policy::default();
    // shield_policy.enable_policy_updata = kbs_policy.enable_policy_updata;
    // shield_policy.privileged_user_config = kbs_policy.privileged_user_config.clone();
    // shield_policy.privileged_user_key_slice = kbs_policy.privileged_user_key_slice.clone();
    // shield_policy.unprivileged_user_config = kbs_policy.unprivileged_user_config.clone();

    // if kbs_secret.env_cmd_secrets.is_some() {
    //     let secrets = kbs_secret.env_cmd_secrets.as_ref().unwrap();

    //     shield_policy.secret.env_variables = secrets.env_variables.clone();
    //     shield_policy.secret.cmd_arg = secrets.cmd_arg.clone();
    // }

    // if kbs_secret.config_fils.is_some() {
    //     shield_policy.secret.config_fils = kbs_secret.config_fils.as_ref().unwrap().clone();
    // }


    log::info!("provisioning_http_client policy for kbs kbs_policy {:?}, kbs_secret {:?}", kbs_policy, kbs_secret);

    Ok((kbs_policy, kbs_secret))
}





