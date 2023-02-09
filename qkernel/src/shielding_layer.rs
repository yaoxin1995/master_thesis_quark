use aes_gcm::aead::rand_core::RngCore;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use spin::rwlock::RwLock;

use qlib::control_msg::*;
use qlib::path::*;
use qlib::common::*;
use qlib::shield_policy::*;
use crate::aes_gcm::{
    aead::{Aead, KeyInit, OsRng, generic_array::{GenericArray, typenum::U32}},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
    Key,
};

use super::qlib::linux_def::*;
use super::qlib::kernel::task::*;
use super::qlib::kernel::{SHARESPACE, IOURING, fd::*, boot::controller::HandleSignal};

lazy_static! {
    pub static ref POLICY_CHEKCER :  RwLock<PolicyChecher> = RwLock::new(PolicyChecher::default());
    pub static ref TERMINAL_SHIELD:  RwLock<TerminalShield> = RwLock::new(TerminalShield::default());
}


#[derive(Debug, Default)]
pub struct TerminalShield {
    key: GenericArray<u8, U32>,
}

#[derive(Debug, Default)]
pub struct PolicyChecher {
    policy: Policy,
    counter: i64,
    key: GenericArray<u8, U32>,
    inode_track: BTreeMap<u64, TrackInodeType>,
}
    
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct IoFrame {
    pub nonce: Vec<u8>,
    // length: usize,
     // encrypted payload structure using aes-gcm
    pub pay_load: Vec<u8>,
}
    
#[derive(Serialize, Deserialize, Debug, Default,Clone)]
pub struct PayLoad {
    pub counter: i64,
    pub data: Vec<u8>,
}
    
    /// Nonce: unique per message.
    /// 96-bits (12 bytes)
const NONCE_LENGTH: usize = 12;
    
    
impl PolicyChecher {
    
    pub fn init(&mut self, policy: Option<&Policy>) -> () {

        self.policy = policy.unwrap().clone();
        self.counter = 0;
        // self.key = policy.unwrap().secret.file_encryption_key.as_bytes().to_vec();
        // todo: get key from policy file
        // self.key = Aes256Gcm::generate_key(&mut OsRng);
        // sfor now, assume that the qkernel and secure client share this key
        const KEY_SLICE: &[u8; 32] = b"a very simple secret key to use!";
        self.key = Key::<Aes256Gcm>::from_slice(KEY_SLICE).clone();
        self.inode_track= BTreeMap::new();

        let mut termianl_shield = TERMINAL_SHIELD.write();
        termianl_shield.key = self.key.clone();
    

    }

    pub fn printPolicy(&self) -> () {

        info!("default policy:{:?}" ,self.policy);

        let key = Aes256Gcm::generate_key(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref()).unwrap();
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
        info!("cipher {:#?}, plain {:#?}", ciphertext, plaintext);

        // let cipher = Aes256Gcm::new(&key);
        // let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

        // // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
        // cipher.encrypt_in_place_detached(nonce, associated_data, buffer)
    }

    pub fn isStdoutEncryptionEnabled (&self) -> bool {

        return !self.policy.debug_mode_opt.disable_container_logs_encryption;

    }

    pub fn terminalEndpointerCheck (&self) -> bool {

        self.policy.debug_mode_opt.enable_terminal

    }


    /*
    TODO: 
        1. Pass credential of role to quark
        2. Encrypt the args on client side and decrypt them here
        3. Validate the credential with the help of KBS
        4. Chose the policy based on Role
     */
    pub fn singleShotCommandLineModeCheck (&self, oneShotCmdArgs: OneShotCmdArgs) -> bool {


        info!("oneShotCmdArgs is {:?}", oneShotCmdArgs);

        if self.policy.debug_mode_opt.single_shot_command_line_mode == false ||  oneShotCmdArgs.args.len() == 0 {
            return false;
        }

        let isCmdAllowed = self.isCmdAllowed(&Role::Host, &oneShotCmdArgs.args);

        info!("singleShotCommandLineModeCheck: role {:?}, cmd {:?}, isCmdAllowed: {:?}", Role::Host, oneShotCmdArgs.args[0], isCmdAllowed);

        // For now the path can only identify 3 type of path : abs path, relative path including "/" or "."
        // isPathAllowed can't identify the path such as "usr", "var" etc.
        // therefore,  ls usr, ls var will be allowd even though "var" and "usr" are not in the allowd dir
        // Todo: identify more dir type from args
        let isPathAllowd = self.isPathAllowed(&Role::Host, &oneShotCmdArgs.args, &oneShotCmdArgs.cwd);

        info!("singleShotCommandLineModeCheck: role {:?}, paths {:?}, isPathAllowd: {:?}", Role::Host, oneShotCmdArgs.args, isPathAllowd);

        return isCmdAllowed & isPathAllowd;
    }

    fn isCmdAllowed (&self, role: &Role, reqArgs: &Vec<String>) ->bool {
        info!("isCmdAllowed role {:?}, reqArgs: {:?}", role, reqArgs);
        if reqArgs.len() <= 0 {
            return false;
        }
        
        let reqCmd = reqArgs.get(0).unwrap();

        for conf in &self.policy.single_shot_command_line_mode_configs {

            if &conf.role == role {
                for cmd in &conf.allowed_cmd {
                    if reqCmd.eq(cmd) {
                        return true;
                    }

                }
                return false;
            }
        }
        false
    }

    fn isPathAllowed (&self, role: &Role, reqArgs: &Vec<String>, cwd: &str) -> bool {

        if reqArgs.len() == 1 {

            let subpaths = vec![cwd.to_string()];
            let allowedPaths= self.findAllowedPath(role);

            let isAllowed = self.IsSubpathCheck (subpaths, allowedPaths);

            info!("isPathAllowed: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}, isAllowed: {:?}", role, reqArgs, cwd, isAllowed);

            return isAllowed;


        }
        info!("isPathAllowed000: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}", role, reqArgs, cwd);
        let mut absPaths = Vec::new();
        let mut relPaths = Vec::new();
        //collect all path like structure including abs path, relative path, files (a.s)

        for e in reqArgs[1..].iter() {
            if e.len() > 0 && e.as_bytes()[0] == '-' as u8 {
                continue;
            }
            if IsPath(e) {
                let str = Clean(e);
                if IsAbs(&str) {
                    absPaths.push(str);
                    continue;
                }

                if IsRel(e) {
                    let str = Clean(e);
                    relPaths.push(str);
                    continue;
                }
            }


        }

        info!("relPaths {:?}, absPaths {:?}", relPaths, absPaths);

        // convert rel path to abs path
        for relPath in relPaths {
            let absPath = Join(cwd, &relPath);
            info!("absPath {:?}", absPath);
            absPaths.push(absPath);
        }

        let allowedPaths= self.findAllowedPath(role);

        if allowedPaths.len() <= 0 {
            return false;
        }

        let isAllowed = self.IsSubpathCheck (absPaths, allowedPaths);

        info!("isPathAllowed111: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}, isAllowed: {:?}", role, reqArgs, cwd, isAllowed);

        return isAllowed;
            

    }


    fn findAllowedPath (&self,  role: &Role) -> Vec<String> {

        let mut allowedPaths= &Vec::new();
        for conf in &self.policy.single_shot_command_line_mode_configs {

            if &conf.role == role {
                allowedPaths = &conf.allowed_dir;
            }
        }

        return allowedPaths.clone();
    }

    fn IsSubpathCheck (&self, subPaths: Vec<String>, paths: Vec<String>) -> bool {

        info!("IsSubpathCheck:  subPaths: {:?}, paths: {:?}", subPaths, paths);
        for absPath in subPaths {
            
            let mut isAllowd = false;
            for  allowedPath in &paths {
                if Clean(&absPath) == Clean(allowedPath) {
                    isAllowd = true;
                    break;
                }

                let (_, isSub) = IsSubpath(&absPath, &allowedPath);
                if  isSub {
                    isAllowd = true;
                    break;
                }
            }
            if !isAllowd {
                return false;
            }
        }
        true

    }


    
    fn encrypt(&self, plain_txt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(&self.key);

        let mut nonce_rnd = vec![0; NONCE_LENGTH];
        random_bytes(&mut nonce_rnd);
        let nonce = Nonce::from_slice(&nonce_rnd);

        let encrypt_msg = cipher.encrypt(nonce, plain_txt).map_err(|e| Error::Common(format!("failed to encryp the data error {:?}", e)))?;

        let mut cipher_txt = Vec::new();
        // cipher_txt.extend_from_slice(&nonce_rnd);
        cipher_txt.extend(encrypt_msg);
        Ok((cipher_txt, nonce_rnd.to_vec()))
    }
    
    fn decrypt(&self, cipher_txt: &[u8], nouce: &[u8]) -> Result<Vec<u8>> {
        // if cipher_txt.len() <= NONCE_LENGTH {
        //     bail!("cipher text is invalid");
        // }
        // let key = GenericArray::from_slice(self.key.as_slice());
        let cipher = Aes256Gcm::new(&self.key);
        // let nonce_rnd = &cipher_txt[..NONCE_LENGTH];
        let nonce = Nonce::from_slice(nouce);
        let plain_txt = cipher
            .decrypt(nonce, &cipher_txt[..])
            .map_err(|e| Error::Common(format!("failed to dencryp the data error {:?}", e)))?;
        Ok(plain_txt)
    }
        
    fn prepareEncodedIoFrame(&self, plainText :&[u8]) -> Result<Vec<u8>> {
    
        let mut payload = PayLoad::default();
        payload.counter = 1;
        payload.data = plainText.to_vec();
        assert!(payload.data.len() == plainText.len());
    
        let encoded_payload: Vec<u8> = postcard::to_allocvec(&payload).unwrap();

        let mut io_frame = IoFrame::default();
    
        (io_frame.pay_load, io_frame.nonce)= self.encrypt(encoded_payload.as_ref()).unwrap();
    
        let encoded_frame = postcard::to_allocvec_cobs(&io_frame).unwrap();
    
        Ok(encoded_frame)
    }
    
    
    fn getDecodedPayloads(&self, encoded_payload :&Vec<u8>) -> Result<Vec<PayLoad>> {

        let mut payloads = Vec::new();
        let mut frame;
        let mut payloads_slice= encoded_payload.as_slice();
    
        while payloads_slice.len() > 0 {
             (frame , payloads_slice) =  postcard::take_from_bytes::<IoFrame>(payloads_slice.as_ref()).unwrap();
            // let frame2:IoFrame = bincode::deserialize(encoded12[]).unwrap();
            // print!("frame111111111111 : {:?}\n", frame1);
            
        
            let decrypted = self.decrypt(&frame.pay_load, &frame.nonce).unwrap();
            let payload:PayLoad = postcard::from_bytes(decrypted.as_ref()).unwrap();
    
            payloads.push(payload);
        
        
            // print!("decrypted22222222222 {:?}, PLAIN_TEXT{:?}\n", payload, PLAIN_TEXT1.as_ref());
    
            // print!("payload111 :{:?}\n", &payload);
            if payloads_slice.len() == 0 {
                break;
            }
        }
        // print!("payloads22222 :{:?}\n", payloads);
        Ok(payloads)
    
    }

    pub fn addInoteToTrack(&mut self, key: u64, value: TrackInodeType) -> (){

        info!("add inode id {:?}, type:{:?}", key, value);
        self.inode_track.insert(key, value);
    }

    pub fn rmInoteToTrack(&mut self, key: u64) -> (){

        let res = self.inode_track.remove_entry(&key);
        let (_k, _v) = res.unwrap();
        info!("removed inode id {:?}, type:{:?}", _k, _v);
    }

    pub fn isInodeExist(&self, key: &u64) -> bool {
        info!("isInodeExist, key{:?} , exist{:?}", key ,self.inode_track.contains_key(key));
        self.inode_track.contains_key(key)
    }


    pub fn getInodeType (&self, key: &u64) ->  TrackInodeType{
        
        let res =  self.inode_track.get(key).unwrap().clone();
        res
    }

    pub fn encryptContainerStdouterr (&self, src: DataBuff) -> DataBuff {

        if self.policy.debug_mode_opt.disable_container_logs_encryption {
            return src;
        }

        let rawData= src.buf.clone();

        let str = String::from_utf8_lossy(&rawData).to_string();

        info!("stdout is : {:?}", str);

        let encodedOutBoundDate = self.prepareEncodedIoFrame(rawData.as_slice()).unwrap();
        assert!(encodedOutBoundDate.len() != 0);

        let mut res = DataBuff::New(encodedOutBoundDate.len());


        res.buf = encodedOutBoundDate.clone();

        // for (i, el) in encodedOutBoundDate.iter().enumerate(){
        //     assert!(res.buf[i] == *el);
        // }
        
        res

    }

    // pub fn terminalIoDecryption(&self, dsts: &[IoVec], task: &Task) -> Result<(usize, Option<Vec::<IoVec>>) {
    //     let size = IoVec::NumBytes(dsts);

    //     let mut vec = Vec::<IoVec>::new();
    //     let mut src_buf = DataBuff::New(size);

    // }

    pub fn termianlIoEncryption(&self, src: &[IoVec], task: &Task) -> Result<(usize, Option<Vec::<IoVec>>)>{
        let size = IoVec::NumBytes(src);
        if size == 0 {
            return Ok((0, None));
        }

        let mut vec = Vec::<IoVec>::new();
        let mut src_buf = DataBuff::New(size);
        let _ = task.CopyDataInFromIovs(&mut src_buf.buf, src, true)?;

        let rawData= src_buf.buf.clone();

        let str = String::from_utf8_lossy(&rawData).to_string();

        info!("terminal output is : {:?}", str);

        //let encodedOutBoundDate = self.prepareEncodedIoFrame(rawData.as_slice()).unwrap();
        let encodedOutBoundDate = rawData;
        let mut encrypted_iov = DataBuff::New(encodedOutBoundDate.len());
        encrypted_iov.buf = encodedOutBoundDate.clone();
        vec.push(encrypted_iov.IoVec(encodedOutBoundDate.len()));
        return Ok((encodedOutBoundDate.len(), Some(vec)));


        // let mut new_len : usize = 0;
        // let mut vec = Vec::<IoVec>::new();

        // for iov in src {
        //     let mut buf= DataBuff::New(iov.len);
        //     let _ = task.CopyDataInFromIovs(&mut buf.buf, &[iov.clone()], true)?;
        //     let rawData= buf.buf.clone();
        //     let encodedOutBoundDate = self.prepareEncodedIoFrame(rawData.as_slice()).unwrap();
        //     //let encodedOutBoundDate = rawData;
        //     let mut encrypted_iov = DataBuff::New(encodedOutBoundDate.len());
        //     encrypted_iov.buf = encodedOutBoundDate.clone();
        //     vec.push(encrypted_iov.IoVec(encodedOutBoundDate.len()));
        //     new_len = new_len + encodedOutBoundDate.len();
        // }

        // return Ok((new_len, Some(vec)));
    
    }
 
}


fn random_bytes(slice: &mut [u8]) -> (){
    // let mut rmd_nonce= Vec::with_capacity(NONCE_LENGTH);
    // getrandom(&mut rmd_nonce).unwrap();
    assert!(slice.len() == NONCE_LENGTH);
    let mut rng = OsRng;
    rng.fill_bytes(slice);
    info!("generate nounce {:?}", slice);
    // rmd_nonce
    // thread_rng().gen::<[u8; NONCE_LENGTH]>()
}


pub trait TermianlIoShiled{
    fn console_copy_from_fifo_to_tty(&self, fifo_fd: i32, tty_fd: i32, cid: &str, pid: i32, filter_sig: bool, task: &Task) -> Result<i64>;
    fn filter_signal_and_write(&self, task: &Task, to_fd: i32, s: &[u8], cid: &str, pid: i32) -> Result<()>;
    fn get_signal(&self, c: u8) -> Option<i32>;
    fn write_buf(&self, task: &Task, to: i32, buf: &[u8]) -> Result<i64>;
    fn read_from_fifo(&self, fd:i32, task: &Task, buf: &mut DataBuff, count: usize) -> Result<i64>;
    fn write_to_tty (&self, host_fd: i32, task: &Task, src_buf: &mut DataBuff, count: usize) -> Result<i64>;
}


pub const ENABLE_RINGBUF: bool = true;

impl TermianlIoShiled for TerminalShield {

    fn console_copy_from_fifo_to_tty(&self, fifo_fd: i32, tty_fd: i32, cid: &str, pid: i32, _filter_sig: bool, task: &Task) -> Result<i64> {

        //TODO: Now let's assume the max input len is 512
        // Add while loop or use bigger buffer to address this issue

        info!("console_copy_from_fifo_to_tty fifo_fd {:?}, tty {:?}, cid {:?}, pid {:?}", fifo_fd, tty_fd, cid, pid);
        let mut src_buf = DataBuff::New(512);
        let len = src_buf.Len();

        let ret = self.read_from_fifo(fifo_fd, task, &mut src_buf, len);

        if ret.is_err() {
            info!("read from stdin pipr got error, {:?}", ret);
            return ret;
        }
        
        let cnt = ret.unwrap();
        if cnt == 0 {
            info!("read from stdin pipr got 0 byte");
            return Ok(cnt);
        }
        assert!(cnt > 0);

        let buf_slice = src_buf.buf.as_slice();

        self.filter_signal_and_write(task, tty_fd, &buf_slice[..cnt as usize], cid, pid)?;

        Ok(cnt)
    }

    fn filter_signal_and_write(&self, task: &Task, to_fd: i32, s: &[u8], cid: &str, pid: i32) -> Result<()> {
        let len = s.len();
        let mut offset = 0;
        let rawData= s.clone();
        for i in 0..len {
            if let Some(sig) = self.get_signal(s[i]) {
                let sigArgs = SignalArgs {
                    CID: cid.to_string(),
                    Signo: sig,
                    PID: pid,
                    Mode: SignalDeliveryMode::DeliverToProcess,
                };
    
                let str = String::from_utf8_lossy(&rawData[offset..i]).to_string();
                info!("filter_signal_and_write, signal exist tty input {:?}", str);
                self.write_buf(task, to_fd, &s[offset..i])?;
                HandleSignal(&sigArgs);
                offset = i + 1;
            }
        }
        if offset < len {
            let str = String::from_utf8_lossy(&rawData[offset..len]).to_string();
            info!("filter_signal_and_write, offset < len, tty input {:?}", str);
            self.write_buf(task, to_fd, &s[offset..len])?;
        }
        return Ok(());
    }
    

    
    fn write_buf(&self, task: &Task, to: i32, buf: &[u8]) -> Result<i64> {
        let len = buf.len() as usize;
        let mut offset = 0;
        while offset < len {
            let count = len - offset;
            let but_to_write = &buf[offset..count];

            let mut src_buf = DataBuff::New(count);
            src_buf.buf = but_to_write.to_vec().clone();
            let len = src_buf.Len();

            let writeCnt = self.write_to_tty(to, task, &mut src_buf, len);
            if writeCnt.is_err() {
                info! ("qkernel write_buf got error {:?}", writeCnt);
                return writeCnt;
            }

    
            offset += writeCnt.unwrap() as usize;
        }
        return Ok(offset as i64);
    }

    fn get_signal(&self, c: u8) -> Option<i32> {
        // signal characters for x86
        const INTR_CHAR: u8 = 3;
        const QUIT_CHAR: u8 = 28;
        const SUSP_CHAR: u8 = 26;
        return match c {
            INTR_CHAR => Some(Signal::SIGINT),
            QUIT_CHAR => Some(Signal::SIGQUIT),
            SUSP_CHAR => Some(Signal::SIGTSTP),
            _ => None,
        };
    }


    fn read_from_fifo(&self, host_fd: i32, task: &Task, buf: &mut DataBuff, _count: usize) -> Result<i64> {
        if SHARESPACE.config.read().UringIO {

                let ret = IOURING.Read(
                    task,
                    host_fd,
                    buf.Ptr(),
                    buf.Len() as u32,
                    0 as i64,
                );

                if ret < 0 {
                    info!("read_from_fifo IOURING.READ got error {:?}", ret);
                    if ret as i32 != -SysErr::EINVAL {
                        return Err(Error::SysError(-ret as i32));
                    }
                } else if ret >= 0 {
                    info!("read_from_fifo IOURING.READ read {:?} bytes data from pipe", ret);
                    return Ok(ret as i64);
                }

                // if ret == SysErr::EINVAL, the file might be tmpfs file, io_uring can't handle this
                // fallback to normal case
                // todo: handle tmp file elegant
        }

        match IOReadAt(host_fd, &buf.Iovs(buf.Len()), 0 as u64) {
            Err(e) => {
                info!("read_from_fifo IOReadAt  got error {:?}", e);
                return Err(e)
            },
            Ok(ret) => {
                info!("read_from_fifo IOReadAt  read {:?} bytes data from pipe", ret);
                return Ok(ret);
        }
    }

    }


    
    fn write_to_tty (&self, host_fd: i32, task: &Task, src_buf: &mut DataBuff, _count: usize) -> Result<i64> {


        let ret;
        let offset:i64 = -1;
        if SHARESPACE.config.read().UringIO {

            /*
            IORING_OP_WRITE:
            Issue the equivalent of a pread(2) or pwrite(2) system call. fd is the file descriptor to be operated on, addr contains the buffer in question, len contains the length of the 
            IO operation, and offs contains the read or write offset. If fd does not refer to a seekable file, off must be set to zero or -1. If offs is set to -1 , the offset will use
            (and advance) the file position, like the read(2) and write(2) system calls. These are non-vectored versions of the IORING_OP_READV and IORING_OP_WRITEV opcodes. See also read(2) 
            and write(2) for the general description of the related system call. Available since 5.6.
             */
            ret = IOURING.Write(task, host_fd, src_buf.Ptr(), src_buf.Len() as u32, offset);

            if ret < 0 {
                info!("write_to_tty ucall got error {:?}", ret);
                if ret as i32 != -SysErr::EINVAL {
                   
                    return Err(Error::SysError(-ret as i32));
                }
            } else if ret >= 0 {
                info!("write_to_tty ucall wirte {:?} bytes data to tty", ret);
                return Ok(ret as i64);
            }
        }

        match IOWriteAt(host_fd, &src_buf.Iovs(src_buf.Len()), offset as u64) {
            Err(e) => {
                info!("write_to_tty IOWriteAt  got error {:?}", e);
                return Err(e)
            },
            Ok(ret) => {
                info!("write_to_tty IOWriteAt  irte {:?} bytes data to tty", ret);
                return Ok(ret);
            }
        }

    }


}

    