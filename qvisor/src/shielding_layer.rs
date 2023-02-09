use core::convert::TryInto;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use spin::rwlock::RwLock;


use super::qlib::control_msg::*;
use super::qlib::path::*;
use super::qlib::common::*;
use super::qlib::shield_policy::*;
use crate::getrandom::getrandom;
use crate::aes_gcm::{
    aead::{Aead, KeyInit, OsRng, generic_array::{GenericArray, typenum::U32}},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};

use alloc::collections::btree_map::BTreeMap;
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
        self.key = Aes256Gcm::generate_key(&mut OsRng);
        self.inode_track= BTreeMap::new();
    }

    pub fn printPolicy(&self) -> () {

        // info!("default policy:{:?}" ,self.policy);

        
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref()).unwrap();
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
        // info!("cipher {:#?}, plain {:#?}", ciphertext, plaintext);

        // let cipher = Aes256Gcm::new(&key);
        // let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

        // // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
        // cipher.encrypt_in_place_detached(nonce, associated_data, buffer)
    }

    pub fn terminalEndpointerCheck (&self) -> bool {

        self.policy.debug_mode_opt.enable_terminal

    }

    pub fn isStdoutEncryptionEnabled (&self) -> bool {

        return !self.policy.debug_mode_opt.disable_container_logs_encryption;

    }

    /*
    TODO: 
        1. Pass credential of role to quark
        2. Encrypt the args on client side and decrypt them here
        3. Validate the credential with the help of KBS
        4. Chose the policy based on Role
     */
    pub fn singleShotCommandLineModeCheck (&self, oneShotCmdArgs: OneShotCmdArgs) -> bool {


        // info!("oneShotCmdArgs is {:?}", oneShotCmdArgs);

        if self.policy.debug_mode_opt.single_shot_command_line_mode == false ||  oneShotCmdArgs.args.len() == 0 {
            return false;
        }

        let isCmdAllowed = self.isCmdAllowed(&Role::Host, &oneShotCmdArgs.args);

        // info!("singleShotCommandLineModeCheck: role {:?}, cmd {:?}, isCmdAllowed: {:?}", Role::Host, oneShotCmdArgs.args[0], isCmdAllowed);

        // For now the path can only identify 3 type of path : abs path, relative path including "/" or "."
        // isPathAllowed can't identify the path such as "usr", "var" etc.
        // therefore,  ls usr, ls var will be allowd even though "var" and "usr" are not in the allowd dir
        // Todo: identify more dir type from args
        let isPathAllowd = self.isPathAllowed(&Role::Host, &oneShotCmdArgs.args, &oneShotCmdArgs.cwd);

        // info!("singleShotCommandLineModeCheck: role {:?}, paths {:?}, isPathAllowd: {:?}", Role::Host, oneShotCmdArgs.args, isPathAllowd);

        return isCmdAllowed & isPathAllowd;
    }

    fn isCmdAllowed (&self, role: &Role, reqArgs: &Vec<String>) ->bool {
        // info!("isCmdAllowed role {:?}, reqArgs: {:?}", role, reqArgs);
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

            // info!("isPathAllowed: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}, isAllowed: {:?}", role, reqArgs, cwd, isAllowed);

            return isAllowed;


        }
        // info!("isPathAllowed000: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}", role, reqArgs, cwd);
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

        // info!("relPaths {:?}, absPaths {:?}", relPaths, absPaths);

        // convert rel path to abs path
        for relPath in relPaths {
            let absPath = Join(cwd, &relPath);
            // info!("absPath {:?}", absPath);
            absPaths.push(absPath);
        }

        let allowedPaths= self.findAllowedPath(role);

        if allowedPaths.len() <= 0 {
            return false;
        }

        let isAllowed = self.IsSubpathCheck (absPaths, allowedPaths);

        // info!("isPathAllowed111: isAllowed role {:?}, reqArgs: {:?}, cwd: {:?}, isAllowed: {:?}", role, reqArgs, cwd, isAllowed);

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

        // info!("IsSubpathCheck:  subPaths: {:?}, paths: {:?}", subPaths, paths);
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

    fn random_bytes(&self) -> [u8; NONCE_LENGTH] {
        let mut rmd_nonce= Vec::with_capacity(NONCE_LENGTH);
        getrandom(&mut rmd_nonce).unwrap();
        rmd_nonce.as_slice().try_into().unwrap()
        // thread_rng().gen::<[u8; NONCE_LENGTH]>()
    }
    
    pub fn encrypt(&self, plain_txt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce_rnd = self.random_bytes();
        let nonce = Nonce::from_slice(&nonce_rnd);
        let encrypt_msg = cipher.encrypt(nonce, plain_txt).map_err(|e| Error::Common(format!("failed to encryp the data error {:?}", e)))?;
        let mut cipher_txt = Vec::new();
        // cipher_txt.extend_from_slice(&nonce_rnd);
        cipher_txt.extend(encrypt_msg);
        Ok((cipher_txt, nonce_rnd.to_vec()))
    }
    
    pub fn decrypt(&self, cipher_txt: &[u8], nouce: &[u8]) -> Result<Vec<u8>> {
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
    
    
    pub fn prepareEncodedIoFrame(&self, _plainText :&[u8]) -> Result<Vec<u8>> {
    
        // const KEY: &[u8; 32] = b"a very simple secret key to use!";
    
        // let mut payload = PayLoad::default();
        // payload.counter = 1;
        // payload.data = plainText.to_vec();
    
        // let encoded_payload: Vec<u8> = postcard::to_allocvec(&payload).unwrap();

        // let mut io_frame = IoFrame::default();
    
        // (io_frame.pay_load, io_frame.nonce)= self.encrypt(encoded_payload.as_ref()).unwrap();
    
        // let encoded_frame = postcard::to_allocvec(&io_frame).unwrap();
    
        Ok(Vec::new())
    }
    
    
    pub fn getDecodedPayloads(&self, _encoded_payload :&Vec<u8>) -> Result<Vec<PayLoad>> {

        let mut _payloads = Vec::new();
    
        // while encoded_payload.len() > 0 {
        //     let (frame1 , encoded_payload) =  postcard::take_from_bytes::<IoFrame>(encoded_payload.as_ref()).unwrap();
        //     // let frame2:IoFrame = bincode::deserialize(encoded12[]).unwrap();
        //     // print!("frame111111111111 : {:?}\n", frame1);
        
        
        //     let decrypted = self.decrypt(&frame1.pay_load, &frame1.nonce).unwrap();
        //     let payload:PayLoad = postcard::from_bytes(decrypted.as_ref()).unwrap();
    
        //     payloads.push(payload);
        
        
        //     // print!("decrypted22222222222 {:?}, PLAIN_TEXT{:?}\n", payload, PLAIN_TEXT1.as_ref());
    
        //     // print!("payload111 :{:?}\n", &payload);
        //     // if unuesed_byte.len() == 0 {
        //     //     break;
        //     // }
        // }
        // print!("payloads22222 :{:?}\n", payloads);
        Ok(_payloads)
    
    }



    
    pub fn addInoteToTrack(&mut self, key: u64, value: TrackInodeType) -> (){

        self.inode_track.insert(key, value);
    }

    pub fn rmInoteToTrack(&mut self, key: u64) -> (){

        let res = self.inode_track.remove_entry(&key);
        let (_k, _v) = res.unwrap();
    }

    pub fn isInodeExist(&self, key: &u64) -> bool {
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

        let encodedOutBoundDate = self.prepareEncodedIoFrame(rawData.as_slice()).unwrap();
        assert!(encodedOutBoundDate.len() != 0);

        let mut res = DataBuff::New(encodedOutBoundDate.len());

        res.buf = encodedOutBoundDate;
        
        res

    }

    pub fn termianlIoEncryption(&self, src: &[IoVec], task: &Task) -> Result<(usize, Option<Vec::<IoVec>>)>{
        let size = IoVec::NumBytes(src);
        if size == 0 {
            return Ok((0, None));
        }
        let mut new_len : usize = 0;

        let mut vec = Vec::<IoVec>::new();

        for iov in src {
            let mut buf= DataBuff::New(iov.len);
            let _ = task.CopyDataInFromIovs(&mut buf.buf, &[iov.clone()], true)?;
            let rawData= buf.buf.clone();
            let encodedOutBoundDate = self.prepareEncodedIoFrame(rawData.as_slice()).unwrap();
            let mut encrypted_iov = DataBuff::New(encodedOutBoundDate.len());
            encrypted_iov.buf = encodedOutBoundDate.clone();
            vec.push(encrypted_iov.IoVec(encodedOutBoundDate.len()));
            new_len = new_len + encodedOutBoundDate.len();
        }

        return Ok((new_len, Some(vec)));
    
    }



    

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

        let mut src_buf = DataBuff::New(512);
        let buf_len = src_buf.Len();

        let ret = self.read_from_fifo(fifo_fd, task, &mut src_buf, buf_len);

        if ret.is_err() {
            return ret;
        }
        
        let cnt = ret.unwrap();
        if cnt == 0 {
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
        for i in 0..len {
            if let Some(sig) = self.get_signal(s[i]) {
                let sigArgs = SignalArgs {
                    CID: cid.to_string(),
                    Signo: sig,
                    PID: pid,
                    Mode: SignalDeliveryMode::DeliverToForegroundProcessGroup,
                };
    
                self.write_buf(task, to_fd, &s[offset..i])?;
                HandleSignal(&sigArgs);
                offset = i + 1;
            }
        }
        if offset < len {
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
            let src_buf_len = src_buf.Len();

            let writeCnt = self.write_to_tty(to, task, &mut src_buf, src_buf_len);
            if writeCnt.is_err() {
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
                    if ret as i32 != -SysErr::EINVAL {
                        return Err(Error::SysError(-ret as i32));
                    }
                } else if ret >= 0 {
                    return Ok(ret as i64);
                }

                // if ret == SysErr::EINVAL, the file might be tmpfs file, io_uring can't handle this
                // fallback to normal case
                // todo: handle tmp file elegant
        }

        let ret = IOReadAt(host_fd, &buf.Iovs(buf.Len()), 0 as u64)?;

        return Ok(ret as i64);

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
                if ret as i32 != -SysErr::EINVAL {
                    return Err(Error::SysError(-ret as i32));
                }
            } else if ret >= 0 {
                return Ok(ret as i64);
            }
        }

        match IOWriteAt(host_fd, &src_buf.Iovs(src_buf.Len()), offset as u64) {
            Err(e) => return Err(e),
            Ok(ret) => {
                return Ok(ret);
            }
        }

    }


}

    