use core::convert::TryInto;

use qlib::control_msg::*;
use qlib::path::*;
use qlib::common::*;
use qlib::shield_policy::*;

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use spin::mutex::Mutex;
use crate::getrandom::getrandom;
use crate::aes_gcm::{
    aead::{Aead, KeyInit, OsRng, generic_array::{GenericArray, typenum::U32}},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use alloc::collections::btree_map::BTreeMap;

lazy_static! {
    pub static ref POLICY_CHEKCER :  Mutex< PolicyChecher> = Mutex::new(PolicyChecher::default());
}




#[derive(Debug, Default)]
pub struct PolicyChecher {
    policy: Policy,
    counter: i64,
    key: GenericArray<u8, U32>,
    inode_track: BTreeMap<u64, InodeType>,
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


    
    pub fn encrypt(&self, plain_txt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce_rnd = random_bytes();
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
        
    pub fn prepareEncodedIoFrame(&self, plainText :&[u8]) -> Result<Vec<u8>> {
    
        const KEY: &[u8; 32] = b"a very simple secret key to use!";
    
        let mut payload = PayLoad::default();
        payload.counter = 1;
        payload.data = plainText.to_vec();
    
        let encoded_payload: Vec<u8> = postcard::to_allocvec(&payload).unwrap();

        let mut io_frame = IoFrame::default();
    
        (io_frame.pay_load, io_frame.nonce)= self.encrypt(encoded_payload.as_ref()).unwrap();
    
        let encoded_frame = postcard::to_allocvec(&io_frame).unwrap();
    
        Ok(encoded_frame)
    }
    
    
    pub fn getDecodedPayloads(&self, encoded_payload :&Vec<u8>) -> Result<Vec<PayLoad>> {

        let mut payloads = Vec::new();

        let mut frame = IoFrame::default();
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



    pub fn addInoteToTrack(&mut self, key: u64, value: InodeType) -> (){

        self.inode_track.insert(key, value);

    }


    pub fn isInodeExist(&self, key: &u64) -> bool {
        self.inode_track.contains_key(key)
    }


    pub fn getInodeType (&self, key: &u64) -> Option<&InodeType> {
        
        return self.inode_track.get(key);
    
    }
    


}


fn random_bytes() -> [u8; NONCE_LENGTH] {
    let mut rmd_nonce= Vec::with_capacity(NONCE_LENGTH);
    getrandom(&mut rmd_nonce).unwrap();
    rmd_nonce.as_slice().try_into().unwrap()
    // thread_rng().gen::<[u8; NONCE_LENGTH]>()

}

    