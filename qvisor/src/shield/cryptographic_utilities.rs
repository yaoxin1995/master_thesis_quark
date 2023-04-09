use alloc::vec::Vec;
use crate::aes_gcm::{
       aead::{OsRng, generic_array::{GenericArray, typenum::U32}, rand_core::RngCore},
};
use crate::qlib::common::*;

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

pub fn encrypt(_plain_txt: &[u8], _key: &GenericArray<u8, U32>) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(Error::InvalidArgument("Error".to_string()))
}

pub fn decrypt(_cipher_txt: &[u8], _nouce: &[u8], _key: &GenericArray<u8, U32>) -> Result<Vec<u8>> {
    Err(Error::InvalidArgument("Error".to_string()))
}
    
pub fn random_bytes(slice: &mut [u8]) -> (){
    // let mut rmd_nonce= Vec::with_capacity(NONCE_LENGTH);
    // getrandom(&mut rmd_nonce).unwrap();
    assert!(slice.len() == NONCE_LENGTH);
    let mut rng = OsRng;
    rng.fill_bytes(slice);
    info!("generate nounce {:?}", slice);
    // rmd_nonce
    // thread_rng().gen::<[u8; NONCE_LENGTH]>()
}

pub fn prepareEncodedIoFrame(_plainText :&[u8], _key: &GenericArray<u8, U32>) -> Result<Vec<u8>> {
    Err(Error::InvalidArgument("Error".to_string()))

}


pub fn getDecodedPayloads(_encoded_payload :&Vec<u8>, _key: &GenericArray<u8, U32>) -> Result<Vec<PayLoad>> {

    Err(Error::InvalidArgument("Error".to_string()))

}