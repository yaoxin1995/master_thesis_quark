use alloc::vec::Vec;
use crate::aes_gcm::{
       aead::{Aead, KeyInit, OsRng, generic_array::{GenericArray, typenum::U32}, rand_core::RngCore},
       Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use qlib::common::*;

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

pub fn encrypt(plain_txt: &[u8], key: &GenericArray<u8, U32>) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(key);

    let mut nonce_rnd = vec![0; NONCE_LENGTH];
    random_bytes(&mut nonce_rnd);
    let nonce = Nonce::from_slice(&nonce_rnd);

    let encrypt_msg = cipher.encrypt(nonce, plain_txt).map_err(|e| Error::Common(format!("failed to encryp the data error {:?}", e)))?;

    let mut cipher_txt = Vec::new();
    // cipher_txt.extend_from_slice(&nonce_rnd);
    cipher_txt.extend(encrypt_msg);
    Ok((cipher_txt, nonce_rnd.to_vec()))
}

pub fn decrypt(cipher_txt: &[u8], nouce: &[u8], key: &GenericArray<u8, U32>) -> Result<Vec<u8>> {
    // if cipher_txt.len() <= NONCE_LENGTH {
    //     bail!("cipher text is invalid");
    // }
    // let key = GenericArray::from_slice(self.key.as_slice());
    let cipher = Aes256Gcm::new(key);
    // let nonce_rnd = &cipher_txt[..NONCE_LENGTH];
    let nonce = Nonce::from_slice(nouce);
    let plain_txt = cipher
        .decrypt(nonce, &cipher_txt[..])
        .map_err(|e| Error::Common(format!("failed to dencryp the data error {:?}", e)))?;
    Ok(plain_txt)
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

pub fn prepareEncodedIoFrame(plainText :&[u8], key: &GenericArray<u8, U32>) -> Result<Vec<u8>> {
    
    let mut payload = PayLoad::default();
    payload.counter = 1;
    payload.data = plainText.to_vec();
    assert!(payload.data.len() == plainText.len());

    let encoded_payload: Vec<u8> = postcard::to_allocvec(&payload).unwrap();

    let mut io_frame = IoFrame::default();

    (io_frame.pay_load, io_frame.nonce)= encrypt(encoded_payload.as_ref(), key).unwrap();

    let encoded_frame = postcard::to_allocvec_cobs(&io_frame).unwrap();

    Ok(encoded_frame)
}


pub fn getDecodedPayloads(encoded_payload :&Vec<u8>, key: &GenericArray<u8, U32>) -> Result<Vec<PayLoad>> {

    let mut payloads = Vec::new();
    let mut frame;
    let mut payloads_slice= encoded_payload.as_slice();

    while payloads_slice.len() > 0 {
            (frame , payloads_slice) =  postcard::take_from_bytes::<IoFrame>(payloads_slice.as_ref()).unwrap();
        // let frame2:IoFrame = bincode::deserialize(encoded12[]).unwrap();
        // print!("frame111111111111 : {:?}\n", frame1);
        
    
        let decrypted = decrypt(&frame.pay_load, &frame.nonce, key).unwrap();
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