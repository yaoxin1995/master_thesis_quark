use alloc::vec::Vec;
use spin::rwlock::RwLock;
use crate::aes_gcm::{
    aead::{generic_array::{GenericArray, typenum::U32}},
};

use crate::qlib::common::*;
use crate::qlib::shield_policy::*;
use crate::qlib::linux_def::*;
use crate::qlib::kernel::task::*;

// use log::{error, info, debug};

lazy_static! {
    pub static ref TERMINAL_SHIELD:  RwLock<TerminalShield> = RwLock::new(TerminalShield::default());

}

#[derive(Debug, Default)]
pub struct TerminalShield {
    key: GenericArray<u8, U32>,
}


/*
1. Redirect the FIFO stdin from shim to qkernel (Done)    
2. Emulate TTY in qkernel
    - add qkernel buffer for fifo stdin
    - filter the signal from the client and notify the qkernel foreground process
    - send the data from the FIFO stdin to the FIFO stdout so that the client can view the character he typed
    - notify qkernel to read the buffer once the character '/r' coming
    - preprocessing the outbound data of qkernel (add /n after '/r' etc.)
    - write the output data to FIFO stdout
3. End-to-end encryption and decryption
    - Enrypte the outboud and decrypt the inbound in qkernel
    - Encrypte the outboud and decyrpt the inbound in secure client
*/
pub trait TermianlIoShiled{
    fn console_copy_from_fifo_to_tty(&self, fifo_fd: i32, tty_fd: i32, cid: &str, pid: i32, filter_sig: bool, task: &Task) -> Result<i64>;
    fn filter_signal_and_write(&self, task: &Task, to_fd: i32, s: &[u8], cid: &str, pid: i32) -> Result<()>;
    fn get_signal(&self, c: u8) -> Option<i32>;
    fn write_buf(&self, task: &Task, to: i32, buf: &[u8]) -> Result<i64>;
    fn read_from_fifo(&self, fd:i32, task: &Task, buf: &mut DataBuff, count: usize) -> Result<i64>;
    fn write_to_tty (&self, host_fd: i32, task: &Task, src_buf: &mut DataBuff, count: usize) -> Result<i64>;
    fn termianlIoEncryption(&self, src: &[IoVec], task: &Task) -> Result<(usize, Option<Vec::<IoVec>>)>;
}


pub const ENABLE_RINGBUF: bool = true;


impl TerminalShield {

    pub fn init(&mut self, _policy: &Policy, _key: &GenericArray<u8, U32>) -> () {
    }

}

impl TermianlIoShiled for TerminalShield {

    fn termianlIoEncryption(&self, _src: &[IoVec], _task: &Task) -> Result<(usize, Option<Vec::<IoVec>>)>{
        Err(Error::NotSupport)
    }

    fn console_copy_from_fifo_to_tty(&self, _fifo_fd: i32, _tty_fd: i32, _cid: &str, _pid: i32, _filter_sig: bool, _task: &Task) -> Result<i64> {
        Err(Error::NotSupport)
    }

    fn filter_signal_and_write(&self, _task: &Task, _to_fd: i32, _s: &[u8], _cid: &str, _pid: i32) -> Result<()> {
        Err(Error::NotSupport)
    }
    
    fn write_buf(&self, _task: &Task, _to: i32, _buf: &[u8]) -> Result<i64> {
        Err(Error::NotSupport)
    }

    fn get_signal(&self, _c: u8) -> Option<i32> {
        None
    }

    fn read_from_fifo(&self, _host_fd: i32, _task: &Task, _buf: &mut DataBuff, _count: usize) -> Result<i64> {
        Err(Error::NotSupport)
    }

    fn write_to_tty (&self, _host_fd: i32, _task: &Task, _src_buf: &mut DataBuff, _count: usize) -> Result<i64> {
        Err(Error::NotSupport)
    }
}







