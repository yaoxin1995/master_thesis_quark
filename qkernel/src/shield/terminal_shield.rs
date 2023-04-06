use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use spin::rwlock::RwLock;
use crate::aes_gcm::{
    aead::{generic_array::{GenericArray, typenum::U32}},
};
use qlib::control_msg::*;
use qlib::common::*;
use qlib::shield_policy::*;
use qlib::linux_def::*;
use qlib::kernel::task::*;
use qlib::kernel::{SHARESPACE, IOURING, fd::*, boot::controller::HandleSignal};

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

    pub fn init(&mut self, _policy: &Policy, key: &GenericArray<u8, U32>) -> () {
    
       // self.key = policy.unwrap().secret.file_encryption_key.as_bytes().to_vec();
        self.key = key.clone();
    }

}




impl TermianlIoShiled for TerminalShield {

    fn termianlIoEncryption(&self, src: &[IoVec], task: &Task) -> Result<(usize, Option<Vec::<IoVec>>)>{
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







