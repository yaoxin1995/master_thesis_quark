use alloc::slice;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use spin::{Mutex, MutexGuard};
use std::{env, mem, ptr, thread, time};

use super::qlib::rdma_share::*;
use super::qlib::unix_socket::UnixSocket;
use super::qlib::rdma_svc_cli::*;

impl RDMASvcClient {
    pub fn New(
        srvEventFd: i32,
        srvMemFd: i32,
        cliEventFd: i32,
        cliMemFd: i32,
        agentId: u32,
        cliSock: UnixSocket,
    ) -> Self {
        let cliShareSize = mem::size_of::<ClientShareRegion>();
        let cliShareAddr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                cliShareSize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                cliMemFd,
                0,
            )
        };
        let cliShareRegion = unsafe { &mut (*(cliShareAddr as *mut ClientShareRegion)) };

        let cliShareRegion = Mutex::new(cliShareRegion);

        let srvShareSize = mem::size_of::<ShareRegion>();
        let srvShareAddr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                srvShareSize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                srvMemFd,
                0,
            )
        };
        let srvShareRegion = unsafe { &mut (*(srvShareAddr as *mut ShareRegion)) };
        let srvShareRegion = Mutex::new(srvShareRegion);
        RDMASvcClient {
            intern: Arc::new(RDMASvcCliIntern {
                agentId,
                cliSock,
                cliMemFd,
                srvMemFd,
                srvEventFd,
                cliEventFd,
                cliMemRegion: MemRegion {
                    addr: cliShareAddr as u64,
                    len: cliShareSize as u64,
                },
                cliShareRegion,
                srvMemRegion: MemRegion {
                    addr: srvShareAddr as u64,
                    len: srvShareSize as u64,
                },
                srvShareRegion,
            }),
        }
    }

    // pub fn init(path: &str) -> RDMASvcClient {
    //     let cli_sock = UnixSocket::NewClient(path).unwrap();

    //     let body = 1;
    //     let ptr = &body as *const _ as *const u8;
    //     let buf = unsafe { slice::from_raw_parts(ptr, 4) };
    //     cli_sock.WriteWithFds(buf, &[]).unwrap();

    //     let mut body = [0, 0];
    //     let ptr = &mut body as *mut _ as *mut u8;
    //     let buf = unsafe { slice::from_raw_parts_mut(ptr, 8) };
    //     let (size, fds) = cli_sock.ReadWithFds(buf).unwrap();
    //     if body[0] == 123 {
    //         println!("size: {}, fds: {:?}, agentId: {}", size, fds, body[1]);
    //     }

    //     let rdmaSvcCli = RDMASvcClient::New(fds[0], fds[1], fds[2], fds[3], body[1], cli_sock);
    //     rdmaSvcCli
    // }

    pub fn initialize(path: &str) -> Self {
        let cli_sock = UnixSocket::NewClient(path).unwrap();

        let body = 1;
        let ptr = &body as *const _ as *const u8;
        let buf = unsafe { slice::from_raw_parts(ptr, 4) };
        cli_sock.WriteWithFds(buf, &[]).unwrap();

        let mut body = [0, 0];
        let ptr = &mut body as *mut _ as *mut u8;
        let buf = unsafe { slice::from_raw_parts_mut(ptr, 8) };
        let (_size, fds) = cli_sock.ReadWithFds(buf).unwrap();

        let rdmaSvcCli = RDMASvcClient::New(fds[0], fds[1], fds[2], fds[3], body[1], cli_sock);
        rdmaSvcCli
    }

    pub fn wakeupSvc(&self) {
        let data = 16u64;
        let ret = unsafe {
            libc::write(
                self.srvEventFd,
                &data as *const _ as *const libc::c_void,
                mem::size_of_val(&data) as usize,
            )
        };
        // println!("ret: {}", ret);
        if ret < 0 {
            println!("error: {}", std::io::Error::last_os_error());
        }
    }
}
