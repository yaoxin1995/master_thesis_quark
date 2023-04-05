// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::qlib::mutex::*;
use alloc::sync::Arc;
use super::super::super::super::device::*;
use super::super::super::threadmgr::thread::*;
use super::super::attr::*;
use super::super::inode::*;
use super::super::mount::*;




pub fn NewSecretInode(
    iops: Iops,
    msrc: &Arc<QMutex<MountSource>>,
    typ: InodeType,
    _thread: Option<Thread>,
) -> Inode {
    let deviceId = PROC_DEVICE.lock().id.DeviceID();
    let inodeId = PROC_DEVICE.lock().NextIno();

    let sattr = StableAttr {
        Type: typ,
        DeviceId: deviceId,
        InodeId: inodeId,
        BlockSize: 4096,
        DeviceFileMajor: 0,
        DeviceFileMinor: 0,
    };


    return Inode::New(iops, msrc, &sattr);
}
