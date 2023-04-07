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
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::any::Any;
use core::ops::Deref;

use super::super::super::super::auth::*;
use super::super::super::super::common::*;
use super::super::super::super::linux_def::*;
use super::super::super::fs::dentry::*;
use super::super::super::fs::fsutil::file::*;
use super::super::super::kernel::kernel::*;
use super::super::super::kernel::waiter::*;
use super::super::super::task::*;
use super::super::super::threadmgr::pid_namespace::*;
use super::super::attr::*;
use super::super::dirent::*;
use super::super::file::*;
use super::super::flags::*;
use super::super::host::hostinodeop::*;
use super::super::inode::*;
use super::super::mount::*;
use super::super::ramfs::dir::*;
use super::dir_proc::*;
use super::inode::*;

use crate::shield::secret_injection::SECRET_KEEPER;
use super::secretinfo::*;


pub struct ProcNodeInternal {
    pub kernel: Kernel,
    pub pidns: PIDNamespace,
    pub cgroupControllers: Arc<QMutex<BTreeMap<String, String>>>,
}

#[derive(Clone)]
pub struct ProcNode(Arc<QMutex<ProcNodeInternal>>);

impl Deref for ProcNode {
    type Target = Arc<QMutex<ProcNodeInternal>>;

    fn deref(&self) -> &Arc<QMutex<ProcNodeInternal>> {
        &self.0
    }
}

impl SecretDirDataNodeTrait for ProcNode {
    fn Lookup(&self, d: &Dir, task: &Task, dir: &Inode, name: &str) -> Result<Dirent> {
        match d.Lookup(task, dir, name) {
            Ok(dirent) => {
                info!("SecretDirDataNodeTrait lookup {}", dirent.Name());
                return Ok(dirent);
            },
            Err(e) => {
                info!("SecretDirDataNodeTrait lookup get err {:?}", e);
                return Err(e);
            },
        };

    }

    fn GetFile(
        &self,
        d: &Dir,
        _task: &Task,
        _dir: &Inode,
        dirent: &Dirent,
        flags: FileFlags,
    ) -> Result<File> {
        let p = SecDirNode {
            dir: d.clone(),
            data: self.clone().into(),
        };

        info!("SecretDirDataNodeTrait GetFile  name {:?}", dirent.Name());

        return Ok(File::New(dirent, &flags, SecretFile { iops: p }.into()));
    }
}

pub fn NewSecret(
    task: &Task,
    msrc: &Arc<QMutex<MountSource>>,
    cgroupControllers: BTreeMap<String, String>,
) -> Inode {
    let mut contents = BTreeMap::new();

    info!("new secret");

    {
        let secret_keeper = SECRET_KEEPER.read();
        for (file_name, content) in secret_keeper.file_secrets.iter() {
            let inode = NewSecinfo(task, msrc, content.len() as i64);
            info!("NewSecret insert file  {:?} with inode id {:?} to secret file system, file len {:?}", file_name, inode.ID(), content.len());
            contents.insert(file_name.clone(), inode);
        }
    }


    let iops = Dir::New(
        task,
        contents,
        &ROOT_OWNER,
        &FilePermissions::FromMode(FileMode(0o0555)),
    );
    let kernel = GetKernel();
    let pidns = kernel.RootPIDNamespace();

    let proc = ProcNodeInternal {
        kernel: kernel,
        pidns: pidns,
        cgroupControllers: Arc::new(QMutex::new(cgroupControllers)),
    };

    let p = SecDirNode {
        dir: iops,
        data: ProcNode(Arc::new(QMutex::new(proc))).into(),
    };

    return NewSecretInode(p.into(), msrc, InodeType::SpecialDirectory, None);
}


#[derive(Clone)]
pub struct SecretFile {
    pub iops: SecDirNode,
}

impl Waitable for SecretFile {}

impl SpliceOperations for SecretFile {}

impl FileOperations for SecretFile {
    fn as_any(&self) -> &Any {
        return self;
    }

    fn FopsType(&self) -> FileOpsType {
        return FileOpsType::RootProcFile;
    }

    fn Seekable(&self) -> bool {
        return true;
    }

    fn Seek(&self, task: &Task, f: &File, whence: i32, current: i64, offset: i64) -> Result<i64> {
        info!("SecretFile seek whence {:?}, current: {:?}, offset {:?}", whence, current, offset);
        return SeekWithDirCursor(task, f, whence, current, offset, None);
    }

    fn ReadAt(
        &self,
        _task: &Task,
        _f: &File,
        _dsts: &mut [IoVec],
        _offset: i64,
        _blocking: bool,
    ) -> Result<i64> {
        return Err(Error::SysError(SysErr::ENOSYS));
    }

    fn WriteAt(
        &self,
        _task: &Task,
        _f: &File,
        _srcs: &[IoVec],
        _offset: i64,
        _blocking: bool,
    ) -> Result<i64> {
        return Err(Error::SysError(SysErr::ENOSYS));
    }

    fn Append(&self, _task: &Task, _f: &File, _srcs: &[IoVec]) -> Result<(i64, i64)> {
        return Err(Error::SysError(SysErr::ENOSYS));
    }

    fn Fsync(
        &self,
        _task: &Task,
        _f: &File,
        _start: i64,
        _end: i64,
        _syncType: SyncType,
    ) -> Result<()> {
        return Ok(());
    }

    fn Flush(&self, _task: &Task, _f: &File) -> Result<()> {
        return Ok(());
    }

    fn Ioctl(&self, _task: &Task, _f: &File, _fd: i32, _request: u64, _val: u64) -> Result<u64> {
        return Err(Error::SysError(SysErr::ENOTTY));
    }

    fn UnstableAttr(&self, task: &Task, f: &File) -> Result<UnstableAttr> {
        info!("FileOperations for SecretFile unstablattr");
        let inode = f.Dirent.Inode().clone();
        return inode.UnstableAttr(task);
    }

    fn Mappable(&self) -> Result<MMappable> {
        return Err(Error::SysError(SysErr::ENODEV));
    }

    fn ReadDir(
        &self,
        task: &Task,
        _f: &File,
        offset: i64,
        serializer: &mut DentrySerializer,
    ) -> Result<i64> {
        let mut dirCtx = DirCtx {
            Serializer: serializer,
            DirCursor: "".to_string(),
        };

        // Get normal directory contents from ramfs dir.
        let mut map = self.iops.dir.Children();

        let root = task.Root();

        let (dot, dotdot) = root.GetDotAttrs(&root);
        map.insert(".".to_string(), dot);
        map.insert("..".to_string(), dotdot);

        if offset > map.len() as i64 {
            return Ok(offset);
        }

        let mut cnt = 0;
        for (name, entry) in &map {
            if cnt >= offset {
                dirCtx.DirEmit(task, name, entry)?
            }

            cnt += 1;
        }

        return Ok(map.len() as i64);
    }

    fn IterateDir(
        &self,
        _task: &Task,
        _d: &Dirent,
        _dirCtx: &mut DirCtx,
        _offset: i32,
    ) -> (i32, Result<i64>) {
        return (0, Err(Error::SysError(SysErr::ENOTDIR)));
    }
}

impl SockOperations for SecretFile {}
