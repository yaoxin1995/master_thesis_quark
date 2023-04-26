use alloc::collections::btree_map::BTreeMap;
use spin::rwlock::RwLock;
use crate::qlib::shield_policy::*;


lazy_static! {
    pub static ref INODE_TRACKER:  RwLock<InodeTracker> = RwLock::new(InodeTracker::default());
}


#[derive(Debug, Default)]
pub struct InodeTracker {
    inode_track: BTreeMap<u64, TrackInodeType>,
}

impl InodeTracker {

    pub fn init(&mut self) -> () {
        self.inode_track= BTreeMap::new();
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
        debug!("isInodeExist, key{:?} , exist{:?}", key ,self.inode_track.contains_key(key));
        self.inode_track.contains_key(key)
    }

    pub fn getInodeType (&self, key: &u64) -> TrackInodeType{
        
        let res =  self.inode_track.get(key).unwrap().clone();
        res
    }
}
