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
    }

    pub fn addInoteToTrack(&mut self, _key: u64, _value: TrackInodeType) -> (){
    }

    pub fn rmInoteToTrack(&mut self, _key: u64) -> (){
    }

    pub fn isInodeExist(&self, _key: &u64) -> bool {
        false
    }

    pub fn getInodeType (&self, _key: &u64) -> TrackInodeType{
        TrackInodeType::default()
    }
}
