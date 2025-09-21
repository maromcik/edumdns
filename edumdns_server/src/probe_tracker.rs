use crate::listen::ProbeHandles;
use crate::ordered_map::OrderedMap;
use edumdns_core::bincode_types::Uuid;
use log::{debug, error, info, trace, warn};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

pub type SharedProbeLastSeen = Arc<RwLock<OrderedMap<Uuid, ProbeTracker>>>;

#[derive(Debug)]
pub struct ProbeTracker {
    pub id: Uuid,
    pub last_seen: Instant,
}

impl Eq for ProbeTracker {}

impl PartialEq for ProbeTracker {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Hash for ProbeTracker {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Ord for ProbeTracker {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.id == other.id {
            return std::cmp::Ordering::Equal;
        }
        self.last_seen.cmp(&other.last_seen)
    }
}

impl PartialOrd for ProbeTracker {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ProbeTracker {
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            last_seen: Instant::now(),
        }
    }
}

pub async fn watchdog(
    tracker: SharedProbeLastSeen,
    probe_handles: ProbeHandles,
    max_age: Duration,
) {
    loop {
        tokio::time::sleep(max_age).await;
        trace!("Checking for dead probes");
        let mut tracker = tracker.write().await;
        let now = Instant::now();
        while let Some(first) = tracker.get_first() {
            if now.duration_since(first.last_seen) > max_age {
                let id = first.id;
                tracker.ord.remove(&first);
                tracker.map.remove(&id);
                if let Some(handle) = probe_handles.read().await.get(&id) {
                    let _ = handle.close().await;
                }
                probe_handles.write().await.remove(&id);
                info!("Probe {id} considered dead, older than {:?}", max_age);
            } else {
                break;
            }
        }
        trace!("Done checking for dead probes");
    }
}
