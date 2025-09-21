use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;
use edumdns_core::bincode_types::Uuid;
use crate::listen::ProbeHandles;
use crate::ordered_map::OrderedMap;

pub type SharedProbeLastSeen = Arc<RwLock<OrderedMap<Uuid, ProbeTracker>>>;

#[derive(Eq, PartialEq)]
pub struct ProbeTracker {
    pub id: Uuid,
    pub last_seen: Instant,
}

impl Ord for ProbeTracker {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
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

pub async fn watchdog(tracker: SharedProbeLastSeen, probe_handles: ProbeHandles, max_age: Duration) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let mut tracker = tracker.write().await;
        let now = Instant::now();

        while let Some(last) = tracker.get_last() {
            if now.duration_since(last.last_seen) > max_age {
                let id = last.id;
                tracker.ord.remove(&last);
                tracker.map.remove(&id);
                probe_handles.write().await.remove(&id);
                println!("Probe {id} considered dead");
            } else {
                break;
            }
        }
    }
}