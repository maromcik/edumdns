use edumdns_core::app_packet::Id;
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;

pub mod device;
pub mod group;
pub mod helpers;
pub mod index;
pub mod packet;
pub mod probe;
pub mod user;
pub mod utilities;

#[derive(Debug)]
pub struct BulkAddEntityForm {
    pub entity_ids: Vec<Id>,
}
impl<'de> Deserialize<'de> for BulkAddEntityForm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pairs = Vec::<(String, String)>::deserialize(deserializer)?;
        let ids = pairs
            .into_iter()
            .filter_map(|(k, v)| if k == "entity_ids[]" { Some(v) } else { None })
            .filter_map(|id| id.parse::<Id>().ok())
            .collect::<HashSet<Id>>();
        Ok(BulkAddEntityForm {
            entity_ids: Vec::from_iter(ids),
        })
    }
}

#[derive(serde::Deserialize)]
pub struct SearchEntityQuery {
    pub q: String,
}
