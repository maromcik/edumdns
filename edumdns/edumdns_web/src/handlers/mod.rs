use edumdns_core::app_packet::Id;
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use actix_csrf::extractor::CsrfToken;
use serde::de::Error;

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
            .iter()
            .filter_map(|(k, v)| if k == "entity_ids[]" { Some(v) } else { None })
            .filter_map(|id| id.parse::<Id>().ok())
            .collect::<HashSet<Id>>();
        // let csrf_token = pairs.iter().find_map(|(k, v)| { if k == "csrf_token" { Some(v.clone()) } else { None } }).ok_or(D::Error::missing_field("csrf_token"))?;
        Ok(BulkAddEntityForm {
            entity_ids: Vec::from_iter(ids),
        })
    }
}

#[derive(serde::Deserialize)]
pub struct SearchEntityQuery {
    pub q: String,
}
