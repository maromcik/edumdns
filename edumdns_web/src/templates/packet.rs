use crate::forms::packet::PacketQuery;
use crate::templates::PageInfo;
use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{Id, Permissions};
use edumdns_db::repositories::packet::models::PacketDisplay;
use edumdns_db::repositories::user::models::UserDisplay;
use ipnetwork::IpNetwork;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct PacketTemplate<'a> {
    pub user: UserDisplay,
    pub permissions: Permissions,
    pub packets: &'a Vec<PacketDisplay>,
    pub page_info: PageInfo,
    pub filters: PacketQuery,
    pub query_string: String,
}

#[derive(Serialize)]
pub struct PacketDetailTemplate<'a> {
    pub user: UserDisplay,
    pub permissions: Permissions,
    pub packet: &'a PacketDisplay,
    pub device_id: Id,
}

#[derive(Serialize)]
pub struct PacketCreateTemplate {
    pub user: UserDisplay,
    pub probe_id: Uuid,
    pub mac: MacAddr,
    pub ip: IpNetwork,
    pub port: u16,
}
