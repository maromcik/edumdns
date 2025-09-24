use crate::forms::packet::PacketQuery;
use crate::templates::PageInfo;
use edumdns_db::repositories::common::{Id, Permissions};
use edumdns_db::repositories::packet::models::PacketDisplay;
use serde::Serialize;

#[derive(Serialize)]
pub struct PacketTemplate<'a> {
    pub logged_in: bool,
    pub is_admin: bool,
    pub has_groups: bool,
    pub permissions: Permissions,
    pub packets: &'a Vec<PacketDisplay>,
    pub page_info: PageInfo,
    pub filters: PacketQuery,
    pub query_string: String,
}

#[derive(Serialize)]
pub struct PacketDetailTemplate<'a> {
    pub logged_in: bool,
    pub is_admin: bool,
    pub has_groups: bool,
    pub permissions: Permissions,
    pub packet: &'a PacketDisplay,
    pub device_id: Id,
}
