use ipnetwork::IpNetwork;
use uuid::Uuid;
use edumdns_db::repositories::common::Pagination;

pub struct PacketQuery {
    pub page: i32,
    pub probe_id: Option<Uuid>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_addr: Option<IpNetwork>,
    pub dst_addr: Option<IpNetwork>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub pagination: Option<Pagination>,
}