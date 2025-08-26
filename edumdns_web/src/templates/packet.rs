use edumdns_db::repositories::packet::models::PacketDisplay;
use serde::Serialize;

#[derive(Serialize)]
pub struct PacketTemplate<'a> {
    pub logged_in: bool,
    pub packets: &'a Vec<PacketDisplay>,
}

#[derive(Serialize)]
pub struct PacketDetailTemplate<'a> {
    pub logged_in: bool,
    pub packet: &'a PacketDisplay,
}
