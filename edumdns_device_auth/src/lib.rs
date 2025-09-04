use edumdns_db::models::Device;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

pub trait DeviceAuth {
    type AuthData;

    fn auth(&self, data: Self::AuthData) -> bool;
}

pub struct DeviceAuthByCidr {
    device: Device,
    cidr: IpNetwork,
    pass: String,
}

impl DeviceAuth for DeviceAuthByCidr {
    type AuthData = IpNetwork;

    fn auth(&self, data: Self::AuthData) -> bool {
        self.device.acl_src_cidr.is_none()
            || self
                .device
                .acl_src_cidr
                .is_some_and(|net| net.contains(data.ip()))
    }
}
