//! Helper functions for request handlers.
//!
//! This module provides utility functions used across multiple handlers:
//! - Packet transmission request authorization and validation
//! - ACL (Access Control List) verification for device access
//! - Probe reconnection coordination
//!
//! These helpers encapsulate complex business logic for device access control,
//! including CIDR-based IP filtering, password authentication, and AP hostname
//! verification through external databases.

use crate::config::ExternalAuthDatabase;
use crate::error::WebError;
use crate::forms::device::{
    DeviceCustomPacketTransmitRequest, DevicePacketTransmitRequest, DeviceQuery,
};
use crate::handlers::utilities::{get_template_name, verify_transmit_request_client_ap};
use crate::templates::PageInfo;
use crate::templates::probe::ProbeDetailTemplate;
use crate::utils::AppState;
use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, web};
use edumdns_core::app_packet::Id;
use edumdns_core::bincode_types::Uuid;
use edumdns_core::error::CoreError;
use edumdns_db::error::DbError;
use edumdns_db::models::{Device, Group};
use edumdns_db::repositories::common::{
    DbReadOne, PAGINATION_ELEMENTS_PER_PAGE, Pagination, Permission,
};
use edumdns_db::repositories::device::models::{
    CreatePacketTransmitRequest, DeviceDisplay, SelectManyDevices,
};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::models::SelectManyGroups;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::probe::models::ProbeDisplay;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use edumdns_db::repositories::user::models::UserDisplay;
use edumdns_server::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use strum::IntoEnumIterator;
use time::OffsetDateTime;
use tokio::sync::mpsc::Sender;

/// Creates and initiates a packet transmission request for a device.
///
/// This function validates that a transmission request can be created (checking for
/// exclusive/proxy device conflicts), creates the request in the database, and sends
/// a command to the server to start transmission. If transmission fails, it cleans
/// up the database record.
///
/// # Arguments
///
/// * `device_repo` - Device repository for database operations
/// * `device` - The device to transmit packets for
/// * `user_id` - ID of the user making the request
/// * `command_channel` - Channel for sending commands to the server
/// * `form` - Form data containing transmission parameters (target IP, port, permanent flag)
///
/// # Returns
///
/// Returns `Ok(())` if transmission is successfully initiated, or a `WebError` if:
/// - Device has an ongoing exclusive/proxy transmission
/// - Database operation fails
/// - Server command fails
/// - Duplicate request exists (unique constraint violation)
pub async fn request_packet_transmit_helper(
    device_repo: web::Data<PgDeviceRepository>,
    device: Device,
    user_id: &Id,
    command_channel: Sender<AppPacket>,
    form: &DeviceCustomPacketTransmitRequest,
) -> Result<(), WebError> {
    let ongoing = device_repo
        .read_packet_transmit_requests_by_device(&device.id)
        .await?;
    if (device.proxy || device.exclusive) && !ongoing.is_empty() {
        return Err(WebError::DeviceTransmitRequestDenied(
            "Discovery already in progress to another client, please try again later.".to_string(),
        ));
    }
    let request_db = CreatePacketTransmitRequest {
        device_id: device.id,
        user_id: *user_id,
        target_ip: form.target_ip,
        target_port: form.target_port as i32,
        permanent: form.permanent,
        created_at: (!form.permanent).then_some(OffsetDateTime::now_utc()),
    };

    let request = match device_repo
        .create_packet_transmit_request(&request_db)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            return if let DbError::UniqueConstraintError(_) = e {
                Err(WebError::DeviceTransmitRequestDenied(
                    "The combination of device and target IP/port is already in use. Please try again later or delete existing packet transmissions."
                        .to_string(),
                ))
            } else {
                Err(e.into())
            };
        }
    };
    let request_id = request.id;
    let request = PacketTransmitRequestPacket::new(device, request);

    let channel = tokio::sync::oneshot::channel();
    command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::TransmitDevicePackets {
                request,
                respond_to: channel.0,
            },
        )))
        .await
        .map_err(CoreError::from)?;

    let res = channel.1.await.map_err(CoreError::from)?;
    if res.is_err() {
        device_repo
            .delete_packet_transmit_request(&request_id)
            .await?;
    }
    res?;
    Ok(())
}

pub async fn reconnect_probe(
    command_channel: Sender<AppPacket>,
    probe_id: uuid::Uuid,
    session: Session,
) -> Result<(), WebError> {
    let uuid = session.get::<uuid::Uuid>("session_id")?.map(Uuid);
    command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::ReconnectProbe(Uuid(probe_id), uuid),
        )))
        .await
        .map_err(CoreError::from)?;
    Ok(())
}

/// Authorizes a packet transmission request by validating ACL rules.
///
/// This function performs multiple authorization checks before allowing a packet
/// transmission request:
/// 1. Extracts the client's IP address from the request
/// 2. Validates the IP is within the device's allowed CIDR range (if configured)
/// 3. Validates the ACL password (if configured)
/// 4. Verifies the client's access point hostname matches the regex (if configured)
///
/// # Arguments
///
/// * `request` - HTTP request containing client connection information
/// * `device` - Device to authorize access for
/// * `form` - Form data potentially containing ACL password
/// * `device_acl_ap_database` - Configuration for AP hostname verification database
///
/// # Returns
///
/// Returns `Ok(IpNetwork)` with the validated target IP if all checks pass, or a
/// `WebError` if:
/// - Client IP cannot be determined
/// - IP is not in the allowed CIDR range
/// - ACL password is missing or incorrect
/// - AP hostname does not match the required regex pattern
pub async fn authorize_packet_transmit_request(
    request: &HttpRequest,
    device: &Device,
    form: &DevicePacketTransmitRequest,
    device_acl_ap_database: &Option<ExternalAuthDatabase>,
) -> Result<IpNetwork, WebError> {
    let target_ip = request
        .connection_info()
        .realip_remote_addr()
        .map(|a| a.to_string());
    let target_ip = target_ip.ok_or(WebError::InternalServerError(
        "Could not determine target ip".to_string(),
    ))?;

    let target_ip = target_ip.parse::<IpNetwork>()?;

    if let Some(acl_src_cidr) = device.acl_src_cidr
        && !acl_src_cidr.contains(target_ip.ip())
    {
        return Err(WebError::DeviceTransmitRequestDenied(format!(
            "Target IP is not allowed to request packets from this device. Allowed subnet is {acl_src_cidr}"
        )));
    }

    if let Some(acl_pwd_hash) = &device.acl_pwd_hash {
        let Some(pwd) = &form.acl_pwd else {
            return Err(WebError::Unauthorized(
                "ACL password is required to request packets from this device".to_string(),
            ));
        };
        if acl_pwd_hash != pwd {
            return Err(WebError::Unauthorized(
                "ACL password is incorrect".to_string(),
            ));
        }
    }

    if let Some(acl_ap_hostname_regex) = &device.acl_ap_hostname_regex
        && !verify_transmit_request_client_ap(
            device_acl_ap_database,
            acl_ap_hostname_regex,
            target_ip.ip().to_string().as_str(),
        )
        .await?
    {
        return Err(WebError::DeviceTransmitRequestDenied(
            "AP hostname that you are connected to does not match allowed APs".to_string(),
        ));
    }
    Ok(target_ip)
}

pub async fn get_probe_content(
    request: HttpRequest,
    probe_repo: web::Data<PgProbeRepository>,
    group_repo: web::Data<PgGroupRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    user: UserDisplay,
    probe_id: uuid::Uuid,
    query: web::Query<DeviceQuery>,
) -> Result<HttpResponse, WebError> {
    let page = query.page.unwrap_or(1);
    let probe = probe_repo.read_one_auth(&probe_id, &user.user.id).await?;

    let granted: HashSet<(Id, Permission)> = probe_repo
        .get_permissions(&probe_id)
        .await?
        .iter()
        .map(|x| (x.group_id, x.permission))
        .collect();

    let matrix = group_repo
        .read_many(&SelectManyGroups::new(
            None,
            None,
            Some(Pagination::default_pagination(query.page)),
        ))
        .await?
        .into_iter()
        .map(|g| {
            (
                {
                    Permission::iter()
                        .map(|p| (p, granted.contains(&(g.id, p))))
                        .collect::<Vec<(Permission, bool)>>()
                },
                g,
            )
        })
        .collect::<Vec<(Vec<(Permission, bool)>, Group)>>();

    let query = query.into_inner();
    let mut params = SelectManyDevices::from(query.clone());
    params.probe_id = Some(probe_id);
    let devices = device_repo.read_many(&params).await?;
    let device_count = device_repo.get_device_count(params, &user.user.id).await?;
    let total_pages = (device_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;

    let template_name = get_template_name(&request, "probe/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(ProbeDetailTemplate {
        user,
        permissions: probe.permissions,
        permission_matrix: matrix,
        probe: ProbeDisplay::from(probe.data.0),
        devices: devices.into_iter().map(DeviceDisplay::from).collect(),
        configs: probe.data.1,
        page_info: PageInfo::new(page, total_pages),
        filters: query,
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
