use crate::authorized;
use crate::error::{WebError, WebErrorKind};
use crate::forms::device::DevicePacketTransmitRequest;
use crate::handlers::utilities::is_htmx;
use crate::templates::probe::ProbeDetailTemplate;
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, web};
use edumdns_core::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::error::CoreError;
use edumdns_db::models::{Device, Group};
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Permission};
use edumdns_db::repositories::device::models::{CreatePacketTransmitRequest, DeviceDisplay};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::models::SelectManyGroups;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::probe::models::ProbeDisplay;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use ipnetwork::IpNetwork;
use log::warn;
use std::collections::HashSet;
use strum::IntoEnumIterator;
use tokio::sync::mpsc::Sender;

pub fn get_template_name(request: &HttpRequest, path: &str) -> String {
    if is_htmx(request) {
        format!("{path}/content.html")
    } else {
        format!("{path}/page.html")
    }
}

pub fn parse_user_id(identity: &Identity) -> Result<Id, WebError> {
    Ok(identity.id()?.parse::<i64>()?)
}

pub async fn request_packet_transmit_helper(
    device_repo: web::Data<PgDeviceRepository>,
    device: &Device,
    command_channel: Sender<AppPacket>,
    form: &DevicePacketTransmitRequest,
) -> Result<(), WebError> {
    let packet = PacketTransmitRequestPacket::new(
        device.probe_id,
        device.mac,
        device.ip,
        &form.target_ip,
        form.target_port,
    );

    let request = CreatePacketTransmitRequest {
        device_id: device.id,
        target_ip: form
            .target_ip
            .parse::<IpNetwork>()
            .map_err(CoreError::from)?,
        target_port: form.target_port as i32,
        permanent: form.permanent,
    };

    let packet_transmit_request = match device_repo.create(&request).await {
        Ok(p) => p,
        Err(_) => {
            return Err(WebError::new(
                WebErrorKind::BadRequest,
                "Transmission already in progress to a different client, please try again later.",
            ));
        }
    };
    let command_channel_local = command_channel.clone();
    let packet_local = packet.clone();
    let device_duration = device.duration as u64;
    if !form.permanent {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(device_duration)).await;
            if let Err(e) = device_repo
                .delete_packet_transmit_request(&packet_transmit_request.id)
                .await
            {
                warn!(
                    "Could not delete packet transmit request {:?}: {}",
                    request,
                    WebError::from(e)
                );
            }

            command_channel_local
                .send(AppPacket::Local(LocalAppPacket::Command(
                    LocalCommandPacket::StopTransmitDevicePackets(packet_local),
                )))
                .await
        });
    }

    command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::TransmitDevicePackets(packet),
        )))
        .await
        .map_err(CoreError::from)?;
    Ok(())
}

pub async fn reconnect_probe(
    command_channel: Sender<AppPacket>,
    probe_id: uuid::Uuid,
) -> Result<(), WebError> {
    command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::ReconnectProbe(Uuid(probe_id)),
        )))
        .await
        .map_err(CoreError::from)?;
    Ok(())
}

pub async fn get_probe_helper(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(uuid::Uuid,)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let probe_id = path.0;

    let probe = probe_repo
        .read_one_auth(&probe_id, &parse_user_id(&i)?)
        .await?;

    let granted: HashSet<(Id, Permission)> = probe_repo
        .get_permissions(&probe_id)
        .await?
        .iter()
        .map(|x| (x.group_id, x.permission))
        .collect();

    let matrix = group_repo
        .read_many(&SelectManyGroups::new(None, None))
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

    let template_name = get_template_name(&request, "probe/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeDetailTemplate {
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
        permissions: probe.permissions,
        permission_matrix: matrix,
        probe: ProbeDisplay::from(probe.data.0),
        devices: probe.data.1.into_iter().map(DeviceDisplay::from).collect(),
        configs: probe.data.2,
        admin: probe.admin,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
