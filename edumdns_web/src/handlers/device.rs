use crate::error::WebError;
use crate::forms::device::{DevicePacketTransmitRequest, DeviceQuery};
use crate::forms::packet::PacketQuery;
use crate::handlers::helpers::{get_template_name, parse_user_id};
use crate::templates::device::{DeviceDetailTemplate, DeviceTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, get, post, web, delete};
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitRequestPacket};
use edumdns_core::error::CoreError;
use edumdns_db::models::PacketTransmitRequest;
use edumdns_db::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, SelectSingleById, Id, Pagination};
use edumdns_db::repositories::device::models::{CreatePacketTransmitRequest, DeviceDisplay, SelectManyDevices};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use ipnetwork::IpNetwork;
use log::{error, warn};
use edumdns_db::repositories::probe::models::SelectSingleProbe;
use crate::authorized;

#[get("")]
pub async fn get_devices(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    query: web::Query<DeviceQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let devices = device_repo
        .read_many(&SelectManyDevices::new(
            parse_user_id(&i)?,
            query.probe_id,
            query.mac,
            query.ip,
            query.port,
            Some(Pagination::default_pagination(query.page)),
        ))
        .await?
        .into_iter()
        .map(|(p, d)| (p, DeviceDisplay::from(d)))
        .collect();

    let template_name = get_template_name(&request, "device");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceTemplate {
        logged_in: true,
        devices,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    packet_repo: web::Data<PgPacketRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    query: web::Query<PacketQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let params = SelectSingleById::new(parse_user_id(&i)?, path.0);
    let device = device_repo.read_one(&params).await?;

    let packets = packet_repo
        .read_many(&SelectManyPackets::new(
            Some(device.probe_id),
            Some(device.mac),
            None,
            Some(device.ip),
            None,
            None,
            None,
            Some(Pagination::default_pagination(query.page)),
        ))
        .await?
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect();

    let packet_transmit_requests = device_repo.read_packet_transmit_requests(&device.id).await?;

    let template_name = get_template_name(&request, "device/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceDetailTemplate {
        logged_in: true,
        device: DeviceDisplay::from(device),
        packets,
        packet_transmit_requests,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("{id}/transmit")]
pub async fn request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    form: web::Form<DevicePacketTransmitRequest>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let params = SelectSingleById::new(parse_user_id(&i)?, path.0);
    let device = device_repo.read_one(&params).await?;

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

    let packet_transmit_request = device_repo.create(&request).await?;
    if !form.permanent {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(
                device.duration as u64,
            ))
                .await;
            if let Err(e) = device_repo.delete_packet_transmit_request(&packet_transmit_request.id).await {
                warn!(
                    "Could not delete packet transmit request {:?}: {}",
                    request,
                    WebError::from(e)
                );
            }
        });
    }

    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
            packet,
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device.id)))
        .finish())
}


#[delete("{device_id}/transmit/{request_id}")]
pub async fn delete_request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,Id)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let device_id = path.0;
    let request_id = path.1;
    let i = authorized!(identity, request.path());
    let params = SelectSingleById::new(parse_user_id(&i)?, path.0);
    let device = device_repo.read_one(&params).await?;


    let request = device_repo.delete_packet_transmit_request(&request_id).await?;

    let Some(r) = request.first() else {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, format!("/device/{}", device_id)))
            .finish())
    };

    let packet = PacketTransmitRequestPacket::new(
        device.probe_id,
        device.mac,
        device.ip,
        &r.target_ip.ip().to_string(),
        r.target_port as u16,
    );

    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::StopTransmitDevicePackets(
            packet,
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}


// #[get("{id}/transmit")]
// pub async fn device_request_packet_transmit_auto(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     device_repo: web::Data<PgDeviceRepository>,
//     path: web::Path<(Id,)>,
//     state: web::Data<AppState>,
// ) -> Result<HttpResponse, WebError> {
//     let device_id = path.into_inner().0;
//     let device = device_repo.read_one(&device_id).await?;
//
//     let target_ip = request.peer_addr();
//
//
//     let packet = PacketTransmitRequestPacket::new(
//         device.probe_id,
//         device.mac,
//         device.ip,
//         &form.target_ip,
//         form.target_port,
//     );
//
//     let request = PacketTransmitRequest {
//         device_id: device.id,
//         target_ip: form
//             .target_ip
//             .parse::<IpNetwork>()
//             .map_err(CoreError::from)?,
//         target_port: form.target_port as i32,
//     };
//
//     device_repo.create(&request).await?;
//     if !form.permanent {
//         tokio::spawn(async move {
//             tokio::time::sleep(std::time::Duration::from_secs(
//                 device.duration.unwrap_or(DEFAULT_PACKET_TRANSMIT_DURATION) as u64,
//             ))
//                 .await;
//             if let Err(e) = device_repo.delete_packet_transmit_request(&device_id).await {
//                 error!(
//                     "Could not delete packet transmit request {:?}: {}",
//                     request,
//                     WebError::from(e)
//                 );
//             }
//         });
//     }
//
//     state
//         .command_channel
//         .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
//             packet,
//         )))
//         .await
//         .map_err(CoreError::from)?;
//
//     Ok(HttpResponse::SeeOther()
//         .insert_header((LOCATION, format!("/device/{}", device_id)))
//         .finish())
// }