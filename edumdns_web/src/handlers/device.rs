use crate::authorized;
use crate::error::{WebError, WebErrorKind};
use crate::forms::device::{
    CreateDeviceForm, DeviceCustomPacketTransmitRequest, DevicePacketTransmitRequest, DeviceQuery,
    UpdateDeviceForm,
};
use crate::forms::packet::PacketQuery;
use crate::handlers::helpers::request_packet_transmit_helper;
use crate::handlers::utilities::{
    get_template_name, parse_user_id, validate_has_groups, verify_transmit_request_client_ap,
};
use crate::templates::PageInfo;
use crate::templates::device::{
    DeviceCreateTemplate, DeviceDetailTemplate, DeviceTemplate, DeviceTransmitTemplate,
};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, web};
use edumdns_core::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use edumdns_core::error::CoreError;
use edumdns_db::repositories::common::{
    DbCreate, DbDelete, DbReadMany, DbReadOne, DbUpdate, Id, PAGINATION_ELEMENTS_PER_PAGE,
    Pagination,
};
use edumdns_db::repositories::device::models::{CreateDevice, DeviceDisplay, SelectManyDevices};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use edumdns_db::repositories::utilities::verify_password_hash;
use std::collections::HashMap;
use uuid::Uuid;

#[get("")]
pub async fn get_devices(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    query: web::Query<DeviceQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    validate_has_groups(&user)?;
    let page = query.page.unwrap_or(1);
    let query = query.into_inner();
    let params = SelectManyDevices::from(query.clone());
    let devices = device_repo.read_many_auth(&params, &user_id).await?;
    let devices_parsed = devices
        .data
        .into_iter()
        .map(|(p, d)| (p, DeviceDisplay::from(d)))
        .collect();

    let device_count = device_repo.get_device_count(params).await?;
    let total_pages = (device_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;

    let template_name = get_template_name(&request, "device");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(DeviceTemplate {
        permissions: devices.permissions,
        devices: devices_parsed,
        user,
        page_info: PageInfo::new(page, total_pages),
        filters: query,
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    packet_repo: web::Data<PgPacketRepository>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    query: web::Query<PacketQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let device = device_repo.read_one_auth(&path.0, &user_id).await?;
    let page = query.page.unwrap_or(1);
    let params = SelectManyPackets::new(
        query.id,
        Some(device.data.probe_id),
        Some(device.data.mac),
        query.dst_mac.map(|mac| mac.to_octets()),
        Some(device.data.ip),
        query.dst_addr,
        query.src_port,
        query.dst_port,
        query.payload_string.clone(),
        Some(Pagination::default_pagination(query.page)),
    );
    let packets = packet_repo
        .read_many(&params)
        .await?
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect();

    let packet_transmit_requests = device_repo
        .read_packet_transmit_requests(&device.data.id)
        .await?;

    let packet_count = packet_repo.get_packet_count(params).await?;
    let total_pages = (packet_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let template_name = get_template_name(&request, "device/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceDetailTemplate {
        user,
        permissions: device.permissions,
        device: DeviceDisplay::from(device.data),
        packets,
        packet_transmit_requests,
        page_info: PageInfo::new(page, total_pages),
        filters: query.into_inner(),
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("update")]
pub async fn update_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    form: web::Form<UpdateDeviceForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = form.into_inner().to_db_params()?;
    device_repo
        .update_auth(&params, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", params.id)))
        .finish())
}

#[delete("{id}/delete")]
pub async fn delete_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/device");

    device_repo
        .delete_auth(&path.0, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

#[post("{id}/transmit-custom")]
pub async fn request_custom_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    form: web::Form<DeviceCustomPacketTransmitRequest>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device = device_repo.read_one_auth(&path.0, &user_id).await?;

    request_packet_transmit_helper(
        device_repo.clone(),
        &device.data,
        &user_id,
        state.command_channel.clone(),
        &form,
    )
    .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device.data.id)))
        .finish())
}

#[delete("{device_id}/transmit/{request_id}")]
pub async fn delete_request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id, Id)>,
    state: web::Data<AppState>,
    mut query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let device_id = path.0;
    let request_id = path.1;
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;

    let request = device_repo
        .read_packet_transmit_request_by_user(&device_id, &user_id)
        .await?;

    let device = match request.first() {
        None => device_repo.read_one_auth(&device_id, &user_id).await?.data,
        Some(_) => device_repo.read_one(&device_id).await?,
    };

    let request = device_repo
        .delete_packet_transmit_request(&request_id)
        .await?;

    let return_url = query
        .remove("return_url")
        .unwrap_or(format!("/device/{}", device_id));

    let Some(r) = request.first() else {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, return_url))
            .finish());
    };

    let packet = PacketTransmitRequestPacket::new(
        device.probe_id,
        device.mac,
        device.ip,
        r.target_ip,
        r.target_port as u16,
        device.proxy,
        device.interval,
    );

    state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::StopTransmitDevicePackets(packet),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
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
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device = device_repo.read_one(&path.0).await?;
    if !device.published {
        device_repo.read_one_auth(&path.0, &user_id).await?;
    }
    let target_ip = request
        .connection_info()
        .realip_remote_addr()
        .map(|a| a.to_string());
    let target_ip = target_ip.ok_or(WebError::new(
        WebErrorKind::InternalServerError,
        "Could not determine target ip",
    ))?;

    let target_ip = target_ip.parse::<ipnetwork::IpNetwork>()?;
    if let Some(acl_src_cidr) = device.acl_src_cidr
        && !acl_src_cidr.contains(target_ip.ip())
    {
        return Err(WebError::new(
                WebErrorKind::DeviceTransmitRequestDenied,
                format!("Target IP is not allowed to request packets from this device. Allowed subnet is {acl_src_cidr}").as_str(),
            ));
    }

    if let Some(acl_pwd_hash) = &device.acl_pwd_hash {
        let Some(pwd) = &form.acl_pwd else {
            return Err(WebError::new(
                WebErrorKind::DeviceTransmitRequestDenied,
                "ACL password is required to request packets from this device",
            ));
        };
        if acl_pwd_hash != pwd {
            return Err(WebError::new(
                WebErrorKind::DeviceTransmitRequestDenied,
                "ACL password is incorrect",
            ));
        }
    }

    if let Some(acl_ap_hostname_regex) = &device.acl_ap_hostname_regex
        && !verify_transmit_request_client_ap(
            &state.device_acl_ap_database,
            acl_ap_hostname_regex,
            target_ip.ip().to_string().as_str(),
        )
        .await?
    {
        return Err(WebError::new(
            WebErrorKind::DeviceTransmitRequestDenied,
            "AP hostname that you are connected to does not match allowed APs",
        ));
    }

    let form = DeviceCustomPacketTransmitRequest::new(target_ip, device.port as u16, false);
    request_packet_transmit_helper(
        device_repo.clone(),
        &device,
        &user_id,
        state.command_channel.clone(),
        &form,
    )
    .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}/transmit", device.id)))
        .finish())
}

#[get("{id}/transmit")]
pub async fn get_device_for_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let device = device_repo.read_one(&path.0).await?;
    let user_id = parse_user_id(&i)?;
    if !device.published {
        device_repo.read_one_auth(&path.0, &user_id).await?;
    }
    let target_ip = request
        .connection_info()
        .realip_remote_addr()
        .map(|a| a.to_string());
    let target_ip = target_ip.ok_or(WebError::new(
        WebErrorKind::InternalServerError,
        "Could not determine target ip",
    ))?;

    let packet_transmit_request = device_repo
        .read_packet_transmit_request_by_user(&device.id, &user_id)
        .await?
        .into_iter()
        .next();

    let template_name = get_template_name(&request, "device/public");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceTransmitTemplate {
        user: user_repo.read_one(&user_id).await?,
        device: DeviceDisplay::from(device),
        client_ip: target_ip,
        packet_transmit_request,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}/publish")]
pub async fn publish_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device_id = path.0;

    device_repo
        .toggle_publicity(&device_id, &user_id, true)
        .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}

#[get("{id}/hide")]
pub async fn hide_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device_id = path.0;
    device_repo
        .toggle_publicity(&device_id, &user_id, false)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}

#[post("create")]
pub async fn create_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    form: web::Form<CreateDeviceForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = CreateDevice::from(form.into_inner());
    let device = device_repo
        .create_auth(&params, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device.id)))
        .finish())
}

#[get("create/{id}")]
pub async fn create_device_form(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let template_name = get_template_name(&request, "device/create");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceCreateTemplate { probe_id: path.0, user })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
