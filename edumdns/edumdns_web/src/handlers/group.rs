//! Group management handlers.
//!
//! This module provides HTTP handlers for managing user groups and permissions:
//! - Group listing with filtering
//! - Group detail viewing with member users
//! - Group creation, updates, and deletion
//! - User assignment to groups (bulk and individual)
//! - User removal from groups
//! - User search for group assignment
//!
//! Groups are used to organize users and control access to probes and devices through
//! permission assignments.

use crate::authorized;
use crate::error::WebError;
use crate::forms::group::{CreateGroupForm, GroupQuery};
use crate::handlers::utilities::{get_template_name, parse_user_id};
use crate::handlers::{BulkAddEntityForm, SearchEntityQuery};
use crate::templates::group::{GroupDetailTemplate, GroupDetailUsersTemplate, GroupTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, web};
use edumdns_core::app_packet::Id;
use edumdns_db::repositories::common::{DbCreate, DbDelete, DbUpdate};
use edumdns_db::repositories::common::{DbReadOne, Pagination};
use edumdns_db::repositories::group::models::{CreateGroup, SelectManyGroups, UpdateGroup};
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use std::collections::HashMap;
#[get("")]
pub async fn get_groups(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    query: web::Query<GroupQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let groups = group_repo
        .read_many_auth(
            &SelectManyGroups::new(
                query.name.clone(),
                query.description.clone(),
                Some(Pagination::default_pagination(query.page)),
            ),
            &user_id,
        )
        .await?;

    let template_name = get_template_name(&request, "group");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupTemplate {
        user,
        groups,
        filters: query.into_inner(),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_group(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let group = group_repo.read_one_auth(&path.0, &user_id).await?;
    let users = group_repo.read_users(&path.0, &user_id).await?;
    let template_name = get_template_name(&request, "group/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupDetailTemplate { user, users, group })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("create")]
pub async fn create_group(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    form: web::Form<CreateGroupForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let g = group_repo
        .create_auth(
            &CreateGroup::new(&form.name, form.description.as_ref()),
            &parse_user_id(&i)?,
        )
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/group/{}", g.id)))
        .finish())
}

#[delete("{id}")]
pub async fn delete_group(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let _ = group_repo.delete_auth(&path.0, &parse_user_id(&i)?).await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, "/group"))
        .finish())
}

#[post("{id}/users/add")]
pub async fn add_group_users(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    path: web::Path<(Id,)>,
    form: web::Form<BulkAddEntityForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let group_id = path.0;
    let admin_id = parse_user_id(&i)?;
    if !form.entity_ids.is_empty() {
        group_repo
            .add_users(&group_id, &form.entity_ids, &admin_id)
            .await?;
    }
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/group/{}", group_id)))
        .finish())
}

#[get("{id}/users/{user_id}/delete")]
pub async fn delete_group_user(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    path: web::Path<(Id, Id)>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let group_id = path.0;
    let user_id = path.1;
    let admin_id = parse_user_id(&i)?;
    group_repo
        .delete_user(&group_id, &user_id, &admin_id)
        .await?;

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/group");
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

#[get("{id}/search")]
pub async fn search_group_users(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
    query: web::Query<SearchEntityQuery>,
) -> Result<impl Responder, WebError> {
    let i = authorized!(identity, request);
    let users = group_repo
        .search_group_users(&query.q, &parse_user_id(&i)?, &path.0)
        .await?;
    let template_name = "group/users/search.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(GroupDetailUsersTemplate { users })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("update")]
pub async fn update_group(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    form: web::Form<UpdateGroup>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = form.into_inner();
    group_repo.update_auth(&params, &parse_user_id(&i)?).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/group/{}", params.id)))
        .finish())
}
