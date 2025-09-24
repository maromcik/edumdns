use crate::authorized;
use crate::error::WebError;
use crate::forms::group::{AddGroupUsersForm, CreateGroupForm, GroupQuery, SearchUsersQuery};
use crate::handlers::utilities::{get_template_name, parse_user_id};
use crate::templates::group::{GroupDetailTemplate, GroupDetailUsersTemplate, GroupTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, web};
use edumdns_db::repositories::common::{DbCreate, DbDelete, DbUpdate};
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination};
use edumdns_db::repositories::group::models::{CreateGroup, SelectManyGroups, UpdateGroup};
use edumdns_db::repositories::group::repository::PgGroupRepository;

#[get("")]
pub async fn get_groups(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    query: web::Query<GroupQuery>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let groups = group_repo
        .read_many_auth(
            &SelectManyGroups::new(
                query.name.clone(),
                Some(Pagination::default_pagination(query.page)),
            ),
            &parse_user_id(&i)?,
        )
        .await?;

    let template_name = get_template_name(&request, "group");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupTemplate {
        logged_in: true,
        permissions: groups.permissions,
        groups: groups.data,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
        filters: query.into_inner(),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_group(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let group = group_repo
        .read_one_auth(&path.0, &parse_user_id(&i)?)
        .await?;

    let template_name = get_template_name(&request, "group/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupDetailTemplate {
        logged_in: true,
        permissions: group.permissions,
        group: group.data,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
    })?;

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
    let _ = group_repo
        .create(&CreateGroup::new(
            parse_user_id(&i)?,
            &form.name,
            form.description.as_ref(),
        ))
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, "/group"))
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

#[get("{id}/users")]
pub async fn get_group_users(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let users = group_repo.read_users(&path.0, &user_id).await?;
    let template_name = "group/users/content.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(GroupDetailUsersTemplate {
        users,
        group_id: path.0,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("{id}/users/add")]
pub async fn add_group_users(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
    form: web::Form<AddGroupUsersForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let group_id = path.0;
    let admin_id = parse_user_id(&i)?;
    if !form.user_ids.is_empty() {
        group_repo
            .add_users(&group_id, &form.user_ids, &admin_id)
            .await?;
    }
    // Re-render the "users in this group" panel
    let users = group_repo.read_users(&group_id, &admin_id).await?;
    let template_name = get_template_name(&request, "group/users");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupDetailUsersTemplate { users, group_id })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}/users/{user_id}/delete")]
pub async fn delete_group_user(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id, Id)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let group_id = path.0;
    let user_id = path.1;
    let admin_id = parse_user_id(&i)?;
    group_repo
        .delete_user(&group_id, &user_id, &admin_id)
        .await?;

    let users = group_repo.read_users(&group_id, &admin_id).await?;
    let template_name = get_template_name(&request, "group/users");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupDetailUsersTemplate { users, group_id })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}/search")]
pub async fn search_group_users(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
    query: web::Query<SearchUsersQuery>,
) -> Result<impl Responder, WebError> {
    let i = authorized!(identity, request);
    let users = group_repo
        .search_group_users(&query.q, &parse_user_id(&i)?, &path.0)
        .await?;
    let template_name = "group/users/search.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(GroupDetailUsersTemplate {
        users,
        group_id: path.0,
    })?;

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
