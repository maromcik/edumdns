use crate::error::WebError;
use crate::forms::group::GroupQuery;
use crate::handlers::helpers::get_template_name;
use crate::templates::group::{GroupDetailTemplate, GroupTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, get, web};
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination};
use edumdns_db::repositories::group::models::SelectManyGroups;
use edumdns_db::repositories::group::repository::PgGroupRepository;

#[get("")]
pub async fn get_groups(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    query: web::Query<GroupQuery>,
) -> Result<HttpResponse, WebError> {
    let groups = group_repo
        .read_many_auth(&SelectManyGroups::new(
            query.name.clone(),
            Some(Pagination::default_pagination(query.page)),
        ))
        .await?;

    let template_name = get_template_name(&request, "group");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupTemplate {
        logged_in: true,
        permissions: groups.permissions,
        groups: groups.data,
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
) -> Result<HttpResponse, WebError> {
    let group = group_repo.read_one_auth(&path.0).await?;

    let template_name = get_template_name(&request, "group/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupDetailTemplate {
        logged_in: true,
        permissions: group.permissions,
        group: group.data,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
