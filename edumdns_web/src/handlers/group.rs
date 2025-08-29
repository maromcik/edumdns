use actix_identity::Identity;
use actix_web::{get, web, HttpRequest, HttpResponse};
use uuid::Uuid;
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination};
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::group::models::SelectManyGroups;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::probe::models::ProbeDisplay;
use crate::error::WebError;
use crate::forms::group::GroupQuery;
use crate::handlers::helpers::get_template_name;
use crate::templates::group::{GroupDetailTemplate, GroupTemplate};
use crate::templates::probe::ProbeDetailTemplate;
use crate::utils::AppState;

#[get("")]
pub async fn get_groups(
    request: HttpRequest,
    identity: Option<Identity>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    query: web::Query<GroupQuery>
) -> Result<HttpResponse, WebError> {
    let groups = group_repo
        .read_many(&SelectManyGroups::new(
            query.name.clone(),
            Some(Pagination::default_pagination(query.page))))
        .await?;

    let template_name = get_template_name(&request, "group");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupTemplate {
        logged_in: identity.is_some(),
        groups
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

    let group = group_repo
        .read_one(&path.0)
        .await?;

    let template_name = get_template_name(&request, "group/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(GroupDetailTemplate {
        logged_in: identity.is_some(),
        group,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))


}