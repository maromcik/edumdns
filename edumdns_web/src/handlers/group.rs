use actix_identity::Identity;
use actix_web::{get, web, HttpRequest, HttpResponse};
use edumdns_db::repositories::common::{DbReadMany, Pagination};
use edumdns_db::repositories::group::models::SelectManyGroups;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use crate::error::WebError;
use crate::forms::group::GroupQuery;
use crate::handlers::helpers::get_template_name;
use crate::templates::group::GroupTemplate;
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