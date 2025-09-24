use crate::error::WebError;
use crate::forms::user::{UserCreateForm, UserQuery, UserUpdateForm, UserUpdateFormAdmin, UserUpdatePasswordForm};
use crate::handlers::utilities::{get_template_name, parse_user_id, validate_password};
use crate::templates::user::{UserDetailTemplate, UserManagePasswordTemplate, UserManageProfileTemplate, UserManageProfileUserFormTemplate, UserTemplate};
use crate::{authorized, AppState};
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{delete, get, post, web, HttpRequest, HttpResponse, Responder};
use edumdns_db::error::{BackendError, BackendErrorKind, DbError};
use edumdns_db::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, DbUpdate, Id};
use edumdns_db::repositories::user::models::{SelectManyUsers, UserCreate, UserUpdate, UserUpdatePassword};
use edumdns_db::repositories::user::repository::PgUserRepository;

#[get("")]
pub async fn get_users(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    query: web::Query<UserQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let query = query.into_inner();
    let params = SelectManyUsers::from(query.clone());
    let users = user_repo
        .read_many_auth(
            &params,
            &user_id,
        )
        .await?;

    let template_name = get_template_name(&request, "user");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserTemplate {
        logged_in: true,
        permissions: users.permissions,
        users: users.data,
        is_admin: user_repo.read_one(&user_id).await?.admin,
        has_groups: !user_repo.get_groups(&user_id).await?.is_empty(),
        filters: query,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_user(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo
        .read_one_auth(&path.0, &user_id)
        .await?;

    let template_name = get_template_name(&request, "user/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserDetailTemplate {
        logged_in: true,
        permissions: user.permissions,
        user: user.data,
        is_admin: user_repo.read_one(&user_id).await?.admin,
        has_groups: !user_repo.get_groups(&user_id).await?.is_empty(),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("create")]
pub async fn create_user(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: web::Form<UserCreateForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    user_repo
        .create_auth(&UserCreate::new_from_admin(
            &form.email,
            &form.name,
            &form.surname,
            form.admin
        ),
        &user_id)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, "/user"))
        .finish())
}

#[delete("{id}")]
pub async fn delete_user(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let _ = user_repo.delete_auth(&path.0, &parse_user_id(&i)?).await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, "/user"))
        .finish())
}

#[post("update")]
pub async fn update_user(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: web::Form<UserUpdateFormAdmin>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let target_user_id = form.0.id;
    let params = form.into_inner();
    user_repo.update_auth(&UserUpdate::from(params), &parse_user_id(&i)?).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/user/{}", target_user_id)))
        .finish())
}

#[get("/manage")]
pub async fn user_manage_form_page(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;

    let template_name = get_template_name(&request, "user/manage/profile");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserManageProfileTemplate {
        user: &user,
        message: String::new(),
        success: true,
        logged_in: true,
        is_admin: user_repo.read_one(&user_id).await?.admin,
        has_groups: !user_repo.get_groups(&user_id).await?.is_empty(),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("/manage/password")]
pub async fn user_manage_password_form(
    request: HttpRequest,
    identity: Option<Identity>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    authorized!(identity, request);

    let template_name = "user/manage/password/content.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(UserManagePasswordTemplate {
        message: String::new(),
        success: true,
        logged_in: true,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("/manage/profile")]
pub async fn user_manage_profile_form(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    let u = authorized!(identity, request);
    let user = user_repo.read_one(&parse_user_id(&u)?).await?;

    let template_name = get_template_name(&request, "user/manage/profile");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserManageProfileUserFormTemplate {
        user: &user,
        message: String::new(),
        success: true,
        logged_in: true,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("/manage")]
pub async fn user_manage(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: web::Form<UserUpdateForm>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    let u = authorized!(identity, request);
    let user_update = UserUpdate::new(
        &parse_user_id(&u)?,
        Some(&form.email),
        Some(&form.name),
        Some(&form.surname),
        None,
        None,
    );
    let user = user_repo.update(&user_update).await?;
    let Some(user_valid) = user.into_iter().next() else {
        return Err(WebError::from(DbError::from(BackendError::new(
            BackendErrorKind::UpdateParametersEmpty,
            "",
        ))));
    };

    let template_name = get_template_name(&request, "user/manage/profile");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserManageProfileUserFormTemplate {
        user: &user_valid,
        message: "Profile successfully updated".to_string(),
        success: true,
        logged_in: true,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("/manage/password")]
pub async fn user_manage_password(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: web::Form<UserUpdatePasswordForm>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    let u = authorized!(identity, request);

    let template_name = "user/manage/password/content.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;

    if form.new_password != form.confirm_password {
        let context = UserManagePasswordTemplate {
            message: "Passwords do not match".to_string(),
            success: false,
            logged_in: true,
        };

        let body = template.render(context)?;

        return Ok(HttpResponse::Ok().content_type("text/html").body(body));
    }

    if !validate_password(&form.new_password) {
        let context = UserManagePasswordTemplate::weak_password();
        let body = template.render(context)?;
        return Ok(HttpResponse::Ok().content_type("text/html").body(body));
    }

    let update_status = user_repo
        .update_password(&UserUpdatePassword::new(
            &parse_user_id(&u)?,
            &form.old_password,
            &form.new_password,
        ))
        .await;

    if update_status.is_err() {
        let context = UserManagePasswordTemplate {
            message: "Old password incorrect".to_string(),
            success: false,
            logged_in: true,
        };
        let body = template.render(context)?;
        return Ok(HttpResponse::Ok().content_type("text/html").body(body));
    }

    let context = UserManagePasswordTemplate {
        message: "Password successfully updated".to_string(),
        success: true,
        logged_in: true,
    };
    let body = template.render(context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
