use crate::error::WebError;
use crate::forms::user::{
    UserLoginForm, UserLoginReturnURL, UserUpdateForm, UserUpdatePasswordForm,
};
use crate::handlers::utilities::{get_template_name, parse_user_id, validate_password};
use crate::templates::user::{
    LoginTemplate, UserManagePasswordTemplate, UserManageProfileTemplate,
    UserManageProfileUserFormTemplate,
};
use crate::{AppState, authorized};
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::http::header::LOCATION;
use actix_web::web::Redirect;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, post, web};
use edumdns_db::error::{BackendError, BackendErrorKind, DbError};
use edumdns_db::repositories::common::{DbReadOne, DbUpdate};
use edumdns_db::repositories::user::models::{UserLogin, UserUpdate, UserUpdatePassword};
use edumdns_db::repositories::user::repository::PgUserRepository;
use log::debug;

#[get("/manage")]
pub async fn user_manage_form_page(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    session: Session,
) -> Result<impl Responder, WebError> {
    let u = authorized!(identity, request);
    let user = user_repo.read_one(&parse_user_id(&u)?).await?;

    let template_name = get_template_name(&request, "user/manage/profile");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserManageProfileTemplate {
        user: &user,
        message: String::new(),
        success: true,
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
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
    );
    println!("{:?}", user_update);
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
