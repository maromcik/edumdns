use crate::error::WebError;
use crate::forms::user::{UserLoginForm, UserLoginReturnURL};
use crate::templates::user::LoginTemplate;
use crate::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::http::StatusCode;
use actix_web::web::Redirect;
use actix_web::{get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use edumdns_db::error::DbErrorKind::BackendError;
use edumdns_db::repositories::user::models::UserLogin;
use edumdns_db::repositories::user::repository::PgUserRepository;

#[get("/login")]
pub async fn login(
    request: HttpRequest,
    identity: Option<Identity>,
    query: web::Query<UserLoginReturnURL>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let referer = request
        .headers()
        .get(actix_web::http::header::REFERER)
        .map_or("/", |header_value| header_value.to_str().unwrap_or("/"));

    let return_url = query.ret.clone().unwrap_or(referer.to_string());
    if identity.is_some() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, return_url))
            .finish());
    }

    let template_name = "user/login.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(LoginTemplate {
        message: String::new(),
        return_url,
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("/login")]
pub async fn login_user(
    request: HttpRequest,
    user_repo: web::Data<PgUserRepository>,
    form: web::Form<UserLoginForm>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    match user_repo
        .login(&UserLogin::new(&form.email, &form.password))
        .await
    {
        Ok(user) => {
            Identity::login(&request.extensions(), user.id.to_string())?;
            Ok(HttpResponse::SeeOther()
                .insert_header((LOCATION, form.return_url.clone()))
                .finish())
        }
        Err(db_error) => {
            if let BackendError(err) = db_error.error_kind {
                let template_name = "user/login.html";
                let env = state.jinja.acquire_env()?;
                let template = env.get_template(template_name)?;
                let body = template.render(LoginTemplate {
                    message: err.to_string(),
                    return_url: form.return_url.clone(),
                })?;

                return Ok(HttpResponse::Ok().content_type("text/html").body(body));
            }

            Err(WebError::from(db_error))
        }
    }
}

#[get("/logout")]
pub async fn logout_user(identity: Option<Identity>) -> Result<impl Responder, WebError> {
    if let Some(u) = identity {
        u.logout();
    }
    Ok(Redirect::to("/").using_status_code(StatusCode::FOUND))
}


// #[get("/manage")]
// pub async fn user_manage_form_page(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     user_repo: web::Data<UserRepository>,
//     state: web::Data<AppState>,
// ) -> Result<impl Responder, WebError> {
//     let u = authorized!(identity, request.path());
//     let user = user_repo
//         .read_one(&GetById::new(parse_user_id(&u)?))
//         .await?;
//
//     let template_name = get_template_name(&request, "user/manage/profile");
//     let env = state.jinja.acquire_env()?;
//     let template = env.get_template(&template_name)?;
//     let body = template.render(UserManageProfileTemplate {
//         user: &user,
//         message: String::new(),
//         success: true,
//         logged_in: true,
//     })?;
//
//     Ok(HttpResponse::Ok().content_type("text/html").body(body))
// }
//
// #[get("/manage/password")]
// pub async fn user_manage_password_form(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     state: web::Data<AppState>,
// ) -> Result<impl Responder, WebError> {
//     authorized!(identity, request.path());
//
//     let template_name = "user/manage/password/content.html";
//     let env = state.jinja.acquire_env()?;
//     let template = env.get_template(&template_name)?;
//     let body = template.render(UserManagePasswordTemplate {
//         message: String::new(),
//         success: true,
//         logged_in: true,
//     })?;
//
//     Ok(HttpResponse::Ok().content_type("text/html").body(body))
// }
//
// #[get("/manage/profile")]
// pub async fn user_manage_profile_form(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     user_repo: web::Data<UserRepository>,
//     state: web::Data<AppState>,
// ) -> Result<impl Responder, WebError> {
//     let u = authorized!(identity, request.path());
//     let user = user_repo
//         .read_one(&GetById::new(parse_user_id(&u)?))
//         .await?;
//
//     let template_name = get_template_name(&request, "user/manage/profile");
//     let env = state.jinja.acquire_env()?;
//     let template = env.get_template(&template_name)?;
//     let body = template.render(UserManageProfileUserFormTemplate {
//         user: &user,
//         message: String::new(),
//         success: true,
//         logged_in: true,
//     })?;
//
//     Ok(HttpResponse::Ok().content_type("text/html").body(body))
// }

// #[post("/manage")]
// pub async fn user_manage(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     user_repo: web::Data<UserRepository>,
//     form: web::Form<UserUpdateForm>,
//     state: web::Data<AppState>,
// ) -> Result<impl Responder, WebError> {
//     let u = authorized!(identity, request.path());
//     let user_update = UserUpdate::new(
//         &parse_user_id(&u)?,
//         Some(&form.email),
//         Some(&form.name),
//         Some(&form.surname),
//         None,
//         None,
//     );
//     let user = user_repo.update(&user_update).await?;
//
//     let Some(user_valid) = user.into_iter().next() else {
//         return Err(WebError::from(BackendError::new(
//             BackendErrorKind::UserUpdateParametersEmpty,
//         )));
//     };
//
//     let template_name = get_template_name(&request, "user/manage/profile");
//     let env = state.jinja.acquire_env()?;
//     let template = env.get_template(&template_name)?;
//     let body = template.render(UserManageProfileUserFormTemplate {
//         user: &user_valid,
//         message: "Profile successfully updated".to_string(),
//         success: true,
//         logged_in: true,
//     })?;
//
//     Ok(HttpResponse::Ok().content_type("text/html").body(body))
// }

// #[post("/manage/password")]
// pub async fn user_manage_password(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     user_repo: web::Data<UserRepository>,
//     form: web::Form<UserUpdatePasswordForm>,
//     state: web::Data<AppState>,
// ) -> Result<impl Responder, WebError> {
//     let u = authorized!(identity, request.path());
//
//     let template_name = "user/manage/password/content.html";
//     let env = state.jinja.acquire_env()?;
//     let template = env.get_template(template_name)?;
//
//     if form.new_password != form.confirm_password {
//         let context = UserManagePasswordTemplate {
//             message: "Passwords do not match".to_string(),
//             success: false,
//             logged_in: true,
//         };
//
//         let body = template.render(context)?;
//
//         return Ok(HttpResponse::Ok().content_type("text/html").body(body));
//     }
//
//     if !validate_password(&form.new_password) {
//         let context = UserManagePasswordTemplate::weak_password();
//         let body = template.render(context)?;
//         return Ok(HttpResponse::Ok().content_type("text/html").body(body));
//     }
//
//     let update_status = user_repo
//         .update_password(&UserUpdatePassword::new(
//             &parse_user_id(&u)?,
//             &form.old_password,
//             &form.new_password,
//         ))
//         .await;
//
//     if update_status.is_err() {
//         let context = UserManagePasswordTemplate {
//             message: "Old password incorrect".to_string(),
//             success: false,
//             logged_in: true,
//         };
//         let body = template.render(context)?;
//         return Ok(HttpResponse::Ok().content_type("text/html").body(body));
//     }
//
//     let context = UserManagePasswordTemplate {
//         message: "Password successfully updated".to_string(),
//         success: true,
//         logged_in: true,
//     };
//     let body = template.render(context)?;
//     Ok(HttpResponse::Ok().content_type("text/html").body(body))
// }
