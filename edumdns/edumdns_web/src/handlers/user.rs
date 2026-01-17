//! User management handlers.
//!
//! This module provides HTTP handlers for managing users and their accounts:
//! - User listing with filtering and pagination
//! - User detail viewing with group memberships
//! - User creation, updates, and deletion
//! - Password management (user self-service and admin)
//! - Group assignment management
//! - User profile management
//!
//! These handlers enforce permission checks and coordinate with the database to
//! manage user accounts and their relationships with groups.

use crate::authorized;
use crate::error::WebError;
use crate::forms::user::{
    UserCreateForm, UserQuery, UserUpdateForm, UserUpdateFormAdmin, UserUpdatePasswordForm,
    UserUpdatePasswordFormAdmin,
};
use crate::handlers::utilities::{get_template_name, parse_user_id};
use crate::handlers::{BulkAddEntityForm, SearchEntityQuery};
use crate::templates::PageInfo;
use crate::templates::user::{
    UserDetailGroupsTemplate, UserDetailTemplate, UserManagePasswordTemplate,
    UserManageProfileTemplate, UserTemplate,
};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, web};
use edumdns_core::app_packet::Id;
use edumdns_db::error::{BackendError, DbError};
use edumdns_db::repositories::common::{
    DbCreate, DbDelete, DbReadOne, DbUpdate, PAGINATION_ELEMENTS_PER_PAGE,
};
use edumdns_db::repositories::user::models::{
    SelectManyUsers, UserCreate, UserUpdate, UserUpdatePassword,
};
use edumdns_db::repositories::user::repository::PgUserRepository;
use edumdns_db::repositories::utilities::validate_password;
use std::collections::HashMap;
use actix_csrf::extractor::Csrf;

/// Lists all users with filtering and pagination.
///
/// Retrieves users accessible to the authenticated user and renders them in a paginated list view.
/// Admin users can see all users; regular users see a limited view.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `state` - Application state containing template engine
/// * `query` - Query parameters for filtering and pagination
///
/// # Returns
///
/// Returns an HTML response with the user list page, or redirects to login if not authenticated.
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
    let page = query.page.unwrap_or(1);
    let query = query.into_inner();
    let params = SelectManyUsers::from(query.clone());
    let user = user_repo.read_one(&user_id).await?;
    let users = user_repo.read_many_auth(&params, &user_id).await?;

    let user_count = user_repo.get_user_count(params).await?;
    let total_pages = (user_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;

    let template_name = get_template_name(&request, "user");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(UserTemplate {
        user,
        users,
        filters: query,
        page_info: PageInfo::new(page, total_pages),
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Displays detailed information about a specific user.
///
/// Shows user details and group memberships. The user must have permission to view the target user.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `state` - Application state containing template engine
/// * `path` - Path parameter containing user ID
///
/// # Returns
///
/// Returns an HTML response with the user detail page, or an error if the user is not found
/// or the current user lacks permission.
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
    let target_user = user_repo.read_one_auth(&path.0, &user_id).await?;
    let user = user_repo.read_one(&user_id).await?;
    let groups = user_repo.read_groups(&path.0, &user_id).await?;
    let template_name = get_template_name(&request, "user/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserDetailTemplate {
        user,
        groups,
        target_user: target_user.data,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Creates a new user account.
///
/// Creates a user with the specified email, name, surname, password, and admin status.
/// The current user must have permission to create users.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `form` - Form data containing user information and password
///
/// # Returns
///
/// Returns a redirect response to the newly created user's detail page.
#[post("create")]
pub async fn create_user(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: Csrf<web::Form<UserCreateForm>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let u = user_repo
        .create_auth(
            &UserCreate::new_from_admin(
                &form.email,
                &form.name,
                &form.surname,
                form.admin,
                &form.password,
                &form.confirm_password,
            )?,
            &user_id,
        )
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/user/{}", u.id)))
        .finish())
}

/// Deletes a user account.
///
/// Removes a user from the database. Users cannot delete their own account.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `path` - Path parameter containing user ID to delete
/// * `query` - Query parameters containing optional return URL
///
/// # Returns
///
/// Returns a redirect response to the return URL (or user list) after deletion, or an error
/// if attempting to delete the currently logged-in user.
#[delete("{id}")]
pub async fn delete_user(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let admin_id = parse_user_id(&i)?;
    if admin_id == path.0 {
        return Err(WebError::BadRequest(
            "Cannot delete the currently logged-in user".to_string(),
        ));
    }

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/user");

    let _ = user_repo.delete_auth(&path.0, &admin_id).await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

/// Updates user information.
///
/// Modifies user properties such as email, name, surname, and admin status.
/// The current user must have permission to update the target user.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `form` - Form data containing updated user information
///
/// # Returns
///
/// Returns a redirect response to the user detail page after updating.
#[post("update")]
pub async fn update_user(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: Csrf<web::Form<UserUpdateFormAdmin>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let target_user_id = form.0.id;
    let params = form.into_inner();
    user_repo
        .update_auth(&UserUpdate::from(params.0), &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/user/{}", target_user_id)))
        .finish())
}

/// Updates a user's password (admin operation).
///
/// Changes a user's password without requiring the old password. This is an admin-only
/// operation. The current user must have permission to update passwords.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `form` - Form data containing user ID, new password, and confirmation
///
/// # Returns
///
/// Returns a redirect response to the user detail page after updating the password.
#[post("update-pwd")]
pub async fn update_user_password(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: Csrf<web::Form<UserUpdatePasswordFormAdmin>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let admin_id = parse_user_id(&i)?;
    let target_user_id = form.0.id;
    let params = form.into_inner();
    user_repo
        .update_password(&UserUpdatePassword::new_from_admin(
            &target_user_id,
            &admin_id,
            &params.new_password,
            &params.confirm_password,
        )?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/user/{}", target_user_id)))
        .finish())
}

/// Displays the user profile management page.
///
/// Shows a form for users to update their own profile information (email, name, surname).
/// OIDC users may have limited editing capabilities depending on configuration.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection and OIDC cookie checking
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `state` - Application state containing template engine
///
/// # Returns
///
/// Returns an HTML response with the profile management form.
#[get("/manage")]
pub async fn user_manage_form_page(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    let i = authorized!(identity, request);
    let oidc = request
        .cookie("auth")
        .map(|c| c.value() == "oidc")
        .unwrap_or(false);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;

    let template_name = get_template_name(&request, "user/manage/profile");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserManageProfileTemplate {
        user,
        message: String::new(),
        success: true,
        oidc,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Displays the password change form.
///
/// Shows a form for users to change their own password. Requires the current password.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `state` - Application state containing template engine
///
/// # Returns
///
/// Returns an HTML response with the password change form.
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
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Updates the current user's profile information.
///
/// Allows users to update their own email, name, and surname. OIDC users may have
/// restrictions on what fields can be updated.
///
/// # Arguments
///
/// * `request` - HTTP request for OIDC cookie checking
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `form` - Form data containing updated profile information
/// * `state` - Application state containing template engine
///
/// # Returns
///
/// Returns an HTML response with the profile management page showing a success message.
#[post("/manage")]
pub async fn user_manage(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: Csrf<web::Form<UserUpdateForm>>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    let u = authorized!(identity, request);

    let oidc = request
        .cookie("auth")
        .map(|c| c.value() == "oidc")
        .unwrap_or(false);

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
        return Err(WebError::from(DbError::from(
            BackendError::UpdateParametersEmpty,
        )));
    };
    let template_name = get_template_name(&request, "user/manage/profile");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(UserManageProfileTemplate {
        user: user_valid,
        message: "Profile successfully updated".to_string(),
        success: true,
        oidc,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Changes the current user's password.
///
/// Validates the old password and updates to the new password. The new password must
/// meet strength requirements and match the confirmation.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `form` - Form data containing old password, new password, and confirmation
/// * `state` - Application state containing template engine
///
/// # Returns
///
/// Returns an HTML response with the password change form showing success or error messages.
#[post("/manage/password")]
pub async fn user_manage_password(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    form: Csrf<web::Form<UserUpdatePasswordForm>>,
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
        };
        let body = template.render(context)?;
        return Ok(HttpResponse::Ok().content_type("text/html").body(body));
    }

    let context = UserManagePasswordTemplate {
        message: "Password successfully updated".to_string(),
        success: true,
    };
    let body = template.render(context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Adds a user to one or more groups.
///
/// Assigns a user to multiple groups in a single operation. The current user must have
/// permission to manage group memberships.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `path` - Path parameter containing user ID
/// * `form` - Form data containing list of group IDs to add
///
/// # Returns
///
/// Returns a redirect response to the user detail page after adding groups.
#[post("{id}/groups/add")]
pub async fn add_user_groups(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
    form: web::Form<BulkAddEntityForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = path.0;
    let admin_id = parse_user_id(&i)?;
    if !form.entity_ids.is_empty() {
        user_repo
            .add_groups(&user_id, &form.entity_ids, &admin_id)
            .await?;
    }
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/user/{}", user_id)))
        .finish())
}

/// Searches for groups that can be assigned to a user.
///
/// Returns a list of groups matching the search query that can be added to the user.
/// Used for dynamic group selection in the user interface.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for database operations
/// * `state` - Application state containing template engine
/// * `path` - Path parameter containing user ID
/// * `query` - Query parameters containing search term
///
/// # Returns
///
/// Returns an HTML response with search results for groups.
#[get("{id}/search")]
pub async fn search_user_groups(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
    query: web::Query<SearchEntityQuery>,
) -> Result<impl Responder, WebError> {
    let i = authorized!(identity, request);
    let groups = user_repo
        .search_user_groups(&query.q, &parse_user_id(&i)?, &path.0)
        .await?;
    let template_name = "user/groups/search.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(UserDetailGroupsTemplate { groups })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
