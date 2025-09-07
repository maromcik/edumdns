use std::str::FromStr;
use serde::{Deserialize, Deserializer};
use crate::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use crate::models::{GroupProbePermission, User};
use crate::repositories::common::{DbResult, Id, Permission};
use crate::schema::group_probe_permission;
use crate::schema::group_user;
use crate::schema::user;
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection};
use std::ops::DerefMut;
use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::Pbkdf2;
use rand_core::OsRng;
use uuid::Uuid;

pub async fn validate_permissions(
    pool: &Pool<AsyncPgConnection>,
    user_id: &Id,
    probe_id: &Uuid,
    permission: Permission,
) -> Result<(bool, Vec<GroupProbePermission>), DbError> {
    let mut conn = pool.get().await?;

    let user_entry = user::table
        .find(user_id)
        .select(User::as_select())
        .first(&mut conn)
        .await?;

    if user_entry.admin {
        return Ok((true, vec![GroupProbePermission::full()]));
    }

    let permissions = group_user::table
        .filter(group_user::user_id.eq(user_id))
        .inner_join(
            group_probe_permission::table
                .on(group_probe_permission::group_id.eq(group_user::group_id)),
        )
        .filter(group_probe_permission::probe_id.eq(probe_id))
        .select(GroupProbePermission::as_select())
        .load::<GroupProbePermission>(&mut conn)
        .await?;
    if permissions
        .iter()
        .any(|p| p.permission == permission || p.permission == Permission::Full)
    {
        return Ok((false, permissions));
    }
    Err(no_permission_error(&user_entry.email, permission))
}

pub fn no_permission_error(email: &str, permission: Permission) -> DbError {
    DbError::new(
        DbErrorKind::BackendError(BackendError::new(
            BackendErrorKind::PermissionDenied,
            format!(
                "User `{}` does not have `{}` permissions for this entity",
                email, permission
            )
            .as_str(),
        )),
        "",
    )
}

pub async fn validate_admin_transaction(
    conn: &mut AsyncPgConnection,
    user_id: &Id,
) -> DbResult<()> {
    let user_entry = user::table
        .find(user_id)
        .select(User::as_select())
        .first(conn)
        .await?;
    if !user_entry.admin {
        return Err(DbError::from(BackendError::new(
            BackendErrorKind::PermissionDenied,
            "User is not admin",
        )));
    }
    Ok(())
}

pub async fn validate_admin(pool: &Pool<AsyncPgConnection>, user_id: &Id) -> Result<(), DbError> {
    pool.get()
        .await?
        .deref_mut()
        .transaction(|c| {
            async move {
                validate_admin_transaction(c, user_id).await?;
                Ok::<(), DbError>(())
            }
            .scope_boxed()
        })
        .await
}

pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

pub fn hash_password(password: String, salt: &SaltString) -> Result<String, DbError> {
    let password_hash = Pbkdf2.hash_password(password.as_bytes(), salt)?.to_string();
    Ok(password_hash)
}

pub fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<bool, DbError> {
    let parsed_hash = PasswordHash::new(expected_password_hash)?;
    let bytes = password_candidate.bytes().collect::<Vec<u8>>();
    Ok(Pbkdf2.verify_password(&bytes, &parsed_hash).is_ok())
}


pub fn empty_string_is_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        Some(s) if s.trim() == "none" => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => s.parse::<T>().map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}