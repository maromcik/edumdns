use crate::error::{BackendError, DbError};
use crate::models::{GroupProbePermission, Probe, User};
use crate::repositories::MIN_PASS_LEN;
use crate::repositories::common::{DbResult, Permission};
use crate::schema::group_user;
use crate::schema::user;
use crate::schema::{group_probe_permission, probe};
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use edumdns_core::app_packet::Id;
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::str::FromStr;
use time::{OffsetDateTime, UtcOffset, format_description};
use uuid::Uuid;

pub const WEAK_PASSWORD_MESSAGE: &str = "Weak Password! Must contain at least one char from: {lower, upper, number, special} and be at least 6 characters long.";

pub fn validate_user(user: &User) -> Result<(), DbError> {
    if user.disabled {
        return Err(DbError::from(BackendError::PermissionDenied(
            "User is disabled".to_string(),
        )));
    }

    if user.deleted_at.is_some() {
        return Err(DbError::from(BackendError::PermissionDenied(
            "User has been deleted".to_string(),
        )));
    }
    Ok(())
}

/// Validates whether a user has the required permission for a given probe.
///
/// This function performs several checks to determine if a user has access:
///
/// - Loads the user from the database and verifies that the user record is valid.
/// - If the user is an admin, they automatically receive full permissions.
/// - Otherwise, the function loads all group-based probe permissions assigned to the user.
/// - If the user owns the probe, they are granted full *web* permissions in addition to any group permissions.
/// - If any of the user’s permissions match the requested `permission` or are `Permission::Full`,
///   the permission check succeeds.
/// - If none of the above conditions are met, an error is returned.
///
/// # Arguments
///
/// * `conn` — A mutable async PostgreSQL connection.
/// * `user_id` — The ID of the user whose permissions should be checked.
/// * `probe_id` — The ID of the probe being accessed.
/// * `permission` — The specific permission being requested.
///
/// # Returns
///
/// Returns:
/// - `Ok((true, vec![GroupProbePermission])` if the user is an admin (full access).
/// - `Ok((false, Vec<GroupProbePermission>))` if the user has sufficient permissions,
///   with the boolean indicating whether the permission was admin-provided (`true`)
///   or group/ownership-provided (`false`).
/// - `Err(DbError)` if the user lacks permissions or the database operations fail.
///
/// # Errors
///
/// Returns an error if:
/// - The user does not exist or fails validation.
/// - The required permission is not found and the user is neither admin nor owner.
/// - Any database query fails.
///
/// # Asynchronous
///
/// This function is asynchronous and should be awaited.
///
/// # Examples
///
/// ```ignore
/// let (is_admin, permissions) = validate_permissions(
///     &mut conn,
///     &user_id,
///     &probe_id,
///     Permission::Read
/// ).await?;
/// ```
pub async fn validate_permissions(
    conn: &mut AsyncPgConnection,
    user_id: &Id,
    probe_id: &Uuid,
    permission: Permission,
) -> Result<(bool, Vec<GroupProbePermission>), DbError> {
    let user_entry = user::table
        .find(user_id)
        .select(User::as_select())
        .first(conn)
        .await?;

    validate_user(&user_entry)?;

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
        .load::<GroupProbePermission>(conn)
        .await?;

    let probe = probe::table
        .find(probe_id)
        .select(Probe::as_select())
        .first(conn)
        .await?;

    if probe.owner_id == Some(*user_id) {
        let mut perms: HashSet<GroupProbePermission> = HashSet::from_iter(permissions);
        perms.extend(GroupProbePermission::create_web());
        return Ok((false, Vec::from_iter(perms)));
    }

    if permissions
        .iter()
        .any(|p| p.permission == permission || p.permission == Permission::Full)
    {
        return Ok((false, permissions));
    }

    Err(no_permission_error(&user_entry.email, permission))
}

pub fn no_permission_error(email: &str, permission: Permission) -> DbError {
    DbError::from(BackendError::PermissionDenied(format!(
        "User `{}` does not have `{}` permissions for this entity",
        email, permission
    )))
}

pub async fn validate_admin_conn(conn: &mut AsyncPgConnection, user_id: &Id) -> DbResult<()> {
    let user_entry = user::table
        .find(user_id)
        .select(User::as_select())
        .first(conn)
        .await?;
    if !user_entry.admin {
        return Err(DbError::from(BackendError::PermissionDenied(
            "User is not admin".to_string(),
        )));
    }
    validate_user(&user_entry)?;
    Ok(())
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

pub fn empty_string_is_false<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        Some(s) if s.trim().is_empty() => Ok(Some(false)),
        Some(s) if s.eq_ignore_ascii_case("true") => Ok(Some(true)),
        Some(s) if s.eq_ignore_ascii_case("false") => Ok(Some(false)),
        Some(_) => Err(serde::de::Error::custom("invalid bool")),
        None => Ok(Some(false)), // now it works!
    }
}

pub fn validate_password(password: &str) -> bool {
    let (lower, upper, numeric, special) =
        password
            .chars()
            .fold((false, false, false, false), |(l, u, n, s), c| {
                (
                    { if c.is_lowercase() { true } else { l } },
                    { if c.is_uppercase() { true } else { u } },
                    { if c.is_numeric() { true } else { n } },
                    { if !c.is_alphanumeric() { true } else { s } },
                )
            });
    lower && upper && numeric && special && password.len() >= MIN_PASS_LEN
}

pub fn format_time(t: OffsetDateTime) -> String {
    let format = format_description::parse("[day]. [month]. [year] [hour]:[minute]:[second]").ok();
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let local = t.to_offset(offset);
    if let Some(fmt) = &format {
        local.format(fmt).unwrap_or_else(|_| local.to_string())
    } else {
        local.to_string()
    }
}
