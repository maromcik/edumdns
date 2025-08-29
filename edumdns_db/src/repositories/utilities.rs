use crate::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use crate::models::{GroupProbePermission, User};
use crate::repositories::common::Permission;
use crate::repositories::probe::models::SelectSingleProbe;
use crate::schema::group_probe_permission;
use crate::schema::group_user;
use crate::schema::user;
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;

pub async fn validate_permissions(
    pool: &Pool<AsyncPgConnection>,
    params: &SelectSingleProbe,
    permission: Permission,
) -> Result<Vec<Permission>, DbError> {
    let mut conn = pool.get().await?;

    let user_entry = user::table
        .find(params.user_id)
        .select(User::as_select())
        .first(&mut conn)
        .await?;

    if !user_entry.admin {
        let permissions = group_user::table
            .filter(group_user::user_id.eq(params.user_id))
            .inner_join(
                group_probe_permission::table
                    .on(group_probe_permission::group_id.eq(group_user::group_id)),
            )
            .filter(group_probe_permission::probe_id.eq(params.id))
            .select(GroupProbePermission::as_select())
            .load::<GroupProbePermission>(&mut conn)
            .await
            .map_err(|_| no_permission_error(&user_entry.email, permission))?;
        if permissions.iter().any(|p| p.permission == permission) {
            return Ok(permissions.into_iter().map(|p| p.permission).collect());
        }
        return Err(no_permission_error(&user_entry.email, permission));
    }

    Ok(vec![Permission::Full])
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
