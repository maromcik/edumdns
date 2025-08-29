use crate::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use crate::models::User;
use crate::repositories::common::PermissionType;
use crate::repositories::probe::models::SelectSingleProbe;
use crate::schema::group_probe_permission;
use crate::schema::group_user;
use crate::schema::permission;
use crate::schema::user;
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use uuid::Uuid;

pub async fn validate_permissions(
    pool: &Pool<AsyncPgConnection>,
    params: &SelectSingleProbe,
    permission_type: PermissionType
) -> Result<(), DbError> {
    let mut conn = pool.get().await?;

    let user_entry = user::table
        .find(params.user_id)
        .select(User::as_select())
        .first(&mut conn)
        .await?;

    if !user_entry.admin {
        let _ = group_user::table
            .filter(group_user::user_id.eq(params.user_id))
            .inner_join(
                group_probe_permission::table
                    .on(group_probe_permission::group_id.eq(group_user::group_id)),
            )
            .filter(group_probe_permission::probe_id.eq(params.id))
            .inner_join(
                permission::table.on(permission::id.eq(group_probe_permission::permission_id)),
            )
            .filter(permission::name.eq(permission_type.to_string()))
            .select(group_probe_permission::probe_id)
            .first::<Uuid>(&mut conn)
            .await
            .map_err(|_| {
                DbError::new(
                    DbErrorKind::BackendError(BackendError::new(
                        BackendErrorKind::PermissionDenied,
                        format!(
                            "User {} does not have read permissions for this probe",
                            user_entry.email
                        )
                        .as_str(),
                    )),
                    "",
                )
            })?;
    }
    Ok(())
}
