use crate::error::{BackendError, BackendErrorKind, DbError};
use crate::models::{Group, GroupProbePermission, User};
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResult, DbResultMultiple,
    DbResultMultiplePerm, DbResultSingle, DbResultSinglePerm, Id, Permission,
};
use crate::repositories::group::models::{CreateGroup, SelectManyGroups};
use std::ops::DerefMut;

use crate::schema::{group, group_user, user};
use diesel::result::Error;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper, TextExpressionMethods};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, RunQueryDsl};

#[derive(Clone)]
pub struct PgGroupRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgGroupRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl DbReadOne<Id, Group> for PgGroupRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Group> {
        let mut conn = self.pg_pool.get().await?;
        let g = group::table
            .find(params)
            .select(Group::as_select())
            .first(&mut conn)
            .await?;
        Ok(g)
    }
    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<Group> {
        let g = self.read_one(params).await?;
        Ok(DbDataPerm::new(g, (false, vec![])))
    }
}

impl DbReadMany<SelectManyGroups, Group> for PgGroupRepository {
    async fn read_many(&self, params: &SelectManyGroups) -> DbResultMultiple<Group> {
        let mut query = group::table.into_boxed();

        if let Some(n) = &params.name {
            query = query.filter(group::name.like(format!("%{n}%")));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let groups = query.load::<Group>(&mut conn).await?;

        Ok(groups)
    }

    async fn read_many_auth(
        &self,
        params: &SelectManyGroups,
        user_id: &Id,
    ) -> DbResultMultiplePerm<Group> {
        let groups = self.read_many(params).await?;
        Ok(DbDataPerm::new(groups, (false, vec![])))
    }
}

impl DbCreate<CreateGroup, Group> for PgGroupRepository {
    async fn create(&self, data: &CreateGroup) -> DbResultSingle<Group> {
        let mut conn = self.pg_pool.get().await?;
        let g = conn
            .deref_mut()
            .transaction::<_, DbError, _>(|c| {
                async move {
                    let user_entry = user::table
                        .find(data.user_id)
                        .select(User::as_select())
                        .first(c)
                        .await?;

                    if !user_entry.admin {
                        return Err(DbError::from(BackendError::new(BackendErrorKind::PermissionDenied, "User is not admin")));
                    }

                    let g = diesel::insert_into(group::table)
                        .values((group::name.eq(&data.name), group::description.eq(&data.description)))
                        .returning(Group::as_returning())
                        .get_result(c)
                        .await?;
                    Ok::<Group, DbError>(g)
                }
                .scope_boxed()
            })
            .await?;
        Ok(g)
    }
}

impl DbDelete<Id, Group> for PgGroupRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(group::table.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<Group> {
        self.delete(params).await
    }
}

impl PgGroupRepository {
    async fn add_user(&self, user_id: &Id, group_id: &Id) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(group_user::table)
            .values((
                group_user::user_id.eq(user_id),
                group_user::group_id.eq(group_id),
            ))
            .execute(&mut conn)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }
}
