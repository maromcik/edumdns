use crate::error::DbError;
use crate::models::Group;
use crate::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultSingle, Id};
use crate::repositories::group::models::{CreateGroup, SelectManyFilter};
use std::ops::DerefMut;

use crate::schema;
use crate::schema::group::name;
use diesel::result::Error;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, RunQueryDsl};
use schema::group::dsl::*;

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
        group
            .find(params)
            .select(Group::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyFilter, Group> for PgGroupRepository {
    async fn read_many(&self, params: &SelectManyFilter) -> DbResultMultiple<Group> {
        let mut query = group.into_boxed();

        if let Some(n) = &params.name {
            query = query.filter(name.eq(n));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let groups = query.load::<Group>(&mut conn).await?;

        Ok(groups)
    }
}

impl DbCreate<CreateGroup, Group> for PgGroupRepository {
    async fn create(&self, data: &CreateGroup) -> DbResultSingle<Group> {
        let mut conn = self.pg_pool.get().await?;
        let g = conn
            .deref_mut()
            .transaction::<_, Error, _>(|c| {
                async move {
                    diesel::insert_into(schema::group::table)
                        .values(data)
                        .returning(Group::as_returning())
                        .get_result(c)
                        .await
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
        diesel::delete(group.find(params)).get_results(&mut conn).await.map_err(DbError::from)
    }
}

impl PgGroupRepository { 
    async fn add_user(&self, user_id: &Id, group_id: &Id) -> Result<(), DbError> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(schema::group_user::table)
            .values((
                schema::group_user::user_id.eq(user_id),
                schema::group_user::group_id.eq(group_id),
            ))
            .execute(&mut conn)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }
}