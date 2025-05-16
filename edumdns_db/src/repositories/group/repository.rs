use std::ops::DerefMut;
use crate::error::DbError;
use crate::models::Group;
use crate::repositories::common::Id;
use crate::repositories::group::models::{CreateGroup, SelectManyFilter};

use diesel_async::{RunQueryDsl, AsyncConnection};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel::result::Error;
use crate::schema;
use crate::schema::group::name;

pub trait GroupRepository {
    async fn get_group(&self, group_id: Id) -> Result<Group, DbError>;
    async fn get_groups(&self, filters: SelectManyFilter) -> Result<Vec<Group>, DbError>;
    async fn create_group(&self, group_create: CreateGroup) -> Result<Group, DbError>;
}

#[derive(Clone)]
pub struct PgGroupRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgGroupRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl GroupRepository for PgGroupRepository {
    async fn get_group(&self, group_id: Id) -> Result<Group, DbError> {
        let mut conn = self.pg_pool.get().await?;
        let group = schema::group::dsl::group
            .find(group_id)
            .select(Group::as_select())
            .first(&mut conn)
            .await?;

        Ok(group)
    }
    
    async fn get_groups(&self, filters: SelectManyFilter) -> Result<Vec<Group>, DbError> {
        let mut query = schema::group::dsl::group.into_boxed();
        
        if let Some(n) = filters.name {
            query = query.filter(name.eq(n));
        }
    
        if let Some(pagination) = filters.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let users = query
            .load::<Group>(&mut conn)
            .await?;
    
        Ok(users)
    }
    
    async fn create_group(&self, group_create: CreateGroup) -> Result<Group, DbError> {
        let mut conn = self.pg_pool.get().await?;
        let group = conn.deref_mut().transaction::<_, Error, _>(|c| async move {
            diesel::insert_into(schema::group::table)
                .values(&group_create)
                .returning(Group::as_returning())
                .get_result(c)
                .await
            
        }.scope_boxed())
            .await?;
        
        Ok(group)
    }
}
