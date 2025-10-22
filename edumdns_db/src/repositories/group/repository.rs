use crate::error::DbError;
use crate::models::{Group, User};
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResult, DbResultMultiple,
    DbResultMultiplePerm, DbResultSingle, DbResultSinglePerm, DbUpdate, Id,
};
use crate::repositories::group::models::{CreateGroup, SelectManyGroups, UpdateGroup};
use std::ops::DerefMut;

use crate::repositories::utilities::{validate_admin, validate_admin_transaction};
use crate::schema::{group, group_user, user};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, PgTextExpressionMethods, QueryDsl,
    SelectableHelper, TextExpressionMethods,
};
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
        validate_admin(&self.pg_pool, user_id).await?;
        let g = self.read_one(params).await?;
        Ok(DbDataPerm::new(g, (false, vec![])))
    }
}

impl DbReadMany<SelectManyGroups, Group> for PgGroupRepository {
    async fn read_many(&self, params: &SelectManyGroups) -> DbResultMultiple<Group> {
        let mut query = group::table.into_boxed();

        if let Some(n) = &params.name {
            query = query.filter(group::name.ilike(format!("%{n}%")));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let groups = query.order_by(group::id).load::<Group>(&mut conn).await?;

        Ok(groups)
    }

    async fn read_many_auth(
        &self,
        params: &SelectManyGroups,
        user_id: &Id,
    ) -> DbResultMultiplePerm<Group> {
        validate_admin(&self.pg_pool, user_id).await?;
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
                    let g = diesel::insert_into(group::table)
                        .values((
                            group::name.eq(&data.name),
                            group::description.eq(&data.description),
                        ))
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
    async fn create_auth(&self, data: &CreateGroup, user_id: &Id) -> DbResultSingle<Group> {
        validate_admin(&self.pg_pool, user_id).await?;
        self.create(data).await
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
        validate_admin(&self.pg_pool, user_id).await?;
        self.delete(params).await
    }
}

impl DbUpdate<UpdateGroup, Group> for PgGroupRepository {
    async fn update(&self, params: &UpdateGroup) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        let groups = diesel::update(group::table.find(&params.id))
            .set(params)
            .get_results(&mut conn)
            .await?;

        Ok(groups)
    }

    async fn update_auth(&self, params: &UpdateGroup, user_id: &Id) -> DbResultMultiple<Group> {
        validate_admin(&self.pg_pool, user_id).await?;
        self.update(params).await
    }
}

impl PgGroupRepository {
    pub async fn add_users(&self, group_id: &Id, user_ids: &[Id], admin_id: &Id) -> DbResult<()> {
        validate_admin(&self.pg_pool, admin_id).await?;
        let mut conn = self.pg_pool.get().await?;
        let rows = user_ids
            .iter()
            .map(|uid| {
                (
                    group_user::group_id.eq(group_id),
                    group_user::user_id.eq(uid),
                )
            })
            .collect::<Vec<_>>();

        diesel::insert_into(group_user::table)
            .values(rows)
            .execute(&mut conn)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    pub async fn delete_user(
        &self,
        group_id: &Id,
        target_user_id: &Id,
        admin_id: &Id,
    ) -> DbResult<()> {
        validate_admin(&self.pg_pool, admin_id).await?;
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(
            group_user::table
                .filter(group_user::group_id.eq(group_id))
                .filter(group_user::user_id.eq(target_user_id)),
        )
        .execute(&mut conn)
        .await
        .map_err(DbError::from)?;
        Ok(())
    }

    pub async fn read_users(&self, group_id: &Id, admin_id: &Id) -> DbResultMultiple<User> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin(&self.pg_pool, admin_id).await?;
        let users = group_user::table
            .filter(group_user::group_id.eq(group_id))
            .inner_join(user::table)
            .select(User::as_select())
            .load::<User>(&mut conn)
            .await?;
        Ok(users)
    }

    pub async fn search_group_users(
        &self,
        params: &str,
        admin_id: &Id,
        exclude_group_id: &Id,
    ) -> DbResultMultiple<User> {
        validate_admin(&self.pg_pool, admin_id).await?;
        let mut conn = self.pg_pool.get().await?;
        let users = user::table
            .or_filter(user::email.ilike(&format!("%{}%", params)))
            .or_filter(user::name.ilike(&format!("%{}%", params)))
            .or_filter(user::surname.ilike(&format!("%{}%", params)))
            .left_join(
                group_user::table.on(group_user::user_id
                    .eq(user::id)
                    .and(group_user::group_id.eq(exclude_group_id))),
            )
            .filter(group_user::user_id.is_null())
            .limit(20)
            .select(User::as_select())
            .load::<User>(&mut conn)
            .await?;
        Ok(users)
    }
}
