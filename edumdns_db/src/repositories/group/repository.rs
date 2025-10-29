use crate::error::DbError;
use crate::models::{Group, User};
use crate::repositories::common::{
    DbCreate, DbDelete, DbResult, DbResultMultiple, DbResultSingle, DbUpdate,
};
use crate::repositories::group::models::{CreateGroup, SelectManyGroups, UpdateGroup};
use edumdns_core::app_packet::Id;

use crate::repositories::utilities::validate_admin_conn;
use crate::schema::{group, group_user, user};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, PgTextExpressionMethods, QueryDsl,
    SelectableHelper,
};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;

#[derive(Clone)]
pub struct PgGroupRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgGroupRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub async fn read_many(&self, params: &SelectManyGroups) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        GroupBackend::select_many(&mut conn, params).await
    }
    pub async fn read_many_auth(
        &self,
        params: &SelectManyGroups,
        user_id: &Id,
    ) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        GroupBackend::select_many(&mut conn, params).await
    }

    pub async fn read_one(&self, params: &Id) -> DbResultSingle<Group> {
        let mut conn = self.pg_pool.get().await?;
        GroupBackend::select_one(&mut conn, params).await
    }
    pub async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSingle<Group> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        GroupBackend::select_one(&mut conn, params).await
    }

    pub async fn add_users(&self, group_id: &Id, user_ids: &[Id], admin_id: &Id) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, admin_id).await?;
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
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, admin_id).await?;
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
        validate_admin_conn(&mut conn, admin_id).await?;
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
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, admin_id).await?;
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

struct GroupBackend {}

impl GroupBackend {
    async fn select_one(conn: &mut AsyncPgConnection, params: &Id) -> DbResultSingle<Group> {
        let g = group::table
            .find(params)
            .select(Group::as_select())
            .first(conn)
            .await?;
        Ok(g)
    }

    async fn select_many(
        conn: &mut AsyncPgConnection,
        params: &SelectManyGroups,
    ) -> DbResultMultiple<Group> {
        let mut query = group::table.into_boxed();

        if let Some(n) = &params.name {
            query = query.filter(group::name.ilike(format!("%{n}%")));
        }

        if let Some(n) = &params.description {
            query = query.filter(group::description.ilike(format!("%{n}%")));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let groups = query.order_by(group::id).load::<Group>(conn).await?;

        Ok(groups)
    }

    async fn insert(conn: &mut AsyncPgConnection, data: &CreateGroup) -> DbResultSingle<Group> {
        let g = diesel::insert_into(group::table)
            .values((
                group::name.eq(&data.name),
                group::description.eq(&data.description),
            ))
            .returning(Group::as_returning())
            .get_result(conn)
            .await?;
        Ok(g)
    }

    async fn update(conn: &mut AsyncPgConnection, params: &UpdateGroup) -> DbResultMultiple<Group> {
        let groups = diesel::update(group::table.find(&params.id))
            .set(params)
            .get_results(conn)
            .await?;
        Ok(groups)
    }
    async fn drop(conn: &mut AsyncPgConnection, params: &Id) -> DbResultMultiple<Group> {
        diesel::delete(group::table.find(params))
            .get_results(conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbCreate<CreateGroup, Group> for PgGroupRepository {
    async fn create(&self, data: &CreateGroup) -> DbResultSingle<Group> {
        let mut conn = self.pg_pool.get().await?;
        GroupBackend::insert(&mut conn, data).await
    }
    async fn create_auth(&self, data: &CreateGroup, user_id: &Id) -> DbResultSingle<Group> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        GroupBackend::insert(&mut conn, data).await
    }
}

impl DbDelete<Id, Group> for PgGroupRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        GroupBackend::drop(&mut conn, params).await
    }

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        GroupBackend::drop(&mut conn, params).await
    }
}

impl DbUpdate<UpdateGroup, Group> for PgGroupRepository {
    async fn update(&self, params: &UpdateGroup) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        GroupBackend::update(&mut conn, params).await
    }

    async fn update_auth(&self, params: &UpdateGroup, user_id: &Id) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        GroupBackend::update(&mut conn, params).await
    }
}
