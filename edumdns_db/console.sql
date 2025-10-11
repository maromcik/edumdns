insert into "group" (name) values ('test');

delete from device;
delete from packet;

SELECT *
FROM "user" AS u
         LEFT JOIN group_user AS gu
                   ON gu.user_id = u.id and (gu.group_id = 2)
WHERE (
    (u.email   ILIKE '%o%'
        OR u.name ILIKE '%o%'
        OR u.surname ILIKE '%o%')
    and gu.user_id is null
    ) ;

select count (*) from packet;
select count (*) from device where probe_id = '019911f9-2fa9-7469-942e-d0269c439a3b';

select * from device where "name" ilike '%st%';

alter table packet_transmit_request add column "user_id" bigint not null references "user" (id) default 1;

alter table probe add column "pre_shared_key" text;

alter table device drop column "user_id";

select probe_id from packet where probe_id = '0199d221-e935-7ad1-b6d1-e98b72a6a0af';