select *
from
    probe as pr
        inner join
    group_probe_permission as gpp on gpp.probe_id = pr.id
        inner join
    group_user as gu on gu.group_id = gpp.group_id
        inner join
    "permission" as p on p.id = gpp.permission_id

where p.name = 'read' and gu.user_id = 1;

select count(*) from packet;
