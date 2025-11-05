(SELECT probe.*
 FROM probe
          INNER JOIN group_probe_permission
                     ON group_probe_permission.probe_id = probe.id
          INNER JOIN group_user
                     ON group_user.group_id = group_probe_permission.group_id
 WHERE group_user.user_id = $1
   AND group_probe_permission.permission IN (0, 1) -- Read or Full
   AND ($2::UUID IS NULL OR probe.id = $2)
   AND ($3::BOOL IS NULL OR probe.adopted = $3)
   AND ($4::MACADDR IS NULL OR probe.mac = $4)
   AND ($5::CIDR IS NULL OR probe.ip <<= $5 OR probe.ip = $5)
   AND ($6::BIGINT IS NULL OR probe.owner_id = $6)
   AND ($7::BIGINT IS NULL OR probe.location_id = $7)
   AND ($8::TEXT IS NULL OR probe.name ILIKE CONCAT('%', $8, '%')))
UNION
(SELECT probe.*
 FROM probe
 WHERE probe.owner_id = $1
   AND ($2::UUID IS NULL OR probe.id = $2)
   AND ($3::BOOL IS NULL OR probe.adopted = $3)
   AND ($4::MACADDR IS NULL OR probe.mac = $4)
   AND ($5::CIDR IS NULL OR probe.ip <<= $5 OR probe.ip = $5)
   AND ($6::BIGINT IS NULL OR probe.owner_id = $6)
   AND ($7::BIGINT IS NULL OR probe.location_id = $7)
   AND ($8::TEXT IS NULL OR probe.name ILIKE CONCAT('%', $8, '%')))
ORDER BY ip
LIMIT $9 OFFSET $10;