(SELECT device.*
 FROM device
          INNER JOIN probe
                     ON device.probe_id = probe.id
          INNER JOIN group_probe_permission
                     ON group_probe_permission.probe_id = probe.id
          INNER JOIN group_user
                     ON group_user.group_id = group_probe_permission.group_id
 WHERE group_user.user_id = $1
   AND group_probe_permission.permission IN (0, 1)
   AND ($2::BIGINT IS NULL OR device.id = $2)
   AND ($3::UUID IS NULL OR device.probe_id = $3)
   AND ($4::MACADDR IS NULL OR device.mac = $4)
   AND ($5::CIDR IS NULL OR device.ip <<= $5 OR device.ip = $5)
   AND ($6::INT IS NULL OR device.port = $6)
   AND ($7::TEXT IS NULL OR device.name ILIKE CONCAT('%', $7, '%'))
   AND ($8::BOOL IS NULL OR device.published = $8)
   AND ($9::BOOL IS NULL OR device.proxy = $9))
UNION
(SELECT device.*
 FROM device
          INNER JOIN probe
                     ON device.probe_id = probe.id
 WHERE probe.owner_id = $1
   AND ($2::BIGINT IS NULL OR device.id = $2)
   AND ($3::UUID IS NULL OR device.probe_id = $3)
   AND ($4::MACADDR IS NULL OR device.mac = $4)
   AND ($5::CIDR IS NULL OR device.ip <<= $5 OR device.ip = $5)
   AND ($6::INT IS NULL OR device.port = $6)
   AND ($7::TEXT IS NULL OR device.name ILIKE CONCAT('%', $7, '%'))
   AND ($8::BOOL IS NULL OR device.published = $8)
   AND ($9::BOOL IS NULL OR device.proxy = $9))
    ORDER BY id
    LIMIT $10
    OFFSET $11;