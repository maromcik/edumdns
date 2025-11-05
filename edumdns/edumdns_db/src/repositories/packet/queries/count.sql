SELECT COUNT(*)
FROM ((SELECT packet.id
       FROM packet
                INNER JOIN probe
                           ON packet.probe_id = probe.id
                INNER JOIN group_probe_permission
                           ON group_probe_permission.probe_id = probe.id
                INNER JOIN group_user
                           ON group_user.group_id = group_probe_permission.group_id
       WHERE group_user.user_id = $1
         AND group_probe_permission.permission IN (0, 1)
         AND ($2::BIGINT IS NULL OR packet.id = $2)
         AND ($3::UUID IS NULL OR packet.probe_id = $3)
         AND ($4::MACADDR IS NULL OR packet.src_mac = $4)
         AND ($5::MACADDR IS NULL OR packet.dst_mac = $5)
         AND ($6::CIDR IS NULL OR packet.src_addr <<= $6 OR packet.src_addr = $6)
         AND ($7::CIDR IS NULL OR packet.dst_addr <<= $7 OR packet.dst_addr = $7)
         AND ($8::INT IS NULL OR packet.src_port = $8)
         AND ($9::INT IS NULL OR packet.dst_port = $9)
         AND ($10::TEXT IS NULL OR packet.payload_string ILIKE CONCAT('%', $10, '%')))
      UNION
      (SELECT packet.id
       FROM packet
                INNER JOIN probe
                           ON packet.probe_id = probe.id
       WHERE probe.owner_id = $1
         AND ($2::BIGINT IS NULL OR packet.id = $2)
         AND ($3::UUID IS NULL OR packet.probe_id = $3)
         AND ($4::MACADDR IS NULL OR packet.src_mac = $4)
         AND ($5::MACADDR IS NULL OR packet.dst_mac = $5)
         AND ($6::CIDR IS NULL OR packet.src_addr <<= $6 OR packet.src_addr = $6)
         AND ($7::CIDR IS NULL OR packet.dst_addr <<= $7 OR packet.dst_addr = $7)
         AND ($8::INT IS NULL OR packet.src_port = $8)
         AND ($9::INT IS NULL OR packet.dst_port = $9)
         AND ($10::TEXT IS NULL OR packet.payload_string ILIKE CONCAT('%', $10, '%')))) AS combined;