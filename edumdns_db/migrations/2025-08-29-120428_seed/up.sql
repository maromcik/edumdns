INSERT INTO "user"
VALUES (1, 'a@a.com', 'Acko', 'Ackove',
        '$pbkdf2-sha256$i=600000,l=32$UOB/uNKLd1iRmBTTmMqjFQ$OTyclcE7FXybX7hqnBP1hVGudyxME+dqsB6jaPeQgpU',
        'UOB/uNKLd1iRmBTTmMqjFQ', true);

INSERT INTO "group"
VALUES (1, 'adminstrators', '' );

INSERT INTO "group"
VALUES (2, 'users', '' );

INSERT INTO "group_user"
VALUES (1, 1);

INSERT INTO "group_user"
VALUES (2, 1);