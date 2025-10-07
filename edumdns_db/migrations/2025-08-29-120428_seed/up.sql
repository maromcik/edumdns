INSERT INTO "user"
VALUES (1, 's@s.com', 'Superadmin', 'Superadminovi',
        '$pbkdf2-sha256$i=600000,l=32$UOB/uNKLd1iRmBTTmMqjFQ$OTyclcE7FXybX7hqnBP1hVGudyxME+dqsB6jaPeQgpU',
        'UOB/uNKLd1iRmBTTmMqjFQ', true);

INSERT INTO "user"
VALUES (2, 'a@a.com', 'Acko', 'Ackove',
        '$pbkdf2-sha256$i=600000,l=32$UOB/uNKLd1iRmBTTmMqjFQ$OTyclcE7FXybX7hqnBP1hVGudyxME+dqsB6jaPeQgpU',
        'UOB/uNKLd1iRmBTTmMqjFQ', false);

INSERT INTO "user"
VALUES (3, 'b@b.com', 'Bcko', 'Bckove',
        '$pbkdf2-sha256$i=600000,l=32$UOB/uNKLd1iRmBTTmMqjFQ$OTyclcE7FXybX7hqnBP1hVGudyxME+dqsB6jaPeQgpU',
        'UOB/uNKLd1iRmBTTmMqjFQ', false);

INSERT INTO "group"
VALUES (1, 'adminstrators', '' );

INSERT INTO "group"
VALUES (2, 'users', '' );

INSERT INTO "group_user"
VALUES (1, 2);

INSERT INTO "group_user"
VALUES (2, 3);


LOCK TABLE "user" IN EXCLUSIVE MODE;
SELECT setval('"user_id_seq"', COALESCE((SELECT MAX(id) + 1 FROM "user"), 1), false);

LOCK TABLE "group" IN EXCLUSIVE MODE;
SELECT setval('"group_id_seq"', COALESCE((SELECT MAX(id) + 1 FROM "group"), 1), false);