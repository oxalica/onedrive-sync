PRAGMA foreign_keys = ON;
PRAGMA case_sensitive_like = ON;

BEGIN;

CREATE TABLE IF NOT EXISTS `meta` (
    `key`   TEXT NOT NULL PRIMARY KEY,
    `value` TEXT NULL
);

INSERT OR IGNORE INTO `meta` VALUES ('login_info', NULL);
INSERT OR IGNORE INTO `meta` VALUES ('delta_url', NULL);
INSERT OR IGNORE INTO `meta` VALUES ('delta_url_time', NULL);

CREATE TABLE IF NOT EXISTS `item` (
    `item_id`           TEXT NOT NULL
                            PRIMARY KEY,
    `item_name`         TEXT NOT NULL,
    `parent_item_id`    TEXT NULL
                            REFERENCES `item` (`item_id`)
                            DEFERRABLE INITIALLY DEFERRED,
    `is_directory`      INTEGER NOT NULL
                            CHECK (`is_directory` IN (0, 1)),
    `size`              INTEGER NULL
                            CHECK (`is_directory` = (`size` IS NULL)),
    `ctag`              INTEGER NULL
                            CHECK (`is_directory` = (`ctag` IS NULL)),
    `mtime`             TEXT NULL
                            CHECK (`is_directory` = (`mtime` IS NULL)),
    `sha1`              TEXT NULL
                            CHECK (NOT `is_directory` OR `sha1` IS NULL)
);

CREATE TABLE IF NOT EXISTS `pending` (
    `pending_id`    INTEGER NOT NULL
                        PRIMARY KEY AUTOINCREMENT,
    `operation`     TEXT NOT NULL,
    `local_path`    TEXT NOT NULL UNIQUE,
    `item_id`       TEXT NULL UNIQUE
                        REFERENCES `item`
                        ON DELETE RESTRICT,
    `lock_size`     INTEGER NULL,
    `lock_mtime`    TEXT NULL
);

CREATE TABLE IF NOT EXISTS `download` (
    `pending_id`        INTEGER NOT NULL
                            PRIMARY KEY
                            REFERENCES `pending`
                            ON DELETE CASCADE,
    `url`               TEXT NULL,
    `current_size`      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS `upload` (
    `pending_id`        INTEGER NOT NULL
                            PRIMARY KEY
                            REFERENCES `pending`
                            ON DELETE CASCADE,
    `session_url`       TEXT NULL
);

COMMIT;
