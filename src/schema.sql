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
    `mtime`             TEXT NULL
                            CHECK (`is_directory` = (`mtime` IS NULL)),
    `sha1`              TEXT NULL
                            CHECK (NOT `is_directory` OR `sha1` IS NULL)
);

CREATE TABLE IF NOT EXISTS `pending` (
    `pending_id`    INTEGER NOT NULL
                        PRIMARY KEY AUTOINCREMENT,
    `item_id`       TEXT NULL UNIQUE
                        REFERENCES `item`
                        ON UPDATE RESTRICT
                        ON DELETE RESTRICT,
    `local_path`    TEXT NOT NULL,
    `operation`     TEXT NOT NULL
);

COMMIT;
