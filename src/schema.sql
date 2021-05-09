PRAGMA foreign_keys = ON;

BEGIN;

CREATE TABLE IF NOT EXISTS `meta` (
    `key`   TEXT NOT NULL PRIMARY KEY,
    `value` TEXT NULL
);

INSERT OR IGNORE INTO `meta` VALUES ('login_info', NULL);
INSERT OR IGNORE INTO `meta` VALUES ('delta_url', NULL);
INSERT OR IGNORE INTO `meta` VALUES ('delta_url_time', NULL);

CREATE TABLE IF NOT EXISTS `items` (
    `id`            TEXT NOT NULL PRIMARY KEY,
    `name`          TEXT NOT NULL,
    `parent`        TEXT     NULL REFERENCES `items` (id) DEFERRABLE INITIALLY DEFERRED,
    `is_directory`  INT  NOT NULL,
    `size`          INT      NULL,
    `mtime`         TEXT     NULL,
    `sha1`          TEXT     NULL,
    CHECK (`is_directory` IS (`size` IS NULL AND `mtime` IS NULL)),
    CHECK (NOT `is_directory` OR `sha1` IS NULL)
);

COMMIT;
