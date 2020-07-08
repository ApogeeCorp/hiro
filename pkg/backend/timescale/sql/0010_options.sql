-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS options(
    id BIGSERIAL,
    name TEXT NOT NULL,
    value JSONB
);

CREATE UNIQUE INDEX option_name ON options(name);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE options;