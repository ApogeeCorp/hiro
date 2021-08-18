-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.options(
    instance_id UUID NOT NULL REFERENCES hiro.instances(id),
    key VARCHAR(256) NOT NULL,
    value JSONB,
    PRIMARY KEY(instance_id, key)
);

CREATE UNIQUE INDEX IF NOT EXISTS option_name ON hiro.options(instance_id, key);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.options;