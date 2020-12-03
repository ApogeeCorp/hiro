-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.options(
    audience_id UUID NOT NULL REFERENCES hiro.audiences(id),
    name VARCHAR(256) NOT NULL,
    value JSONB,
    PRIMARY KEY(audience_id, name)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.options;