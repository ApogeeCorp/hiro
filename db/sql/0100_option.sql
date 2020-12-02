-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS options(
    audience_id UUID NOT NULL REFERENCES audiences(id),
    name VARCHAR(256) NOT NULL,
    value JSONB,
    PRIMARY KEY(audience_id, name)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE options;