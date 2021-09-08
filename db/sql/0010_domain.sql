-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.domains(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL,
    description VARCHAR(1024),
    audience VARCHAR(1024) NOT NULL UNIQUE,
    metadata JSONB
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.domains;
