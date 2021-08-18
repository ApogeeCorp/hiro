-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.apis(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL,
    version VARCHAR(64) NOT NULL,
    description VARCHAR(1024),
    spec JSONB NOT NULL,
    metadata JSONB,
    CONSTRAINT api_version UNIQUE(name,version)
);

CREATE TABLE IF NOT EXISTS hiro.api_permissions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id UUID NOT NULL,
    definition VARCHAR(256) NOT NULL,
    scope VARCHAR(256) NOT NULL,
    description VARCHAR(1024),
    CONSTRAINT api_permission_fk FOREIGN KEY (api_id) REFERENCES hiro.apis(id) ON DELETE CASCADE,
    CONSTRAINT api_permission_scope UNIQUE(api_id, scope, definition)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.apis;
DROP TABLE hiro.api_permissions;