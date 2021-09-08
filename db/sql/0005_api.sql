-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.apis(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL,
    description VARCHAR(1024),
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS hiro.api_specs(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    api_id UUID NOT NULL,
    version VARCHAR(64) NOT NULL,
    spec BYTEA NOT NULL,
    spec_type VARCHAR(256),
    spec_format VARCHAR(256),
    CONSTRAINT spec_format UNIQUE(api_id, version, spec_type, spec_format)
);

CREATE TABLE IF NOT EXISTS hiro.api_permissions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    api_id UUID NOT NULL,
    spec_id UUID NULL,
    definition VARCHAR(256),
    scope VARCHAR(256) NOT NULL,
    description VARCHAR(1024),
    CONSTRAINT api_permission_fk FOREIGN KEY (api_id) REFERENCES hiro.apis(id) ON DELETE CASCADE,
    CONSTRAINT api_permission_scope UNIQUE(api_id, spec_id, definition, scope)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.apis;
DROP TABLE hiro.api_permissions;