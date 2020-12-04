-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.applications(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    type TEXT NOT NULL DEFAULT 'web',
    secret_key TEXT,
    permissions JSONB,
    grants JSONB,
    uris TEXT[],
    metadata JSONB
);

CREATE INDEX application_credentials ON hiro.applications(id, secret_key);

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.applications
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.applications;