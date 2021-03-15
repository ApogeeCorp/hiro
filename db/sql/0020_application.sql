-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TYPE hiro.GRANT_TYPE AS ENUM ('authorization_code', 'client_credentials', 'password', 'refresh_token');

CREATE TABLE IF NOT EXISTS hiro.applications(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    slug VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    type TEXT NOT NULL DEFAULT 'web',
    secret_key TEXT,
    uris JSONB,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS application_credentials ON hiro.applications(id, secret_key);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.applications;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.applications
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

DROP TRIGGER IF EXISTS update_slug ON hiro.applications;

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.applications
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("name", "slug");

CREATE TABLE IF NOT EXISTS hiro.application_permissions(
  application_id UUID NOT NULL REFERENCES hiro.applications(id) ON DELETE CASCADE,
  audience_id UUID NOT NULL,
  permission TEXT NOT NULL,
  FOREIGN KEY(audience_id, permission) 
    REFERENCES hiro.audience_permissions(audience_id, permission) 
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  PRIMARY KEY(application_id, audience_id, permission)
);

CREATE TABLE IF NOT EXISTS hiro.application_grants(
  application_id UUID NOT NULL REFERENCES hiro.applications(id) ON DELETE CASCADE,
  audience_id UUID NOT NULL REFERENCES hiro.audiences(id) ON DELETE CASCADE,
  grant_type hiro.GRANT_TYPE NOT NULL,
  PRIMARY KEY(application_id, audience_id, grant_type)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.applications;
DROP TABLE hiro.application_permissions;
DROP TABLE hiro.application_grants;