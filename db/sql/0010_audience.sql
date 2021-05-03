-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE IF NOT EXISTS hiro.audiences(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    slug VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    domain VARCHAR(1024) UNIQUE,
    token_algorithm VARCHAR(16) NOT NULL,
    token_lifetime BIGINT NOT NULL,
    session_lifetime BIGINT NOT NULL, 
    metadata JSONB
);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.audiences;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.audiences
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

DROP TRIGGER IF EXISTS update_slug ON hiro.audiences;

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.audiences
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("name", "slug");

CREATE TABLE IF NOT EXISTS hiro.audience_permissions(
  audience_id UUID NOT NULL REFERENCES hiro.audiences(id) ON DELETE CASCADE,
  permission VARCHAR(256) NOT NULL,
  description TEXT NULL,
  PRIMARY KEY(audience_id, permission)
);

DROP TRIGGER IF EXISTS update_slug  ON hiro.audience_permissions;

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.audience_permissions
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("permission", "permission", "\:");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.audiences;
DROP TABLE hiro.audience_permissions;