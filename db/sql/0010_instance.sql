-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE IF NOT EXISTS hiro.instances(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    slug VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    audience VARCHAR(1024) NOT NULL UNIQUE,
    token_algorithm VARCHAR(16) NOT NULL,
    refresh_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000, 
    token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    session_lifetime BIGINT NOT NULL DEFAULT 3600000000000, 
    login_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    invite_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    verify_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    auth_code_lifetime BIGINT NOT NULL DEFAULT 600000000000,
    metadata JSONB
);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.instances;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.instances
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

DROP TRIGGER IF EXISTS update_slug ON hiro.instances;

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.instances
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("name", "slug");

CREATE TABLE IF NOT EXISTS hiro.instance_permissions(
  instance_id UUID NOT NULL REFERENCES hiro.instances(id) ON DELETE CASCADE,
  permission VARCHAR(256) NOT NULL,
  description TEXT NULL,
  PRIMARY KEY(instance_id, permission)
);

DROP TRIGGER IF EXISTS update_slug  ON hiro.instance_permissions;

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.instance_permissions
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("permission", "permission", "\:");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.instances;
DROP TABLE hiro.instance_permissions;