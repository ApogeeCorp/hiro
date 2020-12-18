-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.roles(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    slug VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    metadata JSONB
);

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.roles
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.roles
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("name", "slug", "\:");

CREATE TABLE IF NOT EXISTS hiro.role_permissions(
  role_id UUID NOT NULL REFERENCES hiro.roles(id) ON DELETE CASCADE,
  audience_id UUID NOT NULL,
  permission TEXT NOT NULL,
  FOREIGN KEY(audience_id, permission) 
    REFERENCES hiro.audience_permissions(audience_id, permission) 
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  PRIMARY KEY(role_id, audience_id, permission)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.roles;
DROP TABLE hiro.role_permissions;
