-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.roles(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    description VARCHAR(1024),
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS role_name ON hiro.roles(instance_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS role_slug ON hiro.roles(instance_id, slug);

DROP TRIGGER IF EXISTS update_timestamp on hiro.roles CASCADE;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.roles
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

DROP TRIGGER IF EXISTS update_slug on hiro.roles CASCADE;

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.roles
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("name", "slug", "\:");

CREATE TABLE IF NOT EXISTS hiro.role_permissions(
  role_id UUID NOT NULL REFERENCES hiro.roles(id) ON DELETE CASCADE,
  instance_id UUID NOT NULL,
  permission TEXT NOT NULL,
  FOREIGN KEY(instance_id, permission) 
    REFERENCES hiro.instance_permissions(instance_id, permission) 
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  PRIMARY KEY(role_id, instance_id, permission)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.roles;
DROP TABLE hiro.role_permissions;
