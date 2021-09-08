-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.roles(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL,
    description VARCHAR(1024),
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS role_name ON hiro.roles(instance_id, name);

DROP TRIGGER IF EXISTS update_timestamp on hiro.roles CASCADE;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.roles
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

DROP TRIGGER IF EXISTS update_slug on hiro.roles CASCADE;

CREATE TABLE IF NOT EXISTS hiro.role_permissions(
  role_id UUID NOT NULL,
  instance_id UUID NOT NULL,
  permission_id UUID NOT NULL,
  PRIMARY KEY(role_id, instance_id, permission_id),
  FOREIGN KEY (role_id) REFERENCES hiro.roles(id) ON DELETE CASCADE,
  FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES hiro.api_permissions(id) ON DELETE CASCADE
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.roles;
DROP TABLE hiro.role_permissions;
