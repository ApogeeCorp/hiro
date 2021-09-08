-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE IF NOT EXISTS hiro.assets(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID NOT NULL,
    owner_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    title VARCHAR(256) NOT NULL,
    filename VARCHAR(512) NOT NULL,
    description VARCHAR(1024),
    mime_type VARCHAR(256) NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    public BOOLEAN DEFAULT FALSE NOT NULL,
    sha256 CHAR(64),
    metadata JSONB,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES hiro.users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS asset_path ON hiro.assets(instance_id, filename);
CREATE INDEX IF NOT EXISTS asset_meta ON hiro.assets(metadata);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.assets;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.assets
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

CREATE TABLE IF NOT EXISTS hiro.asset_acl_roles(
    asset_id UUID NOT NULL,
    role_id UUID NOT NULL,
    read_access BOOLEAN NOT NULL DEFAULT TRUE,
    write_access BOOLEAN NOT NULL DEFAULT FALSE,
    share_access BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (asset_id) REFERENCES hiro.assets(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES hiro.roles(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_id, role_id)
);

CREATE TABLE IF NOT EXISTS hiro.asset_acl_users(
    asset_id UUID NOT NULL,
    user_id UUID NOT NULL,
    read_access BOOLEAN NOT NULL DEFAULT TRUE,
    write_access BOOLEAN NOT NULL DEFAULT FALSE,
    share_access BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (asset_id) REFERENCES hiro.assets(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES hiro.users(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_id, user_id)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.assets;
DROP TABLE hiro.asset_acl_roles;
DROP TABLE hiro.asset_acl_users;
