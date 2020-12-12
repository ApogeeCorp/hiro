-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.users(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    login VARCHAR(128) NOT NULL UNIQUE,
    password_hash CHAR(64),    
    password_expires_at TIMESTAMPTZ,
    profile JSONB,
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS hiro.user_permissions(
  user_id UUID NOT NULL REFERENCES hiro.users(id) ON DELETE CASCADE,
  audience_id UUID NOT NULL,
  permission TEXT NOT NULL,
  FOREIGN KEY(audience_id, permission) 
    REFERENCES hiro.audience_permissions(audience_id, permission) 
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  PRIMARY KEY(user_id, audience_id, permission)
);

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.users
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.users;
DROP TABLE hiro.user_permissions;
