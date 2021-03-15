-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.users(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    login VARCHAR(128) NOT NULL UNIQUE,
    password_hash CHAR(64),    
    password_expires_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ,
    profile JSONB,
    metadata JSONB
);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.users;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.users
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

CREATE TABLE IF NOT EXISTS hiro.user_roles(
  user_id UUID NOT NULL REFERENCES hiro.users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES hiro.roles(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, role_id)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.users;
DROP TABLE hiro.user_roles;
