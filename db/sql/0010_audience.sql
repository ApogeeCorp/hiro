-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TYPE TOKEN_ALGORITHM AS ENUM ('HS256', 'RS256');

CREATE TABLE IF NOT EXISTS hiro.audiences(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    token JSONB NOT NULL,
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS hiro.audience_permissions(
  audience_id UUID NOT NULL REFERENCES hiro.audiences(id) ON DELETE CASCADE,
  permission TEXT NOT NULL,
  PRIMARY KEY(audience_id, permission)
);

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.audiences
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.audiences;
DROP TABLE hiro.audience_permissions;