-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TYPE TOKEN_ALGORITHM AS ENUM ('HS256', 'RS256');

CREATE TABLE IF NOT EXISTS hiro.audiences(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    token_lifetime BIGINT NOT NULL DEFAULT(3600),
    token_algorithm TOKEN_ALGORITHM,
    token_secret TEXT NOT NULL,
    permissions JSONB NOT NULL,
    metadata JSONB
);

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.audiences
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.audiences;