-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TYPE APPLICATION_TYPE as ENUM ('web', 'native', 'machine');
CREATE TYPE GRANT_TYPE as ENUM ('authorization_code', 'refresh_token', 'client_credentials');

CREATE TABLE IF NOT EXISTS applications(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(1024),
    type APPLICATION_TYPE NOT NULL DEFAULT 'web',
    client_id VARCHAR(32) NOT NULL,
    client_secret TEXT NOT NULL,
    token_lifetime INT NOT NULL DEFAULT(3600),
    permissions JSONB NOT NULL,
    allowed_grants GRANT_TYPE[] NOT NULL,
    authorized_uris JSONB,
    metadata JSONB,
    UNIQUE(client_id, client_secret)
);

CREATE INDEX application_client_id ON applications(client_id);

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON applications
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE applications;