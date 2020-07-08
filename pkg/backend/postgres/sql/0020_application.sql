-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TYPE GRANT_TYPE as ENUM ('authorization_code', 'refresh_token', 'client_credentials');
CREATE TYPE APPLICATION_TYPE as ENUM ('web', 'native', 'machine');

CREATE TABLE IF NOT EXISTS applications(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    name TEXT NOT NULL,
    description TEXT,
    type APPLICATION_TYPE,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    login_uris TEXT[],
    redirect_uris TEXT[],
    logout_uris TEXT[],
    allowed_grants GRANT_TYPE[],
    token_lifetime INT NOT NULL DEFAULT 3600,
    permissions TEXT[]
);

CREATE UNIQUE INDEX application_name ON applications(name);
CREATE UNIQUE INDEX application_client ON applications(client_id, client_secret);

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON applications
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE applications;