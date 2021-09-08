-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TYPE hiro.GRANT_TYPE AS ENUM ('authorization_code', 'client_credentials', 'password', 'refresh_token');

CREATE TABLE IF NOT EXISTS hiro.applications(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL,
    description VARCHAR(1024),
    type TEXT NOT NULL DEFAULT 'web',
    client_id CHAR(22),
    client_secret CHAR(32),
    token_secret_id UUID,
    login_uri VARCHAR(1024),
    logout_uri VARCHAR(1024),
    signup_uri VARCHAR(1024),
    password_uri VARCHAR(1024),
    metadata JSONB,
    FOREIGN KEY (domain_id) REFERENCES hiro.domains(id) ON DELETE CASCADE,
    FOREIGN KEY (token_secret_id) REFERENCES hiro.secrets(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS application_client_id ON hiro.applications(domain_id, client_id);
CREATE UNIQUE INDEX IF NOT EXISTS application_name ON hiro.applications(domain_id, name);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.applications;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.applications
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

CREATE TABLE IF NOT EXISTS hiro.application_permissions(
  application_id UUID NOT NULL,
  instance_id UUID NOT NULL,
  permission_id UUID NOT NULL,
  PRIMARY KEY(application_id, instance_id, permission_id),
  FOREIGN KEY (application_id) REFERENCES hiro.applications(id) ON DELETE CASCADE,
  FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES hiro.api_permissions(id) ON DELETE CASCADE  
);

CREATE TABLE IF NOT EXISTS hiro.application_grants(
  application_id UUID NOT NULL REFERENCES hiro.applications(id) ON DELETE CASCADE,
  grant_type hiro.GRANT_TYPE NOT NULL,
  PRIMARY KEY(application_id, grant_type)
);

CREATE TABLE IF NOT EXISTS hiro.application_uris(
  application_id UUID NOT NULL REFERENCES hiro.applications(id) ON DELETE CASCADE,
  instance_id UUID NOT NULL REFERENCES hiro.instances(id) ON DELETE CASCADE,
  uri VARCHAR(1024) NOT NULL,
  PRIMARY KEY(application_id, instance_id, uri)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.applications;
DROP TABLE hiro.application_permissions;
DROP TABLE hiro.application_grants;
DROP TABLE hiro.application_uris;