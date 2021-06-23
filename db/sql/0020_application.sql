-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TYPE hiro.GRANT_TYPE AS ENUM ('authorization_code', 'client_credentials', 'password', 'refresh_token');
CREATE TYPE hiro.URI_TYPE AS ENUM ('application', 'redirect');

CREATE TABLE IF NOT EXISTS hiro.applications(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(64) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    description VARCHAR(1024),
    type TEXT NOT NULL DEFAULT 'web',
    secret_id UUID,
    uris JSONB,
    metadata JSONB,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
    FOREIGN KEY (secret_id) REFERENCES hiro.secrets(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS application_name ON hiro.applications(instance_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS application_name ON hiro.applications(instance_id, slug);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.applications;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.applications
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

DROP TRIGGER IF EXISTS update_slug ON hiro.applications;

CREATE TRIGGER update_slug
  BEFORE INSERT OR UPDATE ON hiro.applications
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_slug("name", "slug");

CREATE TABLE IF NOT EXISTS hiro.application_permissions(
  application_id UUID NOT NULL REFERENCES hiro.applications(id) ON DELETE CASCADE,
  instance_id UUID NOT NULL,
  permission TEXT NOT NULL,
  FOREIGN KEY(instance_id, permission) 
    REFERENCES hiro.instance_permissions(instance_id, permission) 
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  PRIMARY KEY(application_id, instance_id, permission)
);

CREATE TABLE IF NOT EXISTS hiro.application_grants(
  application_id UUID NOT NULL REFERENCES hiro.applications(id) ON DELETE CASCADE,
  instance_id UUID NOT NULL REFERENCES hiro.instances(id) ON DELETE CASCADE,
  grant_type hiro.GRANT_TYPE NOT NULL,
  PRIMARY KEY(application_id, instance_id, grant_type)
);

CREATE TABLE IF NOT EXISTS hiro.application_uris(
  application_id UUID NOT NULL REFERENCES hiro.applications(id) ON DELETE CASCADE,
  instance_id UUID NOT NULL REFERENCES hiro.instances(id) ON DELETE CASCADE,
  uri VARCHAR(1024) NOT NULL,
  uri_type hiro.URI_TYPE NOT NULL,
  PRIMARY KEY(application_id, instance_id, uri, uri_type)
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.applications;
DROP TABLE hiro.application_permissions;
DROP TABLE hiro.application_grants;
DROP TABLE hiro.application_uris;