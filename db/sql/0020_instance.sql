-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE IF NOT EXISTS hiro.instances(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain_id UUID NOT NULL,
    api_id UUID NOT NULL,
    name VARCHAR(256) NOT NULL,
    description VARCHAR(1024),
    metadata JSONB,
    CONSTRAINT instance_api_fk FOREIGN KEY (api_id) REFERENCES hiro.apis(id) ON DELETE RESTRICT,
    CONSTRAINT instance_domain_fk FOREIGN KEY (domain_id) REFERENCES hiro.domains(id) ON DELETE RESTRICT,
    CONSTRAINT instance_domain_api UNIQUE(domain_id, api_id)
);

CREATE TABLE IF NOT EXISTS hiro.instance_endpoints(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    spec_id UUID NOT NULL,
    url VARCHAR(1024) NOT NULL,
    name VARCHAR(256),
    CONSTRAINT endpoint_spec FOREIGN KEY (spec_id) REFERENCES hiro.api_specs(id) ON DELETE RESTRICT
);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.instances;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.instances
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.instances;