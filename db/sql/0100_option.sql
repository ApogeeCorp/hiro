-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.options(
    id SERIAL,
    domain_id UUID NOT NULL,
    instance_id UUID,
    key VARCHAR(256) NOT NULL,
    value JSONB,
    ttl INT NOT NULL DEFAULT 300000,
    CONSTRAINT option_domain_fk FOREIGN KEY (domain_id) REFERENCES hiro.domains(id) ON DELETE CASCADE,
    CONSTRAINT option_instance_fk FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
    CONSTRAINT option_domain_key UNIQUE(domain_id, instance_id, key)
);

CREATE UNIQUE INDEX IF NOT EXISTS option_name ON hiro.options(instance_id, key);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.options;