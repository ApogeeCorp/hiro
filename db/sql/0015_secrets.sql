-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.secrets(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(32) NOT NULL,
    instance_id UUID NOT NULL,
    algorithm VARCHAR(16),
    key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    default BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IN NOT EXISTS secret_default ON hiro.secrets(instance_id, default) WHERE default;

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.secrets;