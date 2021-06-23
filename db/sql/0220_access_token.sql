-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.access_tokens(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id UUID NOT NULL,
    application_id UUID NOT NULL,
    issuer TEXT,
    user_id UUID,
    token_use VARCHAR(64),
    scope JSONB,
    claims JSONB,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES hiro.applications(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES hiro.users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS access_token_user ON hiro.access_tokens(user_id);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.access_tokens;