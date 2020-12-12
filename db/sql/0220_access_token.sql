-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.access_tokens(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    audience_id UUID NOT NULL,
    application_id UUID NOT NULL,
    user_id UUID,
    token_use VARCHAR(64),
    scope JSONB,
    claims JSONB,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (audience_id) REFERENCES hiro.audiences(id) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES hiro.applications(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES hiro.users(id) ON DELETE CASCADE
);

CREATE INDEX access_token_user ON hiro.access_tokens(user_id);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.access_tokens;