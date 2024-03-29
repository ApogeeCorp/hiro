-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.request_tokens(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id UUID NOT NULL,
    audience VARCHAR(1024),
    application_id UUID NOT NULL,
    client_id CHAR(22) NOT NULL,
    user_id UUID,
    type VARCHAR(32) NOT NULL,
    scope JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    passcode VARCHAR(64),
    code_challenge TEXT NOT NULL,
    code_challenge_method CHAR(4) NOT NULL DEFAULT 'S256',
    app_uri TEXT,
    redirect_uri TEXT,
    login_attempts INT,
    state TEXT,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES hiro.applications(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES hiro.users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS request_token_app ON hiro.request_tokens(application_id, type);
CREATE INDEX IF NOT EXISTS request_token_user ON hiro.request_tokens(user_id, type);
CREATE INDEX IF NOT EXISTS request_token_aud ON hiro.request_tokens(audience);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.request_tokens;