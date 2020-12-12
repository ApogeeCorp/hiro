-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.request_tokens(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    audience_id UUID NOT NULL,
    application_id UUID NOT NULL,
    scope JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method CHAR(4) NOT NULL DEFAULT 'S256',
    app_uri TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    state TEXT,
    FOREIGN KEY (audience_id) REFERENCES hiro.audiences(id) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES hiro.applications(id) ON DELETE CASCADE
);

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.request_tokens;