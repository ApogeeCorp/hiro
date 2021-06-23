-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.sessions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID,
    user_id UUID,
    data TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    FOREIGN KEY (instance_id) REFERENCES hiro.instances(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES hiro.users(id) ON DELETE CASCADE
);


-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.sessions;