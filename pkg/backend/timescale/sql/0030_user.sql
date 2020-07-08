-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS users(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    login TEXT NOT NULL,
    password_hash TEXT,
    permissions TEXT[],
    metadata JSONB,
    profile JSONB
);

CREATE UNIQUE INDEX user_login ON users(login);
CREATE UNIQUE INDEX user_email ON users((profile->>'email'));
CREATE UNIQUE INDEX user_phone ON users((profile->>'phone_number'));
CREATE UNIQUE INDEX user_sub ON users((profile->>'sub'));

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE users;