-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS hiro.access_tokens(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id UUID,
    claims JSON NOT NULL,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    redirect_uri TEXT,
    FOREIGN KEY (user_id) REFERENCES hiro.users(id) ON DELETE CASCADE
);


CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.access_tokens
  FOR EACH ROW
  EXECUTE PROCEDURE update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.access_tokens;