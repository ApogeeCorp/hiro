-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE IF NOT EXISTS hiro.instances(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(256) NOT NULL,
    description VARCHAR(1024),
    api_id UUID NOT NULL,
    audience VARCHAR(1024) NOT NULL UNIQUE,
    refresh_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000, 
    token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    session_lifetime BIGINT NOT NULL DEFAULT 3600000000000, 
    login_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    invite_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    verify_token_lifetime BIGINT NOT NULL DEFAULT 3600000000000,
    auth_code_lifetime BIGINT NOT NULL DEFAULT 600000000000,
    metadata JSONB,
    CONSTRAINT instance_api_pk FOREIGN KEY (api_id) REFERENCES hiro.apis(id) ON DELETE RESTRICT
);

DROP TRIGGER IF EXISTS update_timestamp ON hiro.instances;

CREATE TRIGGER update_timestamp
  BEFORE UPDATE ON hiro.instances
  FOR EACH ROW
  EXECUTE PROCEDURE hiro.update_timestamp("updated_at");

-- +migrate Down
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE hiro.instances;