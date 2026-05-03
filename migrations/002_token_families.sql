CREATE TABLE IF NOT EXISTS token_families (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_token_families_user_client ON token_families(user_id, client_id);

ALTER TABLE oauth2_tokens ADD COLUMN IF NOT EXISTS family_id UUID REFERENCES token_families(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_tokens_family_id ON oauth2_tokens(family_id);
