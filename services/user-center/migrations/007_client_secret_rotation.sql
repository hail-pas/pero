ALTER TABLE oauth_clients ADD COLUMN previous_secret_hash text;
ALTER TABLE oauth_clients ADD COLUMN previous_secret_expires_at timestamptz;
ALTER TABLE oauth_clients ADD CONSTRAINT ck_previous_client_secret CHECK ((previous_secret_hash IS NULL)=(previous_secret_expires_at IS NULL));
