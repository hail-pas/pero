ALTER TABLE audit_events ADD COLUMN details jsonb NOT NULL DEFAULT '{}';
CREATE INDEX ix_enrollments_email_created ON enrollments(email,created_at DESC,id DESC);
CREATE INDEX ix_user_app_access_app_created ON user_app_access(app_id,created_at DESC,user_id);
