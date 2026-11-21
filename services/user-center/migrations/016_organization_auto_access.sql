-- Opt-in automatic admission for active organization members; explicit revocation wins.
ALTER TABLE apps ADD COLUMN organization_auto_access boolean NOT NULL DEFAULT false;
ALTER TABLE user_app_access ADD COLUMN admission_origin text NOT NULL DEFAULT 'explicit'
    CONSTRAINT ck_app_admission_origin CHECK (admission_origin IN ('explicit','organization'));
