-- Phone-first self registration shares the existing enrollment approval flow.
ALTER TABLE enrollments ALTER COLUMN email DROP NOT NULL;
ALTER TABLE enrollments ADD COLUMN phone citext;
ALTER TABLE enrollments ADD CONSTRAINT ck_enrollment_contact CHECK (num_nonnulls(email,phone)=1);
CREATE INDEX ix_enrollments_phone_created ON enrollments(phone,created_at DESC,id DESC)
    WHERE phone IS NOT NULL;
