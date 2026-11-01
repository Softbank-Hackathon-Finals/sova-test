-- Apply after lifecycle v1. PostgreSQL row-lock SELECT requires UPDATE on at
-- least one column. Grant UPDATE(lock_guard), never revision/revoked_at/document,
-- to a worker which only needs to lock and revalidate an existing approval.
-- A generated constant can only be assigned DEFAULT and cannot alter approval
-- content, validity, identity or revocation. No privileges are granted here.
ALTER TABLE sova_control.approvals
 ADD COLUMN IF NOT EXISTS lock_guard boolean GENERATED ALWAYS AS (false) STORED;
