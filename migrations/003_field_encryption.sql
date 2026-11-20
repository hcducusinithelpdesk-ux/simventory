-- 003: field-level encryption of mobile no., account no., SIM no.
-- After this migration the API (with the DATA_KEY secret) encrypts existing rows
-- automatically on its first request, in batches, and sets meta.enc_v1 = 1.
--
--   sims.payload      AES-256-GCM blob {number, account, simNo}
--   sims.number_norm  HMAC blind index of the mobile no.   (was: plaintext normalized)
--   sims.sim_norm     HMAC blind index of the SIM no.      (was: plaintext normalized)
--   sims.account_idx  HMAC blind index of the account no.
--   sims.last4_idx    HMAC blind index of the last 4 digits of the mobile no.
--   sims.number / account / sim_no  -> '' (kept only for schema compatibility)

ALTER TABLE sims ADD COLUMN payload TEXT;
ALTER TABLE sims ADD COLUMN account_idx TEXT NOT NULL DEFAULT '';
ALTER TABLE sims ADD COLUMN last4_idx TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_sims_account_idx   ON sims(account_idx);
CREATE INDEX IF NOT EXISTS ix_sims_last4         ON sims(last4_idx);
CREATE INDEX IF NOT EXISTS ix_sims_created       ON sims(created_at, id);
CREATE INDEX IF NOT EXISTS ix_sims_brand_created ON sims(brand, created_at, id);
CREATE INDEX IF NOT EXISTS ix_sims_payload_null  ON sims(id) WHERE payload IS NULL;

-- these indexed plaintext values that no longer exist
DROP INDEX IF EXISTS ix_sims_account;
DROP INDEX IF EXISTS ix_sims_brand_number;

INSERT OR IGNORE INTO meta (k, v) VALUES ('enc_v1', 0);
