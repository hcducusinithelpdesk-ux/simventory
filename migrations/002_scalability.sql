-- 002: scalability — per-brand counters maintained by triggers + search/sort indexes
-- Safe to run once on an existing database (schema.sql already includes all of this).

ALTER TABLE brands ADD COLUMN cnt INTEGER NOT NULL DEFAULT 0;

-- make sure every brand used by a SIM exists, then backfill counts
INSERT OR IGNORE INTO brands (name, pos)
  SELECT DISTINCT brand, (SELECT COALESCE(MAX(pos),0) FROM brands) + 1 FROM sims;
UPDATE brands SET cnt = (SELECT COUNT(*) FROM sims WHERE sims.brand = brands.name);

CREATE TRIGGER IF NOT EXISTS trg_sims_ai AFTER INSERT ON sims BEGIN
  INSERT OR IGNORE INTO brands (name, pos) VALUES (NEW.brand, (SELECT COALESCE(MAX(pos),0)+1 FROM brands));
  UPDATE brands SET cnt = cnt + 1 WHERE name = NEW.brand;
END;

CREATE TRIGGER IF NOT EXISTS trg_sims_ad AFTER DELETE ON sims BEGIN
  UPDATE brands SET cnt = cnt - 1 WHERE name = OLD.brand;
END;

CREATE TRIGGER IF NOT EXISTS trg_sims_au_brand AFTER UPDATE OF brand ON sims WHEN OLD.brand <> NEW.brand BEGIN
  UPDATE brands SET cnt = cnt - 1 WHERE name = OLD.brand;
  INSERT OR IGNORE INTO brands (name, pos) VALUES (NEW.brand, (SELECT COALESCE(MAX(pos),0)+1 FROM brands));
  UPDATE brands SET cnt = cnt + 1 WHERE name = NEW.brand;
END;

CREATE INDEX IF NOT EXISTS ix_sims_status       ON sims(status);
CREATE INDEX IF NOT EXISTS ix_sims_brand_status ON sims(brand, status);
CREATE INDEX IF NOT EXISTS ix_sims_brand_number ON sims(brand, number_norm);
CREATE INDEX IF NOT EXISTS ix_sims_account      ON sims(account);
