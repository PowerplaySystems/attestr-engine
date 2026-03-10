-- Enforce append-only behavior on ledger_entries
-- These rules silently prevent any UPDATE or DELETE operations

CREATE OR REPLACE RULE no_update_ledger AS
    ON UPDATE TO ledger_entries
    DO INSTEAD NOTHING;

CREATE OR REPLACE RULE no_delete_ledger AS
    ON DELETE TO ledger_entries
    DO INSTEAD NOTHING;
