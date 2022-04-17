-- TODO (jimlambrt 4/2002) this additional migration needs to be in a future PR.
-- We decide to NOT delete these tables now, but wait a release or two just to
-- be sure we don't need to recover the keys from these tables for anyone.
-- see: https://github.com/hashicorp/boundary/issues/2026


-- begin;

-- drop table kms_database_key_version;
-- drop table kms_database_key;
-- drop table kms_oplog_key_version;
-- drop table kms_oplog_key;
-- drop table kms_audit_key_version;
-- drop table kms_audit_key;

-- commit;