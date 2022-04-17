begin;

-- make the required schema changes to adopt
-- github.com/hashicorp/go-kms-wrapping/extras/kms/v2 

create table kms_schema_version(
    version text not null,
    create_time wt_timestamp,
    update_time wt_timestamp
);

-- ensure that it's only ever one row
create unique index kms_schema_version_one_row
ON kms_schema_version((version is not null)); 

insert into kms_schema_version(version) values('v0.0.1');

-- we can use our existing kms_root_key table.

-- we need to add an add additional constraint to the kms_roolt_key_version
-- table: 
-- https://github.com/hashicorp/go-kms-wrapping/blob/c06f9db9380f2c26cad07cf51f7a324d25dd55ba/extras/kms/migrations/postgres/04_keys.up.sql#L29 
alter table kms_root_key_version
  add constraint not_empty_key
  check (
      length(key) > 0
    );


-- we need to create kms_data_key and kms_data_key_version tables.  we will
-- intentionally be using the boundary domain types and trigger functions. 
create table kms_data_key (
  private_id wt_private_id primary key,
  root_key_id wt_private_id not null
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  purpose text not null
    constraint not_empty_purpose
    check (
      length(trim(purpose)) > 0
    ),
  create_time wt_timestamp,
  unique (root_key_id, purpose) -- there can only be one dek for a specific purpose per root key
);
comment on table kms_data_key is
  'kms_data_key contains deks (data keys) for specific purposes derived from a kms_root_key';

 -- define the immutable fields for kms_data_key (all of them)
create trigger immutable_columns
before
update on kms_data_key
  for each row execute procedure immutable_columns('private_id', 'root_key_id', 'purpose', 'create_time');

create trigger default_create_time_column
before
insert on kms_data_key
  for each row execute procedure default_create_time();

create table kms_data_key_version (
  private_id wt_private_id primary key,
  data_key_id wt_private_id not null
    references kms_data_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id wt_private_id not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version wt_version,
  key bytea not null
    constraint not_empty_key
    check (
      length(key) > 0
    ),
  create_time wt_timestamp,
  unique(data_key_id, version)
);
comment on table kms_data_key is
  'kms_data_key_version contains versions of a kms_data_key (dek aka data keys)';

 -- define the immutable fields for kms_data_key_version (all of them)
create trigger immutable_columns
before
update on kms_data_key_version
  for each row execute procedure immutable_columns('private_id', 'data_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger default_create_time
before
insert on kms_data_key_version
  for each row execute procedure default_create_time();

create trigger kms_version_column
before insert on kms_data_key_version
	for each row execute procedure kms_version_column('data_key_id');

-- Next: we will convert all the existing DEKs into the new schema model

-- convert database DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'database', create_time
from kms_database_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, database_key_id, root_key_version_id, version, key, create_time
from kms_database_key_version;

alter table credential_vault_token drop constraint kms_database_key_version_fkey;
alter table credential_vault_token
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table credential_vault_client_certificate drop constraint kms_database_key_version_fkey;
alter table credential_vault_client_certificate
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table auth_oidc_method drop constraint kms_database_key_version_fkey;
alter table auth_oidc_method
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table host_plugin_catalog_secret drop constraint kms_database_key_version_fkey;
alter table host_plugin_catalog_secret
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

alter table session_credential drop constraint kms_database_key_version_fkey;
alter table session_credential
add constraint kms_data_key_version_fkey
    foreign key(key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;


-- convert oplog DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'oplog', create_time
from kms_oplog_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, oplog_key_id, root_key_version_id, version, key, create_time
from kms_oplog_key_version;

-- convert the audit DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'audit', create_time
from kms_audit_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, audit_key_id, root_key_version_id, version, key, create_time
from kms_audit_key_version;

-- convert the oidc DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'oidc', create_time
from kms_oidc_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, oidc_key_id, root_key_version_id, version, key, create_time
from kms_oidc_key_version;

-- convert the token DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'tokens', create_time
from kms_token_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, token_key_id, root_key_version_id, version, key, create_time
from kms_token_key_version;

-- convert the session DEK tables
insert into kms_data_key (private_id, root_key_id, purpose, create_time)
select private_id, root_key_id, 'sessions', create_time
from kms_session_key;

insert into kms_data_key_version (private_id, data_key_id, root_key_version_id, version, key, create_time)
select private_id, session_key_id, root_key_version_id, version, key, create_time
from kms_session_key_version;

commit;