-- Security tests. Run in a SCRATCH database after 0001 (+0002). Needs superuser (psql). See docs/TESTING.md.
\set ON_ERROR_STOP off
\set A '00000000-0000-0000-0000-00000000000a'
\set B '00000000-0000-0000-0000-00000000000b'
\set C '00000000-0000-0000-0000-00000000000c'
\set E '00000000-0000-0000-0000-00000000000e'
\set dA '00000000-0000-0000-0000-0000000000a1'
\set dB '00000000-0000-0000-0000-0000000000b1'
\set dB2 '00000000-0000-0000-0000-0000000000b2'
\set dC '00000000-0000-0000-0000-0000000000c1'
\set dE '00000000-0000-0000-0000-0000000000e1'

create schema if not exists t;
drop table if exists t.results; create table t.results(name text, ok boolean, info text);
create or replace function t.run(uid uuid, aal text, q text) returns text language plpgsql as $$
declare r text; n bigint;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', uid, 'aal', aal)::text, true);
  set local role authenticated;
  begin
    execute q; get diagnostics n = row_count; r := 'ok:' || n;
  exception when others then r := 'err:' || sqlstate;
  end;
  reset role;
  return r;
end $$;
create or replace function t.assert(n text, got text, want text) returns void language sql as $$
  insert into t.results values (n, got like want, got) $$;

-- ---- setup (superuser) ----
insert into allowed_emails(email, display_name) values ('a@x','Admin'),('b@x','Bee'),('c@x','Cee'),('e@x','Eee');
insert into auth.users(id,email) values (:'A','a@x'),(:'B','b@x'),(:'C','c@x'),(:'E','e@x');
update profiles set role='admin' where id = :'A';
insert into auth.sessions(user_id) values (:'C'),(:'C');
insert into devices(id,user_id,name,registration_id,identity_key,signed_prekey,approved_at) values
 (:'dA',:'A','a',1,'\x01','{}',now()),(:'dB',:'B','b',2,'\x02','{}',now()),
 (:'dC',:'C','c',3,'\x03','{}',now()),(:'dE',:'E','e',4,'\x05','{}',now());
insert into devices(id,user_id,name,registration_id,identity_key,signed_prekey) values (:'dB2',:'B','b2',5,'\x06','{}');

-- ---- 1. invitation-only access ----
select t.assert('hook rejects unapproved email', (public.hook_before_user_created('{"user":{"email":"evil@x"}}'))::text, '%error%');
select t.assert('hook accepts invited email',    (public.hook_before_user_created('{"user":{"email":"b@x"}}'))::text, '{}');
insert into auth.users(id,email) values ('00000000-0000-0000-0000-0000000000f0','evil@x');
select t.assert('unapproved signup blocked by trigger', (select count(*)::text from profiles where email='evil@x'), '0');

-- ---- 2. admin hidden / privilege escalation ----
select t.assert('member cannot see admin profile', t.run(:'B','aal1', format('select id from profiles where id=%L', :'A')), 'ok:0');
select t.assert('member cannot read emails',       t.run(:'B','aal1','select email from profiles'), 'err:42501');
select t.assert('member cannot self-promote',      t.run(:'B','aal1', format('update profiles set role=''admin'' where id=%L', :'B')), 'err:42501');
select t.assert('member cannot self-reactivate',   t.run(:'B','aal1', format('update profiles set status=''active'' where id=%L', :'B')), 'err:42501');
select t.assert('member cannot read invitations',  t.run(:'B','aal1','select * from allowed_emails'), 'ok:0');
select t.assert('member cannot read audit log',    t.run(:'B','aal1','select * from audit_log'), 'ok:0');
select t.assert('member cannot invite',            t.run(:'B','aal1',$q$select admin_invite_member('z@x','Z')$q$), 'err:42501');
select t.assert('admin w/o MFA cannot invite',     t.run(:'A','aal1',$q$select admin_invite_member('z@x','Z')$q$), 'err:42501');
select t.assert('admin with MFA can invite',       t.run(:'A','aal2',$q$select admin_invite_member('z@x','Z')$q$), 'ok:1');
select t.assert('member cannot call revoke',       t.run(:'B','aal2', format('select admin_revoke_member(%L)', :'C')), 'err:42501');
select t.assert('DM with admin refused',           t.run(:'B','aal1', format('select create_direct_conversation(%L)', :'A')), 'err:%');

-- ---- 3. admin-only theme/ringtone ----
select t.assert('member cannot change theme',      t.run(:'B','aal2',$q$update app_settings set theme='{"x":1}'$q$), 'ok:0');
select t.assert('admin w/o MFA cannot change theme', t.run(:'A','aal1',$q$update app_settings set theme='{"x":1}'$q$), 'ok:0');
select t.assert('admin MFA can change theme',      t.run(:'A','aal2',$q$update app_settings set theme='{"x":1}'$q$), 'ok:1');
select t.assert('member cannot set ringtone',      t.run(:'B','aal2',$q$update app_settings set ringtone_path='x'$q$), 'ok:0');
select t.assert('members can read settings',       t.run(:'B','aal1','select * from app_settings'), 'ok:1');

-- ---- 4. conversations / messages / envelopes ----
select t.assert('B creates DM with C', t.run(:'B','aal1', format('select create_direct_conversation(%L)', :'C')), 'ok:1');
select id as cid from conversations limit 1 \gset
select gen_random_uuid() as mid \gset
select t.assert('E cannot see conversation', t.run(:'E','aal1','select * from conversations'), 'ok:0');
select t.assert('C sees conversation',       t.run(:'C','aal1','select * from conversations'), 'ok:1');
select t.assert('E cannot post into conv', t.run(:'E','aal1', format('insert into messages(conversation_id,sender_id,sender_device_id,client_msg_id) values (%L,%L,%L,gen_random_uuid())', :'cid', :'E', :'dE')), 'err:42501');
select t.assert('B cannot spoof sender',  t.run(:'B','aal1', format('insert into messages(conversation_id,sender_id,sender_device_id,client_msg_id) values (%L,%L,%L,gen_random_uuid())', :'cid', :'C', :'dC')), 'err:42501');
select t.assert('B cannot use pending device', t.run(:'B','aal1', format('insert into messages(conversation_id,sender_id,sender_device_id,client_msg_id) values (%L,%L,%L,gen_random_uuid())', :'cid', :'B', :'dB2')), 'err:42501');
select t.assert('B sends message', t.run(:'B','aal1', format('insert into messages(id,conversation_id,sender_id,sender_device_id,client_msg_id) values (%L,%L,%L,%L,gen_random_uuid())', :'mid', :'cid', :'B', :'dB')), 'ok:1');
select t.assert('B adds envelope for C device', t.run(:'B','aal1', format('insert into
