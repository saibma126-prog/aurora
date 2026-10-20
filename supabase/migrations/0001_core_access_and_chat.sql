-- 0001: invitation-only access, roles, devices, chat, receipts, blocks, reports, settings, audit.
-- STATUS: written, NOT yet executed against a real Postgres/Supabase instance. Run tests in /supabase/tests before trusting.
create extension if not exists pgcrypto;
create extension if not exists citext;

create type member_status as enum ('invited','active','suspended','revoked');
create type member_role   as enum ('member','admin');

-- ---------- Invitations (admin pre-approves emails) ----------
create table public.allowed_emails (
  email        citext primary key,
  display_name text not null,
  status       member_status not null default 'invited',
  invited_by   uuid,
  created_at   timestamptz not null default now()
);

-- ---------- Profiles (DP only + admin-assigned display name) ----------
create table public.profiles (
  id               uuid primary key references auth.users(id) on delete cascade,
  email            citext not null unique,
  display_name     text not null,
  role             member_role not null default 'member',
  status           member_status not null default 'active',
  dp_path          text,
  show_last_seen   boolean not null default true,
  hide_lock_preview boolean not null default true,
  created_at       timestamptz not null default now()
);

-- ---------- Helper functions (server-side authority; never trust client flags) ----------
create function public.is_active_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles p where p.id = auth.uid() and p.status = 'active');
$$;

create function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles p where p.id = auth.uid() and p.role = 'admin' and p.status = 'active');
$$;

-- Admin writes additionally require MFA (aal2).
create function public.is_admin_aal2() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_admin() and coalesce(auth.jwt() ->> 'aal', '') = 'aal2';
$$;

-- ---------- Auth hook: block signup for non-approved emails (also blocks direct API calls) ----------
-- Enable in Dashboard: Auth > Hooks > "Before User Created" -> public.hook_before_user_created
create function public.hook_before_user_created(event jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare em text := lower(event -> 'user' ->> 'email');
begin
  if em is null or not exists (
       select 1 from allowed_emails a where a.email = em::citext and a.status in ('invited','active')) then
    return jsonb_build_object('error', jsonb_build_object('message','Sign-in is not available for this account.','http_code',403));
  end if;
  return '{}'::jsonb;
end $$;
revoke execute on function public.hook_before_user_created(jsonb) from public, anon, authenticated;
grant  execute on function public.hook_before_user_created(jsonb) to supabase_auth_admin;

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare a allowed_emails%rowtype;
begin
  select * into a from allowed_emails where email = lower(new.email)::citext;
  if not found or a.status not in ('invited','active') then
    raise exception 'not approved';
  end if;
  insert into profiles(id, email, display_name, status) values (new.id, lower(new.email)::citext, a.display_name, 'active');
  update allowed_emails set status = 'active' where email = a.email;
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
-- Bootstrap the first admin ONCE, manually, in the SQL editor (no hardcoded admin in code):
--   update public.profiles set role='admin' where email='YOUR_ADMIN_EMAIL';  then enrol TOTP MFA.

-- ---------- Devices & E2EE public key material (private keys NEVER reach the server) ----------
create table public.devices (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references profiles(id) on delete cascade,
  name             text not null,
  platform         text not null default 'android',
  registration_id  int  not null,
  identity_key     bytea not null,
  signed_prekey    jsonb not null,
  approved_at      timestamptz,
  revoked_at       timestamptz,
  created_at       timestamptz not null default now(),
  last_active_at   timestamptz
);
create index on public.devices(user_id) where revoked_at is null;

create table public.device_prekeys (
  device_id  uuid references devices(id) on delete cascade,
  key_id     int not null,
  public_key bytea not null,
  primary key (device_id, key_id)
);

create table public.push_tokens (
  device_id uuid primary key references devices(id) on delete cascade,
  user_id   uuid not null references profiles(id) on delete cascade,
  fcm_token text not null,
  updated_at timestamptz not null default now()
);

-- ---------- Conversations ----------
create table public.conversations (
  id         uuid primary key default gen_random_uuid(),
  kind       text not null check (kind in ('direct','group')),
  title      text,
  direct_key text unique,
  created_by uuid not null references profiles(id),
  created_at timestamptz not null default now()
);

create table public.conversation_members (
  conversation_id uuid references conversations(id) on delete cascade,
  user_id         uuid references profiles(id) on delete cascade,
  role            text not null default 'member' check (role in ('owner','admin','member')),
  muted_until     timestamptz,
  pinned          boolean not null default false,
  archived        boolean not null default false,
  joined_at       timestamptz not null default now(),
  left_at         timestamptz,
  primary key (conversation_id, user_id)
);
create index on public.conversation_members(user_id) where left_at is null;

create function public.is_conv_member(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_active_member() and exists (
    select 1 from conversation_members m
    where m.conversation_id = cid and m.user_id = auth.uid() and m.left_at is null);
$$;

-- ---------- Blocks / reports ----------
create table public.blocks (
  blocker uuid references profiles(id) on delete cascade,
  blocked uuid references profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker, blocked)
);
create table public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter uuid not null references profiles(id),
  reported_user uuid references profiles(id),
  conversation_id uuid references conversations(id),
  reason text not null check (char_length(reason) <= 1000),
  created_at timestamptz not null default now()
);

create function public.dm_blocked(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from conversations c
    join conversation_members a on a.conversation_id = c.id
    join conversation_members b on b.conversation_id = c.id and b.user_id <> a.user_id
    join blocks bl on (bl.blocker = a.user_id and bl.blocked = b.user_id)
    where c.id = cid and c.kind = 'direct');
$$;

-- ---------- Messages: metadata row + per-recipient-device ciphertext envelopes ----------
create table public.messages (
  id               uuid primary key default gen_random_uuid(),
  conversation_id  uuid not null references conversations(id) on delete cascade,
  sender_id        uuid not null references profiles(id),
  sender_device_id uuid not null references devices(id),
  client_msg_id    uuid not null,
  kind             text not null default 'text' check (kind in ('text','media','voice','doc','control')),
  created_at       timestamptz not null default now(),
  deleted_at       timestamptz,
  unique (sender_device_id, client_msg_id)
);
create index on public.messages(conversation_id, created_at desc);

create table public.message_envelopes (
  message_id          uuid references messages(id) on delete cascade,
  recipient_device_id uuid references devices(id) on delete cascade,
  ciphertext          bytea not null,
  primary key (message_id, recipient_device_id)
);
create index on public.message_envelopes(recipient_device_id);

create table public.message_receipts (
  message_id   uuid references messages(id) on delete cascade,
  user_id      uuid references profiles(id) on delete cascade,
  delivered_at timestamptz,
  read_at      timestamptz,
  primary key (message_id, user_id)
);

create table public.message_hidden (
  user_id uuid references profiles(id) on delete cascade,
  message_id uuid references messages(id) on delete cascade,
  primary key (user_id, message_id)
);

create table public.attachments (
  id uuid primary key default gen_random_uuid(),
  message_id uuid not null references messages(id) on delete cascade,
  storage_path text not null unique,
  size_bytes bigint not null check (size_bytes > 0 and size_bytes <= 26214400),
  created_at timestamptz not null default now()
);

create function public.rate_limit_messages() returns trigger language plpgsql as $$
begin
  if (select count(*) from messages where sender_id = new.sender_id and created_at > now() - interval '60 seconds') >= 60 then
    raise exception 'rate limit exceeded' using errcode = 'P0001';
  end if;
  return new;
end $$;
create trigger trg_rate_limit before insert on public.messages for each row execute function public.rate_limit_messages();

create function public.on_message_deleted() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.deleted_at is not null and old.deleted_at is null then
    delete from message_envelopes where message_id = new.id;
    delete from attachments where message_id = new.id;
  end if;
  return new;
end $$;
create trigger trg_msg_deleted after update of deleted_at on public.messages for each row execute function public.on_message_deleted();

-- ---------- Calls ----------
create table public.calls (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references conversations(id) on delete cascade,
  caller_id uuid not null references profiles(id),
  kind text not null check (kind in ('audio','video')),
  state text not null default 'ringing' check (state in ('ringing','active','declined','missed','ended','busy','expired')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '45 seconds',
  answered_at timestamptz,
  ended_at timestamptz
);

-- ---------- Admin-controlled global settings ----------
create table public.app_settings (
  id int primary key default 1 check (id = 1),
  theme jsonb not null default '{"name":"Midnight","mode":"dark","accent":"#7C9CFF","bubbleOut":"#2B3A67","bubbleIn":"#1B1F2A","wallpaper":"plain-dark","fontScale":1.0}',
  ringtone_path text,
  updated_by uuid references profiles(id),
  updated_at timestamptz not null default now()
);
insert into public.app_settings default values on conflict do nothing;

-- ---------- Audit log (hash chain, append-only) ----------
create table public.audit_log (
  id bigserial primary key,
  at timestamptz not null default now(),
  actor uuid,
  action text not null,
  detail jsonb not null default '{}',
  prev_hash text,
  hash text not null default ''
);
create function public.audit_chain() returns trigger language plpgsql as $$
declare ph text;
begin
  perform pg_advisory_xact_lock(7001);
  select hash into ph from audit_log order by id desc limit 1;
  new.prev_hash := ph;
  new.hash := encode(digest(coalesce(ph,'') || new.at::text || coalesce(new.actor::text,'') || new.action || new.detail::text, 'sha256'), 'hex');
  return new;
end $$;
create trigger trg_audit_chain before insert on public.audit_log for each row execute function public.audit_chain();
create function public.audit_immutable() returns trigger language plpgsql as $$
begin raise exception 'audit_log is append-only'; end $$;
create trigger trg_audit_no_mod before update or delete on public.audit_log for each row execute function public.audit_immutable();

create function public.log_audit(p_action text, p_detail jsonb default '{}') returns void
language sql security definer set search_path = public as $$
  insert into audit_log(actor, action, detail) values (auth.uid(), p_action, p_detail);
$$;
revoke execute on function public.log_audit(text, jsonb) from public, anon, authenticated;

-- ---------- Encrypted backups ----------
create table public.backups (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  storage_path text not null,
  size_bytes bigint not null,
  sha256 text not null,
  created_at timestamptz not null default now()
);

-- ---------- Admin actions ----------
create function public.admin_revoke_member(target uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin_aal2() then raise exception 'forbidden' using errcode = '42501'; end if;
  if target = auth.uid() then raise exception 'cannot revoke self'; end if;
  update allowed_emails set status = 'revoked' where email = (select email from profiles where id = target);
  update profiles set status = 'revoked' where id = target;
  update devices set revoked_at = now() where user_id = target and revoked_at is null;
  delete from push_tokens where user_id = target;
  update conversation_members set left_at = now() where user_id = target and left_at is null;
  delete from auth.sessions where user_id = target;
  perform public.log_audit('member.revoked', jsonb_build_object('target', target));
end $$;
revoke execute on function public.admin_revoke_member(uuid) from public, anon;
grant  execute on function public.admin_revoke_member(uuid) to authenticated;

create function public.admin_invite_member(p_email text, p_name text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin_aal2() then raise exception 'forbidden' using errcode = '42501'; end if;
  insert into allowed_emails(email, display_name, invited_by) values (lower(p_email)::citext, p_name, auth.uid())
    on conflict (email) do update set display_name = excluded.display_name, status = 'invited';
  perform public.log_audit('member.invited', jsonb_build_object('email', lower(p_email)));
end $$;
revoke execute on function public.admin_invite_member(text, text) from public, anon;
grant  execute on function public.admin_invite_member(text, text) to authenticated;

-- ---------- Conversation creation RPCs ----------
create function public.create_direct_conversation(other uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare cid uuid; k text;
begin
  if not public.is_active_member() then raise exception 'forbidden' using errcode = '42501'; end if;
  if other = auth.uid() or not exists (select 1 from profiles where id = other and status = 'active' and role = 'member') then
    raise exception 'invalid target'; end if;
  if exists (select 1 from blocks where (blocker = other and blocked = auth.uid()) or (blocker = auth.uid() and blocked = other)) then
    raise exception 'blocked'; end if;
  k := least(auth.uid()::text, other::text) || ':' || greatest(auth.uid()::text, other::text);
  select id into cid from conversations where direct_key = k;
  if cid is null then
    insert into conversations(kind, direct_key, created_by) values ('direct', k, auth.uid()) returning id into cid;
    insert into conversation_members(conversation_id, user_id) values (cid, auth.uid()), (cid, other);
  end if;
  return cid;
end $$;
revoke execute on function public.create_direct_conversation(uuid) from public, anon;
grant  execute on function public.create_direct_conversation(uuid) to authenticated;

create function public.create_group(p_title text, p_members uuid[]) returns uuid
language plpgsql security definer set search_path = public as $$
declare cid uuid; m uuid;
begin
  if not public.is_active_member() then raise exception 'forbidden' using errcode = '42501'; end if;
  if coalesce(array_length(p_members,1),0) < 1 or array_length(p_members,1) > 63 then raise exception 'invalid member count'; end if;
  insert into conversations(kind, title, created_by) values ('group', left(p_title, 80), auth.uid()) returning id into cid;
  insert into conversation_members(conversation_id, user_id, role) values (cid, auth.uid(), 'owner');
  foreach m in array p_members loop
    if m <> auth.uid() and exists (select 1 from profiles where id = m and status = 'active' and role = 'member') then
      insert into conversation_members(conversation_id, user_id) values (cid, m) on conflict do nothing;
    end if;
  end loop;
  return cid;
end $$;
revoke execute on function public.create_group(text, uuid[]) from public, anon;
grant  execute on function public.create_group(text, uuid[]) to authenticated;

-- =====================================================================
-- RLS: deny by default, then grant narrowly
-- =====================================================================
revoke all on all tables in schema public from anon, authenticated;
do $$ declare t text; begin
  for t in select tablename from pg_tables where schemaname='public' loop
    execute format('alter table public.%I enable row level security', t);
  end loop; end $$;

grant select on public.allowed_emails, public.audit_log to authenticated;
create policy ae_admin_read    on public.allowed_emails for select to authenticated using (public.is_admin_aal2());
create policy audit_admin_read on public.audit_log      for select to authenticated using (public.is_admin_aal2());

grant select (id, display_name, dp_path) on public.profiles to authenticated;
grant update (dp_path, show_last_seen, hide_lock_preview) on public.profiles to authenticated;
create policy prof_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin() or (public.is_active_member() and role = 'member' and status = 'active'));
create policy prof_update_self on public.profiles for update to authenticated
  using (id = auth.uid() and status = 'active') with check (id = auth.uid());

grant select, insert, update on public.devices to authenticated;
create policy dev_select on public.devices for select to authenticated
  using (public.is_active_member() and (user_id = auth.uid() or exists (
    select 1 from conversation_members a join conversation_members b on a.conversation_id = b.conversation_id
    where a.user_id = auth.uid() and b.user_id = devices.user_id and a.left_at is null and b.left_at is null)));
create policy dev_insert on public.devices for insert to authenticated
  with check (user_id = auth.uid() and public.is_active_member() and approved_at is null and revoked_at is null);
create policy dev_update_self on public.devices for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
-- TODO(0002): column-restrict device updates (users must not self-approve) + approval RPC from an existing approved device.

grant select, insert, delete on public.device_prekeys to authenticated;
create policy pk_own on public.device_prekeys for all to authenticated
  using (exists (select 1 from devices d where d.id = device_id and d.user_id = auth.uid()))
  with check (exists (select 1 from devices d where d.id = device_id and d.user_id = auth.uid()));
-- TODO(0002): atomic claim_prekey RPC so one-time prekeys are consumed once.

grant select, insert, update, delete on public.push_tokens to authenticated;
create policy push_own on public.push_tokens for all to authenticated
  using (user_id = auth.uid() and public.is_active_member()) with check (user_id = auth.uid() and public.is_active_member());

grant select on public.conversations to authenticated;
create policy conv_select on public.conversations for select to authenticated using (public.is_conv_member(id));
grant select on public.conversation_members to authenticated;
grant update (muted_until, pinned, archived) on public.conversation_members to authenticated;
create policy cm_select on public.conversation_members for select to authenticated using (public.is_conv_member(conversation_id));
create policy cm_update_self on public.conversation_members for update to authenticated
  using (user_id = auth.uid() and public.is_active_member()) with check (user_id = auth.uid());

grant select, insert, delete on public.blocks to authenticated;
create policy blocks_own on public.blocks for all to authenticated
  using (blocker = auth.uid() and public.is_active_member()) with check (blocker = auth.uid() and public.is_active_member());
grant select, insert on public.reports to authenticated;
create policy rep_insert on public.reports for insert to authenticated with check (reporter = auth.uid() and public.is_active_member());
create policy rep_admin_read on public.reports for select to authenticated using (public.is_admin_aal2());

grant select, insert on public.messages to authenticated;
grant update (deleted_at) on public.messages to authenticated;
create policy msg_select on public.messages for select to authenticated using (public.is_conv_member(conversation_id));
create policy msg_insert on public.messages for insert to authenticated with check (
  sender_id = auth.uid() and public.is_conv_member(conversation_id) and not public.dm_blocked(conversation_id)
  and exists (select 1 from devices d where d.id = sender_device_id and d.user_id = auth.uid() and d.revoked_at is null and d.approved_at is not null));
create policy msg_delete_everyone on public.messages for update to authenticated
  using (sender_id = auth.uid() and public.is_conv_member(conversation_id)) with check (sender_id = auth.uid());

grant select, insert on public.message_envelopes to authenticated;
create policy env_select on public.message_envelopes for select to authenticated using (
  public.is_active_member() and exists (select 1 from devices d where d.id = recipient_device_id and d.user_id = auth.uid() and d.revoked_at is null));
create policy env_insert on public.message_envelopes for insert to authenticated with check (
  exists (select 1 from messages m where m.id = message_id and m.sender_id = auth.uid())
  and exists (select 1 from messages m join conversation_members cm on cm.conversation_id = m.conversation_id
              join devices d on d.user_id = cm.user_id
              where m.id = message_id and d.id = recipient_device_id and cm.left_at is null and d.revoked_at is null));

grant select, insert, update on public.message_receipts to authenticated;
create policy rcpt_select on public.message_receipts for select to authenticated using (
  user_id = auth.uid() or exists (select 1 from messages m where m.id = message_id and m.sender_id = auth.uid()));
create policy rcpt_insert on public.message_receipts for insert to authenticated with check (
  user_id = auth.uid() and exists (select 1 from messages m where m.id = message_id and public.is_conv_member(m.conversation_id)));
create policy rcpt_update on public.message_receipts for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

grant select, insert, delete on public.message_hidden to authenticated;
create policy hid_own on public.message_hidden for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

grant select, insert on public.attachments to authenticated;
create policy att_select on public.attachments for select to authenticated
  using (exists (select 1 from messages m where m.id = message_id and public.is_conv_member(m.conversation_id)));
create policy att_insert on public.attachments for insert to authenticated
  with check (exists (select 1 from messages m where m.id = message_id and m.sender_id = auth.uid()));

grant select on public.calls to authenticated;
create policy calls_select on public.calls for select to authenticated using (public.is_conv_member(conversation_id));

grant select on public.app_settings to authenticated;
grant update (theme, ringtone_path, updated_by, updated_at) on public.app_settings to authenticated;
create policy set_read  on public.app_settings for select to authenticated using (public.is_active_member());
create policy set_admin on public.app_settings for update to authenticated using (public.is_admin_aal2()) with check (public.is_admin_aal2());

grant select, insert, delete on public.backups to authenticated;
create policy bk_own on public.backups for all to authenticated
  using (user_id = auth.uid() and public.is_active_member()) with check (user_id = auth.uid() and public.is_active_member());

-- ---------- Realtime Authorization (private channels: conv:<id>, call:<id>, user:<uid>) ----------
create function public.topic_ok(t text) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare cid uuid;
begin
  if t = 'user:' || auth.uid()::text then return public.is_active_member(); end if;
  if t ~ '^conv:[0-9a-f-]{36}$' then return public.is_conv_member(split_part(t, ':', 2)::uuid); end if;
  if t ~ '^call:[0-9a-f-]{36}$' then
    cid := split_part(t, ':', 2)::uuid;
    return exists (select 1 from calls c where c.id = cid and public.is_conv_member(c.conversation_id) and c.state in ('ringing','active'));
  end if;
  return false;
exception when others then return false;
end $$;
create policy rt_select on realtime.messages for select to authenticated using (public.topic_ok(realtime.topic()));
create policy rt_insert on realtime.messages for insert to authenticated with check (public.topic_ok(realtime.topic()));

alter publication supabase_realtime add table public.messages, public.message_envelopes,
  public.message_receipts, public.app_settings, public.calls, public.conversation_members;

-- ---------- Storage: private buckets, membership-checked ----------
insert into storage.buckets (id, name, public, file_size_limit) values
  ('media','media',false,26214400), ('backups','backups',false,52428800),
  ('dp','dp',false,2097152), ('ringtones','ringtones',false,1048576)
on conflict (id) do nothing;

create function public.storage_conv_ok(obj_name text) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare seg text := split_part(obj_name, '/', 1);
begin
  if seg !~ '^[0-9a-f-]{36}$' then return false; end if;
  return public.is_conv_member(seg::uuid);
end $$;

create policy st_media_read   on storage.objects for select to authenticated using (bucket_id = 'media' and public.storage_conv_ok(name));
create policy st_media_insert on storage.objects for insert to authenticated with check (bucket_id = 'media' and public.storage_conv_ok(name));
create policy st_media_delete on storage.objects for delete to authenticated using (bucket_id = 'media' and owner_id = auth.uid()::text and public.is_active_member());

create policy st_bk_own on storage.objects for all to authenticated
  using (bucket_id = 'backups' and split_part(name,'/',1) = auth.uid()::text and public.is_active_member())
  with check (bucket_id = 'backups' and split_part(name,'/',1) = auth.uid()::text and public.is_active_member());

create policy st_dp_read   on storage.objects for select to authenticated using (bucket_id = 'dp' and public.is_active_member());
create policy st_dp_write  on storage.objects for insert to authenticated with check (bucket_id = 'dp' and split_part(name,'/',1) = auth.uid()::text and public.is_active_member());
create policy st_dp_update on storage.objects for update to authenticated using (bucket_id = 'dp' and split_part(name,'/',1) = auth.uid()::text);

create policy st_ring_read  on storage.objects for select to authenticated using (bucket_id = 'ringtones' and public.is_active_member());
create policy st_ring_admin on storage.objects for all to authenticated using (bucket_id = 'ringtones' and public.is_admin_aal2()) with check (bucket_id = 'ringtones' and public.is_admin_aal2());
