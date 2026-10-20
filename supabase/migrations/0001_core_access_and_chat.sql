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
