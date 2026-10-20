-- Minimal stand-ins for Supabase-managed schemas so migrations/tests can run on plain Postgres (CI only; never run on Supabase).
do $$ begin
  create role anon nologin; exception when duplicate_object then null; end $$;
do $$ begin
  create role authenticated nologin; exception when duplicate_object then null; end $$;
do $$ begin
  create role service_role nologin bypassrls; exception when duplicate_object then null; end $$;
do $$ begin
  create role supabase_auth_admin nologin; exception when duplicate_object then null; end $$;
grant anon, authenticated, service_role to current_user;
create schema auth; create schema storage; create schema realtime;
create table auth.users (id uuid primary key default gen_random_uuid(), email text);
create table auth.sessions (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id) on delete cascade);
create function auth.uid() returns uuid language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claim.sub', true),''), (nullif(current_setting('request.jwt.claims', true),'')::jsonb ->> 'sub'))::uuid $$;
create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true),'')::jsonb, '{}'::jsonb) $$;
create table storage.buckets (id text primary key, name text, public boolean, file_size_limit bigint);
create table storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text, name text, owner_id text);
alter table storage.objects enable row level security;
create table realtime.messages (id uuid primary key default gen_random_uuid(), topic text, extension text);
alter table realtime.messages enable row level security;
create function realtime.topic() returns text language sql stable as $$ select nullif(current_setting('realtime.topic', true),'') $$;
create publication supabase_realtime;
grant usage on schema auth, storage, realtime, public to authenticated, anon, supabase_auth_admin, service_role;
grant select, insert, update, delete on storage.objects to authenticated;
grant select, insert on realtime.messages to authenticated;
