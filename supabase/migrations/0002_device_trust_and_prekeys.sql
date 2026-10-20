-- 0002: fix device self-approval gap, add trusted-device approval, device revoke, atomic one-time-prekey claim.

drop policy if exists dev_update_self on public.devices;
drop policy if exists dev_insert on public.devices;
revoke update on public.devices from authenticated;
grant update (name, last_active_at) on public.devices to authenticated;

create policy dev_insert on public.devices for insert to authenticated
  with check (user_id = auth.uid() and public.is_active_member());
create policy dev_update_self on public.devices for update to authenticated
  using (user_id = auth.uid() and revoked_at is null) with check (user_id = auth.uid());

-- Server decides trust: first device of an approved user is trusted on first use; every later device starts PENDING.
create function public.devices_before_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.revoked_at := null;
  if exists (select 1 from devices where user_id = new.user_id and approved_at is not null and revoked_at is null) then
    new.approved_at := null;
  else
    new.approved_at := now();
  end if;
  return new;
end $$;
create trigger trg_devices_before_insert before insert on public.devices
  for each row execute function public.devices_before_insert();

-- A new device must be approved from an already-trusted device of the same user.
create function public.approve_device(p_device uuid, p_from_device uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_active_member() then raise exception 'forbidden' using errcode = '42501'; end if;
  if not exists (select 1 from devices where id = p_from_device and user_id = auth.uid()
                 and approved_at is not null and revoked_at is null) then
    raise exception 'approving device not trusted' using errcode = '42501';
  end if;
  update devices set approved_at = now()
   where id = p_device and user_id = auth.uid() and revoked_at is null and approved_at is null;
  if not found then raise exception 'no such pending device'; end if;
  perform public.log_audit('device.approved', jsonb_build_object('device', p_device));
end $$;
revoke execute on function public.approve_device(uuid, uuid) from public, anon;
grant  execute on function public.approve_device(uuid, uuid) to authenticated;

create function public.revoke_device(p_device uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_active_member() then raise exception 'forbidden' using errcode = '42501'; end if;
  update devices set revoked_at = now() where id = p_device and user_id = auth.uid() and revoked_at is null;
  if not found then raise exception 'no such device'; end if;
  delete from push_tokens where device_id = p_device;
  perform public.log_audit('device.revoked', jsonb_build_object('device', p_device));
end $$;
revoke execute on function public.revoke_device(uuid) from public, anon;
grant  execute on function public.revoke_device(uuid) to authenticated;

-- Atomic bundle fetch: consumes one one-time prekey; caller must share a conversation with the device owner.
create function public.claim_prekey_bundle(p_device uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare d devices%rowtype; pk device_prekeys%rowtype;
begin
  if not public.is_active_member() then raise exception 'forbidden' using errcode = '42501'; end if;
  select * into d from devices where id = p_device and revoked_at is null and approved_at is not null;
  if not found then raise exception 'unknown device'; end if;
  if not exists (select 1 from conversation_members a join conversation_members b on a.conversation_id = b.conversation_id
                 where a.user_id = auth.uid() and b.user_id = d.user_id and a.left_at is null and b.left_at is null) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  delete from device_prekeys where ctid = (
      select ctid from device_prekeys where device_id = p_device order by key_id limit 1 for update skip locked)
    returning * into pk;
  return jsonb_build_object(
    'registration_id', d.registration_id,
    'identity_key', encode(d.identity_key, 'base64'),
    'signed_prekey', d.signed_prekey,
    'prekey', case when pk.key_id is null then null
                   else jsonb_build_object('id', pk.key_id, 'public', encode(pk.public_key, 'base64')) end);
end $$;
revoke execute on function public.claim_prekey_bundle(uuid) from public, anon;
grant  execute on function public.claim_prekey_bundle(uuid) to authenticated;
