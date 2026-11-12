-- Experiment: the access-rules suite without its storage.objects rows. Run it
-- against the vulnerable schema to see storage tests pass on an empty bucket.
-- Otherwise identical to supabase/tests/database/access-rules.test.sql.
--
-- Acme's access rules, one test per rule. Run with `supabase test db`.
-- Each test acts the way the API does: as the anon role, or as a signed-in
-- user through request.jwt.claims. Everything runs in one transaction that
-- rolls back, so the database is left as it was.
--
-- These cover findings 2 to 7, 9, 10, 11 and 15 of the sample audit at
-- https://pulore.com/services/code-audit/sample-report. The Edge Functions and
-- the auth settings need HTTP tests, which aren't here.
begin;
create extension if not exists pgtap with schema extensions;

select plan(40);

-- Helpers, created inside the transaction and gone with the rollback.
create schema tests;
grant usage on schema tests to anon, authenticated;

-- Act as a signed-in user. The role is set separately, with set local role.
create function tests.act_as(uid uuid) returns void
language sql as $$
  select set_config('request.jwt.claims', json_build_object('sub', uid, 'role', 'authenticated')::text, true);
$$;

-- Rows the current role can see. A permission error counts as none, and any
-- other error as -1, so the test fails without stopping the run.
create function tests.visible_rows(query text) returns integer
language plpgsql as $$
declare
  n integer;
begin
  execute format('select count(*) from (%s) q', query) into n;
  return n;
exception
  when insufficient_privilege then return 0;
  when others then return -1;
end;
$$;

-- Rows a statement would change, rolled back straight away. A refusal from
-- RLS, grants, a check constraint or a foreign key counts as none.
create function tests.changed_rows(statement text) returns integer
language plpgsql as $$
declare
  n integer;
begin
  begin
    execute statement;
    get diagnostics n = row_count;
    raise exception using errcode = 'P0001', message = 'undo:' || n;
  exception
    when insufficient_privilege or check_violation or foreign_key_violation then
      return 0;
    when raise_exception then
      if sqlerrm like 'undo:%' then
        return substr(sqlerrm, 6)::integer;
      end if;
      return -1;
    when others then
      return -1;
  end;
end;
$$;

-- The current user creates a studio, makes themselves its client, writes an
-- invoice naming another studio's file, and counts what they can then read.
-- Everything is rolled back.
create function tests.read_through_own_studio(target text) returns integer
language plpgsql as $$
declare
  studio uuid;
  client uuid;
  n integer;
begin
  begin
    insert into public.workspaces (name, slug, owner_id)
    values ('Crafted', 'crafted-' || replace(gen_random_uuid()::text, '-', ''), auth.uid())
    returning id into studio;
    -- Without the owner trigger, the open join policy lets them add themselves.
    begin
      insert into public.workspace_members (workspace_id, user_id, role) values (studio, auth.uid(), 'owner');
    exception when others then null;
    end;
    insert into public.clients (workspace_id, user_id, name, email)
    values (studio, auth.uid(), 'Crafted', 'crafted@example.com')
    returning id into client;
    begin
      insert into public.invoices (workspace_id, client_id, number, amount_cents, pdf_path)
      values (studio, client, 'X-1', 0, target);
    exception when check_violation or insufficient_privilege then null;
    end;
    select count(*) into n from storage.objects where bucket_id = 'invoices' and name = target;
    raise exception using errcode = 'P0001', message = 'undo:' || n;
  exception
    when raise_exception then
      if sqlerrm like 'undo:%' then
        return substr(sqlerrm, 6)::integer;
      end if;
      return -1;
    when others then
      return -1;
  end;
end;
$$;

-- An owner writes an invoice for their own client naming another studio's
-- file, then the client counts what they can read. Rolled back.
create function tests.read_through_owner_invoice(owner uuid, studio uuid, client_row uuid, client_user uuid, target text)
returns integer
language plpgsql as $$
declare
  n integer;
begin
  begin
    perform tests.act_as(owner);
    begin
      insert into public.invoices (workspace_id, client_id, number, amount_cents, pdf_path)
      values (studio, client_row, 'X-2', 0, target);
    exception when check_violation or insufficient_privilege then null;
    end;
    perform tests.act_as(client_user);
    select count(*) into n from storage.objects where bucket_id = 'invoices' and name = target;
    raise exception using errcode = 'P0001', message = 'undo:' || n;
  exception
    when raise_exception then
      if sqlerrm like 'undo:%' then
        return substr(sqlerrm, 6)::integer;
      end if;
      return -1;
    when others then
      return -1;
  end;
end;
$$;

-- The owner removes a member, then the member counts the projects, invoices,
-- messages and files of the client row they were linked to. Rolled back.
create function tests.access_after_removal(owner uuid, studio uuid, member uuid, client_row uuid) returns integer
language plpgsql as $$
declare
  n integer := 0;
  m integer;
begin
  begin
    perform tests.act_as(owner);
    delete from public.workspace_members where workspace_id = studio and user_id = member;
    perform tests.act_as(member);
    select count(*) into m from public.projects where client_id = client_row;
    n := n + m;
    select count(*) into m from public.invoices where client_id = client_row;
    n := n + m;
    select count(*) into m from public.messages where workspace_id = studio;
    n := n + m;
    select count(*) into m from storage.objects where bucket_id = 'invoices' and name like studio::text || '/%';
    n := n + m;
    raise exception using errcode = 'P0001', message = 'undo:' || n;
  exception
    when raise_exception then
      if sqlerrm like 'undo:%' then
        return substr(sqlerrm, 6)::integer;
      end if;
      return -1;
    when others then
      return -1;
  end;
end;
$$;

-- The current user creates an invite. Its token is kept for the next tests.
create function tests.create_invite(studio uuid, invitee text, invite_role text) returns text
language plpgsql as $$
declare
  t text;
begin
  insert into public.workspace_invites (workspace_id, email, role)
  values (studio, invitee, invite_role)
  returning token into t;
  perform set_config('tests.token', t, true);
  return t;
exception when others then
  return null;
end;
$$;

-- A user accepts an invite, and we read back their role in the studio.
create function tests.accept_as(invite_token text, member uuid, studio uuid) returns text
language plpgsql as $$
declare
  r text;
begin
  perform tests.act_as(member);
  perform public.accept_invite(invite_token);
  select m.role into r from public.workspace_members m where m.workspace_id = studio and m.user_id = member;
  return coalesce(r, 'none');
exception when others then
  return 'error ' || sqlstate;
end;
$$;

grant execute on all functions in schema tests to anon, authenticated;

-- The answer key: every invoice with its studio and client, read as postgres
-- before any test switches role, so RLS can't filter it. Tests compare the
-- invoice IDs a user gets with the IDs they should get.
create table tests.invoice_key as
  select id, workspace_id, client_id from public.invoices;
grant select on tests.invoice_key to anon, authenticated;

-- Experiment: no rows are added to storage.objects.

-- Structure
select is(
  (select count(*)::integer from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind in ('r', 'p') and not c.relrowsecurity),
  0, 'RLS is on for every table in public');

select is(
  (select count(*)::integer from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind = 'v'
     and coalesce(array_to_string(c.reloptions, ','), '') !~* 'security_invoker=(true|on|yes|1)'),
  0, 'every view in public runs as the caller');

select is((select public from storage.buckets where id = 'invoices'), false, 'the invoices bucket is private');

select is(
  (select allowed_mime_types = array['application/pdf'] and file_size_limit = 10485760
   from storage.buckets where id = 'invoices'),
  true, 'the invoices bucket takes only PDFs, up to 10 MB');

-- Signed out
set local role anon;
set local request.jwt.claims = '{"role": "anon"}';

select is(tests.visible_rows('select 1 from public.invoices'), 0, 'signed out: no invoices');
select is(tests.visible_rows('select 1 from public.messages'), 0, 'signed out: no messages');
select is(tests.changed_rows($$insert into public.messages (workspace_id, project_id, sender_id, body)
  values ('a1de5000-0000-4000-8000-000000000001', md5('alder-project-1')::uuid,
          '11111111-1111-4111-8111-111111111111', 'test')$$), 0, 'signed out: can''t post messages');
select is(tests.visible_rows('select 1 from public.client_overview'), 0, 'signed out: nothing from client_overview');
select is(tests.visible_rows($$select 1 from storage.objects where bucket_id = 'invoices'$$), 0, 'signed out: can''t list invoice files');
select throws_ok('select public.get_pdf_settings()', '42501', null, 'signed out: can''t call get_pdf_settings()');

-- Ana, a client of Juniper Dev
set local role authenticated;
set local request.jwt.claims = '{"sub": "66666666-6666-4666-8666-666666666666", "role": "authenticated"}';

select is(tests.visible_rows($$select 1 from public.invoices where workspace_id = 'a1de5000-0000-4000-8000-000000000001'$$),
  0, 'Ana: none of Alder''s invoices');
select is(tests.changed_rows($$insert into public.workspace_members (workspace_id, user_id, role)
  values ('a1de5000-0000-4000-8000-000000000001', '66666666-6666-4666-8666-666666666666', 'owner')$$),
  0, 'Ana: can''t add herself to Alder');
select is(tests.visible_rows($$select 1 from storage.objects where bucket_id = 'invoices'
  and name like 'a1de5000-0000-4000-8000-000000000001/%'$$), 0, 'Ana: can''t list Alder''s invoice files');
select is(tests.changed_rows($$update storage.objects set metadata = metadata where bucket_id = 'invoices'
  and name like 'a1de5000-0000-4000-8000-000000000001/%'$$), 0, 'Ana: can''t overwrite Alder''s invoice files');

-- Sam, a client of Alder Studio
set local request.jwt.claims = '{"sub": "33333333-3333-4333-8333-333333333333", "role": "authenticated"}';

select set_eq(
  'select id from public.invoices',
  $$select id from tests.invoice_key where client_id = 'c1000000-0000-4000-8000-000000000001'$$,
  'Sam: exactly his own 20 invoices, by ID');
select is_empty(
  $$select client_id, number from public.invoices
    where client_id is distinct from 'c1000000-0000-4000-8000-000000000001' order by client_id, number$$,
  'Sam: no invoice of another client');
select set_eq(
  'select client_id from public.client_overview',
  $$values ('c1000000-0000-4000-8000-000000000001'::uuid)$$,
  'Sam: only his own row in client_overview');
select is(tests.changed_rows($$update public.profiles set role = 'admin' where id = '33333333-3333-4333-8333-333333333333'$$),
  0, 'Sam: can''t make himself an admin');
select is(tests.changed_rows($$update public.profiles set full_name = 'Sam R.' where id = '33333333-3333-4333-8333-333333333333'$$),
  1, 'Sam: can still change his name');
select is(tests.changed_rows($$insert into public.messages (workspace_id, project_id, sender_id, body)
  values ('a1de5000-0000-4000-8000-000000000001', md5('alder-project-1')::uuid,
          '11111111-1111-4111-8111-111111111111', 'posing as Maya')$$), 0, 'Sam: can''t post as someone else');
select is(tests.visible_rows($$select 1 from public.profiles where id = '44444444-4444-4444-8444-444444444444'$$),
  0, 'Sam: can''t see Priya, another client, in profiles');
select is(tests.visible_rows($$select 1 from public.workspace_members where user_id = '44444444-4444-4444-8444-444444444444'$$),
  0, 'Sam: can''t see Priya''s membership');
select is(tests.visible_rows($$select 1 from public.profiles where id = '11111111-1111-4111-8111-111111111111'$$),
  1, 'Sam: can still see Maya, the studio''s owner');
select is(tests.read_through_own_studio('a1de5000-0000-4000-8000-000000000001/INV-2026-0025.pdf'),
  0, 'Sam: can''t read Priya''s PDF through an invoice he writes in a studio of his own');

-- Regression case: the wrong client with the same number of invoices. A bad
-- backfill links Sam's login to Priya's client record and hers to his. Both
-- have 20 invoices, so a count can't tell them apart, and the IDs can. The
-- links are swapped back straight after.
reset role;
update public.clients
set user_id = case id
  when 'c1000000-0000-4000-8000-000000000001' then '44444444-4444-4444-8444-444444444444'::uuid
  else '33333333-3333-4333-8333-333333333333'::uuid
end
where id in ('c1000000-0000-4000-8000-000000000001', 'c1000000-0000-4000-8000-000000000002');
set local role authenticated;

select is(tests.visible_rows('select 1 from public.invoices'), 20,
  'regression case: linked to Priya''s record, Sam still counts 20 invoices');
select set_eq(
  'select id from public.invoices',
  $$select id from tests.invoice_key where client_id = 'c1000000-0000-4000-8000-000000000002'$$,
  'regression case: the IDs show they''re Priya''s 20, not his');

reset role;
update public.clients
set user_id = case id
  when 'c1000000-0000-4000-8000-000000000001' then '33333333-3333-4333-8333-333333333333'::uuid
  else '44444444-4444-4444-8444-444444444444'::uuid
end
where id in ('c1000000-0000-4000-8000-000000000001', 'c1000000-0000-4000-8000-000000000002');
set local role authenticated;

-- Tom, Juniper Dev's owner
set local request.jwt.claims = '{"sub": "55555555-5555-4555-8555-555555555555", "role": "authenticated"}';

select is(tests.changed_rows($$update public.workspaces set plan = 'agency' where id = 'b1de5000-0000-4000-8000-000000000002'$$),
  0, 'Tom: can''t change his own plan');
select is(tests.changed_rows($$insert into public.projects (workspace_id, client_id, name)
  values ('b1de5000-0000-4000-8000-000000000002', 'c1000000-0000-4000-8000-000000000001', 'Not ours')$$),
  0, 'Tom: can''t attach Alder''s client to a Juniper project');
select is(tests.changed_rows($$insert into public.invoices (workspace_id, project_id, client_id, number, amount_cents)
  values ('b1de5000-0000-4000-8000-000000000002', md5('alder-project-1')::uuid,
          'c2000000-0000-4000-8000-000000000001', 'X-3', 0)$$),
  0, 'Tom: can''t attach Alder''s project to a Juniper invoice');
select is(tests.read_through_owner_invoice('55555555-5555-4555-8555-555555555555', 'b1de5000-0000-4000-8000-000000000002',
    'c2000000-0000-4000-8000-000000000001', '66666666-6666-4666-8666-666666666666',
    'a1de5000-0000-4000-8000-000000000001/INV-2026-0007.pdf'),
  0, 'Tom: can''t point an invoice for Ana at an Alder PDF for her to read');

-- Leo, Alder Studio's staff
set local request.jwt.claims = '{"sub": "22222222-2222-4222-8222-222222222222", "role": "authenticated"}';

select set_eq(
  'select id from public.invoices',
  $$select id from tests.invoice_key where workspace_id = 'a1de5000-0000-4000-8000-000000000001'$$,
  'Leo: exactly Alder''s 60 invoices, by ID');
select is(tests.changed_rows($$insert into public.workspace_invites (workspace_id, email, role, token)
  values ('a1de5000-0000-4000-8000-000000000001', 'nobody@example.com', 'client', 'x')$$),
  0, 'Leo: can''t choose an invite''s token');
select is(tests.changed_rows($$insert into public.workspace_invites (workspace_id, email, role, expires_at)
  values ('a1de5000-0000-4000-8000-000000000001', 'nobody@example.com', 'client', '2099-01-01')$$),
  0, 'Leo: can''t choose an invite''s expiry');

-- Removing a client
select is(tests.access_after_removal('11111111-1111-4111-8111-111111111111', 'a1de5000-0000-4000-8000-000000000001',
    '33333333-3333-4333-8333-333333333333', 'c1000000-0000-4000-8000-000000000001'),
  0, 'after Maya removes Sam, he reads none of his projects, invoices, messages or files');

-- The file policy on its own: with the path constraint dropped for the rest of
-- this transaction, it still refuses both crafted invoices.
reset role;
alter table public.invoices drop constraint if exists invoices_pdf_path_matches_invoice;
set local role authenticated;
set local request.jwt.claims = '{"sub": "33333333-3333-4333-8333-333333333333", "role": "authenticated"}';
select is(tests.read_through_own_studio('a1de5000-0000-4000-8000-000000000001/INV-2026-0025.pdf'),
  0, 'without the path constraint, the file policy alone keeps Priya''s PDF from Sam');
select is(tests.read_through_owner_invoice('55555555-5555-4555-8555-555555555555', 'b1de5000-0000-4000-8000-000000000002',
    'c2000000-0000-4000-8000-000000000001', '66666666-6666-4666-8666-666666666666',
    'a1de5000-0000-4000-8000-000000000001/INV-2026-0007.pdf'),
  0, 'without the path constraint, the file policy alone keeps Sam''s PDF from Ana');

-- Invites, end to end. These change memberships until the final rollback.
set local request.jwt.claims = '{"sub": "11111111-1111-4111-8111-111111111111", "role": "authenticated"}';
select ok(tests.create_invite('a1de5000-0000-4000-8000-000000000001', 'ana.orbit@example.com', 'client') is not null,
  'Maya: invites Ana to Alder as a client');
select is(tests.accept_as(current_setting('tests.token', true), '66666666-6666-4666-8666-666666666666',
    'a1de5000-0000-4000-8000-000000000001'),
  'client', 'Ana: joins Alder through the invite, as a client');
select is(tests.accept_as(current_setting('tests.token', true), '66666666-6666-4666-8666-666666666666',
    'a1de5000-0000-4000-8000-000000000001'),
  'error P0002', 'Ana: the invite works only once');

set local request.jwt.claims = '{"sub": "11111111-1111-4111-8111-111111111111", "role": "authenticated"}';
do $$ begin perform tests.create_invite('a1de5000-0000-4000-8000-000000000001', 'sam.brightline@example.com', 'staff'); end $$;
select is(tests.accept_as(current_setting('tests.token', true), '33333333-3333-4333-8333-333333333333',
    'a1de5000-0000-4000-8000-000000000001'),
  'staff', 'Sam: a client invited as staff becomes staff');

reset role;
select * from finish();
rollback;
