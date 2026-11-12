-- Techniques beyond the access-rules suite, written for the post on testing
-- Supabase RLS policies: who a test runs as, results_eq and is_empty on writes
-- with returning, throws_ok, why lives_ok misleads, the two claim settings,
-- service_role and policies_are. Like the suite, it runs in one transaction
-- and rolls back.
begin;
create extension if not exists pgtap with schema extensions;

select plan(25);

-- Files for the storage test, as in the suite: a test on an empty bucket
-- passes whatever the policies say.
insert into storage.objects (bucket_id, name) values
  ('invoices', 'a1de5000-0000-4000-8000-000000000001/INV-2026-0001.pdf'),
  ('invoices', 'a1de5000-0000-4000-8000-000000000001/INV-2026-0007.pdf'),
  ('invoices', 'a1de5000-0000-4000-8000-000000000001/INV-2026-0025.pdf')
on conflict do nothing;

-- 1. Who a test runs as before it switches role
select is(current_user::text, 'postgres', 'the test starts as postgres');
select ok((select rolbypassrls from pg_roles where rolname = current_user), 'postgres has BYPASSRLS');
select is((select count(*)::integer from public.invoices), 68, 'so before set role, the test sees all 68 invoices');

-- 2. Sam, a client of Alder Studio
set local role authenticated;
set local request.jwt.claims = '{"sub": "33333333-3333-4333-8333-333333333333", "role": "authenticated"}';

select is(auth.uid(), '33333333-3333-4333-8333-333333333333'::uuid, 'Sam: auth.uid() returns the sub claim');

select results_eq(
  'select distinct client_id from public.invoices',
  $$values ('c1000000-0000-4000-8000-000000000001'::uuid)$$,
  'Sam: every invoice he can read is his own');

select is_empty(
  $$select 1 from public.invoices where client_id = 'c1000000-0000-4000-8000-000000000002'$$,
  'Sam: none of Priya''s invoices');

select results_eq(
  $$select name from storage.objects where bucket_id = 'invoices' order by name$$,
  $$values ('a1de5000-0000-4000-8000-000000000001/INV-2026-0001.pdf'),
           ('a1de5000-0000-4000-8000-000000000001/INV-2026-0007.pdf')$$,
  'Sam: lists his own two invoice files, not Priya''s');

-- A write that a policy's USING filters out raises no error and changes
-- nothing, so lives_ok passes whether or not anything changed.
select lives_ok(
  $$update public.profiles set full_name = 'Changed by Sam' where id = '44444444-4444-4444-8444-444444444444'$$,
  'lives_ok passes on an update that matched no rows');
select is_empty(
  $$update public.profiles set full_name = 'Changed by Sam' where id = '44444444-4444-4444-8444-444444444444' returning id$$,
  'Sam: an update of Priya''s profile matches no rows');
select is_empty(
  $$delete from public.invoices where client_id = 'c1000000-0000-4000-8000-000000000002' returning id$$,
  'Sam: a delete of Priya''s invoices matches no rows');

reset role;
select is((select full_name from public.profiles where id = '44444444-4444-4444-8444-444444444444'),
  'Priya Shah', 'checked as postgres: Priya''s name is unchanged');
select is((select count(*)::integer from public.invoices where client_id = 'c1000000-0000-4000-8000-000000000002'),
  20, 'checked as postgres: all 20 of Priya''s invoices are still there');

-- An allowed write, proved by what it returns.
set local role authenticated;
select results_eq(
  $$update public.profiles set full_name = 'Sam R.' where id = '33333333-3333-4333-8333-333333333333' returning full_name$$,
  array['Sam R.'],
  'Sam: changes his own name, and returning shows it');

-- A row that fails a policy's WITH CHECK is an error.
select throws_ok(
  $$insert into public.messages (workspace_id, project_id, sender_id, body)
    values ('a1de5000-0000-4000-8000-000000000001', md5('alder-project-1')::uuid,
            '11111111-1111-4111-8111-111111111111', 'posing as Maya')$$,
  '42501', 'new row violates row-level security policy for table "messages"',
  'Sam: a message in Maya''s name fails the policy''s check');

-- 3. The older one-claim setting: auth.uid() reads it, auth.jwt() doesn't
set local request.jwt.claims = '';
set local request.jwt.claim.sub = '33333333-3333-4333-8333-333333333333';
select is(auth.uid(), '33333333-3333-4333-8333-333333333333'::uuid, 'request.jwt.claim.sub alone: auth.uid() works');
select is(auth.jwt(), null, 'request.jwt.claim.sub alone: auth.jwt() is null');

-- 4. Signed out
set local role anon;
set local request.jwt.claim.sub = '';
set local request.jwt.claims = '{"role": "anon"}';

select is(auth.uid(), null, 'signed out: auth.uid() is null');
select throws_ok(
  'select 1 from public.invoices',
  '42501', 'permission denied for table invoices',
  'signed out: with the grant revoked, reading invoices is an error, not zero rows');

-- 5. The secret key's role skips RLS, on purpose
reset role;
select ok((select rolbypassrls from pg_roles where rolname = 'service_role'), 'service_role has BYPASSRLS');
select ok(not (select rolbypassrls from pg_roles where rolname = 'authenticated'), 'authenticated doesn''t');
select ok(not (select rolbypassrls from pg_roles where rolname = 'anon'), 'anon doesn''t');

set local role service_role;
set local request.jwt.claims = '{"role": "service_role"}';
select results_eq('select count(*)::integer from public.invoices', array[68], 'service_role: reads all 68 invoices');
select results_eq(
  $$update public.workspaces set plan = 'agency' where id = 'b1de5000-0000-4000-8000-000000000002' returning plan$$,
  array['agency'],
  'service_role: server-side billing code can still change a plan');

-- 6. The policies themselves
reset role;
select policies_are('public', 'invoices',
  array['Clients read their own invoices', 'Staff can manage invoices'],
  'invoices has exactly these two policies');
select is_empty(
  $$select tablename, policyname from pg_policies
    where schemaname in ('public', 'storage') and (qual = 'true' or with_check = 'true')
      and tablename <> 'plans'$$,
  'no policy outside plans lets every row through');

select * from finish();
rollback;
