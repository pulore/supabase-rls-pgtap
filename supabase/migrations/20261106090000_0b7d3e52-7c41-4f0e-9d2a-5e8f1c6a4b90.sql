-- Security fixes from the 6 Nov 2026 audit. One section per finding.

-- Finding 2. Invoices were readable by anyone through an always-true policy.
-- Replace it in one transaction. Policies combine with OR, so adding an owner
-- policy beside the old one would leave every invoice readable.

drop policy "Enable read access for all users" on public.invoices;

create policy "Clients read their own invoices"
on public.invoices for select
to authenticated
using (
  client_id in (
    select c.id from public.clients c
    where c.user_id = (select auth.uid())
  )
);

-- Signed-out visitors never need invoices.
revoke all on table public.invoices from anon;


-- Finding 3. Invoice PDFs were in a public bucket, listable by anyone, and any
-- signed-in user could upload or overwrite them. Make the bucket private, take
-- only PDFs up to 10 MB, and give each file to its studio's staff and its own
-- client only. The three bucket-wide policies go in the same transaction, or
-- they keep every file open. The app switches from public URLs to signed ones.

update storage.buckets
set public = false,
    allowed_mime_types = array['application/pdf'],
    file_size_limit = 10485760
where id = 'invoices';

drop policy "Invoice files are publicly accessible" on storage.objects;
drop policy "Authenticated users can upload invoice files" on storage.objects;
drop policy "Authenticated users can update invoice files" on storage.objects;

-- Files live at <workspace id>/<invoice number>.pdf.
create policy "Staff read their studio's invoice files"
on storage.objects for select
to authenticated
using (
  bucket_id = 'invoices'
  and (storage.foldername(name))[1] in (
    select m.workspace_id::text from public.workspace_members m
    where m.user_id = (select auth.uid()) and m.role in ('owner', 'staff')
  )
);

-- A client reads a file only through one of their own invoices that names it,
-- where the invoice, the client and the file's folder all belong to the same
-- studio. Anyone can create a studio and be its staff and its client, so an
-- invoice they write must not reach another studio's files.
create policy "Clients read their own invoice files"
on storage.objects for select
to authenticated
using (
  bucket_id = 'invoices'
  and exists (
    select 1
    from public.invoices i
    join public.clients c on c.id = i.client_id
    where i.pdf_path = storage.objects.name
      and c.workspace_id = i.workspace_id
      and (storage.foldername(storage.objects.name))[1] = i.workspace_id::text
      and c.user_id = (select auth.uid())
  )
);

create policy "Staff upload their studio's invoice files"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'invoices'
  and (storage.foldername(name))[1] in (
    select m.workspace_id::text from public.workspace_members m
    where m.user_id = (select auth.uid()) and m.role in ('owner', 'staff')
  )
);

create policy "Staff replace their studio's invoice files"
on storage.objects for update
to authenticated
using (
  bucket_id = 'invoices'
  and (storage.foldername(name))[1] in (
    select m.workspace_id::text from public.workspace_members m
    where m.user_id = (select auth.uid()) and m.role in ('owner', 'staff')
  )
)
with check (
  bucket_id = 'invoices'
  and (storage.foldername(name))[1] in (
    select m.workspace_id::text from public.workspace_members m
    where m.user_id = (select auth.uid()) and m.role in ('owner', 'staff')
  )
);

-- And at the source: an invoice's file is always its own studio's, under its
-- own number, which is the path the app writes.
alter table public.invoices
  add constraint invoices_pdf_path_matches_invoice
  check (pdf_path is null or pdf_path = workspace_id::text || '/' || number || '.pdf');


-- Finding 4. messages had RLS off, so anyone could read, post and delete. Turn it
-- on with the policies in the same change, or the feature stops working.

alter table public.messages enable row level security;
revoke all on table public.messages from anon;

create policy "Staff read their studio's messages"
on public.messages for select
to authenticated
using ( public.is_workspace_staff(workspace_id) );

create policy "Clients read messages on their projects"
on public.messages for select
to authenticated
using (
  project_id in (
    select p.id from public.projects p
    join public.clients c on c.id = p.client_id
    where c.user_id = (select auth.uid())
  )
);

-- Posts go out under the sender's own ID, on a project they can see, with the
-- project's real studio ID.
create policy "Members post as themselves on their projects"
on public.messages for insert
to authenticated
with check (
  sender_id = (select auth.uid())
  and exists (
    select 1 from public.projects p
    where p.id = messages.project_id
      and p.workspace_id = messages.workspace_id
      and (
        public.is_workspace_staff(p.workspace_id)
        or exists (
          select 1 from public.clients c
          where c.id = p.client_id and c.user_id = (select auth.uid())
        )
      )
  )
);

-- No update or delete policies: the app doesn't edit or delete messages.


-- Finding 5. "Users can join workspaces" only checked that users added themselves,
-- so anyone could join any studio with any role. Memberships now come from
-- invites that staff create, accepted by the invited address, and the owner's
-- own membership comes from a trigger. The address check only proves something
-- once email confirmation is on (finding 12), so that ships first.

drop policy "Users can join workspaces" on public.workspace_members;

create table public.workspace_invites (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  email text not null,
  role text not null default 'client' check (role in ('staff', 'client')),
  token text not null unique default encode(extensions.gen_random_bytes(24), 'hex'),
  created_by uuid not null default auth.uid() references auth.users(id) on delete cascade,
  expires_at timestamptz not null default now() + interval '7 days',
  accepted_at timestamptz,
  created_at timestamptz not null default now()
);

create index workspace_invites_workspace_id_idx on public.workspace_invites (workspace_id);

alter table public.workspace_invites enable row level security;

-- Explicit grants, not the API's old defaults: since October 30, 2026, hosted
-- projects don't expose new tables on their own. The browser sets only the
-- studio, the address and the role. The token, expiry, creator and acceptance
-- time come from the database.
revoke all on table public.workspace_invites from anon, authenticated;
grant select, delete on table public.workspace_invites to authenticated;
grant insert (workspace_id, email, role) on table public.workspace_invites to authenticated;

-- Staff invite clients. Only the owner invites staff.
create policy "Staff read their studio's invites"
on public.workspace_invites for select
to authenticated
using ( public.is_workspace_staff(workspace_id) );

create policy "Staff create invites"
on public.workspace_invites for insert
to authenticated
with check (
  public.is_workspace_staff(workspace_id)
  and (
    role = 'client'
    or exists (
      select 1 from public.workspaces w
      where w.id = workspace_id and w.owner_id = (select auth.uid())
    )
  )
);

create policy "Staff delete invites"
on public.workspace_invites for delete
to authenticated
using ( public.is_workspace_staff(workspace_id) );

create function public.accept_invite(invite_token text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  invite public.workspace_invites%rowtype;
begin
  select * into invite
  from public.workspace_invites
  where token = invite_token
    and accepted_at is null
    and expires_at > now()
  for update;

  if not found then
    raise exception 'invite not found or expired' using errcode = 'P0002';
  end if;

  if lower(invite.email) <> lower((select u.email from auth.users u where u.id = auth.uid())) then
    raise exception 'this invite is for another address' using errcode = '42501';
  end if;

  -- A new member gets the invite's role. An existing client invited as staff
  -- becomes staff. Nobody is moved down, and an owner stays an owner.
  insert into public.workspace_members as m (workspace_id, user_id, role)
  values (invite.workspace_id, auth.uid(), invite.role)
  on conflict (workspace_id, user_id) do update
    set role = excluded.role
    where m.role = 'client' and excluded.role = 'staff';

  update public.workspace_invites set accepted_at = now() where id = invite.id;

  return invite.workspace_id;
end;
$$;

revoke execute on function public.accept_invite(text) from public, anon;
grant execute on function public.accept_invite(text) to authenticated;

create function public.add_workspace_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.workspace_members (workspace_id, user_id, role)
  values (new.id, new.owner_id, 'owner')
  on conflict (workspace_id, user_id) do nothing;
  return new;
end;
$$;

revoke execute on function public.add_workspace_owner() from public, anon, authenticated;

create trigger on_workspace_created
  after insert on public.workspaces
  for each row execute function public.add_workspace_owner();


-- Finding 6. RLS picks rows, not columns. "Users can update their own profile" let
-- users set every column of their row, role included, and owners could set
-- their own plan. Limit which columns the browser can write.

revoke insert, update on table public.profiles from anon, authenticated;
grant insert (id, full_name, avatar_url) on table public.profiles to authenticated;
grant update (full_name, avatar_url) on table public.profiles to authenticated;

-- The plan changes only from server-side billing code, with the secret key.
revoke insert, update on table public.workspaces from anon, authenticated;
grant insert (name, slug, owner_id) on table public.workspaces to authenticated;
grant update (name, slug) on table public.workspaces to authenticated;


-- Finding 7. client_overview ran as its owner, so it skipped the clients table's
-- RLS. Make it run as the caller (Postgres 15 or later), and keep signed-out
-- visitors off it.
alter view public.client_overview set (security_invoker = true);
revoke all on table public.client_overview from anon;

-- Finding 9. get_pdf_settings() is SECURITY DEFINER and anyone could call it, so it
-- handed out the PDF service's API key. The browser no longer needs it: the
-- render-invoice Edge Function reads the key from its secrets. Close the
-- function and take the key out of the database. The old key was exposed, so
-- it also has to be rotated with the PDF service.
revoke execute on function public.get_pdf_settings() from public, anon, authenticated;
delete from public.app_settings where key = 'pdf_api_key';

-- Finding 10. "Members can view profiles in their workspaces" and "Members can
-- view workspace members" covered every member, so one client read the names
-- and emails of the studio's other clients. Staff see their studio's members.
-- A client sees their own profile and membership, and the studio's staff.

drop policy "Members can view workspace members" on public.workspace_members;

create policy "Staff read their studio's memberships"
on public.workspace_members for select
to authenticated
using ( public.is_workspace_staff(workspace_id) );

create policy "Members read their own membership and their studio's staff"
on public.workspace_members for select
to authenticated
using (
  user_id = (select auth.uid())
  or (role in ('owner', 'staff') and public.is_workspace_member(workspace_id))
);

-- The memberships a caller can read now decide whose profiles they can read.
drop policy "Members can view profiles in their workspaces" on public.profiles;

create policy "Members read the profiles of memberships they can see"
on public.profiles for select
to authenticated
using (
  exists (
    select 1 from public.workspace_members m
    where m.user_id = profiles.id
  )
);


-- Finding 11. Every client policy follows clients.user_id, not the membership,
-- so a client the owner removed still read their projects, invoices, messages
-- and PDFs. When a membership goes, unlink that user from the studio's client
-- rows, in the same statement.

create function public.unlink_removed_client()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.clients
  set user_id = null
  where workspace_id = old.workspace_id
    and user_id = old.user_id;
  return old;
end;
$$;

revoke execute on function public.unlink_removed_client() from public, anon, authenticated;

create trigger on_workspace_member_removed
  after delete on public.workspace_members
  for each row execute function public.unlink_removed_client();


-- Finding 15. projects.client_id, invoices.client_id and invoices.project_id
-- only had to exist, not belong to the row's own studio, so one studio's staff
-- could put a project or invoice into another studio's client portal.
-- Composite foreign keys tie each reference to the row's own studio.

alter table public.clients add constraint clients_id_workspace_id_key unique (id, workspace_id);
alter table public.projects add constraint projects_id_workspace_id_key unique (id, workspace_id);

alter table public.projects drop constraint projects_client_id_fkey;
alter table public.projects
  add constraint projects_client_in_same_studio_fkey
  foreign key (client_id, workspace_id) references public.clients (id, workspace_id)
  on delete set null (client_id);

alter table public.invoices drop constraint invoices_client_id_fkey;
alter table public.invoices
  add constraint invoices_client_in_same_studio_fkey
  foreign key (client_id, workspace_id) references public.clients (id, workspace_id)
  on delete set null (client_id);

alter table public.invoices drop constraint invoices_project_id_fkey;
alter table public.invoices
  add constraint invoices_project_in_same_studio_fkey
  foreign key (project_id, workspace_id) references public.projects (id, workspace_id)
  on delete set null (project_id);


-- Finding 17, fix this quarter, from Supabase's performance advisor. Index the foreign
-- keys that policies and joins use, and let Postgres work out auth.uid() once
-- per query instead of once per row, by writing it as (select auth.uid()).
-- Each policy is replaced in place, with the same rule. Three foreign keys the
-- advisor lists already lead an index: messages (project_id, created_at), the
-- workspace_members primary key and invoices' unique (workspace_id, number).
-- The client and project indexes are composite, so they also cover finding 15's
-- same-studio foreign keys. Finding 10 replaces the members' profile policy.

create index if not exists clients_workspace_id_idx on public.clients (workspace_id);
create index if not exists clients_user_id_idx on public.clients (user_id);
create index if not exists projects_workspace_id_idx on public.projects (workspace_id);
create index if not exists projects_client_id_workspace_id_idx on public.projects (client_id, workspace_id);
create index if not exists invoices_project_id_workspace_id_idx on public.invoices (project_id, workspace_id);
create index if not exists invoices_client_id_workspace_id_idx on public.invoices (client_id, workspace_id);
create index if not exists messages_workspace_id_idx on public.messages (workspace_id);
create index if not exists messages_sender_id_idx on public.messages (sender_id);
create index if not exists workspace_members_user_id_idx on public.workspace_members (user_id);
create index if not exists workspaces_owner_id_idx on public.workspaces (owner_id);
create index if not exists workspaces_plan_idx on public.workspaces (plan);
create index if not exists workspace_invites_created_by_idx on public.workspace_invites (created_by);

drop policy "Users can view their own profile" on public.profiles;
create policy "Users can view their own profile"
on public.profiles for select
to authenticated
using ( (select auth.uid()) = id );

drop policy "Users can insert their own profile" on public.profiles;
create policy "Users can insert their own profile"
on public.profiles for insert
to authenticated
with check ( (select auth.uid()) = id );

drop policy "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
on public.profiles for update
to authenticated
using ( (select auth.uid()) = id )
with check ( (select auth.uid()) = id );

drop policy "Members can view their workspaces" on public.workspaces;
create policy "Members can view their workspaces"
on public.workspaces for select
to authenticated
using ( public.is_workspace_member(id) or (select auth.uid()) = owner_id );

drop policy "Users can create workspaces" on public.workspaces;
create policy "Users can create workspaces"
on public.workspaces for insert
to authenticated
with check ( (select auth.uid()) = owner_id );

drop policy "Owners can update their workspace" on public.workspaces;
create policy "Owners can update their workspace"
on public.workspaces for update
to authenticated
using ( (select auth.uid()) = owner_id )
with check ( (select auth.uid()) = owner_id );

drop policy "Owners can remove members" on public.workspace_members;
create policy "Owners can remove members"
on public.workspace_members for delete
to authenticated
using (
  exists (
    select 1 from public.workspaces w
    where w.id = workspace_members.workspace_id
      and w.owner_id = (select auth.uid())
  )
);

drop policy "Staff and the client can view clients" on public.clients;
create policy "Staff and the client can view clients"
on public.clients for select
to authenticated
using ( public.is_workspace_staff(workspace_id) or (select auth.uid()) = user_id );

drop policy "Clients can view their projects" on public.projects;
create policy "Clients can view their projects"
on public.projects for select
to authenticated
using (
  exists (
    select 1 from public.clients c
    where c.id = projects.client_id
      and c.user_id = (select auth.uid())
  )
);

