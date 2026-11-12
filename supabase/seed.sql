-- Seed data for Acme, a demo client portal for small studios. Every person,
-- studio and client here is made up, and every address is on example.com.
-- The users have no passwords: the tests act as them through JWT claims and
-- never sign in.
--   maya.alder@example.com      owner, Alder Studio
--   leo.alder@example.com       staff, Alder Studio
--   sam.brightline@example.com  client of Alder Studio
--   priya.kettle@example.com    client of Alder Studio
--   tom.juniper@example.com     owner, Juniper Dev
--   ana.orbit@example.com       client of Juniper Dev
--   ops.acme@example.com        Acme staff (platform admin)

-- The CLI sends this file as one batch, so the users go in through one DO block.
DO $$
DECLARE
  u RECORD;
BEGIN
  FOR u IN
    SELECT * FROM (VALUES
      ('11111111-1111-4111-8111-111111111111'::uuid, 'maya.alder@example.com', 'Maya Chen'),
      ('22222222-2222-4222-8222-222222222222'::uuid, 'leo.alder@example.com', 'Leo Park'),
      ('33333333-3333-4333-8333-333333333333'::uuid, 'sam.brightline@example.com', 'Sam Rivera'),
      ('44444444-4444-4444-8444-444444444444'::uuid, 'priya.kettle@example.com', 'Priya Shah'),
      ('55555555-5555-4555-8555-555555555555'::uuid, 'tom.juniper@example.com', 'Tom Okafor'),
      ('66666666-6666-4666-8666-666666666666'::uuid, 'ana.orbit@example.com', 'Ana Silva'),
      ('77777777-7777-4777-8777-777777777777'::uuid, 'ops.acme@example.com', 'Acme Ops')
    ) AS t(id, email, full_name)
  LOOP
    INSERT INTO auth.users (
      instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      confirmation_token, recovery_token, email_change_token_new, email_change,
      email_change_token_current, phone_change, phone_change_token, reauthentication_token,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at
    ) VALUES (
      '00000000-0000-0000-0000-000000000000', u.id, 'authenticated', 'authenticated', u.email,
      '', now(),
      '', '', '', '', '', '', '', '',
      '{"provider": "email", "providers": ["email"]}'::jsonb,
      jsonb_build_object('full_name', u.full_name),
      now() - interval '60 days', now() - interval '60 days'
    );

    INSERT INTO auth.identities (id, provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
    VALUES (
      gen_random_uuid(), u.id::text, u.id,
      jsonb_build_object('sub', u.id::text, 'email', u.email, 'email_verified', true),
      'email', now(), now(), now()
    );
  END LOOP;
END
$$;

-- The sign-up trigger created the profiles. Acme Ops runs the platform.
UPDATE public.profiles SET role = 'admin' WHERE id = '77777777-7777-4777-8777-777777777777';

-- Studios
INSERT INTO public.workspaces (id, name, slug, owner_id, plan) VALUES
  ('a1de5000-0000-4000-8000-000000000001', 'Alder Studio', 'alder', '11111111-1111-4111-8111-111111111111', 'studio'),
  ('b1de5000-0000-4000-8000-000000000002', 'Juniper Dev', 'juniper', '55555555-5555-4555-8555-555555555555', 'starter');

INSERT INTO public.workspace_members (workspace_id, user_id, role) VALUES
  ('a1de5000-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'owner'),
  ('a1de5000-0000-4000-8000-000000000001', '22222222-2222-4222-8222-222222222222', 'staff'),
  ('a1de5000-0000-4000-8000-000000000001', '33333333-3333-4333-8333-333333333333', 'client'),
  ('a1de5000-0000-4000-8000-000000000001', '44444444-4444-4444-8444-444444444444', 'client'),
  ('b1de5000-0000-4000-8000-000000000002', '55555555-5555-4555-8555-555555555555', 'owner'),
  ('b1de5000-0000-4000-8000-000000000002', '66666666-6666-4666-8666-666666666666', 'client')
ON CONFLICT (workspace_id, user_id) DO NOTHING;

-- Clients
INSERT INTO public.clients (id, workspace_id, user_id, name, company, email) VALUES
  ('c1000000-0000-4000-8000-000000000001', 'a1de5000-0000-4000-8000-000000000001', '33333333-3333-4333-8333-333333333333', 'Sam Rivera', 'Brightline Coffee', 'sam.brightline@example.com'),
  ('c1000000-0000-4000-8000-000000000002', 'a1de5000-0000-4000-8000-000000000001', '44444444-4444-4444-8444-444444444444', 'Priya Shah', 'Kettle & Co', 'priya.kettle@example.com'),
  ('c1000000-0000-4000-8000-000000000003', 'a1de5000-0000-4000-8000-000000000001', NULL, 'Noah Bell', 'Fernway Books', 'noah.fernway@example.com'),
  ('c2000000-0000-4000-8000-000000000001', 'b1de5000-0000-4000-8000-000000000002', '66666666-6666-4666-8666-666666666666', 'Ana Silva', 'Orbit Bikes', 'ana.orbit@example.com'),
  ('c2000000-0000-4000-8000-000000000002', 'b1de5000-0000-4000-8000-000000000002', NULL, 'Ravi Menon', 'Quarry Labs', 'ravi.quarry@example.com');

-- Alder Studio: 30 projects, ten for each client
INSERT INTO public.projects (id, workspace_id, client_id, name, status, due_date, created_at)
SELECT
  md5('alder-project-' || n)::uuid,
  'a1de5000-0000-4000-8000-000000000001',
  (ARRAY[
    'c1000000-0000-4000-8000-000000000001',
    'c1000000-0000-4000-8000-000000000002',
    'c1000000-0000-4000-8000-000000000003'
  ])[((n - 1) / 10) + 1]::uuid,
  (ARRAY['Brightline Coffee', 'Kettle & Co', 'Fernway Books'])[((n - 1) / 10) + 1] || ': ' ||
  (ARRAY['Brand refresh', 'Menu boards', 'Website redesign', 'Packaging', 'Social kit',
         'Signage', 'Seasonal campaign', 'Pitch deck', 'Product photos', 'Newsletter templates'])[((n - 1) % 10) + 1],
  CASE WHEN n % 10 IN (1, 2, 3) THEN 'active' WHEN n % 10 = 4 THEN 'on_hold' ELSE 'done' END,
  DATE '2026-01-15' + (n * 9),
  TIMESTAMP WITH TIME ZONE '2026-01-05 09:00:00+00' + (n * INTERVAL '8 days')
FROM generate_series(1, 30) AS n;

-- Juniper Dev: 4 projects
INSERT INTO public.projects (id, workspace_id, client_id, name, status, due_date, created_at) VALUES
  (md5('juniper-project-1')::uuid, 'b1de5000-0000-4000-8000-000000000002', 'c2000000-0000-4000-8000-000000000001', 'Orbit Bikes: Booking app', 'active', '2026-12-01', '2026-08-03 10:00:00+00'),
  (md5('juniper-project-2')::uuid, 'b1de5000-0000-4000-8000-000000000002', 'c2000000-0000-4000-8000-000000000001', 'Orbit Bikes: Fleet dashboard', 'done', '2026-07-15', '2026-05-11 10:00:00+00'),
  (md5('juniper-project-3')::uuid, 'b1de5000-0000-4000-8000-000000000002', 'c2000000-0000-4000-8000-000000000002', 'Quarry Labs: Marketing site', 'active', '2026-11-20', '2026-09-14 10:00:00+00'),
  (md5('juniper-project-4')::uuid, 'b1de5000-0000-4000-8000-000000000002', 'c2000000-0000-4000-8000-000000000002', 'Quarry Labs: API docs', 'on_hold', '2027-01-10', '2026-10-01 10:00:00+00');

-- Two invoices per project, numbered per studio
INSERT INTO public.invoices (workspace_id, project_id, client_id, number, amount_cents, status, issued_on, due_on, pdf_path)
SELECT
  p.workspace_id,
  p.id,
  p.client_id,
  'INV-2026-' || lpad(ROW_NUMBER() OVER (PARTITION BY p.workspace_id ORDER BY p.created_at, k)::text, 4, '0'),
  (60000 + ((ROW_NUMBER() OVER (ORDER BY p.created_at, k) * 37) % 40) * 12500)::integer,
  CASE
    WHEN k = 1 THEN 'paid'
    ELSE (ARRAY['sent', 'overdue', 'paid', 'draft'])[(ROW_NUMBER() OVER (ORDER BY p.created_at, k) % 4) + 1]
  END,
  (p.created_at + (k * INTERVAL '20 days'))::date,
  (p.created_at + (k * INTERVAL '20 days') + INTERVAL '30 days')::date,
  NULL
FROM public.projects p
CROSS JOIN generate_series(1, 2) AS k;

UPDATE public.invoices SET pdf_path = workspace_id::text || '/' || number || '.pdf';

-- Messages on a few projects
INSERT INTO public.messages (workspace_id, project_id, sender_id, body, created_at)
SELECT
  p.workspace_id,
  p.id,
  CASE WHEN m % 2 = 1 THEN s.staff_id ELSE COALESCE(c.user_id, s.staff_id) END,
  (ARRAY[
    'First round of concepts is up in the files tab. Three directions, notes on each.',
    'Thanks! We like the second one. Can we try it with the darker green?',
    'Updated. The contract for phase two is attached, can you sign it by Friday?',
    'Signed and sent back. Our launch date moved to the 14th, does that still work?',
    'Yes, that works. Final files will be ready on the 10th.'
  ])[((m - 1) % 5) + 1],
  p.created_at + (m * INTERVAL '2 days')
FROM public.projects p
JOIN public.clients c ON c.id = p.client_id
JOIN (VALUES
  ('a1de5000-0000-4000-8000-000000000001'::uuid, '11111111-1111-4111-8111-111111111111'::uuid),
  ('b1de5000-0000-4000-8000-000000000002'::uuid, '55555555-5555-4555-8555-555555555555'::uuid)
) AS s(workspace_id, staff_id) ON s.workspace_id = p.workspace_id
CROSS JOIN generate_series(1, 4) AS m
WHERE p.status = 'active';

-- Settings for the PDF rendering service. The key is a placeholder: in the
-- vulnerable schema, get_pdf_settings() hands it to anyone who asks, and the
-- fix migration deletes it.
INSERT INTO public.app_settings (key, value) VALUES
  ('pdf_api_key', 'placeholder-not-a-real-key'),
  ('pdf_template_id', 'tmpl_invoice_v2');
