-- Plans shown on the pricing page
CREATE TABLE public.plans (
  id TEXT NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  seat_limit INTEGER NOT NULL,
  client_limit INTEGER,
  storage_gb INTEGER NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0
);

ALTER TABLE public.plans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Plans are viewable by everyone"
ON public.plans FOR SELECT
USING (true);

INSERT INTO public.plans (id, name, seat_limit, client_limit, storage_gb, sort_order) VALUES
  ('starter', 'Starter', 2, 5, 5, 1),
  ('studio', 'Studio', 10, 50, 100, 2),
  ('agency', 'Agency', 50, NULL, 1000, 3);

-- Each workspace is on a plan
ALTER TABLE public.workspaces
  ADD COLUMN plan TEXT NOT NULL DEFAULT 'starter' REFERENCES public.plans(id);

-- Platform admins
ALTER TABLE public.profiles
  ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'));

CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid()
      AND role = 'admin'
  );
$$;

CREATE POLICY "Admins can view all profiles"
ON public.profiles FOR SELECT
USING (public.is_admin());

CREATE POLICY "Admins can view all workspaces"
ON public.workspaces FOR SELECT
USING (public.is_admin());

CREATE POLICY "Admins can view all clients"
ON public.clients FOR SELECT
USING (public.is_admin());

CREATE POLICY "Admins can view all projects"
ON public.projects FOR SELECT
USING (public.is_admin());
