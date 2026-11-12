-- Create profiles table
CREATE TABLE public.profiles (
  id UUID NOT NULL PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT,
  email TEXT,
  avatar_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Create workspaces table (one per studio)
CREATE TABLE public.workspaces (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;

-- Create workspace members table
CREATE TABLE public.workspace_members (
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'client' CHECK (role IN ('owner', 'staff', 'client')),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);

ALTER TABLE public.workspace_members ENABLE ROW LEVEL SECURITY;

-- Helper functions to avoid recursive policies on workspace_members
CREATE OR REPLACE FUNCTION public.is_workspace_member(_workspace_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.workspace_members
    WHERE workspace_id = _workspace_id
      AND user_id = auth.uid()
  );
$$;

CREATE OR REPLACE FUNCTION public.is_workspace_staff(_workspace_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.workspace_members
    WHERE workspace_id = _workspace_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'staff')
  );
$$;

-- Create clients table
CREATE TABLE public.clients (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  company TEXT,
  email TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.clients ENABLE ROW LEVEL SECURITY;

-- Create projects table
CREATE TABLE public.projects (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  client_id UUID REFERENCES public.clients(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'on_hold', 'done')),
  due_date DATE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;

-- Profiles policies
CREATE POLICY "Users can view their own profile"
ON public.profiles FOR SELECT
USING (auth.uid() = id);

CREATE POLICY "Members can view profiles in their workspaces"
ON public.profiles FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM public.workspace_members me
    JOIN public.workspace_members them ON them.workspace_id = me.workspace_id
    WHERE me.user_id = auth.uid()
      AND them.user_id = profiles.id
  )
);

CREATE POLICY "Users can insert their own profile"
ON public.profiles FOR INSERT
WITH CHECK (auth.uid() = id);

CREATE POLICY "Users can update their own profile"
ON public.profiles FOR UPDATE
USING (auth.uid() = id);

-- Workspaces policies
CREATE POLICY "Members can view their workspaces"
ON public.workspaces FOR SELECT
USING (public.is_workspace_member(id) OR auth.uid() = owner_id);

CREATE POLICY "Users can create workspaces"
ON public.workspaces FOR INSERT
TO authenticated
WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "Owners can update their workspace"
ON public.workspaces FOR UPDATE
USING (auth.uid() = owner_id);

-- Workspace members policies
CREATE POLICY "Members can view workspace members"
ON public.workspace_members FOR SELECT
USING (public.is_workspace_member(workspace_id));

CREATE POLICY "Users can join workspaces"
ON public.workspace_members FOR INSERT
TO authenticated
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Owners can remove members"
ON public.workspace_members FOR DELETE
USING (
  EXISTS (
    SELECT 1 FROM public.workspaces w
    WHERE w.id = workspace_members.workspace_id
      AND w.owner_id = auth.uid()
  )
);

-- Clients policies
CREATE POLICY "Staff and the client can view clients"
ON public.clients FOR SELECT
USING (public.is_workspace_staff(workspace_id) OR auth.uid() = user_id);

CREATE POLICY "Staff can manage clients"
ON public.clients FOR ALL
USING (public.is_workspace_staff(workspace_id))
WITH CHECK (public.is_workspace_staff(workspace_id));

-- Projects policies
CREATE POLICY "Staff can view projects"
ON public.projects FOR SELECT
USING (public.is_workspace_staff(workspace_id));

CREATE POLICY "Clients can view their projects"
ON public.projects FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM public.clients c
    WHERE c.id = projects.client_id
      AND c.user_id = auth.uid()
  )
);

CREATE POLICY "Staff can manage projects"
ON public.projects FOR ALL
USING (public.is_workspace_staff(workspace_id))
WITH CHECK (public.is_workspace_staff(workspace_id));

-- Create a profile when a user signs up
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, email)
  VALUES (NEW.id, NEW.raw_user_meta_data ->> 'full_name', NEW.email);
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
