-- Create invoices table
CREATE TABLE public.invoices (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  project_id UUID REFERENCES public.projects(id) ON DELETE SET NULL,
  client_id UUID REFERENCES public.clients(id) ON DELETE SET NULL,
  number TEXT NOT NULL,
  amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'sent', 'paid', 'overdue', 'void')),
  issued_on DATE NOT NULL DEFAULT CURRENT_DATE,
  due_on DATE,
  pdf_path TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, number)
);

ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Staff can manage invoices"
ON public.invoices FOR ALL
USING (public.is_workspace_staff(workspace_id))
WITH CHECK (public.is_workspace_staff(workspace_id));

-- Storage bucket for invoice PDFs
INSERT INTO storage.buckets (id, name, public)
VALUES ('invoices', 'invoices', true);

CREATE POLICY "Invoice files are publicly accessible"
ON storage.objects FOR SELECT
USING (bucket_id = 'invoices');

CREATE POLICY "Authenticated users can upload invoice files"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'invoices');

CREATE POLICY "Authenticated users can update invoice files"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'invoices');
