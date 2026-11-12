-- Settings for the PDF rendering service
CREATE TABLE public.app_settings (
  key TEXT NOT NULL PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.app_settings ENABLE ROW LEVEL SECURITY;

-- Returns the settings the invoice editor needs to render a PDF
CREATE OR REPLACE FUNCTION public.get_pdf_settings()
RETURNS JSON
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT json_build_object(
    'api_key', (SELECT value FROM public.app_settings WHERE key = 'pdf_api_key'),
    'template_id', (SELECT value FROM public.app_settings WHERE key = 'pdf_template_id')
  );
$$;
