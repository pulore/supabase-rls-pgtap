-- Clients couldn't see their invoices in the portal
CREATE POLICY "Enable read access for all users"
ON public.invoices FOR SELECT
USING (true);

-- Summary per client for the dashboard
CREATE OR REPLACE VIEW public.client_overview AS
SELECT
  c.id AS client_id,
  c.workspace_id,
  c.name,
  c.company,
  c.email,
  COUNT(i.id) FILTER (WHERE i.status IN ('sent', 'overdue')) AS open_invoices,
  COALESCE(SUM(i.amount_cents) FILTER (WHERE i.status IN ('sent', 'overdue')), 0) AS amount_due_cents,
  MAX(i.issued_on) AS last_invoiced_on
FROM public.clients c
LEFT JOIN public.invoices i ON i.client_id = c.id
GROUP BY c.id;
