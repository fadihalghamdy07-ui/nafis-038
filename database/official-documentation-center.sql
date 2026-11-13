-- Official documentation center and append-only approval history.
-- Apply only to the verified isolated Preview Neon database.
BEGIN;
CREATE TABLE IF NOT EXISTS public.naf038_document_versions (
  version_id bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  actor_email text NOT NULL,
  action text NOT NULL CHECK (action IN ('create','update','restore')),
  change_summary text NOT NULL,
  restored_from bigint REFERENCES public.naf038_document_versions(version_id),
  document jsonb NOT NULL,
  CHECK (jsonb_typeof(document) = 'object')
);

CREATE OR REPLACE FUNCTION public.naf038_reject_document_version_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'documentation history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS naf038_document_versions_immutable ON public.naf038_document_versions;
CREATE TRIGGER naf038_document_versions_immutable
  BEFORE UPDATE OR DELETE ON public.naf038_document_versions
  FOR EACH ROW EXECUTE FUNCTION public.naf038_reject_document_version_mutation();

ALTER TABLE public.naf038_document_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.naf038_document_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS naf038_document_versions_backend ON public.naf038_document_versions;
CREATE POLICY naf038_document_versions_backend ON public.naf038_document_versions
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON public.naf038_document_versions TO CURRENT_USER;
GRANT USAGE, SELECT ON SEQUENCE public.naf038_document_versions_version_id_seq TO CURRENT_USER;
REVOKE UPDATE, DELETE, TRUNCATE ON public.naf038_document_versions FROM PUBLIC;
COMMIT;
