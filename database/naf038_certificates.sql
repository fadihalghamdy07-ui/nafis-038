-- Nafis 038 certificates: private student access and durable weekly publication gates.
-- Apply only to the isolated Preview Neon project/branch after confirming its identity.
BEGIN;

CREATE TABLE IF NOT EXISTS public.naf038_student_access (
  student_id integer PRIMARY KEY REFERENCES public.nafis_students(id) ON DELETE CASCADE,
  access_hash text NOT NULL UNIQUE CHECK (access_hash ~ '^[a-f0-9]{64}$'),
  issued_by text NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT NOW(),
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS public.naf038_results_publications (
  week_key text PRIMARY KEY CHECK (week_key ~ '^\d{4}-W\d{2}$'),
  published_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT NOW()
);

-- Preserve the currently announced week when this migration is installed.
INSERT INTO public.naf038_results_publications(week_key,published_at)
SELECT results_published_week,results_published_at
  FROM public.naf038_settings
 WHERE results_published_week ~ '^\d{4}-W\d{2}$'
   AND results_published_at IS NOT NULL
ON CONFLICT (week_key) DO NOTHING;

DO $$
DECLARE t text;
DECLARE policy_name text;
BEGIN
  FOREACH t IN ARRAY ARRAY['naf038_student_access','naf038_results_publications'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
    policy_name := 'naf038_backend_' || t;
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I',policy_name,t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
      policy_name,t,current_user);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON public.%I TO %I',t,current_user);
  END LOOP;
END $$;

REVOKE ALL ON public.naf038_student_access,public.naf038_results_publications FROM PUBLIC;
COMMIT;
