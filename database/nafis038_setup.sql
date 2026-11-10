-- Nafis 038 / Neon: non-destructive alignment for existing tables plus exam drafts.
-- Run in Neon SQL Editor as the SAME database role used by Neon Functions.
-- No API key or connection string belongs in this file or in browser JavaScript.

ALTER TABLE public.naf038_attempts
  ADD COLUMN IF NOT EXISTS total_questions integer;
ALTER TABLE public.naf038_settings
  ADD COLUMN IF NOT EXISTS results_published_week text;
ALTER TABLE public.naf038_settings
  ADD COLUMN IF NOT EXISTS results_published_at timestamptz;

-- Persist partial answers between page refreshes. The draft contains no answer key.
CREATE TABLE IF NOT EXISTS public.naf038_drafts (
  exam_id integer NOT NULL REFERENCES public.naf038_exams(id) ON DELETE CASCADE,
  student_id integer NOT NULL REFERENCES public.nafis_students(id) ON DELETE CASCADE,
  started_at timestamptz NOT NULL,
  answers jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT NOW(),
  PRIMARY KEY (exam_id, student_id)
);

-- Enforce one submitted attempt for each student and exam at the database layer.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.naf038_attempts
     GROUP BY exam_id, student_id HAVING COUNT(*) > 1
  ) THEN
    RAISE EXCEPTION 'Duplicate Nafis attempts exist; review them before applying the unique attempt index.';
  END IF;
  CREATE UNIQUE INDEX IF NOT EXISTS naf038_attempts_exam_student_uq
    ON public.naf038_attempts (exam_id, student_id);
END $$;

INSERT INTO public.naf038_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
UPDATE public.naf038_settings SET students_enabled = false WHERE id = 1;

DO $$
DECLARE t text;
DECLARE policy_name text;
BEGIN
  FOREACH t IN ARRAY ARRAY['nafis_students','naf038_settings','naf038_exams','naf038_questions','naf038_attempts','naf038_drafts'] LOOP
    IF to_regclass(format('public.%I', t)) IS NULL THEN
      RAISE EXCEPTION 'Required Nafis table is missing: public.%', t;
    END IF;
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    policy_name := 'naf038_backend_' || t;
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', policy_name, t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
      policy_name, t, current_user);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO %I', t, current_user);
  END LOOP;

  -- Identity columns need sequence usage for inserts. This grants only to the backend role.
  GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO CURRENT_USER;
END $$;

-- Prevent accidental direct browser access through roles typically used by client apps.
REVOKE ALL ON public.nafis_students, public.naf038_settings, public.naf038_exams,
  public.naf038_questions, public.naf038_attempts, public.naf038_drafts FROM PUBLIC;

