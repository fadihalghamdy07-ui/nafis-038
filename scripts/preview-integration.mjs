import { randomBytes, scryptSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { handleRequest, weekDate, weekKey } from '../functions/nafis-api-core.mjs';

if (process.env.NAFIS_PREVIEW_E2E_RUN !== '1') process.exit(0);

const EXPECTED_PROJECT = 'icy-salad-25508888';
const EXPECTED_BRANCH = 'br-weathered-rice-b9d4vuoy';
const EXPECTED_DATABASE = 'neondb';
const EXPECTED_GIT_BRANCH = 'vercel-backend-ready';
const { Pool } = pg;
const originalDateNow = Date.now;
const checks = [];
let basePool;
let examId = null;
let writesStarted = false;
let cleanupComplete = false;
let dbIdentity;
let adminStateBefore;
let testGate = false;
let testPool;
let testNow;
let adminEnv;
let studentEnv;
process.exitCode = 0;
const nonce = randomBytes(8).toString('hex');
const studentName = `اختبار نافس داخلي ${nonce}`;
const grade = 1;
const section = '4';
const subject = 'لغتي';

function check(name, condition) {
  if (!condition) throw new Error(`check_failed:${name}`);
  checks.push(name);
  console.log(`PASS ${name}`);
}

async function call(path, { method = 'GET', body, token = '', student = false } = {}) {
  const allow = new Set(['/auth/login', '/admin/health', '/admin/questions', '/admin/bootstrap']);
  const allowed = allow.has(path) || /^\/admin\/exams\/\d+$/.test(path) ||
    ['/student/start', '/student/draft', '/student/submit'].includes(path);
  if (!allowed) throw new Error('runner_route_blocked');
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  const request = new Request(`https://internal.invalid${path}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
  testGate = student;
  try {
    const response = await handleRequest(request, {
      pool: testPool,
      env: student ? studentEnv : adminEnv,
      now: () => testNow,
    });
    let data = {};
    try { data = await response.json(); } catch { /* Keep status assertion useful. */ }
    return { status: response.status, data };
  } finally {
    testGate = false;
  }
}

async function countRows(client) {
  const { rows } = await client.query(`
    SELECT (SELECT count(*)::integer FROM public.nafis_students) AS students,
           (SELECT count(*)::integer FROM public.naf038_exams) AS exams,
           (SELECT count(*)::integer FROM public.naf038_questions) AS questions,
           (SELECT count(*)::integer FROM public.naf038_attempts) AS attempts,
           (SELECT count(*)::integer FROM public.naf038_drafts) AS drafts,
           (SELECT students_enabled FROM public.naf038_settings WHERE id=1) AS students_enabled`);
  return rows[0];
}

function makePoolShim(pool) {
  const intercept = async (query, values, run) => {
    const sql = typeof query === 'string' ? query : query?.text || '';
    if (/SELECT password_hash FROM public\.naf038_admin_credentials/i.test(sql))
      return { rows: [], rowCount: 0 };
    const result = await run(query, values);
    if (testGate && /SELECT id, current_week, students_enabled, exam_minutes, results_published_week, results_published_at FROM public\.naf038_settings/i.test(sql)) {
      return { ...result, rows: result.rows.map(row => ({ ...row, students_enabled: true })) };
    }
    return result;
  };
  return {
    query: (query, values) => intercept(query, values, (q, v) => pool.query(q, v)),
    connect: async () => {
      const client = await pool.connect();
      return {
        query: (query, values) => intercept(query, values, (q, v) => client.query(q, v)),
        release: () => client.release(),
      };
    },
  };
}

try {
  if (process.env.VERCEL_ENV !== 'preview') throw new Error('preview_only_guard');
  if (process.env.VERCEL_GIT_COMMIT_REF !== EXPECTED_GIT_BRANCH) throw new Error('branch_guard');
  if (process.env.NAFIS_STUDENT_PORTAL_ENABLED === 'true') throw new Error('student_portal_must_remain_closed');
  if (!process.env.DATABASE_URL) throw new Error('database_not_configured');

  basePool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2, connectionTimeoutMillis: 10000 });
  const identityResult = await basePool.query(`
    SELECT current_database() AS database_name,
           current_setting('neon.project_id',true) AS project_id,
           current_setting('neon.branch_id',true) AS branch_id`);
  dbIdentity = identityResult.rows[0];
  check('verified_preview_neon_identity', dbIdentity.database_name === EXPECTED_DATABASE &&
    dbIdentity.project_id === EXPECTED_PROJECT && dbIdentity.branch_id === EXPECTED_BRANCH);

  const beforeClient = await basePool.connect();
  try {
    const counts = await countRows(beforeClient);
    check('isolated_database_empty_and_closed', Number(counts.students) === 0 && Number(counts.exams) === 0 &&
      Number(counts.questions) === 0 && Number(counts.attempts) === 0 && Number(counts.drafts) === 0 &&
      counts.students_enabled === false);
    const credential = await beforeClient.query('SELECT id,updated_at FROM public.naf038_admin_credentials WHERE id=1');
    adminStateBefore = credential.rows[0] || null;
  } finally { beforeClient.release(); }

  const salt = randomBytes(16);
  const ephemeralPassword = randomBytes(32).toString('base64url');
  const ephemeralEmail = `preview-e2e-${nonce}@invalid.example`;
  const hash = `scrypt$${salt.toString('base64url')}$${scryptSync(ephemeralPassword, salt, 64).toString('base64url')}`;
  const secret = randomBytes(32).toString('base64url');
  adminEnv = { NAFIS_ADMIN_EMAIL: ephemeralEmail, NAFIS_ADMIN_PASSWORD_HASH: hash,
    NAFIS_SESSION_SECRET: secret, NAFIS_STUDENT_PORTAL_ENABLED: 'false' };
  studentEnv = { ...adminEnv, NAFIS_STUDENT_PORTAL_ENABLED: 'true' };
  testPool = makePoolShim(basePool);
  const week = weekKey(new Date());
  const monday = weekDate(week);
  if (!monday) throw new Error('current_week_invalid');
  testNow = Date.parse(`${monday}T09:00:00Z`);
  Date.now = () => testNow;
  writesStarted = true;

  const noSession = await call('/admin/bootstrap');
  check('admin_api_rejects_missing_session', noSession.status === 401 && noSession.data.error === 'admin_login_required');

  const login = await call('/auth/login', { method: 'POST', body: { email: ephemeralEmail, password: ephemeralPassword } });
  check('ephemeral_account_authenticates_normally', login.status === 200 && typeof login.data.token === 'string');
  const token = login.data.token;

  const adminHealth = await call('/admin/health', { token });
  check('admin_session_and_rls_health', adminHealth.status === 200 && adminHealth.data.ready === true);

  const add = await call('/admin/questions', { method: 'POST', token, student: true, body: { questions: [{
    grade_number: grade, subject, week, duration_minutes: 10,
    prompt: `سؤال اختبار داخلي ${nonce}`, options: ['الخيار أ', 'الخيار ب', 'الخيار ج', 'الخيار د'], correct_index: 0,
  }] } });
  examId = Number(add.data.exams?.[0]?.id);
  check('temporary_exam_created_through_authenticated_api', add.status === 201 && Number.isSafeInteger(examId));

  const publish = await call(`/admin/exams/${examId}`, { method: 'PATCH', token, body: { published: true } });
  check('temporary_exam_published_in_internal_test_context', publish.status === 200 && publish.data.is_published === true);

  const start = await call('/student/start', { method: 'POST', student: true,
    body: { name: studentName, grade, section, subject } });
  const questionId = String(start.data.exam?.questions?.[0]?.id || '');
  check('test_student_starts_via_application_flow', start.status === 200 && Boolean(start.data.exam_token) && Boolean(questionId));

  const draft = await call('/student/draft', { method: 'PUT', student: true,
    token: start.data.exam_token, body: { answers: { [questionId]: 'أ' } } });
  check('autosave_persists_answer', draft.status === 200 && draft.data.saved === true);

  const resumed = await call('/student/start', { method: 'POST', student: true,
    body: { name: studentName, grade, section, subject } });
  check('answer_restored_after_new_start', resumed.status === 200 &&
    resumed.data.saved_answers?.[questionId] === 'أ' && resumed.data.exam_token === start.data.exam_token);

  const submit = await call('/student/submit', { method: 'POST', student: true,
    token: resumed.data.exam_token, body: { answers: {} } });
  check('submission_uses_saved_answers', submit.status === 201 && submit.data.accepted === true);

  const duplicateStart = await call('/student/start', { method: 'POST', student: true,
    body: { name: studentName, grade, section, subject } });
  const duplicateSubmit = await call('/student/submit', { method: 'POST', student: true,
    token: resumed.data.exam_token, body: { answers: { [questionId]: 'أ' } } });
  check('duplicate_start_rejected', duplicateStart.status === 409 && duplicateStart.data.error === 'attempt_used');
  check('duplicate_submission_rejected', duplicateSubmit.status === 409 && duplicateSubmit.data.error === 'attempt_used');

  const report = await call('/admin/bootstrap', { token });
  const attempt = report.data.attempts?.find(item => item.student_name === studentName);
  check('report_contains_real_test_attempt_and_portal_stays_unarmed', report.status === 200 && Boolean(attempt) &&
    Number(attempt.score) === 1 && Number(attempt.total) === 1 && report.data.settings.students_enabled === false &&
    report.data.portal_armed === false);
  const chartPercent = Math.round((Number(attempt.score) / Number(attempt.total)) * 100);
  const adminHtml = await readFile(new URL('../admin.html', import.meta.url), 'utf8');
  check('chart_metric_and_accessible_chart_markup', chartPercent === 100 &&
    adminHtml.includes('role="img" aria-label="رسم بياني لمتوسط الإتقان حسب المادة والصف"'));
  console.log('REPORT_METRIC chart_percent=100 source=preview_database_attempt');
} catch (error) {
  const safeMessages = new Set(['preview_only_guard', 'branch_guard', 'student_portal_must_remain_closed',
    'database_not_configured', 'runner_route_blocked', 'current_week_invalid', 'cleanup_verification_failed']);
  const reason = error?.message?.startsWith('check_failed:') || safeMessages.has(error?.message)
    ? error.message : `unexpected_${String(error?.code || error?.name || 'error').replace(/[^a-z0-9_-]/gi, '').slice(0, 32)}`;
  console.error(`FAIL ${reason}`);
  process.exitCode = 1;
} finally {
  Date.now = originalDateNow;
  if (basePool && writesStarted) {
    try {
      const client = await basePool.connect();
      try {
        await client.query('BEGIN');
        if (examId) {
          await client.query('DELETE FROM public.naf038_drafts WHERE exam_id=$1', [examId]);
          await client.query('DELETE FROM public.naf038_attempts WHERE exam_id=$1', [examId]);
          await client.query('DELETE FROM public.naf038_questions WHERE exam_id=$1', [examId]);
          await client.query('DELETE FROM public.naf038_exams WHERE id=$1', [examId]);
        }
        await client.query('DELETE FROM public.naf038_drafts WHERE student_id IN (SELECT id FROM public.nafis_students WHERE full_name=$1 AND grade=$2 AND section=$3)', [studentName, grade, section]);
        await client.query('DELETE FROM public.naf038_attempts WHERE student_id IN (SELECT id FROM public.nafis_students WHERE full_name=$1 AND grade=$2 AND section=$3)', [studentName, grade, section]);
        await client.query('DELETE FROM public.nafis_students WHERE full_name=$1 AND grade=$2 AND section=$3', [studentName, grade, section]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally { client.release(); }

      const verify = await basePool.connect();
      try {
        const after = await countRows(verify);
        const credential = await verify.query('SELECT id,updated_at FROM public.naf038_admin_credentials WHERE id=1');
        const state = credential.rows[0] || null;
        cleanupComplete = Number(after.students) === 0 && Number(after.exams) === 0 && Number(after.questions) === 0 &&
          Number(after.attempts) === 0 && Number(after.drafts) === 0 && after.students_enabled === false &&
          JSON.stringify(state) === JSON.stringify(adminStateBefore);
      } finally { verify.release(); }
      if (!cleanupComplete) throw new Error('cleanup_verification_failed');
      console.log('PASS test_records_and_ephemeral_account_cleaned');
    } catch {
      console.error('FAIL cleanup_verification_failed');
      process.exitCode = 1;
    }
  }
  if (basePool) await basePool.end();
  if (process.exitCode === 0 && checks.length > 0 && cleanupComplete)
    console.log(`PREVIEW_INTEGRATION_RESULT ${JSON.stringify({ passed: checks.length, failed: 0, cleanup: 'verified', database: 'expected_preview_sandbox', temporary_account: 'in_memory_only' })}`);
}
