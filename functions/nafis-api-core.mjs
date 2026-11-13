import { createHash, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const TABLES = ['nafis_students', 'naf038_settings', 'naf038_exams', 'naf038_questions', 'naf038_attempts', 'naf038_drafts', 'naf038_admin_credentials', 'naf038_student_access', 'naf038_results_publications'];
const GRADES = new Map([[1, 'الأول متوسط'], [2, 'الثاني متوسط'], [3, 'الثالث متوسط']]);
const SUBJECTS = new Set(['لغتي', 'الرياضيات', 'العلوم']);
const LETTERS = ['أ', 'ب', 'ج', 'د', 'هـ', 'و'];
const MAX_BODY_BYTES = 1_000_000;
const loginAttempts = new Map();
const studentCodeAttempts = new Map();

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
});
const fail = (status, code, message) => json({ error: code, message }, status);
const trim = (value, max = 160) => typeof value === 'string' ? value.trim().slice(0, max) : '';
const norm = value => trim(value, 120).normalize('NFKC').replace(/\s+/gu, ' ').toLocaleLowerCase('ar');
const gradeText = value => GRADES.get(Number(value)) || null;
const weekDate = key => {
  const m = /^(\d{4})-W(\d{2})$/.exec(String(key || ''));
  if (!m) return null;
  const year = Number(m[1]), week = Number(m[2]);
  if (week < 1 || week > 53) return null;
  const jan4 = new Date(Date.UTC(year, 0, 4));
  const monday = new Date(jan4.getTime() - ((jan4.getUTCDay() + 6) % 7) * 86_400_000 + (week - 1) * 7 * 86_400_000);
  const check = new Date(monday.getTime() + 3 * 86_400_000);
  if (check.getUTCFullYear() !== year) return null;
  return monday.toISOString().slice(0, 10);
};
const weekKey = date => {
  const value = String(date || '');
  const d = new Date(/^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : value);
  if (Number.isNaN(d.getTime())) return '';
  const x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  x.setUTCDate(x.getUTCDate() + 4 - (x.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(x.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((x - yearStart) / 86_400_000) + 1) / 7);
  return `${x.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
};
const announcementAt = key => {
  const monday = weekDate(key);
  if (!monday) return null;
  const saturday = new Date(Date.parse(`${monday}T00:00:00Z`) + 5 * 86_400_000).toISOString().slice(0, 10);
  // Saudi Arabia is UTC+3; Neon schedule triggers use UTC.
  return Date.parse(`${saturday}T15:00:00Z`);
};
function answerLetter(value) {
  const text = String(value ?? '').trim().toUpperCase();
  const aliases = { A: 'أ', B: 'ب', C: 'ج', D: 'د', E: 'هـ', F: 'و', '1': 'أ', '2': 'ب', '3': 'ج', '4': 'د', '5': 'هـ', '6': 'و' };
  return aliases[text] || (LETTERS.includes(text) ? text : null);
}
function optionTexts(value) {
  if (Array.isArray(value)) return value.map(x => typeof x === 'string' ? x : String(x?.text ?? x?.label ?? '')).filter(Boolean);
  if (value && typeof value === 'object') return Object.values(value).map(x => typeof x === 'string' ? x : String(x?.text ?? x?.label ?? '')).filter(Boolean);
  return [];
}
function safeEqualText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}
function signedToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function readToken(token, secret) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const [body, sig, extra] = token.split('.');
  if (!body || !sig || extra) return null;
  const expected = createHmac('sha256', secret).update(body).digest();
  let received;
  try { received = Buffer.from(sig, 'base64url'); } catch { return null; }
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return payload.exp > Math.floor(Date.now() / 1000) ? payload : null;
  } catch { return null; }
}
async function bodyJson(request) {
  const text = await request.text();
  if (Buffer.byteLength(text) > MAX_BODY_BYTES) throw Object.assign(new Error('too_large'), { status: 413 });
  try { return JSON.parse(text || '{}'); }
  catch { throw Object.assign(new Error('invalid_json'), { status: 400 }); }
}
function authAdmin(request, env) {
  const secret = env.NAFIS_SESSION_SECRET || '';
  const value = request.headers.get('authorization') || '';
  const token = value.startsWith('Bearer ') ? value.slice(7) : '';
  const payload = secret ? readToken(token, secret) : null;
  return payload?.role === 'admin' && payload.sub === (env.NAFIS_ADMIN_EMAIL || '').toLowerCase() ? payload : null;
}
function authExam(request, env) {
  const value = request.headers.get('authorization') || '';
  const token = value.startsWith('Bearer ') ? value.slice(7) : '';
  const payload = env.NAFIS_SESSION_SECRET ? readToken(token, env.NAFIS_SESSION_SECRET) : null;
  return payload?.role === 'exam' ? payload : null;
}
function authCertificates(request, env) {
  const value = request.headers.get('authorization') || '';
  const cookieToken = (request.headers.get('cookie') || '').split(';').map(part => part.trim())
    .find(part => part.startsWith('naf038_student_session='))?.slice('naf038_student_session='.length) || '';
  const bearer = value.startsWith('Bearer ') ? value.slice(7) : '';
  const payloads = env.NAFIS_SESSION_SECRET ? [bearer,cookieToken].filter(Boolean)
    .map(token => readToken(token,env.NAFIS_SESSION_SECRET)) : [];
  const payload = payloads.find(item => item?.role === 'student_certificates' &&
    Number.isSafeInteger(Number(item.sub)) && Number(item.sub) > 0);
  if (!payload) return null;
  if (payload.source === 'exam-submit' && (!Array.isArray(payload.examIds) || !payload.examIds.length ||
      payload.examIds.some(id => !Number.isSafeInteger(Number(id)) || Number(id) < 1))) return null;
  return { ...payload, studentId:Number(payload.sub) };
}
function studentSessionCookie(studentId, examId, request, secret, now) {
  const issued = Math.floor(now / 1000), expires = issued + 30 * 24 * 60 * 60;
  const prior = authCertificates(new Request(request.url,{headers:{cookie:request.headers.get('cookie')||''}}),{NAFIS_SESSION_SECRET:secret});
  const priorIds = prior?.source==='exam-submit'&&prior.studentId===Number(studentId)?prior.examIds.map(Number):[];
  const examIds = [...new Set([...priorIds,Number(examId)])].slice(-100);
  const token = signedToken({ sub:String(studentId), role:'student_certificates', source:'exam-submit', examIds, iat:issued, exp:expires }, secret);
  return `naf038_student_session=${token}; Path=/api; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict`;
}
function studentAccessHash(code) {
  return createHash('sha256').update(String(code)).digest('hex');
}
function certificateProof(studentId, examId, award, secret) {
  const payload = Buffer.from(JSON.stringify({ v: 1, student_id: Number(studentId), exam_id: Number(examId), award })).toString('base64url');
  return `${payload}.${createHmac('sha256', secret).update(payload).digest('base64url')}`;
}
function readCertificateProof(value, secret) {
  if (typeof value !== 'string' || value.length > 512) return null;
  const [body, signature, extra] = value.split('.');
  if (!body || !signature || extra) return null;
  const expected = createHmac('sha256', secret).update(body).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.v !== 1 || !Number.isSafeInteger(payload.student_id) || payload.student_id < 1 ||
        !Number.isSafeInteger(payload.exam_id) || payload.exam_id < 1 ||
        !['participation','gold','silver','bronze'].includes(payload.award)) return null;
    return payload;
  } catch { return null; }
}
function corsHeaders(request, env) {
  const origin = request.headers.get('origin');
  if (!origin) return {};
  // Same-origin calls do not require CORS headers or an allowlist entry.
  // Keep the allowlist check for cross-origin callers only.
  if (origin === new URL(request.url).origin) return {};
  const allowed = (env.NAFIS_ALLOWED_ORIGINS || 'https://fadihalghamdy07-ui.github.io')
    .split(',').map(x => x.trim()).filter(Boolean);
  if (!allowed.includes(origin)) return null;
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,OPTIONS',
    'access-control-allow-headers': 'authorization,content-type',
    'access-control-max-age': '600',
    vary: 'Origin',
  };
}
function adminOnly(request, env) {
  const admin = authAdmin(request, env);
  return admin || fail(401, 'admin_login_required', 'يلزم تسجيل دخول الإدارة.');
}

function validateDocumentation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const allowed = new Set(['initiative', 'team', 'milestones', 'attachments', 'approval']);
  if (Object.keys(value).some(key => !allowed.has(key))) return false;
  const strings = [
    value.initiative?.idea, value.initiative?.rationale, value.initiative?.objectives,
    value.initiative?.audience, value.initiative?.founded_at,
    value.initiative?.stages, value.approval?.authority, value.approval?.approver,
    value.approval?.date,
  ];
  if (strings.some(x => typeof x !== 'string' || x.length > 12000)) return false;
  if (!Array.isArray(value.team) || value.team.length > 40 || value.team.some(person =>
    !person || typeof person.name !== 'string' || person.name.length > 180 ||
    typeof person.role !== 'string' || person.role.length > 300)) return false;
  if (!Array.isArray(value.milestones) || value.milestones.length > 200 || value.milestones.some(item =>
    !item || typeof item.title !== 'string' || item.title.length > 250 ||
    typeof item.date !== 'string' || item.date.length > 40 ||
    typeof item.description !== 'string' || item.description.length > 2000)) return false;
  if (!Array.isArray(value.attachments) || value.attachments.length > 10 || value.attachments.some(file =>
    !file || typeof file.name !== 'string' || file.name.length > 150 ||
    !['image/png','image/jpeg','application/pdf'].includes(file.type) ||
    typeof file.data !== 'string' || file.data.length > 700000 ||
    !file.data.startsWith(`data:${file.type};base64,`))) return false;
  return true;
}
async function readSettings(pool) {
  const { rows } = await pool.query('SELECT id, current_week, students_enabled, exam_minutes, results_published_week, results_published_at FROM public.naf038_settings WHERE id = 1 LIMIT 1');
  return rows[0] || null;
}
async function validateDb(pool) {
  const { rows } = await pool.query(`
    SELECT c.relname AS table_name, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced,
           EXISTS (SELECT 1 FROM pg_catalog.pg_policies p WHERE p.schemaname='public'
             AND p.tablename=c.relname AND (p.roles @> ARRAY[current_user]::name[]
               OR p.roles @> ARRAY['public']::name[])) AS role_policy
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = ANY($1::text[])
`, [TABLES]);
  const seen = new Map();
  for (const row of rows) {
    const curr = seen.get(row.table_name) || { rls: row.rls, forced: row.forced, policy: false };
    curr.policy ||= Boolean(row.role_policy);
    seen.set(row.table_name, curr);
  }
  return TABLES.map(name => {
    const item = seen.get(name);
    return { table: name, ready: Boolean(item?.rls && item?.forced && item?.policy) };
  });
}
async function currentExam(pool, grade, subject, { ensureFinish = false } = {}) {
  const settings = await readSettings(pool);
  if (!settings || !settings.students_enabled) return { error: 'closed', settings };
  const closesAt = announcementAt(settings.current_week);
  if (!closesAt) return { error: 'announcement_window_closed', settings };
  const monday = weekDate(settings.current_week);
  if (!monday) return { error: 'invalid_week', settings };
  const { rows } = await pool.query(`
    SELECT id, grade, subject, week_start::text AS week_start, duration_minutes, is_published
      FROM public.naf038_exams
     WHERE grade = $1 AND subject = $2 AND week_start = $3::date AND is_published = true
     LIMIT 1`, [grade, subject, monday]);
  if (!rows[0]) return { exam: null, settings };
  if (ensureFinish && Date.now() + Number(rows[0].duration_minutes) * 60_000 > closesAt)
    return { error: 'announcement_window_closed', settings };
  return { exam: rows[0], settings };
}
async function examQuestions(pool, examId, withAnswers = false) {
  const selectAnswer = withAnswers ? ', q.correct_answer' : '';
  const { rows } = await pool.query(`
    SELECT q.id, q.question_number, q.question_text, q.options, q.explanation, q.image_url, q.skill${selectAnswer}
      FROM public.naf038_questions q
     WHERE q.exam_id = $1
     ORDER BY q.question_number, q.id`, [examId]);
  return rows;
}
function publicQuestion(q) {
  return { id: q.id, question_number: q.question_number, question_text: q.question_text,
    options: optionTexts(q.options), image_url: q.image_url || null, skill: q.skill || null };
}
function shapeAdminQuestion(q) {
  const grade = Number(q.grade);
  const options = optionTexts(q.options);
  const answer = answerLetter(q.correct_answer);
  return { id: q.id, prompt: q.question_text, grade: gradeText(grade), subject: q.subject,
    week: weekKey(q.week_start), options, correct_index: Math.max(0, LETTERS.indexOf(answer)),
    explanation: q.explanation || '', active: true, exam_id: q.exam_id };
}
async function collectQuestions(pool) {
  const { rows } = await pool.query(`
    SELECT q.id, q.exam_id, q.question_number, q.question_text, q.options, q.correct_answer,
           q.explanation, e.grade, e.subject, e.week_start::text AS week_start
      FROM public.naf038_questions q JOIN public.naf038_exams e ON e.id = q.exam_id
     ORDER BY e.week_start DESC, q.question_number, q.id LIMIT 2000`);
  return rows.map(shapeAdminQuestion);
}
async function collectExams(pool) {
  const { rows } = await pool.query(`
    SELECT e.id, e.grade, e.subject, e.week_start::text AS week_start, e.duration_minutes, e.is_published,
           COUNT(q.id)::integer AS question_count
      FROM public.naf038_exams e LEFT JOIN public.naf038_questions q ON q.exam_id = e.id
     GROUP BY e.id ORDER BY e.week_start DESC, e.grade, e.subject LIMIT 200`);
  return rows.map(e => ({ id: e.id, grade: gradeText(e.grade), grade_number: e.grade, subject: e.subject,
    week: weekKey(e.week_start), week_start: e.week_start, duration_minutes: e.duration_minutes,
    published: e.is_published, question_count: e.question_count }));
}
async function collectAttempts(pool) {
  const { rows } = await pool.query(`
    SELECT a.id, s.full_name AS student_name, s.grade, s.section, e.subject,
           to_char(e.week_start, 'IYYY-"W"IW') AS week, a.score, a.duration_seconds,
           a.started_at, a.submitted_at, a.exam_id,
           COALESCE(a.total_questions,(SELECT COUNT(*)::integer FROM public.naf038_questions q WHERE q.exam_id = e.id)) AS total
      FROM public.naf038_attempts a
      JOIN public.nafis_students s ON s.id = a.student_id
      JOIN public.naf038_exams e ON e.id = a.exam_id
     ORDER BY a.submitted_at DESC NULLS LAST LIMIT 2000`);
  return rows.map(a => ({ ...a, grade: gradeText(a.grade) }));
}
async function createExamIfNeeded(client, item, settings) {
  const monday = weekDate(item.week || settings.current_week);
  if (!monday) throw Object.assign(new Error('invalid_week'), { status: 400 });
  const grade = Number(item.grade_number || [...GRADES].find(([, label]) => label === item.grade)?.[0]);
  if (!GRADES.has(grade) || !SUBJECTS.has(item.subject)) throw Object.assign(new Error('invalid_exam'), { status: 400 });
  const { rows } = await client.query(`SELECT id FROM public.naf038_exams WHERE grade=$1 AND subject=$2 AND week_start=$3::date LIMIT 1`, [grade, item.subject, monday]);
  if (rows[0]) return { id: rows[0].id, grade, subject: item.subject, monday };
  const { rows: created } = await client.query(`
    INSERT INTO public.naf038_exams(grade, subject, week_start, duration_minutes, is_published)
    VALUES ($1,$2,$3::date,$4,false) RETURNING id`, [grade, item.subject, monday, Number(settings.exam_minutes) || 40]);
  return { id: created[0].id, grade, subject: item.subject, monday };
}
function normalizeQuestion(input) {
  const prompt = trim(input.prompt ?? input.question_text, 2000);
  const options = Array.isArray(input.options) ? input.options.map(x => trim(typeof x === 'string' ? x : x?.text, 500)).filter(Boolean) : [];
  let correct = Number(input.correct_index);
  if (!Number.isInteger(correct)) correct = options.findIndex(x => x === trim(input.answer, 500));
  if (!prompt || options.length < 2 || options.length > LETTERS.length || correct < 0 || correct >= options.length) return null;
  return { ...input, prompt, options, correct_answer: LETTERS[correct] };
}
async function addQuestions(pool, list) {
  if (!Array.isArray(list) || list.length < 1 || list.length > 250) throw Object.assign(new Error('invalid_questions'), { status: 400 });
  const normalized = list.map(normalizeQuestion);
  if (normalized.some(q => !q)) throw Object.assign(new Error('invalid_question'), { status: 400 });
  const settings = await readSettings(pool);
  if (!settings) throw Object.assign(new Error('missing_settings'), { status: 503 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const byExam = new Map();
    for (const q of normalized) {
      const exam = await createExamIfNeeded(client, q, settings);
      const key = `${exam.id}`;
      if (!byExam.has(key)) {
        const { rows } = await client.query('SELECT COALESCE(MAX(question_number),0)::integer AS n FROM public.naf038_questions WHERE exam_id=$1', [exam.id]);
        byExam.set(key, { exam, next: rows[0].n + 1 });
      }
      const slot = byExam.get(key);
      await client.query(`
        INSERT INTO public.naf038_questions(exam_id, question_number, question_text, options, correct_answer, explanation, image_url, skill)
        VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8)`, [slot.exam.id, slot.next++, q.prompt, JSON.stringify(q.options), q.correct_answer,
        trim(q.explanation, 2000) || null, trim(q.image_url, 1000) || null, trim(q.skill, 200) || null]);
    }
    await client.query('COMMIT');
    return { inserted: normalized.length, exams: [...byExam.values()].map(x => x.exam) };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}
function requestLimiter(ip, buckets = loginAttempts) {
  const now = Date.now(), previous = buckets.get(ip) || { start: now, count: 0 };
  if (now - previous.start > 15 * 60_000) { previous.start = now; previous.count = 0; }
  previous.count++;
  buckets.set(ip, previous);
  if (buckets.size > 2000) for (const [key, value] of buckets) if (now - value.start > 15 * 60_000) buckets.delete(key);
  return previous.count <= 6;
}
async function verifyPassword(password, encoded) {
  const [method, salt64, hash64] = String(encoded || '').split('$');
  if (method !== 'scrypt' || !salt64 || !hash64) return false;
  const expected = Buffer.from(hash64, 'base64url');
  const actual = await scrypt(password, Buffer.from(salt64, 'base64url'), expected.length);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
async function activeAdminPasswordHash(pool, fallback) {
  if (!pool) return fallback;
  try {
    const { rows } = await pool.query('SELECT password_hash FROM public.naf038_admin_credentials WHERE id=1 LIMIT 1');
    return rows[0]?.password_hash || fallback;
  } catch (error) {
    // Preserve existing environment-based login until the additive migration is applied.
    if (error?.code === '42P01') return fallback;
    throw error;
  }
}
async function encodePassword(password) {
  const salt = randomBytes(16);
  const hash = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}
async function studentStart(pool, body, env) {
  const name = trim(body.name, 120), section = trim(body.section, 4), grade = Number(body.grade), subject = trim(body.subject, 40);
  if (name.split(/\s+/u).length < 4 || !GRADES.has(grade) || !/^[1-4]$/.test(section) || !SUBJECTS.has(subject))
    throw Object.assign(new Error('invalid_student'), { status: 400 });
  const current = await currentExam(pool, grade, subject, { ensureFinish:true });
  if (current.error === 'closed') throw Object.assign(new Error('students_closed'), { status: 423 });
  if (current.error || !current.exam) throw Object.assign(new Error('exam_unavailable'), { status: 404 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const student = await client.query(`
      INSERT INTO public.nafis_students(full_name, grade, section)
      VALUES ($1,$2,$3)
      ON CONFLICT (lower(btrim(full_name)), grade, lower(btrim(section)))
      DO UPDATE SET section=EXCLUDED.section
      RETURNING id`, [name, grade, section]);
    const studentId = student.rows[0].id;
    const prior = await client.query('SELECT id FROM public.naf038_attempts WHERE exam_id=$1 AND student_id=$2 LIMIT 1', [current.exam.id, studentId]);
    if (prior.rows.length) throw Object.assign(new Error('attempt_used'), { status: 409 });
    const draftResult = await client.query('SELECT answers,started_at FROM public.naf038_drafts WHERE exam_id=$1 AND student_id=$2 LIMIT 1', [current.exam.id, studentId]);
    const draft = draftResult.rows[0] || null;
    const qs = await examQuestions(client, current.exam.id, false);
    if (!qs.length) throw Object.assign(new Error('exam_empty'), { status: 404 });
    const start = draft?.started_at ? Math.floor(new Date(draft.started_at).getTime() / 1000) : Math.floor(Date.now() / 1000);
    const elapsed = Math.max(0, Math.floor(Date.now() / 1000) - start);
    if (elapsed >= Number(current.exam.duration_minutes) * 60) throw Object.assign(new Error('time_expired'), { status: 409 });
    const exp = start + Number(current.exam.duration_minutes) * 60 + 15 * 60;
    const token = signedToken({ role: 'exam', studentId, examId: current.exam.id, grade, section, subject, started: start, exp }, env.NAFIS_SESSION_SECRET);
    await client.query('COMMIT');
    return { exam: { id: current.exam.id, duration_minutes: current.exam.duration_minutes,
      questions: qs.map(publicQuestion) }, exam_token: token, saved_answers: draft?.answers || {}, remaining_seconds: Math.max(0, Number(current.exam.duration_minutes) * 60 - elapsed) };
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') throw Object.assign(new Error('attempt_used'), { status: 409 });
    throw error;
  } finally { client.release(); }
}
async function studentSaveDraft(pool, body, token) {
  const examId = Number(token.examId), studentId = Number(token.studentId), answers = body.answers;
  if (!Number.isSafeInteger(examId) || !Number.isSafeInteger(studentId) || !answers || typeof answers !== 'object' || Array.isArray(answers))
    throw Object.assign(new Error('invalid_submission'), { status: 400 });
  const current = await currentExam(pool, Number(token.grade), token.subject);
  if (current.error === 'closed' || !current.exam) throw Object.assign(new Error('students_closed'), { status: 423 });
  if (String(current.exam.id) !== String(examId)) throw Object.assign(new Error('exam_changed'), { status: 409 });
  const qs = await examQuestions(pool, examId, false);
  const allowed = new Set(qs.map(q => String(q.id)));
  const saved = {};
  for (const [id, raw] of Object.entries(answers)) {
    if (!allowed.has(String(id))) throw Object.assign(new Error('invalid_submission'), { status: 400 });
    const answer = answerLetter(raw);
    const q = qs.find(item => String(item.id) === String(id));
    if (!answer || LETTERS.indexOf(answer) >= optionTexts(q.options).length) throw Object.assign(new Error('invalid_submission'), { status: 400 });
    saved[id] = answer;
  }
  const elapsed = Math.max(0, Math.floor(Date.now() / 1000) - Number(token.started));
  if (elapsed > Number(current.exam.duration_minutes) * 60) throw Object.assign(new Error('time_expired'), { status: 409 });
  await pool.query(`
    INSERT INTO public.naf038_drafts(exam_id,student_id,started_at,answers,updated_at)
    VALUES ($1,$2,to_timestamp($3),$4::jsonb,NOW())
    ON CONFLICT (exam_id,student_id) DO UPDATE
       SET answers=EXCLUDED.answers,updated_at=NOW()`, [examId, studentId, Number(token.started), JSON.stringify(saved)]);
  return { saved: true };
}
async function studentSubmit(pool, body, token) {
  const examId = Number(token.examId), studentId = Number(token.studentId), answers = body.answers;
  if (!Number.isSafeInteger(examId) || !Number.isSafeInteger(studentId) || !answers || typeof answers !== 'object' || Array.isArray(answers))
    throw Object.assign(new Error('invalid_submission'), { status: 400 });
  const current = await currentExam(pool, Number(token.grade), token.subject);
  if (current.error === 'closed' || !current.exam) throw Object.assign(new Error('students_closed'), { status: 423 });
  if (Date.now() >= announcementAt(current.settings?.current_week))
    throw Object.assign(new Error('time_expired'), { status: 409 });
  if (String(current.exam.id) !== String(examId)) throw Object.assign(new Error('exam_changed'), { status: 409 });
  const qs = await examQuestions(pool, examId, true);
  if (!qs.length) throw Object.assign(new Error('invalid_submission'), { status: 400 });
  const draftResult = await pool.query('SELECT answers FROM public.naf038_drafts WHERE exam_id=$1 AND student_id=$2 LIMIT 1', [examId, studentId]);
  const combined = { ...(draftResult.rows[0]?.answers || {}), ...answers };
  let score = 0;
  const saved = {};
  for (const q of qs) {
    const raw = combined[q.id] ?? combined[String(q.id)];
    if (raw === undefined || raw === null || raw === '') continue;
    const answer = answerLetter(raw);
    const opts = optionTexts(q.options);
    if (!answer || LETTERS.indexOf(answer) >= opts.length) throw Object.assign(new Error('invalid_submission'), { status: 400 });
    saved[q.id] = answer;
    if (answer === answerLetter(q.correct_answer)) score++;
  }
  const elapsed = Math.max(0, Math.floor(Date.now() / 1000) - Number(token.started));
  const maxDuration = Number(current.exam.duration_minutes) * 60;
  if (!Number.isFinite(elapsed) || elapsed > maxDuration + 60) throw Object.assign(new Error('time_expired'), { status: 409 });
  try {
    await pool.query(`
      INSERT INTO public.naf038_attempts(exam_id, student_id, started_at, submitted_at, answers, score, duration_seconds, total_questions)
      VALUES ($1,$2,to_timestamp($3),NOW(),$4::jsonb,$5,$6,$7)`, [examId, studentId, Number(token.started), JSON.stringify(saved), score, elapsed, qs.length]);
    await pool.query('DELETE FROM public.naf038_drafts WHERE exam_id=$1 AND student_id=$2', [examId, studentId]);
  } catch (error) {
    if (error.code === '23505') throw Object.assign(new Error('attempt_used'), { status: 409 });
    throw error;
  }
  return { accepted: true, message: 'تم تسليم إجابتك وحفظها بسرية. تُعلن النتائج تلقائيًا يوم السبت الساعة ٦ مساءً بتوقيت السعودية.' };
}
async function collectStudentAchievements(pool, studentId, secret, now, examIds = null) {
  const { rows } = await pool.query(`
    WITH released AS (
      SELECT s.id AS student_id, s.full_name AS student_name, e.id AS exam_id,
             e.grade, e.subject, p.week_key AS week,
             a.score::integer AS score,
             COALESCE(a.total_questions,(SELECT COUNT(*)::integer FROM public.naf038_questions q WHERE q.exam_id=e.id))::integer AS total,
             a.duration_seconds, a.submitted_at
        FROM public.naf038_attempts a
        JOIN public.nafis_students s ON s.id=a.student_id
        JOIN public.naf038_exams e ON e.id=a.exam_id
        JOIN public.naf038_results_publications p
          ON p.week_key=to_char(e.week_start,'IYYY-"W"IW')
         AND p.published_at <= $2::timestamptz
         AND p.published_at >= ((date_trunc('week',e.week_start::timestamp) + INTERVAL '5 days 15 hours') AT TIME ZONE 'UTC')
         AND a.submitted_at <= p.published_at
    ), ranked AS (
      SELECT released.*,
             ROW_NUMBER() OVER (PARTITION BY grade,subject,week
               ORDER BY score::numeric / NULLIF(total,0) DESC,
                        duration_seconds ASC, submitted_at ASC, student_id ASC) AS rank
        FROM released
    )
    SELECT student_id,student_name,exam_id,grade,subject,week,score,total,duration_seconds,rank
      FROM ranked WHERE student_id=$1 AND ($3::bigint[] IS NULL OR exam_id=ANY($3::bigint[]))
     ORDER BY week DESC,grade,subject`, [studentId, new Date(now).toISOString(), examIds]);
  const certificates = [];
  for (const row of rows) {
    const common = { student_name:row.student_name, grade:gradeText(row.grade), subject:row.subject,
      week:row.week, score:Number(row.score), total:Number(row.total) };
    certificates.push({ ...common, type:'participation', title:'شهادة مشاركة', medal:null,
      verification_code:certificateProof(row.student_id,row.exam_id,'participation',secret) });
    const rank=Number(row.rank), medals={1:['gold','ذهبية','🥇'],2:['silver','فضية','🥈'],3:['bronze','برونزية','🥉']};
    if (medals[rank]) certificates.push({ ...common, type:medals[rank][0], title:`شهادة تميز ${medals[rank][1]}`,
      medal:medals[rank][2], rank, verification_code:certificateProof(row.student_id,row.exam_id,medals[rank][0],secret) });
  }
  return certificates;
}
async function handleRequest(request, { pool, env = process.env, now = () => Date.now() } = {}) {
  const cors = corsHeaders(request, env);
  if (cors === null) return fail(403, 'origin_not_allowed', 'مصدر الطلب غير مسموح.');
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors || {} });
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/, '') || '/';
  const headers = cors || {};
  try {
    if (request.method === 'GET' && path === '/health') {
      if (!pool) return json({ ok: false }, 503, headers);
      const {rows}=await pool.query(`SELECT current_database() AS database_name,
        current_setting('neon.project_id',true) AS neon_project_id,
        current_setting('neon.branch_id',true) AS neon_branch_id`);
      const identity=rows[0]||{};
      const isolatedPreview=env.VERCEL_ENV==='preview'&&env.VERCEL_GIT_COMMIT_REF==='vercel-backend-ready'&&
        identity.database_name==='neondb'&&identity.neon_project_id==='icy-salad-25508888'&&
        identity.neon_branch_id==='br-weathered-rice-b9d4vuoy';
      return json({ ok: true, isolated_preview_database: isolatedPreview }, 200, headers);
    }
    if (request.method === 'GET' && path === '/student/status') {
      if (env.NAFIS_STUDENT_PORTAL_ENABLED !== 'true')
        return json({ open: false }, 200, headers);
      const settings = await readSettings(pool);
      const closesAt = announcementAt(settings?.current_week);
      return json({ open: Boolean(settings?.students_enabled && closesAt && now() < closesAt) }, 200, headers);
    }
    if (request.method === 'POST' && path === '/internal/publish-results') {
      // Neon removes client-supplied X-Neon-* headers, so this header identifies scheduled calls.
      if (!request.headers.get('x-neon-trigger-invocation-id'))
        return fail(401, 'trigger_only', 'هذا المسار مخصص لجدولة Neon.');
      const body = await bodyJson(request);
      const scheduledAt = body?.data?.scheduled_at;
      const scheduledTime = Date.parse(scheduledAt || '');
      if (!Number.isFinite(scheduledTime)) return fail(400, 'invalid_trigger_time', 'وقت الجدولة غير صالح.');
      const scheduledDate = new Date(scheduledTime);
      const scheduledWeek = weekKey(scheduledAt);
      if (scheduledDate.getUTCDay() !== 6 || scheduledDate.getUTCHours() !== 15 ||
          scheduledDate.getUTCMinutes() !== 0 || scheduledDate.getUTCSeconds() !== 0)
        return fail(400, 'invalid_trigger_time', 'موعد الإعلان المجدول غير مطابق للسبت الساعة السادسة مساءً بتوقيت السعودية.');
      const result = await pool.query(`
        WITH updated AS (
          UPDATE public.naf038_settings
             SET results_published_week=$2,
                 results_published_at=$1::timestamptz,
                 updated_at=NOW()
           WHERE id=1
           RETURNING current_week,results_published_at
        ), publication AS (
          INSERT INTO public.naf038_results_publications(week_key,published_at)
          SELECT $2,$1::timestamptz FROM updated
          ON CONFLICT (week_key) DO UPDATE SET published_at=EXCLUDED.published_at
          RETURNING week_key,published_at
        )
        SELECT updated.current_week,publication.published_at
          FROM updated JOIN publication ON publication.week_key=$2`, [new Date(scheduledTime).toISOString(), scheduledWeek]);
      const published = result.rows[0];
      if (!published) throw Object.assign(new Error('missing_settings'), { status: 503 });
      console.log('nafis_results_published', { week: scheduledWeek, scheduled_at: new Date(scheduledTime).toISOString() });
      return json({ published: true, week: scheduledWeek, results_published_at: published.results_published_at }, 200, headers);
    }
    if (request.method === 'GET' && path === '/student/results') {
      const settings = await readSettings(pool);
      const resultWeek = settings?.results_published_week;
      const announcementTime = announcementAt(resultWeek);
      const published = resultWeek && settings?.results_published_at &&
        weekKey(settings.results_published_at) === resultWeek && now() >= announcementTime;
      if (!published) return json({ published: false, available_at: announcementTime ? new Date(announcementTime).toISOString() : null }, 200, headers);
      const { rows } = await pool.query(`
        SELECT s.full_name AS student_name, s.grade, s.section, e.subject, a.score,
               COALESCE(a.total_questions,(SELECT COUNT(*)::integer FROM public.naf038_questions q WHERE q.exam_id=e.id)) AS total,
               a.submitted_at
          FROM public.naf038_attempts a
          JOIN public.nafis_students s ON s.id=a.student_id
          JOIN public.naf038_exams e ON e.id=a.exam_id
         WHERE e.week_start=$1::date AND a.submitted_at <= $2::timestamptz
         ORDER BY s.grade, s.section, s.full_name, e.subject`,
        [weekDate(resultWeek), settings.results_published_at]);
      const results = rows.map(r => ({ student_name:r.student_name, grade:gradeText(r.grade), section:r.section,
        subject:r.subject, score:Number(r.score), total:Number(r.total), submitted_at:r.submitted_at }));
      const byStudent = new Map();
      for (const r of results) {
        const key = `${r.student_name}|${r.grade}|${r.section}`;
        const item = byStudent.get(key) || { name:r.student_name, grade:r.grade, section:r.section, sum:0, completed:0 };
        item.sum += r.total ? r.score / r.total : 0;
        item.completed++;
        byStudent.set(key,item);
      }
      const leaders = [...byStudent.values()].map(x => ({ name:x.name, grade:x.grade, section:x.section,
        percentage:Math.round(x.sum/x.completed*100), completed:x.completed }))
        .sort((a,b) => b.percentage-a.percentage || b.completed-a.completed || a.name.localeCompare(b.name,'ar')).slice(0,10);
      // Public callers may learn that release happened, but student identities and scores are private.
      return json({ published:true, week:resultWeek, published_at:settings.results_published_at,
        total_attempts:results.length }, 200, headers);
    }
    if (request.method === 'POST' && path === '/auth/login') {
      const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
      if (!requestLimiter(ip)) return fail(429, 'rate_limited', 'حاولي بعد 15 دقيقة.');
      const body = await bodyJson(request);
      const email = trim(body.email, 254).toLowerCase();
      const correctEmail = safeEqualText(email, (env.NAFIS_ADMIN_EMAIL || '').toLowerCase());
      const passwordHash = await activeAdminPasswordHash(pool, env.NAFIS_ADMIN_PASSWORD_HASH);
      const correctPassword = await verifyPassword(String(body.password || ''), passwordHash);
      if (!correctEmail || !correctPassword || !env.NAFIS_SESSION_SECRET) return fail(401, 'invalid_login', 'بيانات الدخول غير صحيحة.');
      const issued = Math.floor(now() / 1000), exp = issued + 8 * 60 * 60;
      const token = signedToken({ sub: email, role: 'admin', iat: issued, exp }, env.NAFIS_SESSION_SECRET);
      return json({ token, expires_at: exp, email }, 200, headers);
    }
    if (request.method === 'POST' && path === '/student/achievements/session') {
      if (!env.NAFIS_SESSION_SECRET) return fail(503, 'not_configured', 'لم يكتمل إعداد الحماية.');
      const ip=request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()||'unknown';
      if (!requestLimiter(ip,studentCodeAttempts)) return fail(429,'rate_limited','تجاوزت محاولات إدخال الرمز؛ حاولي بعد 15 دقيقة.');
      const body=await bodyJson(request), code=trim(body.access_code,120);
      if (!/^[A-Za-z0-9_-]{30,50}$/.test(code)) return fail(401,'invalid_student_access_code','تعذر التحقق من رمز الطالبة.');
      const {rows}=await pool.query(`SELECT student_id,access_hash FROM public.naf038_student_access
        WHERE access_hash=$1 AND revoked_at IS NULL LIMIT 1`,[studentAccessHash(code)]);
      if (!rows[0]) return fail(401,'invalid_student_access_code','تعذر التحقق من رمز الطالبة.');
      const issued=Math.floor(now()/1000), exp=issued+30*60;
      const token=signedToken({sub:String(rows[0].student_id),role:'student_certificates',source:'access-code',access:rows[0].access_hash,iat:issued,exp},env.NAFIS_SESSION_SECRET);
      return json({token,expires_at:exp},200,headers);
    }
    if (request.method === 'GET' && path === '/student/achievements') {
      const student=authCertificates(request,env);
      if (!student) return fail(401,'student_access_required','تحتاجين جلسة اختبار سابقة أو رمز وصول صادرًا من الإدارة.');
      if (student.source === 'access-code' || (!student.source && student.access)) {
        const access=await pool.query(`SELECT access_hash FROM public.naf038_student_access
          WHERE student_id=$1 AND revoked_at IS NULL LIMIT 1`,[student.studentId]);
        if (!access.rows[0] || !safeEqualText(access.rows[0].access_hash,student.access||''))
          return fail(401,'student_access_revoked','انتهت صلاحية رمز الوصول؛ تواصلي مع إدارة المدرسة.');
      } else if (student.source !== 'exam-submit') {
        return fail(401,'student_access_invalid','جلسة عرض الإنجازات غير صالحة.');
      }
      const certificates=await collectStudentAchievements(pool,student.studentId,env.NAFIS_SESSION_SECRET,now(),student.source==='exam-submit'?student.examIds.map(Number):null);
      return json({certificates},200,headers);
    }
    if (request.method === 'POST' && path === '/student/achievements/logout') {
      return json({ cleared:true },200,{...headers,'set-cookie':'naf038_student_session=; Path=/api; Max-Age=0; HttpOnly; Secure; SameSite=Strict'});
    }
    const verifyCertificate=/^\/student\/certificate\/verify\/([^/]+)$/.exec(path);
    if (request.method==='GET' && verifyCertificate) {
      if (!env.NAFIS_SESSION_SECRET) return json({valid:false},200,headers);
      const proof=readCertificateProof(verifyCertificate[1],env.NAFIS_SESSION_SECRET);
      if (!proof) return json({valid:false},200,headers);
      const certificates=await collectStudentAchievements(pool,proof.student_id,env.NAFIS_SESSION_SECRET,now());
      return json({valid:certificates.some(item=>item.type===proof.award&&item.verification_code===verifyCertificate[1])},200,headers);
    }
    if (request.method === 'GET' && path === '/admin/health') {
      const admin = adminOnly(request, env); if (admin instanceof Response) return json({ error: 'admin_login_required' }, 401, headers);
      const checks = await validateDb(pool);
      return json({ ready: checks.every(x => x.ready), checks }, 200, headers);
    }
    if (path.startsWith('/admin/')) {
      const admin = adminOnly(request, env); if (admin instanceof Response) return json({ error: 'admin_login_required' }, 401, headers);
      if (request.method === 'GET' && path === '/admin/bootstrap') {
        const [settings, questions, exams, attempts, students] = await Promise.all([
          readSettings(pool), collectQuestions(pool), collectExams(pool), collectAttempts(pool),
          pool.query('SELECT COUNT(*)::integer AS count FROM public.nafis_students'),
        ]);
        if (!settings) throw Object.assign(new Error('missing_settings'), { status: 503 });
        return json({ settings, questions, exams, attempts, students_count: students.rows[0].count,
          portal_armed: env.NAFIS_STUDENT_PORTAL_ENABLED === 'true' }, 200, headers);
      }
      if (request.method==='GET' && path==='/admin/certificates/students') {
        const {rows}=await pool.query(`SELECT s.id,s.full_name,s.grade,s.section,
          (a.student_id IS NOT NULL AND a.revoked_at IS NULL) AS access_enabled,a.issued_at
          FROM public.nafis_students s LEFT JOIN public.naf038_student_access a ON a.student_id=s.id
          ORDER BY s.grade,s.section,s.full_name LIMIT 2000`);
        return json({students:rows.map(s=>({id:s.id,full_name:s.full_name,grade:gradeText(s.grade),section:s.section,
          access_enabled:Boolean(s.access_enabled),issued_at:s.issued_at||null}))},200,headers);
      }
      const issueStudentCode=/^\/admin\/certificates\/students\/(\d+)\/access-code$/.exec(path);
      if (issueStudentCode && request.method==='POST') {
        const studentId=Number(issueStudentCode[1]);
        if (!Number.isSafeInteger(studentId)||studentId<1) return fail(400,'invalid_student','سجل الطالبة غير صالح.');
        const accessCode=randomBytes(24).toString('base64url');
        const {rows}=await pool.query(`INSERT INTO public.naf038_student_access(student_id,access_hash,issued_by,issued_at,revoked_at)
          SELECT id,$2,$3,NOW(),NULL FROM public.nafis_students WHERE id=$1
          ON CONFLICT (student_id) DO UPDATE SET access_hash=EXCLUDED.access_hash,issued_by=EXCLUDED.issued_by,
            issued_at=NOW(),revoked_at=NULL
          RETURNING student_id`,[studentId,studentAccessHash(accessCode),admin.sub]);
        if (!rows[0]) return fail(404,'student_not_found','سجل الطالبة غير موجود.');
        return json({issued:true,access_code:accessCode},201,headers);
      }
      const revokeStudentCode=/^\/admin\/certificates\/students\/(\d+)\/access-code$/.exec(path);
      if (revokeStudentCode && request.method==='DELETE') {
        const {rows}=await pool.query(`UPDATE public.naf038_student_access SET revoked_at=NOW(),issued_by=$2
          WHERE student_id=$1 AND revoked_at IS NULL RETURNING student_id`,[Number(revokeStudentCode[1]),admin.sub]);
        return rows[0]?json({revoked:true},200,headers):fail(404,'student_access_not_found','لا يوجد رمز نشط لهذا السجل.');
      }
      if (request.method === 'GET' && path === '/admin/documentation') {
        try {
          const [current, history] = await Promise.all([
            pool.query(`SELECT version_id,created_at,actor_email,action,change_summary,restored_from,document
              FROM public.naf038_document_versions ORDER BY version_id DESC LIMIT 1`),
            pool.query(`SELECT version_id,created_at,actor_email,action,change_summary,restored_from
              FROM public.naf038_document_versions ORDER BY version_id DESC`),
          ]);
          return json({ current: current.rows[0] || null, versions: history.rows }, 200, headers);
        } catch (error) {
          if (error?.code === '42P01') return fail(503, 'documentation_migration_required', 'مركز التوثيق غير مهيأ في قاعدة Preview بعد.');
          throw error;
        }
      }
      if (request.method === 'POST' && path === '/admin/documentation') {
        const body = await bodyJson(request);
        const summary = trim(body.change_summary, 500);
        if (!summary || !validateDocumentation(body.document))
          return fail(400, 'invalid_documentation', 'راجعي حقول الوثيقة والمرفقات قبل الحفظ.');
        try {
          const { rows } = await pool.query(`INSERT INTO public.naf038_document_versions
            (actor_email,action,change_summary,document)
            VALUES ($1,$2,$3,$4::jsonb)
            RETURNING version_id,created_at,actor_email,action,change_summary,document`,
          [admin.sub, body.action === 'create' ? 'create' : 'update', summary, JSON.stringify(body.document)]);
          return json({ saved: true, current: rows[0] }, 201, headers);
        } catch (error) {
          if (error?.code === '42P01') return fail(503, 'documentation_migration_required', 'مركز التوثيق غير مهيأ في قاعدة Preview بعد.');
          throw error;
        }
      }
      const restoreDocumentation = /^\/admin\/documentation\/versions\/(\d+)\/restore$/.exec(path);
      if (restoreDocumentation && request.method === 'POST') {
        const body = await bodyJson(request);
        const summary = trim(body.change_summary, 500);
        if (!summary) return fail(400, 'invalid_documentation', 'اكتبي سبب استعادة الإصدار.');
        try {
          const { rows } = await pool.query(`INSERT INTO public.naf038_document_versions
            (actor_email,action,change_summary,restored_from,document)
            SELECT $1,'restore',$2,version_id,document FROM public.naf038_document_versions
             WHERE version_id=$3 RETURNING version_id,created_at,actor_email,action,change_summary,restored_from,document`,
          [admin.sub, summary, restoreDocumentation[1]]);
          return rows[0] ? json({ restored: true, current: rows[0] }, 201, headers) : fail(404, 'version_not_found', 'الإصدار المطلوب غير موجود.');
        } catch (error) {
          if (error?.code === '42P01') return fail(503, 'documentation_migration_required', 'مركز التوثيق غير مهيأ في قاعدة Preview بعد.');
          throw error;
        }
      }
      if (request.method === 'POST' && path === '/admin/password') {
        const body = await bodyJson(request);
        const currentPassword = String(body.current_password || '');
        const newPassword = String(body.new_password || '');
        if (newPassword.length < 14) return fail(400, 'weak_password', 'اختاري كلمة مرور من 14 محرفًا على الأقل.');
        const passwordHash = await activeAdminPasswordHash(pool, env.NAFIS_ADMIN_PASSWORD_HASH);
        if (!await verifyPassword(currentPassword, passwordHash))
          return fail(401, 'current_password_invalid', 'كلمة المرور الحالية غير صحيحة.');
        const nextHash = await encodePassword(newPassword);
        try {
          await pool.query(`INSERT INTO public.naf038_admin_credentials(id,password_hash,updated_at)
            VALUES (1,$1,NOW()) ON CONFLICT (id) DO UPDATE SET password_hash=EXCLUDED.password_hash,updated_at=NOW()`, [nextHash]);
        } catch (error) {
          if (error?.code === '42P01') return fail(503, 'password_change_unavailable', 'طبّقي ترحيل نافس على Neon أولًا ثم أعيدي المحاولة.');
          throw error;
        }
        return json({ changed: true }, 200, headers);
      }
      if (request.method === 'POST' && path === '/admin/questions') {
        const result = await addQuestions(pool, (await bodyJson(request)).questions);
        return json(result, 201, headers);
      }
      const deleteQuestion = /^\/admin\/questions\/(\d+)$/.exec(path);
      if (deleteQuestion && request.method === 'DELETE') {
        const { rowCount } = await pool.query('DELETE FROM public.naf038_questions WHERE id=$1', [deleteQuestion[1]]);
        return rowCount ? json({ ok: true }, 200, headers) : fail(404, 'question_not_found', 'السؤال غير موجود.');
      }
      const examMatch = /^\/admin\/exams\/(\d+)$/.exec(path);
      if (examMatch && request.method === 'PATCH') {
        const body = await bodyJson(request);
        if (typeof body.published !== 'boolean') return fail(400, 'invalid_exam', 'حالة الاختبار غير صالحة.');
        if (body.published) {
          const { rows } = await pool.query('SELECT COUNT(*)::integer AS n FROM public.naf038_questions WHERE exam_id=$1', [examMatch[1]]);
          if (!rows[0].n) return fail(409, 'exam_empty', 'أضيفي الأسئلة قبل نشر الاختبار.');
        }
        const result = await pool.query('UPDATE public.naf038_exams SET is_published=$2 WHERE id=$1 RETURNING id,is_published', [examMatch[1], body.published]);
        return result.rows[0] ? json({ ok: true, ...result.rows[0] }, 200, headers) : fail(404, 'exam_not_found', 'الاختبار غير موجود.');
      }
      if (request.method === 'PATCH' && path === '/admin/settings') {
        const b = await bodyJson(request);
        const monday = weekDate(b.current_week);
        const minutes = Number(b.exam_minutes);
        if (!monday || !Number.isInteger(minutes) || minutes < 5 || minutes > 180 || typeof b.students_enabled !== 'boolean')
          return fail(400, 'invalid_settings', 'تحققي من الأسبوع والمدة.');
        if (b.students_enabled && env.NAFIS_STUDENT_PORTAL_ENABLED !== 'true')
          return fail(423, 'students_closed', 'لا يمكن فتح البوابة قبل تفعيل بوابة Neon بعد اكتمال المراجعة.');
        const { rows } = await pool.query(`UPDATE public.naf038_settings SET current_week=$1, exam_minutes=$2, students_enabled=$3, updated_at=NOW() WHERE id=1 RETURNING id,current_week,exam_minutes,students_enabled`, [b.current_week, minutes, b.students_enabled]);
        return rows[0] ? json(rows[0], 200, headers) : fail(503, 'settings_missing', 'إعدادات المنصة غير موجودة.');
      }
      return fail(404, 'not_found', 'المسار غير موجود.');
    }
    if (request.method === 'GET' && path === '/student/exams') {
      if (env.NAFIS_STUDENT_PORTAL_ENABLED !== 'true') return fail(423, 'students_closed', 'المنصة مغلقة حاليًا.');
      const grade = Number(url.searchParams.get('grade')), subject = trim(url.searchParams.get('subject'), 40);
      if (!GRADES.has(grade) || !SUBJECTS.has(subject)) return fail(400, 'invalid_exam', 'اختاري الصف والمادة.');
      const current = await currentExam(pool, grade, subject);
      if (current.error === 'closed' || !current.exam) return fail(404, 'exam_unavailable', 'لا يوجد اختبار منشور لهذا الاختيار.');
      const questions = await examQuestions(pool, current.exam.id, false);
      return json({ exam: { id: current.exam.id, duration_minutes: current.exam.duration_minutes, questions: questions.map(publicQuestion) } }, 200, headers);
    }
    if (request.method === 'POST' && path === '/student/start') {
      if (env.NAFIS_STUDENT_PORTAL_ENABLED !== 'true') return fail(423, 'students_closed', 'المنصة مغلقة حاليًا.');
      if (!env.NAFIS_SESSION_SECRET) return fail(503, 'not_configured', 'لم يكتمل إعداد الحماية.');
      const result = await studentStart(pool, await bodyJson(request), env);
      return json(result, 200, headers);
    }
    if (request.method === 'POST' && path === '/student/submit') {
      if (env.NAFIS_STUDENT_PORTAL_ENABLED !== 'true') return fail(423, 'students_closed', 'المنصة مغلقة حاليًا.');
      const token = authExam(request, env);
      if (!token) return fail(401, 'exam_session_invalid', 'انتهت جلسة الاختبار.');
      const result = await studentSubmit(pool, await bodyJson(request), token);
      return json(result, 201, {...headers,'set-cookie':studentSessionCookie(token.studentId,token.examId,request,env.NAFIS_SESSION_SECRET,now())});
    }
    if (request.method === 'PUT' && path === '/student/draft') {
      if (env.NAFIS_STUDENT_PORTAL_ENABLED !== 'true') return fail(423, 'students_closed', 'المنصة مغلقة حاليًا.');
      const token = authExam(request, env);
      if (!token) return fail(401, 'exam_session_invalid', 'انتهت جلسة الاختبار.');
      return json(await studentSaveDraft(pool, await bodyJson(request), token), 200, headers);
    }
    return fail(404, 'not_found', 'المسار غير موجود.');
  } catch (error) {
    const status = Number(error?.status) || 500;
    const known = new Map([
      ['invalid_student', [400, 'بيانات الطالبة غير مكتملة.']], ['students_closed', [423, 'المنصة مغلقة حاليًا.']],
      ['announcement_window_closed', [423, 'انتهى وقت الاختبار لهذا الأسبوع وسيُعلن عن النتائج الآن.']],
      ['exam_unavailable', [404, 'لا يوجد اختبار منشور لهذا الاختيار.']], ['exam_empty', [404, 'الاختبار غير جاهز.']],
      ['attempt_used', [409, 'سبق تسجيل محاولة لهذا الاختبار.']], ['invalid_submission', [400, 'تعذر التحقق من الإجابات.']],
      ['time_expired', [409, 'انتهى وقت الاختبار.']], ['exam_changed', [409, 'تغير الاختبار؛ ابدئي محاولة جديدة.']],
      ['invalid_week', [400, 'صيغة الأسبوع غير صحيحة.']], ['invalid_exam', [400, 'بيانات الاختبار غير صحيحة.']],
      ['invalid_questions', [400, 'عدد الأسئلة غير صالح.']], ['invalid_question', [400, 'راجعي نص السؤال والخيارات والإجابة الصحيحة.']],
      ['missing_settings', [503, 'إعدادات المنصة غير موجودة.']], ['invalid_json', [400, 'بيانات الطلب غير صالحة.']],
      ['too_large', [413, 'حجم البيانات أكبر من الحد المسموح.']],
    ]);
    const detail = known.get(error?.message);
    if (detail) return fail(detail[0], error.message, detail[1]);
    console.error('nafis_api_error', { name: error?.name || 'Error', code: error?.code || 'unknown' });
    return fail(status, 'server_error', 'تعذر إكمال الطلب الآن.');
  }
}

export { handleRequest, weekDate, weekKey, announcementAt, answerLetter, optionTexts, validateDb };
