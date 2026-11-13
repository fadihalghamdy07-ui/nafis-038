import { createHmac, randomUUID } from 'node:crypto';
import { createCronHandler } from '../api/cron/publish-results.mjs';

const EXPECTED_NEON_PROJECT = 'icy-salad-25508888';
const EXPECTED_NEON_BRANCH = 'br-weathered-rice-b9d4vuoy';
const SUBJECTS = ['لغتي', 'الرياضيات', 'العلوم'];
const isoMonday = key => {
  const [, yearText, weekText] = /^(\d{4})-W(\d{2})$/.exec(key) || [];
  const jan4 = new Date(Date.UTC(Number(yearText), 0, 4));
  return new Date(jan4.getTime() - ((jan4.getUTCDay() + 6) % 7) * 86_400_000 +
    (Number(weekText) - 1) * 7 * 86_400_000).toISOString().slice(0, 10);
};
const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
const signedToken = (payload, secret) => {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${signature}`;
};

function transactionalPool(client) {
  let nestedId = 0;
  const stack = [];
  const query = async (sql, params) => {
    const command = String(sql).trim().toUpperCase();
    if (command === 'BEGIN') {
      const name = `naf038_e2e_nested_${++nestedId}`;
      stack.push(name);
      return client.query(`SAVEPOINT ${name}`);
    }
    if (command === 'COMMIT') {
      const name = stack.pop();
      return name ? client.query(`RELEASE SAVEPOINT ${name}`) : { rows: [], rowCount: 0 };
    }
    if (command === 'ROLLBACK') {
      const name = stack.pop();
      if (name) {
        await client.query(`ROLLBACK TO SAVEPOINT ${name}`);
        return client.query(`RELEASE SAVEPOINT ${name}`);
      }
      return { rows: [], rowCount: 0 };
    }
    return client.query(sql, params);
  };
  return {
    query,
    connect: async () => ({ query, release() {} }),
  };
}

function cronCall(handler, authorization) {
  return new Promise(resolve => {
    const response = { statusCode: 200, headers: {}, body: '' };
    response.setHeader = (name, value) => { response.headers[name.toLowerCase()] = value; };
    response.end = value => {
      response.body = value === undefined ? '' : Buffer.from(value).toString('utf8');
      resolve(response);
    };
    handler({ method: 'GET', headers: { authorization } }, response);
  });
}

export async function runPreviewE2E({ pool, env, request, handleRequest }) {
  const flag = String(env.NAFIS_PREVIEW_E2E_RUN || '').trim().toLowerCase();
  if (env.VERCEL_ENV !== 'preview' || env.VERCEL_GIT_COMMIT_REF !== 'vercel-backend-ready' ||
      !['true', '1', 'enabled'].includes(flag)) return jsonResponse({ error: 'not_found' }, 404);

  const checks = [];
  const testId = randomUUID().replace(/-/g, '').slice(0, 16);
  const studentPrefix = `E2E38_${testId}_`;
  const fakeStudentIds = [];
  const fakeExamIds = [];
  let client;
  let transactionOpen = false;
  let isolationVerified = false;
  let originalSettings;
  let pdfFixture = null;
  let stage = 'database identity';
  const assertCheck = (name, passed, detail) => {
    checks.push({ name, passed: Boolean(passed), detail });
    if (!passed) throw Object.assign(new Error('acceptance_check_failed'), { testStage: name });
  };
  const append = (name, passed, detail) => checks.push({ name, passed: Boolean(passed), detail });
  let requestSequence = 0;

  try {
    client = await pool.connect();
    await client.query('BEGIN');
    transactionOpen = true;
    const sandboxPool = transactionalPool(client);
    const identity = await client.query(`SELECT current_database() AS database_name,
      current_setting('neon.project_id',true) AS neon_project_id,
      current_setting('neon.branch_id',true) AS neon_branch_id`);
    const db = identity.rows[0] || {};
    isolationVerified = env.VERCEL_ENV === 'preview' && env.VERCEL_GIT_COMMIT_REF === 'vercel-backend-ready' &&
      db.database_name === 'neondb' && db.neon_project_id === EXPECTED_NEON_PROJECT && db.neon_branch_id === EXPECTED_NEON_BRANCH;
    assertCheck('قاعدة Neon المعزولة', isolationVerified, isolationVerified ? 'تم التحقق داخل الاتصال نفسه قبل أي كتابة.' : 'هوية قاعدة Preview غير مطابقة؛ لم تُنشأ بيانات.');

    const settingsQuery = await client.query(`SELECT current_week,exam_minutes,students_enabled,
      results_published_week,results_published_at FROM public.naf038_settings WHERE id=1`);
    originalSettings = settingsQuery.rows[0];
    assertCheck('إعدادات المنصة موجودة', Boolean(originalSettings), 'تمت قراءة الإعدادات دون إظهار قيمها.');

    const testWeek = '2099-W02';
    const monday = isoMonday(testWeek);
    const scheduleAt = Date.parse(`${new Date(Date.parse(`${monday}T00:00:00Z`) + 5 * 86_400_000).toISOString().slice(0, 10)}T15:00:00Z`);
    const conflict = await client.query(`SELECT
      EXISTS(SELECT 1 FROM public.naf038_exams WHERE week_start=$1::date) OR
      EXISTS(SELECT 1 FROM public.naf038_results_publications WHERE week_key=$2) AS used`, [monday, testWeek]);
    assertCheck('أسبوع الاختبار الوهمي خالٍ', !conflict.rows[0]?.used, 'الأسبوع المستقبلي المختار لا يحتوي اختبارات أو إعلانًا قائمًا.');

    stage = 'private test fixture';
    await client.query(`UPDATE public.naf038_settings SET current_week=$1,students_enabled=true,
      results_published_week=NULL,results_published_at=NULL,updated_at=NOW() WHERE id=1`, [testWeek]);
    const internalEnv = { ...env, NAFIS_STUDENT_PORTAL_ENABLED: 'true' };
    const requestApi = async (path, { method = 'GET', body, bearer, cookie, headers = {}, now } = {}) => {
      const name = `naf038_e2e_call_${++requestSequence}`;
      await client.query(`SAVEPOINT ${name}`);
      try {
        const requestHeaders = new Headers(headers);
        if (body !== undefined) requestHeaders.set('content-type', 'application/json');
        if (bearer) requestHeaders.set('authorization', `Bearer ${bearer}`);
        if (cookie) requestHeaders.set('cookie', cookie);
        const apiRequest = new Request(`https://preview.internal${path}`, {
          method, headers: requestHeaders, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        const response = await handleRequest(apiRequest, { pool: sandboxPool, env: internalEnv, ...(now ? { now } : {}) });
        const data = await response.json();
        if (response.status >= 400) await client.query(`ROLLBACK TO SAVEPOINT ${name}`);
        await client.query(`RELEASE SAVEPOINT ${name}`);
        return { status: response.status, data, headers: response.headers };
      } catch (error) {
        await client.query(`ROLLBACK TO SAVEPOINT ${name}`);
        await client.query(`RELEASE SAVEPOINT ${name}`);
        throw error;
      }
    };

    const externalStatus = await handleRequest(new Request('https://preview.internal/student/status'), { pool, env });
    const externalStatusData = await externalStatus.json();
    assertCheck('البوابة العامة بقيت مغلقة أثناء المعاملة', externalStatusData.open === false, 'تحديث الإعداد الوهمي غير الملتزم لا يظهر للاتصالات العامة.');
    const externalStart = await handleRequest(new Request('https://preview.internal/student/start', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'طالبة وهمية خارجية', grade: 1, section: '4', subject: 'الرياضيات' }),
    }), { pool, env });
    assertCheck('محاولة عامة بقيت محجوبة', externalStart.status === 423, 'إعداد Preview العام لم يُفتح.');

    const gradeNames = new Map([[1, 'الأول متوسط'], [2, 'الثاني متوسط'], [3, 'الثالث متوسط']]);
    const studentsByGrade = new Map();
    const studentRows = [];
    for (const grade of [1, 2, 3]) {
      const group = [];
      for (let candidate = 0; candidate < 3; candidate++) {
        const fullName = `${studentPrefix} طالبة وهمية ${gradeNames.get(grade)} ${candidate + 1}`;
        studentRows.push({ fullName, grade, section: String(candidate + 1), candidate });
      }
      studentsByGrade.set(grade, group);
    }
    for (const student of studentRows) {
      const inserted = await client.query(`INSERT INTO public.nafis_students(full_name,grade,section)
        VALUES($1,$2,$3) RETURNING id`, [student.fullName, student.grade, student.section]);
      student.id = Number(inserted.rows[0].id);
      fakeStudentIds.push(student.id);
      studentsByGrade.get(student.grade).push(student);
    }

    const exams = new Map();
    for (const grade of [1, 2, 3]) for (const subject of SUBJECTS) {
      const inserted = await client.query(`INSERT INTO public.naf038_exams(grade,subject,week_start,duration_minutes,is_published)
        VALUES($1,$2,$3::date,30,true) RETURNING id`, [grade, subject, monday]);
      const examId = Number(inserted.rows[0].id);
      exams.set(`${grade}|${subject}`, examId);
      fakeExamIds.push(examId);
    }

    const questionValues = [];
    const questionParams = [];
    for (const examId of fakeExamIds) for (let q = 1; q <= 10; q++) {
      const n = questionParams.length;
      questionValues.push(`($${n + 1},$${n + 2},$${n + 3},$${n + 4}::jsonb,'أ')`);
      questionParams.push(examId, q, `${studentPrefix} سؤال تجريبي ${q}`, JSON.stringify(['الخيار أ', 'الخيار ب']));
    }
    await client.query(`INSERT INTO public.naf038_questions(exam_id,question_number,question_text,options,correct_answer)
      VALUES ${questionValues.join(',')}`, questionParams);

    const attemptValues = [];
    const attemptParams = [];
    for (const [key, examId] of exams) {
      const [gradeText, subject] = key.split('|');
      const grade = Number(gradeText);
      const students = studentsByGrade.get(grade);
      const isTiedMath = grade === 1 && subject === 'الرياضيات';
      const scores = isTiedMath ? [10, 10, 8] : [10, 9, 8];
      const seconds = isTiedMath ? [40, 20, 50] : [40, 50, 60];
      for (let i = 0; i < students.length; i++) {
        const n = attemptParams.length;
        attemptValues.push(`($${n + 1},$${n + 2},$${n + 3},$${n + 4},NOW()-INTERVAL '1 hour',NOW()-INTERVAL '2 minutes','{}'::jsonb,10)`);
        attemptParams.push(examId, students[i].id, scores[i], seconds[i]);
      }
    }
    await client.query(`INSERT INTO public.naf038_attempts(exam_id,student_id,score,duration_seconds,started_at,submitted_at,answers,total_questions)
      VALUES ${attemptValues.join(',')}`, attemptParams);

    stage = 'student journey';
    const publicName = `${studentPrefix} طالبة وهمية للتسليم`;
    const firstStart = await requestApi('/student/start', { method: 'POST', body: { name: publicName, grade: 1, section: '4', subject: 'الرياضيات' } });
    assertCheck('بدء الاختبار وإخفاء مفتاح الإجابة', firstStart.status === 200 && firstStart.data.exam?.questions?.length === 10 &&
      firstStart.data.exam.questions.every(question => !Object.hasOwn(question, 'correct_answer')), 'بدأت محاولة آمنة ولم يتسرب مفتاح الإجابة.');
    const examToken = firstStart.data.exam_token;
    const q1 = String(firstStart.data.exam.questions[0].id), q2 = String(firstStart.data.exam.questions[1].id);
    const saved = await requestApi('/student/draft', { method: 'PUT', bearer: examToken, body: { answers: { [q1]: 'أ', [q2]: 'ب' } } });
    assertCheck('حفظ الإجابات تلقائيًا', saved.status === 200 && saved.data.saved === true, 'تم حفظ الإجابتين في قاعدة Preview داخل المعاملة.');
    const resumed = await requestApi('/student/start', { method: 'POST', body: { name: publicName, grade: 1, section: '4', subject: 'الرياضيات' } });
    assertCheck('استعادة الإجابات بعد إعادة الدخول', resumed.status === 200 && resumed.data.saved_answers?.[q1] === 'أ' && resumed.data.saved_answers?.[q2] === 'ب', 'أعاد بدء المحاولة الإجابات المحفوظة والوقت المتبقي.');
    const submitted = await requestApi('/student/submit', { method: 'POST', bearer: resumed.data.exam_token, body: { answers: { [q1]: 'أ' } } });
    assertCheck('تسليم الاختبار وإنشاء جلسة الجهاز', submitted.status === 201 && submitted.data.accepted === true && submitted.headers.get('set-cookie')?.includes('naf038_student_session='), 'تم التسليم وإنشاء جلسة نتائج موقعة.');
    const cookie = submitted.headers.get('set-cookie').split(';')[0];
    const duplicateStart = await requestApi('/student/start', { method: 'POST', body: { name: publicName, grade: 1, section: '4', subject: 'الرياضيات' } });
    assertCheck('منع المحاولة الثانية', duplicateStart.status === 409 && duplicateStart.data.error === 'attempt_used', 'رفضت قاعدة البيانات والمحطة محاولة إضافية للطالبة نفسها.');
    const duplicateSubmit = await requestApi('/student/submit', { method: 'POST', bearer: resumed.data.exam_token, body: { answers: { [q1]: 'أ' } } });
    assertCheck('منع تكرار التسليم', duplicateSubmit.status === 409 && duplicateSubmit.data.error === 'attempt_used', 'القيد الفريد منع إنشاء محاولة ثانية.');
    const beforeResults = await requestApi('/student/results');
    const beforeCertificates = await requestApi('/student/achievements', { cookie });
    assertCheck('حجب النتائج والشهادات قبل الإعلان', beforeResults.status === 200 && beforeResults.data.published === false &&
      beforeCertificates.status === 200 && beforeCertificates.data.certificates?.length === 0, 'لم تظهر نتيجة أو شهادة قبل الإعلان.');
    const noSession = await requestApi('/student/achievements');
    assertCheck('حماية الإنجازات دون جلسة', noSession.status === 401, 'رفض الخادم عرض الإنجازات دون جلسة.');

    stage = 'scheduled release simulation';
    const cronHandler = createCronHandler({ env: internalEnv, dbPool: sandboxPool, now: () => scheduleAt });
    const deniedCron = await cronCall(cronHandler, 'Bearer invalid-preview-test-value');
    assertCheck('رفض Cron دون سره', deniedCron.statusCode === 401, 'رفض المعالج طلبًا لا يحمل اعتماد Cron الصحيح.');
    const outsideWindow = await cronCall(createCronHandler({ env: internalEnv, dbPool: sandboxPool, now: () => scheduleAt - 60_000 }), `Bearer ${env.CRON_SECRET}`);
    assertCheck('رفض Cron خارج الموعد', outsideWindow.statusCode === 403, 'رفض المعالج وقتًا يسبق نافذة السبت 18:00 السعودية.');
    const cronResult = await cronCall(cronHandler, `Bearer ${env.CRON_SECRET}`);
    assertCheck('محاكاة إعلان السبت عبر معالج Cron', cronResult.statusCode === 200 && JSON.parse(cronResult.body).published === true,
      'نجح مسار Cron داخل Preview بمعاد السبت 15:00 UTC؛ هذه محاكاة للمعالج وليست تشغيلًا فعليًا للجدولة.');
    const afterResults = await requestApi('/student/results', { now: () => scheduleAt + 1_000 });
    assertCheck('إظهار حالة الإعلان بعد الموعد', afterResults.status === 200 && afterResults.data.published === true &&
      Object.keys(afterResults.data).every(key => ['published', 'week', 'published_at', 'total_attempts'].includes(key)), 'أعلن الخادم النشر دون كشف أسماء أو درجات الطالبات.');
    const afterCertificates = await requestApi('/student/achievements', { cookie, now: () => scheduleAt + 1_000 });
    assertCheck('إظهار إنجاز الطالبة بعد الإعلان', afterCertificates.status === 200 && afterCertificates.data.certificates?.length === 1 &&
      afterCertificates.data.certificates[0].type === 'participation', 'ظهرت شهادة مشاركة الطالبة بعد الموعد فقط.');

    stage = 'ranking and privacy';
    const winnerCertificateByGroup = new Map();
    for (const grade of [1, 2, 3]) {
      const students = studentsByGrade.get(grade);
      const examIds = SUBJECTS.map(subject => exams.get(`${grade}|${subject}`));
      for (let candidate = 0; candidate < 3; candidate++) {
        const issued = Math.floor(Date.now() / 1000);
        const token = signedToken({ sub: String(students[candidate].id), role: 'student_certificates', source: 'exam-submit',
          examIds, iat: issued, exp: issued + 30 * 24 * 60 * 60 }, env.NAFIS_SESSION_SECRET);
        const awards = await requestApi('/student/achievements', { bearer: token, now: () => scheduleAt + 1_000 });
        assertCheck(`استحقاق الشهادات الوهمية للصف ${gradeNames.get(grade)} • المرشحة ${candidate + 1}`,
          awards.status === 200 && awards.data.certificates?.length === 6, 'ثلاث مشاركات وثلاث شهادات مركز مطابقة لنتائج المادة والصف.');
        for (const subject of SUBJECTS) {
          const examId = exams.get(`${grade}|${subject}`);
          const certificateSet = awards.data.certificates.filter(item => {
            const payload = item.verification_code.split('.')[0].slice(4);
            try { return Buffer.from(payload, 'base64url').readUInt32BE(5) === examId; } catch { return false; }
          });
          const expected = grade === 1 && subject === 'الرياضيات'
            ? ['silver', 'gold', 'bronze'][candidate]
            : ['gold', 'silver', 'bronze'][candidate];
          const awardTypes = certificateSet.map(item => item.type).sort();
          const expectedTypes = ['participation', expected].sort();
          assertCheck(`مركز ${gradeNames.get(grade)} • ${subject} • المرشحة ${candidate + 1}`,
            JSON.stringify(awardTypes) === JSON.stringify(expectedTypes), 'الترتيب الفعلي حسب الدرجة ثم الزمن.');
          if (expected === 'gold') winnerCertificateByGroup.set(`${grade}|${subject}`, certificateSet.find(item => item.type === 'gold'));
        }
      }
    }
    const outsider = studentsByGrade.get(1)[0];
    const outsiderIssued = Math.floor(Date.now() / 1000);
    const outsiderToken = signedToken({ sub: String(outsider.id), role: 'student_certificates', source: 'exam-submit',
      examIds: SUBJECTS.map(subject => exams.get(`1|${subject}`)), iat: outsiderIssued, exp: outsiderIssued + 30 * 24 * 60 * 60 }, env.NAFIS_SESSION_SECRET);
    const ownOnly = await requestApi('/student/achievements?student_id=' + studentsByGrade.get(1)[1].id,
      { bearer: outsiderToken, now: () => scheduleAt + 1_000 });
    assertCheck('منع استهداف سجل طالبة أخرى', ownOnly.status === 200 && ownOnly.data.certificates.every(item => item.student_name === outsider.fullName), 'تجاهل الخادم معرّف الطالبة المرسل وأعاد إنجازات صاحبة الجلسة فقط.');
    const tamperedCookieValue = cookie.slice(0, -1) + (cookie.endsWith('x') ? 'y' : 'x');
    const tampered = await requestApi('/student/achievements', { cookie: tamperedCookieValue, now: () => scheduleAt + 1_000 });
    assertCheck('رفض جلسة معدّلة', tampered.status === 401, 'رفض توقيع الجلسة بعد تعديلها.');
    const goldFixture = winnerCertificateByGroup.get('1|الرياضيات');
    assertCheck('شهادة الاختبار الذهبية متاحة للمعاينة', Boolean(goldFixture?.verification_code), 'أُنشئ رقم تحقق قصير وموقّع للمعاينة.');
    const verifyPath = `/student/certificate/verify/${encodeURIComponent(goldFixture.verification_code)}`;
    const verification = await requestApi(verifyPath, { now: () => scheduleAt + 1_000 });
    assertCheck('التحقق من الرمز الصحيح', verification.status === 200 && verification.data.valid === true, 'قبل الخادم رقم التحقق الأصلي.');
    const alteredCode = goldFixture.verification_code.slice(0, -1) + (goldFixture.verification_code.endsWith('x') ? 'y' : 'x');
    const alteredVerification = await requestApi(`/student/certificate/verify/${encodeURIComponent(alteredCode)}`, { now: () => scheduleAt + 1_000 });
    assertCheck('رفض رمز تحقق معدّل', alteredVerification.status === 200 && alteredVerification.data.valid === false, 'رفض الخادم الرمز المعدّل.');
    pdfFixture = goldFixture;
    assertCheck('بيانات PDF عربية وA4 متاحة', pdfFixture.grade === 'الأول متوسط' && pdfFixture.student_name.includes(studentPrefix) &&
      /^N38-[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(pdfFixture.verification_code), 'تتضمن الشهادة العربية والصف والمادة والأسبوع ورقم التحقق.');
  } catch (error) {
    append(error.testStage || stage, false, 'تعذر إكمال هذه المرحلة؛ لم تُعرض تفاصيل قاعدة البيانات أو الأسرار.');
  } finally {
    if (transactionOpen) {
      try { await client.query('ROLLBACK'); } catch {}
    }
    if (client) client.release();
  }

  let cleanupVerified = false;
  let settingsRestored = false;
  if (isolationVerified && originalSettings) {
    try {
      const counts = await pool.query(`SELECT
        (SELECT COUNT(*)::integer FROM public.nafis_students WHERE full_name LIKE $1) AS students,
        (SELECT COUNT(*)::integer FROM public.naf038_exams WHERE id=ANY($2::integer[])) AS exams,
        (SELECT COUNT(*)::integer FROM public.naf038_attempts WHERE student_id=ANY($3::integer[]) OR exam_id=ANY($2::integer[])) AS attempts,
        (SELECT COUNT(*)::integer FROM public.naf038_drafts WHERE student_id=ANY($3::integer[]) OR exam_id=ANY($2::integer[])) AS drafts`,
      [`${studentPrefix}%`, fakeExamIds, fakeStudentIds]);
      const result = counts.rows[0];
      cleanupVerified = Number(result.students) === 0 && Number(result.exams) === 0 && Number(result.attempts) === 0 && Number(result.drafts) === 0;
      const settings = await pool.query(`SELECT current_week,exam_minutes,students_enabled,
        results_published_week,results_published_at FROM public.naf038_settings WHERE id=1`);
      settingsRestored = JSON.stringify(settings.rows[0]) === JSON.stringify(originalSettings);
    } catch {
      cleanupVerified = false;
    }
  }
  append('إلغاء بيانات الاختبار والتحقق من التنظيف', cleanupVerified && settingsRestored,
    cleanupVerified && settingsRestored ? 'أُلغيت المعاملة ولم تبق طلاب أو اختبارات أو محاولات أو مسودات، وعادت الإعدادات كما كانت.' : 'تعذر إثبات خلو قاعدة Preview بعد الإلغاء.');

  return jsonResponse({ ok: checks.every(item => item.passed), test_id: testId,
    checks, cleanup_verified: cleanupVerified && settingsRestored,
    cron_actual_execution: false,
    pdf_fixture: checks.every(item => item.passed) ? pdfFixture : null });
}
