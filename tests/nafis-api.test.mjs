import test from 'node:test';
import assert from 'node:assert/strict';
import { scrypt as scryptCallback, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { handleRequest, weekDate, weekKey, announcementAt, answerLetter } from '../functions/nafis-api-core.mjs';

const scrypt = promisify(scryptCallback);
const env = { NAFIS_SESSION_SECRET: 'test-only-secret-with-at-least-32-characters', NAFIS_ADMIN_EMAIL: 'admin@example.org', NAFIS_ALLOWED_ORIGINS: 'https://fadihalghamdy07-ui.github.io' };
const request = (path, { method='GET', body, headers={} }={}) => new Request(`https://api.test${path}`, { method, headers: { origin: 'https://fadihalghamdy07-ui.github.io', ...(body ? { 'content-type':'application/json' } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });

test('week helpers use ISO Monday boundaries and Arabic answer aliases', () => {
  assert.equal(weekDate('2026-W45'), '2026-11-02');
  assert.equal(weekKey('2026-11-02'), '2026-W45');
  assert.equal(weekKey('2026-11-07T15:00:00.000Z'), '2026-W45');
  assert.equal(new Date(announcementAt('2026-W45')).toISOString(), '2026-11-07T15:00:00.000Z');
  assert.equal(answerLetter('2'), 'ب');
  assert.equal(answerLetter('D'), 'د');
});

test('student portal remains closed unless the Neon environment gate is enabled', async () => {
  const status = await handleRequest(request('/student/status'), { env, pool: null });
  assert.equal(status.status, 200);
  assert.deepEqual(await status.json(), { open: false });
  const start = await handleRequest(request('/student/start', { method:'POST', body:{ name:'طالبة اختبار تجريبي', grade:1, section:'1', subject:'الرياضيات' } }), { env, pool: null });
  assert.equal(start.status, 423);
});

test('admin endpoints reject requests without a signed admin session', async () => {
  const response = await handleRequest(request('/admin/bootstrap'), { env, pool: { query: async()=>({rows:[]}) } });
  assert.equal(response.status, 401);
});

test('login issues an eight-hour token after checking the server-side scrypt hash', async () => {
  const salt = randomBytes(16), password = 'test-password-long-enough';
  const digest = await scrypt(password, salt, 64);
  const secureEnv = { ...env, NAFIS_ADMIN_PASSWORD_HASH:`scrypt$${salt.toString('base64url')}$${digest.toString('base64url')}` };
  const response = await handleRequest(request('/auth/login', { method:'POST', body:{ email:env.NAFIS_ADMIN_EMAIL, password } }), { env:secureEnv, pool:null, now:()=>1_800_000_000_000 });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.ok(result.token);
  assert.equal(result.expires_at, 1_800_028_800);
});

test('admin cannot open the student gate while Neon deployment gate is off', async () => {
  const salt = randomBytes(16), password = 'test-password-long-enough';
  const digest = await scrypt(password, salt, 64);
  const secureEnv = { ...env, NAFIS_ADMIN_PASSWORD_HASH:`scrypt$${salt.toString('base64url')}$${digest.toString('base64url')}` };
  const login = await handleRequest(request('/auth/login', { method:'POST', body:{ email:env.NAFIS_ADMIN_EMAIL, password } }), { env:secureEnv, pool:null });
  const { token } = await login.json();
  const response = await handleRequest(request('/admin/settings', { method:'PATCH', headers:{authorization:`Bearer ${token}`}, body:{current_week:'2026-W45',exam_minutes:40,students_enabled:true} }), { env:secureEnv, pool:null });
  assert.equal(response.status, 423);
});

test('CORS rejects an unlisted site', async () => {
  const response = await handleRequest(new Request('https://api.test/health', { headers:{origin:'https://bad.example'} }), { env, pool:{query:async()=>({rows:[]})} });
  assert.equal(response.status, 403);
});

test('published exams return no answer keys or explanations to students', async () => {
  const pool = { async query(sql) {
    if (sql.includes('FROM public.naf038_settings')) return { rows:[{ id:1,current_week:'2026-W45',students_enabled:true,exam_minutes:40 }] };
    if (sql.includes('FROM public.naf038_exams')) return { rows:[{id:8,grade:1,subject:'الرياضيات',week_start:'2026-11-02',duration_minutes:40,is_published:true}] };
    if (sql.includes('FROM public.naf038_questions')) return { rows:[{id:5,question_number:1,question_text:'كم يساوي ٢ + ٢؟',options:['٣','٤'],explanation:'معلومة سرية',image_url:null,skill:'جمع'}] };
    throw new Error(`Unexpected query: ${sql}`);
  } };
  const response = await handleRequest(request('/student/exams?grade=1&subject=%D8%A7%D9%84%D8%B1%D9%8A%D8%A7%D8%B6%D9%8A%D8%A7%D8%AA'), { env:{...env,NAFIS_STUDENT_PORTAL_ENABLED:'true'}, pool });
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.match(text, /كم يساوي/);
  assert.doesNotMatch(text, /correct_answer|explanation|معلومة سرية/);
});

test('public grades stay hidden before the scheduled announcement', async () => {
  const pool = { async query(sql) {
    assert.match(sql, /FROM public\.naf038_settings/);
    return { rows:[{id:1,current_week:'2026-W45',students_enabled:true,exam_minutes:40,
      results_published_week:'2026-W45',results_published_at:'2026-11-07T15:00:00.000Z'}] };
  } };
  const response = await handleRequest(request('/student/results'), { env, pool, now:()=>Date.parse('2026-11-07T14:59:59Z') });
  assert.equal(response.status,200);
  assert.equal((await response.json()).published,false);
});

test('Neon scheduled invocation publishes results idempotently for the matching week', async () => {
  let updates=0;
  const pool = { async query(sql,params) {
    assert.match(sql,/UPDATE public\.naf038_settings/);
    assert.equal(params[1],'2026-W45');updates++;
    return { rows:[{current_week:'2026-W45',results_published_at:params[0]}] };
  } };
  const response = await handleRequest(request('/internal/publish-results',{method:'POST',headers:{'x-neon-trigger-invocation-id':'test-trigger-1'},body:{data:{scheduled_at:'2026-11-07T15:00:00.000Z'}}}),{env,pool});
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{published:true,week:'2026-W45',results_published_at:'2026-11-07T15:00:00.000Z'});
  assert.equal(updates,1);
  const unauthorized = await handleRequest(request('/internal/publish-results',{method:'POST',body:{data:{scheduled_at:'2026-11-07T15:00:00.000Z'}}}),{env,pool});
  assert.equal(unauthorized.status,401);
  assert.equal(updates,1);
});

test('public results disclose scores but never the submitted answers or answer keys', async () => {
  const pool = { async query(sql) {
    if (sql.includes('FROM public.naf038_settings')) return { rows:[{id:1,current_week:'2026-W45',students_enabled:true,exam_minutes:40,
      results_published_week:'2026-W45',results_published_at:'2026-11-07T15:00:00.000Z'}] };
    if (sql.includes('FROM public.naf038_attempts')) return { rows:[{student_name:'طالبة اختبار',grade:1,section:'1',subject:'الرياضيات',score:4,total:5,submitted_at:'2026-11-07T14:30:00.000Z'}] };
    throw new Error('Unexpected query');
  } };
  const response = await handleRequest(request('/student/results'),{env,pool,now:()=>Date.parse('2026-11-07T15:00:00Z')});
  assert.equal(response.status,200);
  const text=await response.text();
  assert.match(text,/"score":4/);
  assert.doesNotMatch(text,/answers|correct_answer|explanation/);
});

test('student attempt is scored and stored by the API without returning the answer key', async () => {
  const saved=[];let draft={};
  const questions=[
    {id:5,question_number:1,question_text:'١ + ١؟',options:['٢','٣'],correct_answer:'أ',explanation:'سر الإجابة',image_url:null,skill:null},
    {id:6,question_number:2,question_text:'٢ + ٢؟',options:['٣','٤'],correct_answer:'ب',explanation:'سر الإجابة',image_url:null,skill:null},
  ];
  const db={
    async query(sql,params=[]) {
      if(sql.includes('FROM public.naf038_settings')) return {rows:[{id:1,current_week:'2026-W46',students_enabled:true,exam_minutes:40,results_published_week:null,results_published_at:null}]};
      if(sql.includes('FROM public.naf038_exams')) return {rows:[{id:8,grade:1,subject:'الرياضيات',week_start:'2026-11-09',duration_minutes:40,is_published:true}]};
      if(sql.includes('FROM public.naf038_questions')) return {rows:questions};
      if(sql.includes('DELETE FROM public.naf038_drafts')) {draft=null;return {rowCount:1,rows:[]};}
      if(sql.includes('FROM public.naf038_drafts')) return {rows:draft? [{answers:draft}]:[]};
      if(sql.includes('INSERT INTO public.naf038_drafts')) {draft=JSON.parse(params[3]);return {rowCount:1,rows:[]};}
      if(sql.includes('INSERT INTO public.naf038_attempts')) {saved.push({sql,params});return {rowCount:1,rows:[]};}
      throw new Error('Unexpected database query');
    },
    async connect(){return {release(){},async query(sql,params=[]) {
      if(sql==='BEGIN'||sql==='COMMIT'||sql==='ROLLBACK') return {rows:[]};
      if(sql.includes('INSERT INTO public.nafis_students')) return {rows:[{id:77}]};
      if(sql.includes('FROM public.naf038_attempts')) return {rows:[]};
      if(sql.includes('FROM public.naf038_drafts')) return {rows:[]};
      if(sql.includes('FROM public.naf038_questions')) return {rows:questions};
      throw new Error('Unexpected transaction query');
    }}}
  };
  const start=await handleRequest(request('/student/start',{method:'POST',body:{name:'طالبة اختبار تجريبي كاملة',grade:1,section:'1',subject:'الرياضيات'}}),{env:{...env,NAFIS_STUDENT_PORTAL_ENABLED:'true'},pool:db});
  assert.equal(start.status,200);
  const started=await start.json();
  assert.doesNotMatch(JSON.stringify(started),/correct_answer|سر الإجابة/);
  const savedDraft=await handleRequest(request('/student/draft',{method:'PUT',headers:{authorization:`Bearer ${started.exam_token}`},body:{answers:{5:'أ'}}}),{env:{...env,NAFIS_STUDENT_PORTAL_ENABLED:'true'},pool:db});
  assert.equal(savedDraft.status,200);
  assert.deepEqual(await savedDraft.json(),{saved:true});
  assert.deepEqual(draft,{5:'أ'});
  const submitted=await handleRequest(request('/student/submit',{method:'POST',headers:{authorization:`Bearer ${started.exam_token}`},body:{answers:{}}}),{env:{...env,NAFIS_STUDENT_PORTAL_ENABLED:'true'},pool:db});
  assert.equal(submitted.status,201);
  assert.match((await submitted.json()).message,/السبت الساعة ٦ مساءً/);
  assert.equal(saved.length,1);
  assert.equal(saved[0].params[4],1);
  assert.equal(saved[0].params[6],2);
  assert.equal(saved[0].params[3],'{"5":"أ"}');
  assert.equal(draft,null);
});
