import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, scrypt as scryptCallback, randomBytes } from 'node:crypto';
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

test('health confirms only the isolated Preview database match without disclosing its identifiers', async () => {
  const previewEnv={...env,VERCEL_ENV:'preview',VERCEL_GIT_COMMIT_REF:'vercel-backend-ready'};
  const pool={async query(){return {rows:[{database_name:'neondb',neon_project_id:'icy-salad-25508888',neon_branch_id:'br-weathered-rice-b9d4vuoy'}]}}};
  const response=await handleRequest(request('/health'),{env:previewEnv,pool});
  assert.deepEqual(await response.json(),{ok:true,isolated_preview_database:true});
  const wrong=await handleRequest(request('/health'),{env:previewEnv,pool:{async query(){return {rows:[{database_name:'neondb',neon_project_id:'different-project',neon_branch_id:'different-branch'}]}}}});
  assert.deepEqual(await wrong.json(),{ok:true,isolated_preview_database:false});
});

test('admin endpoints reject requests without a signed admin session', async () => {
  const response = await handleRequest(request('/admin/bootstrap'), { env, pool: { query: async()=>({rows:[]}) } });
  assert.equal(response.status, 401);
});

test('documentation center requires an admin session and keeps every saved version append-only', async () => {
  const salt = randomBytes(16), password = 'documentation-test-password';
  const digest = await scrypt(password, salt, 64);
  const secureEnv = { ...env, NAFIS_ADMIN_PASSWORD_HASH:`scrypt$${salt.toString('base64url')}$${digest.toString('base64url')}` };
  const versions=[];
  const pool={async query(sql,params=[]) {
    if(sql.includes('SELECT password_hash FROM public.naf038_admin_credentials')) return {rows:[]};
    if(sql.includes('FROM public.naf038_document_versions ORDER BY') && sql.includes('restored_from,document')) return {rows:versions.length?[versions[versions.length-1]]:[]};
    if(sql.includes('FROM public.naf038_document_versions ORDER BY')) return {rows:[...versions].reverse().map(({document,...meta})=>meta)};
    if(sql.includes('INSERT INTO public.naf038_document_versions') && sql.includes('SELECT $1')) {
      const prior=versions.find(x=>x.version_id===Number(params[2])); if(!prior)return {rows:[]};
      const row={version_id:versions.length+1,created_at:'2026-11-13T12:00:00.000Z',actor_email:params[0],action:'restore',change_summary:params[1],restored_from:prior.version_id,document:prior.document};versions.push(row);return {rows:[row]};
    }
    if(sql.includes('INSERT INTO public.naf038_document_versions')) {
      const row={version_id:versions.length+1,created_at:'2026-11-13T12:00:00.000Z',actor_email:params[0],action:params[1],change_summary:params[2],document:JSON.parse(params[3])};versions.push(row);return {rows:[row]};
    }
    throw new Error('Unexpected query');
  }};
  const anonymous=await handleRequest(request('/admin/documentation'),{env:secureEnv,pool});
  assert.equal(anonymous.status,401);
  const login=await handleRequest(request('/auth/login',{method:'POST',body:{email:env.NAFIS_ADMIN_EMAIL,password}}),{env:secureEnv,pool});
  const {token}=await login.json();
  const session={authorization:`Bearer ${token}`};
  const doc={initiative:{idea:'فكرة',rationale:'مبرر',objectives:'هدف',audience:'طالبات',founded_at:'2026-11-13',stages:'تجريب'},team:[{name:'مسؤولة',role:'إشراف'}],milestones:[],attachments:[],approval:{authority:'مدرسة',approver:'مديرة',date:'2026-11-13'}};
  const save=await handleRequest(request('/admin/documentation',{method:'POST',headers:session,body:{document:doc,change_summary:'تأسيس أولي',action:'create'}}),{env:secureEnv,pool});
  assert.equal(save.status,201);
  const saved=await save.json();
  assert.equal(saved.current.actor_email,env.NAFIS_ADMIN_EMAIL);
  const update=await handleRequest(request('/admin/documentation',{method:'POST',headers:session,body:{document:{...doc,initiative:{...doc.initiative,idea:'تحديث'}},change_summary:'تعديل الفكرة'}}),{env:secureEnv,pool});
  assert.equal(update.status,201);
  const restored=await handleRequest(request('/admin/documentation/versions/1/restore',{method:'POST',headers:session,body:{change_summary:'استعادة المراجعة'}}),{env:secureEnv,pool});
  assert.equal(restored.status,201);
  const result=await restored.json();
  assert.equal(result.current.action,'restore');
  assert.equal(result.current.restored_from,1);
  assert.equal(result.current.document.initiative.idea,'فكرة');
  assert.equal(versions.length,3);
  const history=await handleRequest(request('/admin/documentation',{headers:session}),{env:secureEnv,pool});
  assert.equal(history.status,200);
  assert.equal((await history.json()).versions.length,3);
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

test('admin changes password after reauthentication and the stored hash supersedes the environment hash', async () => {
  const salt = randomBytes(16), currentPassword = 'current-test-password-long';
  const digest = await scrypt(currentPassword, salt, 64);
  const secureEnv = { ...env, NAFIS_ADMIN_PASSWORD_HASH:`scrypt$${salt.toString('base64url')}$${digest.toString('base64url')}` };
  let storedHash = null;
  const pool = { async query(sql, params=[]) {
    if (sql.includes('SELECT password_hash FROM public.naf038_admin_credentials')) return { rows:storedHash?[{password_hash:storedHash}]:[] };
    if (sql.includes('INSERT INTO public.naf038_admin_credentials')) { storedHash=params[0]; return { rows:[] }; }
    throw new Error('Unexpected query');
  } };
  const login = await handleRequest(request('/auth/login', { method:'POST', body:{ email:env.NAFIS_ADMIN_EMAIL, password:currentPassword } }), { env:secureEnv, pool });
  const { token } = await login.json();
  const changed = await handleRequest(request('/admin/password', { method:'POST', headers:{authorization:`Bearer ${token}`}, body:{current_password:currentPassword,new_password:'new-test-password-long'} }), { env:secureEnv, pool });
  assert.equal(changed.status, 200);
  assert.deepEqual(await changed.json(), { changed:true });
  const oldLogin = await handleRequest(request('/auth/login', { method:'POST', body:{ email:env.NAFIS_ADMIN_EMAIL, password:currentPassword } }), { env:secureEnv, pool });
  assert.equal(oldLogin.status, 401);
  const newLogin = await handleRequest(request('/auth/login', { method:'POST', body:{ email:env.NAFIS_ADMIN_EMAIL, password:'new-test-password-long' } }), { env:secureEnv, pool });
  assert.equal(newLogin.status, 200);
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
    assert.match(sql,/INSERT INTO public\.naf038_results_publications/);
    assert.match(sql,/ON CONFLICT \(week_key\) DO UPDATE/);
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

test('certificate access requires a private admin-issued code and reveals only published achievements for its student', async () => {
  const salt=randomBytes(16), password='cert-admin-test-password';
  const digest=await scrypt(password,salt,64);
  const secureEnv={...env,NAFIS_ADMIN_PASSWORD_HASH:`scrypt$${salt.toString('base64url')}$${digest.toString('base64url')}`};
  let accessHash=null, revoked=false; const now=()=>Date.parse('2026-11-14T15:01:00.000Z');
  const pool={async query(sql,params=[]) {
    if(sql.includes('SELECT password_hash FROM public.naf038_admin_credentials'))return {rows:[]};
    if(sql.includes('INSERT INTO public.naf038_student_access')){accessHash=params[1];revoked=false;return {rows:[{student_id:41}]};}
    if(sql.includes('UPDATE public.naf038_student_access SET revoked_at')){revoked=true;return {rows:[{student_id:41}]};}
    if(sql.includes('SELECT student_id,access_hash FROM public.naf038_student_access'))return {rows:!revoked&&params[0]===accessHash?[{student_id:41,access_hash:accessHash}]:[]};
    if(sql.includes('SELECT access_hash FROM public.naf038_student_access'))return {rows:!revoked?[{access_hash:accessHash}]:[]};
    if(sql.includes('WITH released AS')){
      assert.equal(params[0],41);assert.match(sql,/naf038_results_publications/);assert.match(sql,/published_at <=/);
      assert.match(sql,/date_trunc\('week',e\.week_start::timestamp\).*5 days 15 hours/);
      assert.match(sql,/PARTITION BY grade,subject,week/);
      assert.match(sql,/score::numeric \/ NULLIF\(total,0\) DESC,\s*duration_seconds ASC/);
      return {rows:[{student_id:41,student_name:'طالبة اختبار وهمية',exam_id:71,grade:1,subject:'الرياضيات',week:'2026-W46',score:10,total:10,duration_seconds:500,rank:'1'},{student_id:41,student_name:'طالبة اختبار وهمية',exam_id:72,grade:2,subject:'العلوم',week:'2026-W46',score:9,total:10,duration_seconds:510,rank:'2'},{student_id:41,student_name:'طالبة اختبار وهمية',exam_id:73,grade:3,subject:'لغتي',week:'2026-W46',score:8,total:10,duration_seconds:520,rank:'3'},{student_id:41,student_name:'طالبة اختبار وهمية',exam_id:74,grade:1,subject:'الرياضيات',week:'2026-W45',score:7,total:10,duration_seconds:530,rank:'4'}]};
    }
    throw new Error(`Unexpected query: ${sql}`);
  }};
  const noSession=await handleRequest(request('/student/achievements'),{env:secureEnv,pool,now});
  assert.equal(noSession.status,401);
  const deniedAdmin=await handleRequest(request('/admin/certificates/students'),{env:secureEnv,pool,now});
  assert.equal(deniedAdmin.status,401);
  const login=await handleRequest(request('/auth/login',{method:'POST',body:{email:env.NAFIS_ADMIN_EMAIL,password}}),{env:secureEnv,pool,now});
  const adminToken=(await login.json()).token;
  const issued=await handleRequest(request('/admin/certificates/students/41/access-code',{method:'POST',headers:{authorization:`Bearer ${adminToken}`},body:{}}),{env:secureEnv,pool,now});
  assert.equal(issued.status,201);
  const {access_code:accessCode}=await issued.json();
  assert.match(accessCode,/^[A-Za-z0-9_-]{30,50}$/);
  assert.equal(accessHash,createHash('sha256').update(accessCode).digest('hex'));
  assert.equal(JSON.stringify({accessHash}).includes(accessCode),false);
  const loginStudent=await handleRequest(request('/student/achievements/session',{method:'POST',body:{access_code:accessCode}}),{env:secureEnv,pool,now});
  assert.equal(loginStudent.status,200);
  const studentToken=(await loginStudent.json()).token;
  const achievements=await handleRequest(request('/student/achievements',{headers:{authorization:`Bearer ${studentToken}`}}),{env:secureEnv,pool,now});
  const data=await achievements.json();
  assert.equal(achievements.status,200);
  assert.deepEqual(data.certificates.map(x=>x.type),['participation','gold','participation','silver','participation','bronze','participation']);
  assert.equal(data.certificates[0].student_name,'طالبة اختبار وهمية');
  assert.ok(data.certificates.every(x=>x.verification_code));
  assert.ok(data.certificates.every(x=>x.verification_code.length<50&&x.verification_code.startsWith('N38-')));
  const code=encodeURIComponent(data.certificates[0].verification_code);
  const verify=await handleRequest(request(`/student/certificate/verify/${code}`),{env:secureEnv,pool,now});
  assert.deepEqual(await verify.json(),{valid:true});
  const original=data.certificates[0].verification_code;
  const changed=original.slice(0,-1)+(original.endsWith('x')?'y':'x');
  const invalidProof=await handleRequest(request(`/student/certificate/verify/${encodeURIComponent(changed)}`),{env:secureEnv,pool,now});
  assert.deepEqual(await invalidProof.json(),{valid:false});
  const revoke=await handleRequest(request('/admin/certificates/students/41/access-code',{method:'DELETE',headers:{authorization:`Bearer ${adminToken}`}}),{env:secureEnv,pool,now});
  assert.equal(revoke.status,200);
  const oldCode=await handleRequest(request('/student/achievements/session',{method:'POST',body:{access_code:accessCode}}),{env:secureEnv,pool,now});
  assert.equal(oldCode.status,401);
  const revokedSession=await handleRequest(request('/student/achievements',{headers:{authorization:`Bearer ${studentToken}`}}),{env:secureEnv,pool,now});
  assert.equal(revokedSession.status,401);
});

test('certificate API rejects malformed proofs and never returns student identity publicly', async () => {
  const response=await handleRequest(request('/student/certificate/verify/not-a-valid-proof'),{env,pool:{query:async()=>{throw new Error('must not query invalid proof')}}});
  assert.deepEqual(await response.json(),{valid:false});
});

test('public results announce release without disclosing student identities or scores', async () => {
  const pool = { async query(sql) {
    if (sql.includes('FROM public.naf038_settings')) return { rows:[{id:1,current_week:'2026-W45',students_enabled:true,exam_minutes:40,
      results_published_week:'2026-W45',results_published_at:'2026-11-07T15:00:00.000Z'}] };
    if (sql.includes('FROM public.naf038_attempts')) return { rows:[{student_name:'طالبة اختبار',grade:1,section:'1',subject:'الرياضيات',score:4,total:5,submitted_at:'2026-11-07T14:30:00.000Z'}] };
    throw new Error('Unexpected query');
  } };
  const response = await handleRequest(request('/student/results'),{env,pool,now:()=>Date.parse('2026-11-07T15:00:00Z')});
  assert.equal(response.status,200);
  const text=await response.text();
  assert.match(text,/"published":true/);
  assert.doesNotMatch(text,/طالبة اختبار|"score":4|"student_name"|"name"/);
  assert.doesNotMatch(text,/answers|correct_answer|explanation/);
});

test('successful submission creates a private same-device achievements session that releases only the current student data', async () => {
  const questions=[{id:5,question_number:1,question_text:'١ + ١؟',options:['٢','٣'],correct_answer:'أ',explanation:'سر',image_url:null,skill:null}];
  let draft=null, released=false, stored=[];
  const settings={id:1,current_week:'2026-W46',students_enabled:true,exam_minutes:40,results_published_week:null,results_published_at:null};
  const exam={id:8,grade:1,subject:'الرياضيات',week_start:'2026-11-09',duration_minutes:40,is_published:true};
  const db={
    async query(sql,params=[]) {
      if(sql.includes('WITH released AS')){assert.deepEqual(params[2],released?[8,9]:[8]);return {rows:released?[{student_id:77,student_name:'طالبة وهمية خاصة',exam_id:8,grade:1,subject:'الرياضيات',week:'2026-W46',score:1,total:1,duration_seconds:120,rank:'1'}]:[]};}
      if(sql.includes('SELECT s.full_name AS student_name'))return {rows:[{student_name:'طالبة وهمية خاصة',grade:1,section:'1',subject:'الرياضيات',score:1,total:1,submitted_at:'2026-11-14T15:00:00.000Z'}]};
      if(sql.includes('FROM public.naf038_settings'))return {rows:[settings]};
      if(sql.includes('FROM public.naf038_exams'))return {rows:[exam]};
      if(sql.includes('FROM public.naf038_questions'))return {rows:questions};
      if(sql.includes('INSERT INTO public.naf038_drafts')){draft=JSON.parse(params[3]);return {rows:[],rowCount:1};}
      if(sql.includes('DELETE FROM public.naf038_drafts')){draft=null;return {rows:[],rowCount:1};}
      if(sql.includes('FROM public.naf038_drafts'))return {rows:draft?[{answers:draft}]:[]};
      if(sql.includes('INSERT INTO public.naf038_attempts')){stored.push({params});return {rows:[],rowCount:1};}
      throw new Error(`Unexpected query: ${sql}`);
    },
    async connect(){return {release(){},async query(sql){
      if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return {rows:[]};
      if(sql.includes('INSERT INTO public.nafis_students'))return {rows:[{id:77}]};
      if(sql.includes('FROM public.naf038_attempts'))return {rows:[]};
      if(sql.includes('FROM public.naf038_drafts'))return {rows:draft?[{answers:draft,started_at:new Date().toISOString()}]:[]};
      if(sql.includes('FROM public.naf038_questions'))return {rows:questions};
      throw new Error(`Unexpected transaction query: ${sql}`);
    }};},
  };
  const portalEnv={...env,NAFIS_STUDENT_PORTAL_ENABLED:'true'};
  const started=await handleRequest(request('/student/start',{method:'POST',body:{name:'طالبة اختبار وهمية كاملة',grade:1,section:'1',subject:'الرياضيات'}}),{env:portalEnv,pool:db});
  assert.equal(started.status,200);
  const examToken=(await started.json()).exam_token;
  const submitted=await handleRequest(request('/student/submit',{method:'POST',headers:{authorization:`Bearer ${examToken}`},body:{answers:{5:'أ'}}}),{env:portalEnv,pool:db});
  assert.equal(submitted.status,201);
  const cookie=submitted.headers.get('set-cookie');
  assert.match(cookie,/HttpOnly/);assert.match(cookie,/Secure/);assert.match(cookie,/SameSite=Strict/);assert.match(cookie,/Max-Age=2592000/);
  assert.doesNotMatch(await submitted.text(),/student_session|eyJ/);
  const cookieHeader=cookie.split(';')[0];
  const noCookie=await handleRequest(request('/student/achievements'),{env:portalEnv,pool:db});
  assert.equal(noCookie.status,401);
  const beforeRelease=await handleRequest(request('/student/achievements',{headers:{cookie:cookieHeader}}),{env:portalEnv,pool:db});
  assert.deepEqual((await beforeRelease.json()).certificates,[]);
  const tampered=cookieHeader.slice(0,-1)+(cookieHeader.endsWith('x')?'y':'x');
  const forged=await handleRequest(request('/student/achievements',{headers:{cookie:tampered}}),{env:portalEnv,pool:db});
  assert.equal(forged.status,401);
  exam.id=9;
  const secondStart=await handleRequest(request('/student/start',{method:'POST',headers:{cookie:cookieHeader},body:{name:'طالبة اختبار وهمية كاملة',grade:1,section:'1',subject:'الرياضيات'}}),{env:portalEnv,pool:db});
  const secondToken=(await secondStart.json()).exam_token;
  const secondSubmit=await handleRequest(request('/student/submit',{method:'POST',headers:{authorization:`Bearer ${secondToken}`,cookie:cookieHeader},body:{answers:{5:'أ'}}}),{env:portalEnv,pool:db});
  const secondCookie=secondSubmit.headers.get('set-cookie').split(';')[0];
  released=true;settings.results_published_week='2026-W46';settings.results_published_at='2026-11-14T15:00:00.000Z';
  const afterRelease=await handleRequest(request('/student/achievements',{headers:{cookie:secondCookie}}),{env:portalEnv,pool:db});
  const personal=(await afterRelease.json()).certificates;
  assert.equal(afterRelease.status,200);assert.equal(personal[0].student_name,'طالبة وهمية خاصة');
  const publicResults=await handleRequest(request('/student/results'),{env:portalEnv,pool:db,now:()=>Date.parse('2026-11-14T15:00:00.000Z')});
  const publicBody=await publicResults.text();
  assert.doesNotMatch(publicBody,/طالبة وهمية خاصة|"score"/);
  const logout=await handleRequest(request('/student/achievements/logout',{method:'POST'}),{env:portalEnv,pool:db});
  assert.match(logout.headers.get('set-cookie'),/Max-Age=0/);
  const ended=await handleRequest(request('/student/achievements'),{env:portalEnv,pool:db});
  assert.equal(ended.status,401);
  assert.equal(stored.length,2);
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
