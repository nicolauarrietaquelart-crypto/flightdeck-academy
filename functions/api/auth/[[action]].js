import { pbkdf2Sync } from 'node:crypto';
const enc = new TextEncoder();
const bytesToHex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const randomHex = n => bytesToHex(crypto.getRandomValues(new Uint8Array(n)));
const digest = async x => bytesToHex(await crypto.subtle.digest('SHA-256',enc.encode(x)));
async function passwordHash(password,salt){return pbkdf2Sync(password,salt,210000,32,'sha256').toString('hex')}
const json=(obj,status=200,headers={})=>new Response(JSON.stringify(obj),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store',...headers}});
const cookie=(token,maxAge)=>`study_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
async function current(request,db){const token=request.headers.get('Cookie')?.match(/(?:^|;\s*)study_session=([a-f0-9]{64})/)?.[1];if(!token)return null;return db.prepare('SELECT users.id,users.username,users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?').bind(await digest(token),Date.now()).first()}
export async function onRequest(context){
 try { return await handleAuth(context) } catch (error) { const stage=context.__authStage||'initialization'; const diagnostic=error?.name||'UnknownError'; console.error('FlightDeck authentication failure:',stage,diagnostic,error); return json({error:'Authentication service error ('+stage+' / '+diagnostic+'). Please contact support.'},500) }
}
async function handleAuth(context){
 const {request,env,params}=context;
 const setStage=(stage)=>{context.__authStage=stage};
 const db=env.DB;if(!db)return json({error:'Database not configured. Bind a D1 database as DB.'},503);
 const action=params.action?.[0]||'';const method=request.method;setStage('routing');

 if(method==='GET'&&action==='me'){const user=await current(request,db);return json({user:user||null})}
 if(method!=='POST')return json({error:'Method not allowed'},405);
 if(request.headers.get('Content-Type')?.split(';')[0]!=='application/json')return json({error:'JSON required'},415);
 let body;try{body=await request.json()}catch{return json({error:'Invalid JSON'},400)}
 const username=String(body.username||'').trim();const email=String(body.email||'').trim().toLowerCase();const password=String(body.password||'');
 if(action==='register'){
  if(!/^[a-zA-Z0-9_]{3,24}$/.test(username))return json({error:'Username must contain 3–24 letters, numbers or underscores'},400);
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)return json({error:'Valid email address required'},400);
  if(password!==String(body.passwordConfirmation||''))return json({error:'Passwords do not match'},400);
  if(password.length<8||password.length>128)return json({error:'Password must be at least 8 characters'},400);
  const salt=randomHex(16),hash=await passwordHash(password,salt),id=crypto.randomUUID();
  try{await db.prepare('INSERT INTO users(id,username,email,salt,password_hash) VALUES(?,?,?,?,?)').bind(id,username,email,salt,hash).run()}catch{return json({error:'Username already exists'},409)}
  return await issueSession(db,id,username,email)
 }
 if(action==='login'){
  setStage('login-database-lookup');const user=await db.prepare('SELECT * FROM users WHERE username=?').bind(username).first();if(!user)return json({error:'Invalid username or password'},401);
  setStage('login-password-verification');const hash=await passwordHash(password,user.salt);if(hash!==user.password_hash)return json({error:'Invalid username or password'},401);
  setStage('login-session-creation');return await issueSession(db,user.id,user.username,user.email)
 }
 const user=await current(request,db);if(!user)return json({error:'Not authenticated'},401);
 if(action==='logout'){
  const token=request.headers.get('Cookie')?.match(/(?:^|;\s*)study_session=([a-f0-9]{64})/)?.[1];if(token)await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();return json({ok:true},200,{'Set-Cookie':cookie('',0)})
 }
 if(action==='change-password'){
  const old=String(body.oldPassword||''),next=String(body.newPassword||'');if(next.length<8||next.length>128)return json({error:'New password must be at least 8 characters'},400);
  const row=await db.prepare('SELECT salt,password_hash FROM users WHERE id=?').bind(user.id).first();if(await passwordHash(old,row.salt)!==row.password_hash)return json({error:'Current password incorrect'},403);
  const salt=randomHex(16);await db.prepare('UPDATE users SET salt=?,password_hash=? WHERE id=?').bind(salt,await passwordHash(next,salt),user.id).run();await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(user.id).run();return json({ok:true},200,{'Set-Cookie':cookie('',0)})
 }
 return json({error:'Unknown action'},404)
}
async function issueSession(db,id,username,email){const token=randomHex(32),expires=Date.now()+30*86400000;await db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await digest(token),id,expires).run();return json({user:{id,username,email}},200,{'Set-Cookie':cookie(token,30*86400)})}
