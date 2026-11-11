// Account authentication for Cloudflare Pages + D1. Passwords are PBKDF2-hashed.
const json=(body,status=200,headers={})=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const digest=async value=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))));
const random=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
async function passwordHash(password,salt){const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);return hex(new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:new TextEncoder().encode(salt),iterations:210000},key,256)))}
function equal(a,b){if(a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0}
async function setup(db){await db.prepare('CREATE TABLE IF NOT EXISTS flightdeck_users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)').run();await db.prepare('CREATE TABLE IF NOT EXISTS flightdeck_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL)').run()}
function cookie(request){return (request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('fd_session='))?.slice(11)||''}
async function currentUser(db,request){const token=cookie(request);if(!/^[a-f0-9]{64}$/.test(token))return null;const hash=await digest(token);return db.prepare('SELECT u.id,u.username FROM flightdeck_sessions s JOIN flightdeck_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(hash,Date.now()).first()}
const cookieSet=(token,maxAge)=>'fd_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age='+maxAge;
async function handleAuth(context){
 const db=context.env.DB;if(!db)return json({error:'Database unavailable'},503);
 try{
 await setup(db);
 const request=context.request,method=request.method;
 if(method==='GET'){const user=await currentUser(db,request);return json({user:user||null})}
 if(method!=='POST')return json({error:'Method not allowed'},405);
 const body=await request.json();const action=body.action;
 if(action==='logout'){const token=cookie(request);if(token)await db.prepare('DELETE FROM flightdeck_sessions WHERE token_hash=?').bind(await digest(token)).run();return json({ok:true},200,{'set-cookie':cookieSet('',0)})}
 const username=String(body.username||'').trim().toLowerCase(),password=String(body.password||'');
 const validUsername=/^[a-z0-9._-]{3,32}$/.test(username),validEmail=/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username)&&username.length<=254;
 if((!validUsername&&!validEmail)||password.length<10||password.length>128)return json({error:'Enter a valid username or email and a password of at least 10 characters.'},400);
 let user;
 if(action==='register'){
  const salt=random(),id=crypto.randomUUID(),hash=await passwordHash(password,salt);
  try{await db.prepare('INSERT INTO flightdeck_users (id,username,salt,password_hash,created_at) VALUES (?,?,?,?,?)').bind(id,username,salt,hash,new Date().toISOString()).run()}catch{return json({error:'Username already taken'},409)}
  user={id,username};
 }else if(action==='login'){
  const row=await db.prepare('SELECT * FROM flightdeck_users WHERE username=?').bind(username).first();
  if(!row)return json({error:'Invalid username or password'},401);
  const hash=await passwordHash(password,row.salt);if(!equal(hash,row.password_hash))return json({error:'Invalid username or password'},401);
  user={id:row.id,username:row.username};
 }else return json({error:'Invalid action'},400);
 const token=random();await db.prepare('INSERT INTO flightdeck_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(await digest(token),user.id,Date.now()+30*86400000).run();
 return json({user},200,{'set-cookie':cookieSet(token,30*86400)});
 }catch(e){return json({error:'Authentication unavailable'},500)}
}

// Explicit method handlers avoid Pages route/method mismatches.
export async function onRequestGet(context){return handleAuth(context)}
export async function onRequestPost(context){return handleAuth(context)}
