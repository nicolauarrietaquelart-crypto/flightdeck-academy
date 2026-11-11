// Cloudflare Pages Function. Bind existing D1 database as DB in Pages settings.
const cors={'content-type':'application/json; charset=utf-8','cache-control':'no-store'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:cors});
async function account(context,db){const token=(context.request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('fd_session='))?.slice(11)||'';if(!/^[a-f0-9]{64}$/.test(token))return null;const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token));const hash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');try{return await db.prepare('SELECT user_id FROM flightdeck_sessions WHERE token_hash=? AND expires_at>?').bind(hash,Date.now()).first()}catch{return null}}
async function database(context){
 const db=context.env.DB;
 if(!db)return null;
 await db.prepare('CREATE TABLE IF NOT EXISTS flightdeck_shared_progress (id TEXT PRIMARY KEY, payload TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)').run();
 return db;
}
export async function onRequestGet(context){
 try{const db=await database(context);if(!db)return reply({error:'D1 binding DB missing'},503);
 const user=await account(context,db);if(!user)return reply({error:'Login required'},401);
 const row=await db.prepare('SELECT payload, revision, updated_at FROM flightdeck_shared_progress WHERE id=?').bind(user.user_id).first();
 return reply(row?{data:JSON.parse(row.payload),revision:row.revision,updatedAt:row.updated_at}:{data:null,revision:0});
 }catch(e){return reply({error:'Unable to read progress'},500)}
}
export async function onRequestPut(context){
 try{const db=await database(context);if(!db)return reply({error:'D1 binding DB missing'},503);
 const user=await account(context,db);if(!user)return reply({error:'Login required'},401);
 const body=await context.request.json();
 if(!body||!Number.isInteger(body.revision)||body.revision<0||!body.data||!Array.isArray(body.data.attempts)||typeof body.data.seen!=='object'||body.data.seen===null)return reply({error:'Invalid progress'},400);
 const payload=JSON.stringify(body.data);if(payload.length>2000000)return reply({error:'Progress too large'},413);
 const existing=await db.prepare('SELECT revision FROM flightdeck_shared_progress WHERE id=?').bind(user.user_id).first();
 if(existing&&existing.revision!==body.revision)return reply({error:'Revision conflict',revision:existing.revision},409);
 if(!existing&&body.revision!==0)return reply({error:'Revision conflict',revision:0},409);
 const now=new Date().toISOString();
 if(existing){const updated=await db.prepare("UPDATE flightdeck_shared_progress SET payload=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?").bind(payload,now,user.user_id,body.revision).run();if(!updated.meta.changes)return reply({error:'Revision conflict'},409)}
 else{try{await db.prepare('INSERT INTO flightdeck_shared_progress (id,payload,revision,updated_at) VALUES (?,?,1,?)').bind(user.user_id,payload,now).run()}catch{return reply({error:'Revision conflict'},409)}}
 return reply({ok:true,revision:body.revision+1,updatedAt:now});
 }catch(e){return reply({error:'Unable to save progress'},500)}
}
