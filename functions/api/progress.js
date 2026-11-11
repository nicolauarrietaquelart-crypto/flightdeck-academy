// Cloudflare Pages Function. Bind existing D1 database as DB in Pages settings.
const cors={'content-type':'application/json; charset=utf-8','cache-control':'no-store'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:cors});
async function database(context){
 const db=context.env.DB;
 if(!db)return null;
 await db.prepare('CREATE TABLE IF NOT EXISTS flightdeck_shared_progress (id TEXT PRIMARY KEY, payload TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)').run();
 return db;
}
export async function onRequestGet(context){
 try{const db=await database(context);if(!db)return reply({error:'D1 binding DB missing'},503);
 const row=await db.prepare("SELECT payload, revision, updated_at FROM flightdeck_shared_progress WHERE id='shared'").first();
 return reply(row?{data:JSON.parse(row.payload),revision:row.revision,updatedAt:row.updated_at}:{data:null,revision:0});
 }catch(e){return reply({error:'Unable to read progress'},500)}
}
export async function onRequestPut(context){
 try{const db=await database(context);if(!db)return reply({error:'D1 binding DB missing'},503);
 const body=await context.request.json();
 if(!body||!Number.isInteger(body.revision)||body.revision<0||!body.data||!Array.isArray(body.data.attempts)||typeof body.data.seen!=='object'||body.data.seen===null)return reply({error:'Invalid progress'},400);
 const payload=JSON.stringify(body.data);if(payload.length>2000000)return reply({error:'Progress too large'},413);
 const existing=await db.prepare("SELECT revision FROM flightdeck_shared_progress WHERE id='shared'").first();
 if(existing&&existing.revision!==body.revision)return reply({error:'Revision conflict',revision:existing.revision},409);
 if(!existing&&body.revision!==0)return reply({error:'Revision conflict',revision:0},409);
 const now=new Date().toISOString();
 if(existing){const updated=await db.prepare("UPDATE flightdeck_shared_progress SET payload=?,revision=revision+1,updated_at=? WHERE id='shared' AND revision=?").bind(payload,now,body.revision).run();if(!updated.meta.changes)return reply({error:'Revision conflict'},409)}
 else{try{await db.prepare("INSERT INTO flightdeck_shared_progress (id,payload,revision,updated_at) VALUES ('shared',?,1,?)").bind(payload,now).run()}catch{return reply({error:'Revision conflict'},409)}}
 return reply({ok:true,revision:body.revision+1,updatedAt:now});
 }catch(e){return reply({error:'Unable to save progress'},500)}
}
