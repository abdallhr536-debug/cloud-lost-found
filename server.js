// Cloud Lost & Found — zero-dependency backend (Node >= 22.5: built-in http, crypto, node:sqlite)
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const{DatabaseSync}=require('node:sqlite');
const PORT=process.env.PORT||3000,SECRET=process.env.JWT_SECRET||'dev-secret-change-me';
const UP=process.env.UPLOAD_DIR||path.join(__dirname,'uploads'),PUB=path.join(__dirname,'public');
fs.mkdirSync(UP,{recursive:true});
const db=new DatabaseSync(process.env.DB_FILE||path.join(__dirname,'lostfound.db'));
db.exec(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));

class HttpErr extends Error{constructor(c,m){super(m);this.code=c}}
// ---- auth helpers
const b64=s=>Buffer.from(s).toString('base64url'),hmac=s=>crypto.createHmac('sha256',SECRET).update(s).digest();
const sign=u=>{const h=b64('{"alg":"HS256","typ":"JWT"}'),p=b64(JSON.stringify({id:u.id,name:u.name,exp:Date.now()+7*864e5}));return`${h}.${p}.${hmac(h+'.'+p).toString('base64url')}`};
const verify=t=>{try{const[h,p,s]=(t||'').split('.');const a=Buffer.from(s,'base64url'),e=hmac(h+'.'+p);
  if(a.length!==e.length||!crypto.timingSafeEqual(a,e))return;const d=JSON.parse(Buffer.from(p,'base64url'));return d.exp>Date.now()?d:undefined}catch{}};
const hash=pw=>{const s=crypto.randomBytes(16).toString('hex');return s+':'+crypto.scryptSync(pw,s,64).toString('hex')};
const check=(pw,st)=>{const[s,h]=st.split(':'),a=Buffer.from(h,'hex'),b=crypto.scryptSync(pw,s,64);return a.length===b.length&&crypto.timingSafeEqual(a,b)};
// ---- body parsing
const readBody=req=>new Promise((ok,no)=>{const c=[];let n=0;req.on('data',d=>{n+=d.length;if(n>6e6){no(new HttpErr(413,'الصورة أكبر من 5MB'));req.destroy()}else c.push(d)});req.on('end',()=>ok(Buffer.concat(c)));req.on('error',no)});
function multipart(buf,ct){const m=/boundary=(.+)$/.exec(ct);if(!m)throw new HttpErr(400,'طلب غير صحيح');const bd=Buffer.from('--'+m[1]),f={},files={};let pos=buf.indexOf(bd);
  while(pos>=0){const nx=buf.indexOf(bd,pos+bd.length);if(nx<0)break;const part=buf.subarray(pos+bd.length+2,nx-2),i=part.indexOf('\r\n\r\n');
    if(i>0){const head=part.subarray(0,i).toString(),body=part.subarray(i+4),nm=/name="([^"]*)"/.exec(head)?.[1],fn=/filename="([^"]*)"/.exec(head)?.[1];
      if(fn!==undefined){if(fn&&body.length)files[nm]={type:(/Content-Type:\s*(\S+)/i.exec(head)||[])[1],data:body}}else f[nm]=body.toString()}pos=nx}
  return{f,files}}
// ---- routes
const EXT={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp','image/gif':'.gif'};
const SEL='SELECT i.*,u.name AS owner_name,u.email AS owner_email FROM items i JOIN users u ON u.id=i.user_id';
const need=(c,m)=>{if(!c)throw new HttpErr(400,m)};
const ownItem=(id,uid)=>{const i=db.prepare('SELECT * FROM items WHERE id=?').get(id);if(!i)throw new HttpErr(404,'مش موجود');if(i.user_id!==uid)throw new HttpErr(403,'مش بتاعك');return i};
const routes=[
['POST',/^\/api\/auth\/register$/,false,({body})=>{const{name,email,password}=body;
  need(name&&/^\S+@\S+\.\S+$/.test(email||'')&&(password||'').length>=6,'بيانات غير صحيحة (الباسورد 6 حروف على الأقل)');
  try{const r=db.prepare('INSERT INTO users(name,email,password) VALUES(?,?,?)').run(name.trim(),email.toLowerCase(),hash(password));
    const u={id:Number(r.lastInsertRowid),name:name.trim()};return[201,{token:sign(u),user:u}]}catch{throw new HttpErr(409,'الإيميل مسجل قبل كده')}}],
['POST',/^\/api\/auth\/login$/,false,({body})=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(body.email||'').toLowerCase());
  if(!u||!check(String(body.password||''),u.password))throw new HttpErr(401,'الإيميل أو الباسورد غلط');return{token:sign(u),user:{id:u.id,name:u.name}}}],
['GET',/^\/api\/items$/,true,({q,user})=>{const w=['1=1'],p=[],s=q.get('q'),t=q.get('type');
  if(s){w.push('(i.name LIKE ? OR i.location LIKE ? OR i.description LIKE ?)');p.push(`%${s}%`,`%${s}%`,`%${s}%`)}
  if(t==='lost'||t==='found'){w.push('i.type=?');p.push(t)}if(q.get('mine')){w.push('i.user_id=?');p.push(user.id)}
  return db.prepare(`${SEL} WHERE ${w.join(' AND ')} ORDER BY i.date DESC,i.id DESC LIMIT 100`).all(...p)}],
['GET',/^\/api\/items\/(\d+)$/,true,({m})=>{const i=db.prepare(`${SEL} WHERE i.id=?`).get(m[1]);if(!i)throw new HttpErr(404,'مش موجود');return i}],
['POST',/^\/api\/items$/,true,({body,user})=>{const{f,files}=body;need(f&&files,'استخدم multipart/form-data');
  const name=(f.name||'').trim(),loc=(f.location||'').trim();need(name&&loc&&f.date&&['lost','found'].includes(f.type),'املا الحقول المطلوبة');
  need(name.length<=100&&loc.length<=100&&(f.description||'').length<=1000,'النص طويل أوي');
  let image=null;const im=files.image;if(im){need(EXT[im.type],'الصورة لازم تكون JPG/PNG/WEBP/GIF');image='/uploads/'+crypto.randomUUID()+EXT[im.type];fs.writeFileSync(path.join(UP,path.basename(image)),im.data)}
  const r=db.prepare('INSERT INTO items(user_id,name,type,location,date,description,image) VALUES(?,?,?,?,?,?,?)').run(user.id,name,f.type,loc,f.date,f.description||'',image);
  const id=Number(r.lastInsertRowid),opp=f.type==='lost'?'found':'lost';
  const ms=name.length<3?[]:db.prepare("SELECT * FROM items WHERE type=? AND status='open' AND user_id!=? AND (LOWER(name) LIKE '%'||LOWER(?)||'%' OR LOWER(?) LIKE '%'||LOWER(name)||'%')").all(opp,user.id,name,name);
  const n=db.prepare('INSERT INTO notifications(user_id,item_id,message) VALUES(?,?,?)');
  for(const o of ms){n.run(o.user_id,id,`ممكن يكون في تطابق مع "${o.name}": اتسجل "${name}" (${f.type==='found'?'تم العثور عليه':'مفقود'}) في ${loc}`);
    n.run(user.id,o.id,`ممكن يكون في تطابق مع "${name}": موجود "${o.name}" في ${o.location}`)}
  return[201,{id,matches:ms.length}]}],
['PATCH',/^\/api\/items\/(\d+)\/resolve$/,true,({m,user})=>{ownItem(m[1],user.id);db.prepare("UPDATE items SET status='resolved' WHERE id=?").run(m[1]);return{ok:true}}],
['DELETE',/^\/api\/items\/(\d+)$/,true,({m,user})=>{const i=ownItem(m[1],user.id);db.prepare('DELETE FROM notifications WHERE item_id=?').run(i.id);db.prepare('DELETE FROM items WHERE id=?').run(i.id);
  if(i.image)fs.rm(path.join(UP,path.basename(i.image)),()=>{});return{ok:true}}],
['GET',/^\/api\/notifications$/,true,({user})=>db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30').all(user.id)],
['POST',/^\/api\/notifications\/read$/,true,({user})=>{db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').run(user.id);return{ok:true}}],
];
// ---- server
const MIME={'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.gif':'image/gif','.svg':'image/svg+xml','.ico':'image/x-icon'};
const json=(res,code,o)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(o))};
function serve(res,root,rel){const f=path.join(root,path.normalize(rel==='/'?'/index.html':rel));
  if(!f.startsWith(root+path.sep))return json(res,403,{error:'ممنوع'});
  fs.readFile(f,(e,d)=>{if(e)return json(res,404,{error:'مش موجود'});res.writeHead(200,{'Content-Type':MIME[path.extname(f).toLowerCase()]||'application/octet-stream','X-Content-Type-Options':'nosniff'});res.end(d)})}
const server=http.createServer(async(req,res)=>{
  try{const url=new URL(req.url,'http://x'),p=decodeURIComponent(url.pathname);
    if(!p.startsWith('/api/')){if(req.method!=='GET')return json(res,405,{error:'Method not allowed'});
      return p.startsWith('/uploads/')?serve(res,UP,p.slice(8)):serve(res,PUB,p)}
    for(const[method,re,priv,fn]of routes){const m=re.exec(p);if(!m||method!==req.method)continue;
      let user;if(priv){user=verify((req.headers.authorization||'').replace('Bearer ',''));if(!user)throw new HttpErr(401,'سجّل الدخول أولاً')}
      let body={};if(req.method==='POST'||req.method==='PATCH'){const buf=await readBody(req),ct=req.headers['content-type']||'';
        if(ct.startsWith('multipart/'))body=multipart(buf,ct);else if(buf.length){try{body=JSON.parse(buf)}catch{throw new HttpErr(400,'JSON غير صحيح')}}}
      const out=fn({req,body,user,m,q:url.searchParams}),[code,data]=Array.isArray(out)&&typeof out[0]==='number'?out:[200,out];return json(res,code,data)}
    json(res,404,{error:'مش موجود'})
  }catch(e){if(!(e instanceof HttpErr))console.error(e);json(res,e.code||500,{error:e instanceof HttpErr?e.message:'خطأ في السيرفر'})}});
if(require.main===module)server.listen(PORT,()=>console.log('Cloud Lost & Found running on http://localhost:'+PORT));
module.exports=server;
