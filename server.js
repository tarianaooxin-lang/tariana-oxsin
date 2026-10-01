const express=require('express');
const path=require('path');
const fs=require('fs');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const {Pool}=require('pg');

const app=express();
app.use(express.json({limit:'2mb'}));
app.use(express.static(path.join(__dirname,'public')));
const PORT=Number(process.env.PORT||10000);
const JWT_SECRET=process.env.JWT_SECRET||'CHANGE_ME_BEFORE_PRODUCTION';
const DATABASE_URL=process.env.DATABASE_URL||'';
let pool;
let mem;

async function getDb(){
  if(pool) return pool;
  if(DATABASE_URL){pool=new Pool({connectionString:DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:undefined});return pool;}
  const {newDb}=require('pg-mem'); mem=newDb({autoCreateForeignKeyIndices:true}); const pg=mem.adapters.createPg(); pool=new pg.Pool(); return pool;
}
const seed=require('./seed-data.json');
async function q(text,params=[]){const db=await getDb();return db.query(text,params)}
async function initDb(){
  await q(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,national_id TEXT UNIQUE,national_id_type TEXT,phone TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',status TEXT NOT NULL DEFAULT 'pending',requested_tier TEXT,tier TEXT,province TEXT,city TEXT,postal_code TEXT,address TEXT,receiver TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY,name TEXT NOT NULL,category TEXT,price TEXT,stock TEXT,updated TEXT,tiers JSONB NOT NULL DEFAULT '{}'::jsonb,package_count TEXT)`);
  await q(`CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,order_number TEXT UNIQUE NOT NULL,user_id TEXT NOT NULL REFERENCES users(id),status TEXT NOT NULL DEFAULT 'new',items JSONB NOT NULL,total_text TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)`);
  const c=await q(`SELECT COUNT(*)::int AS n FROM products`); if(c.rows[0].n===0){
    for(const p of seed.catalog){await q(`INSERT INTO products(id,name,category,price,stock,updated,tiers,package_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[productId(p),p.name,p.category||'',p.price||'',p.stock||'موجود',p.updated||'',JSON.stringify(p.tiers||{}),p.package_count||''])}
  }
  const a=await q(`SELECT id FROM users WHERE role='admin' LIMIT 1`); if(!a.rows.length){const hash=await bcrypt.hash(process.env.ADMIN_INITIAL_PASSWORD||'1234',12);await q(`INSERT INTO users(id,name,phone,password_hash,role,status,tier) VALUES('admin','مدیر سیستم','admin',$1,'admin','approved','admin')`,[hash])}
}
function productId(p){let s=(p.name+'|'+(p.category||''));let h=0;for(let i=0;i<s.length;i++)h=((h<<5)-h+s.charCodeAt(i))|0;return 'p'+Math.abs(h)}
function sign(user,kind){return jwt.sign({sub:user.id,role:user.role,kind},JWT_SECRET,{expiresIn:kind==='admin'?'12h':'30d'})}
function auth(kind){return async(req,res,next)=>{try{const raw=(req.headers.authorization||'').replace(/^Bearer\s+/,'');if(!raw)return res.status(401).json({message:'نیاز به ورود دارید'});const p=jwt.verify(raw,JWT_SECRET);if(p.kind!==kind)throw new Error('bad token');const r=await q(`SELECT * FROM users WHERE id=$1`,[p.sub]);if(!r.rows[0])throw new Error('user');req.user=r.rows[0];next()}catch(e){res.status(401).json({message:'نشست شما معتبر نیست؛ دوباره وارد شوید.'})}}}
function pubUser(u){return {id:u.id,name:u.name,nationalId:u.national_id,nationalIdType:u.national_id_type,phone:u.phone,role:u.role,status:u.status,requestedTier:u.requested_tier,tier:u.tier,province:u.province,city:u.city,postalCode:u.postal_code,address:u.address,receiver:u.receiver}}
function pubProduct(r){return {id:r.id,name:r.name,category:r.category,price:r.price,stock:r.stock,updated:r.updated,tiers:r.tiers||{},package_count:r.package_count}}
function normalizeDigits(v){return String(v||'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))}
function validId(type,id){id=normalizeDigits(id).replace(/\D/g,'');return type==='national'?/^\d{10}$/.test(id):/^\d{11,16}$/.test(id)}
app.get('/health',(req,res)=>res.status(200).json({ok:true,service:'tariana-oxsin-backend'})); q('SELECT 1');res.json({ok:true,service:'tariana-oxsin-backend',time:new Date().toISOString()})}catch(e){res.status(500).json({ok:false,message:e.message})}});
app.get('/api/bootstrap',async(req,res)=>{const r=await q(`SELECT * FROM products ORDER BY id`);const groups=[...new Set(r.rows.map(x=>x.category).filter(Boolean))];res.json({catalog:r.rows.map(pubProduct),groups})});
app.post('/api/auth/register',async(req,res)=>{try{let {name,nationalId,nationalIdType,phone,password,requestedTier}=req.body;name=String(name||'').trim();phone=normalizeDigits(phone).trim();nationalId=normalizeDigits(nationalId).replace(/\D/g,'');if(!name||!phone||!password||!nationalId) return res.status(400).json({message:'همه فیلدهای الزامی را کامل کنید.'});if(!validId(nationalIdType,nationalId))return res.status(400).json({message:nationalIdType==='national'?'کد ملی باید دقیقاً ۱۰ رقم باشد.':'شناسه ملی باید بین ۱۱ تا ۱۶ رقم باشد.'});const dup=await q(`SELECT id FROM users WHERE phone=$1 OR national_id=$2`,[phone,nationalId]);if(dup.rows.length)return res.status(409).json({message:'این شماره موبایل یا کد ملی/شناسه ملی قبلاً ثبت شده است.'});const id='u'+Date.now()+Math.random().toString(36).slice(2,7);const hash=await bcrypt.hash(String(password),12);await q(`INSERT INTO users(id,name,national_id,national_id_type,phone,password_hash,role,status,requested_tier) VALUES($1,$2,$3,$4,$5,$6,'customer','pending',$7)`,[id,name,nationalId,nationalIdType,phone,hash,requestedTier||'retail']);res.json({ok:true})}catch(e){res.status(500).json({message:'خطا در ثبت‌نام'})}});
app.post('/api/auth/login',async(req,res)=>{const {name,phone,password}=req.body;const r=await q(`SELECT * FROM users WHERE role='customer' AND name=$1 AND phone=$2`,[String(name||'').trim(),normalizeDigits(phone)]);const u=r.rows[0];if(!u||!(await bcrypt.compare(String(password||''),u.password_hash)))return res.status(401).json({message:'شماره موبایل یا رمز عبور صحیح نیست.'});if(u.status!=='approved')return res.status(403).json({message:u.status==='pending'?'حساب شما هنوز توسط مدیر تأیید نشده است.':'حساب شما غیرفعال است.'});res.json({token:sign(u,'customer'),user:pubUser(u)})});
app.get('/api/me',auth('customer'),async(req,res)=>res.json({user:pubUser(req.user)}));
app.put('/api/me',auth('customer'),async(req,res)=>{const {name,province,city,postalCode,address,receiver}=req.body;const p=normalizeDigits(postalCode||'').replace(/\D/g,'');if(p&&!/^\d{10}$/.test(p))return res.status(400).json({message:'کد پستی باید دقیقاً ۱۰ رقم باشد.'});const r=await q(`UPDATE users SET name=$1,province=$2,city=$3,postal_code=$4,address=$5,receiver=$6 WHERE id=$7 RETURNING *`,[String(name||'').trim(),String(province||'').trim(),String(city||'').trim(),p,String(address||'').trim(),String(receiver||'').trim(),req.user.id]);res.json({user:pubUser(r.rows[0])})});
app.put('/api/me/password',auth('customer'),async(req,res)=>{const {oldPassword,newPassword}=req.body;if(!newPassword||String(newPassword).length<4)return res.status(400).json({message:'رمز جدید باید حداقل ۴ کاراکتر باشد.'});if(!(await bcrypt.compare(String(oldPassword||''),req.user.password_hash)))return res.status(400).json({message:'رمز فعلی صحیح نیست.'});const h=await bcrypt.hash(String(newPassword),12);await q(`UPDATE users SET password_hash=$1 WHERE id=$2`,[h,req.user.id]);res.json({ok:true})});
app.post('/api/admin/login',async(req,res)=>{const {username,password}=req.body;const r=await q(`SELECT * FROM users WHERE role='admin' AND phone=$1`,[String(username||'').trim()]);const u=r.rows[0];if(!u||!(await bcrypt.compare(String(password||''),u.password_hash)))return res.status(401).json({message:'نام کاربری یا رمز مدیر صحیح نیست.'});res.json({token:sign(u,'admin'),user:pubUser(u)})});
app.get('/api/admin/catalog',auth('admin'),async(req,res)=>{const r=await q(`SELECT * FROM products ORDER BY id`);res.json({catalog:r.rows.map(pubProduct),groups:[...new Set(r.rows.map(x=>x.category).filter(Boolean))]})});
app.put('/api/admin/products/:id',auth('admin'),async(req,res)=>{const {price,tiers}=req.body;const r=await q(`UPDATE products SET price=$1,tiers=$2,updated=$3 WHERE id=$4 RETURNING *`,[String(price??''),JSON.stringify(tiers||{}),new Date().toISOString(),req.params.id]);if(!r.rows[0])return res.status(404).json({message:'کالا پیدا نشد.'});res.json({product:pubProduct(r.rows[0])})});
app.get('/api/admin/users',auth('admin'),async(req,res)=>{const r=await q(`SELECT * FROM users ORDER BY created_at DESC`);res.json({users:r.rows.map(pubUser)})});
app.put('/api/admin/users/:id',auth('admin'),async(req,res)=>{const status=req.body.status==='approved'?'approved':'disabled';const r=await q(`UPDATE users SET status=$1,tier=$2 WHERE id=$3 AND role='customer' RETURNING *`,[status,status==='approved'?'retail':null,req.params.id]);if(!r.rows[0])return res.status(404).json({message:'مشتری پیدا نشد.'});res.json({user:pubUser(r.rows[0])})});
app.put('/api/admin/password',auth('admin'),async(req,res)=>{const {oldPassword,newPassword}=req.body;if(!newPassword||String(newPassword).length<4)return res.status(400).json({message:'رمز جدید باید حداقل ۴ کاراکتر باشد.'});if(!(await bcrypt.compare(String(oldPassword||''),req.user.password_hash)))return res.status(400).json({message:'رمز فعلی صحیح نیست.'});const h=await bcrypt.hash(String(newPassword),12);await q(`UPDATE users SET password_hash=$1 WHERE id=$2`,[h,req.user.id]);res.json({ok:true})});
app.post('/api/orders',auth('customer'),async(req,res)=>{const items=Array.isArray(req.body.items)?req.body.items:[];if(!items.length)return res.status(400).json({message:'سبد سفارش خالی است.'});const ids=items.map(x=>String(x.productId));const r=await q(`SELECT * FROM products WHERE id = ANY($1)`,[ids]);const map=new Map(r.rows.map(x=>[x.id,x]));const finalItems=[];for(const it of items){const p=map.get(String(it.productId));const qty=Math.max(1,Math.min(999,Number(it.quantity)||1));if(p)finalItems.push({productId:p.id,name:p.name,category:p.category,quantity:qty,price:p.price,tiers:p.tiers||{}})}if(!finalItems.length)return res.status(400).json({message:'کالاهای سفارش معتبر نیستند.'});const orderNumber='TX-'+new Date().toISOString().slice(0,10).replace(/-/g,'')+'-'+Math.floor(1000+Math.random()*9000);const id='o'+Date.now()+Math.random().toString(36).slice(2,7);const total=finalItems.reduce((s,x)=>s+(Number(x.price)||0)*x.quantity,0);const o=await q(`INSERT INTO orders(id,order_number,user_id,items,total_text) VALUES($1,$2,$3,$4,$5) RETURNING *`,[id,orderNumber,req.user.id,JSON.stringify(finalItems),String(total)]);res.json({order:{id:o.rows[0].id,orderNumber:o.rows[0].order_number,status:o.rows[0].status,items:finalItems,totalText:o.rows[0].total_text}})});
app.get('/api/admin/orders',auth('admin'),async(req,res)=>{const r=await q(`SELECT o.*,u.name,u.phone FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.created_at DESC`);res.json({orders:r.rows})});
app.get('/{*splat}',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
initDb().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`Tariana backend running on 0.0.0.0:${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
