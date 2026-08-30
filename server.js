const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const Razorpay = require('razorpay');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.sendStatus(204);
  next();
});

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const LICENSE_SECRET = process.env.LICENSE_SECRET;
const RZ_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RZ_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

if(!DATABASE_URL || !ADMIN_PASSWORD || !LICENSE_SECRET){
  console.error('Missing DATABASE_URL / ADMIN_PASSWORD / LICENSE_SECRET');
  process.exit(1);
}

const pool = new Pool({ connectionString:DATABASE_URL, ssl:{rejectUnauthorized:false}, max:5 });
const razorpay = (RZ_KEY_ID && RZ_KEY_SECRET) ? new Razorpay({ key_id:RZ_KEY_ID, key_secret:RZ_KEY_SECRET }) : null;

const sha = v => crypto.createHash('sha256').update(String(v)).digest('hex');
const hmac = v => crypto.createHmac('sha256', LICENSE_SECRET).update(String(v)).digest('hex');
function safeEqual(a,b){ a=String(a||''); b=String(b||''); return a.length===b.length && crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b)); }
function makeKey(){ const x=crypto.randomBytes(12).toString('hex').toUpperCase(); return `MPEB-${x.slice(0,4)}-${x.slice(4,8)}-${x.slice(8,12)}-${x.slice(12,16)}-${x.slice(16,20)}-${x.slice(20,24)}`; }
function validDevice(v){ return /^[A-Za-z0-9._:-]{16,200}$/.test(String(v||'')); }
function signLicense(id,deviceHash,keyHash){ return hmac(`${id}:${deviceHash}:${keyHash}`); }

async function initDb(){
  await pool.query(`CREATE TABLE IF NOT EXISTS licenses(
    id BIGSERIAL PRIMARY KEY,
    key_hash TEXT UNIQUE NOT NULL,
    key_hint TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'lifetime',
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ,
    device_hash TEXT,
    device_hint TEXT,
    activated_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    razorpay_payment_id TEXT UNIQUE,
    razorpay_order_id TEXT,
    customer_name TEXT,
    customer_email TEXT,
    customer_phone TEXT,
    payment_mode TEXT NOT NULL DEFAULT 'online',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  for(const sql of [
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'lifetime'`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS razorpay_payment_id TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS razorpay_order_id TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS customer_name TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS customer_email TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS customer_phone TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS payment_mode TEXT NOT NULL DEFAULT 'online'`,
    `CREATE UNIQUE INDEX IF NOT EXISTS licenses_payment_uidx ON licenses(razorpay_payment_id) WHERE razorpay_payment_id IS NOT NULL`,
    `CREATE INDEX IF NOT EXISTS licenses_device_idx ON licenses(device_hash)`,
    `CREATE TABLE IF NOT EXISTS payments(
      id BIGSERIAL PRIMARY KEY,
      razorpay_payment_id TEXT UNIQUE,
      razorpay_order_id TEXT,
      amount INTEGER NOT NULL,
      currency TEXT NOT NULL,
      status TEXT NOT NULL,
      license_id BIGINT,
      payload JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  ]) await pool.query(sql);
}

function requireAdmin(req,res,next){
  const h=req.headers.authorization||'';
  if(!h.startsWith('Basic ')){ res.setHeader('WWW-Authenticate','Basic realm="MPEB License Admin"'); return res.status(401).send('Authentication required'); }
  const raw=Buffer.from(h.slice(6),'base64').toString('utf8');
  const i=raw.indexOf(':');
  if(i<1 || !safeEqual(raw.slice(0,i),ADMIN_USER) || !safeEqual(raw.slice(i+1),ADMIN_PASSWORD)) return res.status(401).send('Authentication required');
  next();
}

app.get('/health', async (req,res)=>{
  try{ await pool.query('SELECT 1'); res.json({ok:true,service:'mpeb-license-api',time:new Date().toISOString()}); }
  catch(e){ res.status(503).json({ok:false,error:'database_unavailable'}); }
});

app.post('/api/trial', async (req,res)=>{
  const key=makeKey();
  const r=await pool.query(`INSERT INTO licenses(key_hash,key_hint,type,status,expires_at) VALUES($1,$2,'trial','active',NOW()+INTERVAL '1 day') RETURNING id,expires_at`,[sha(key),key.slice(-8)]);
  res.json({success:true,key,license:r.rows[0]});
});

app.post('/api/payment/order', async (req,res)=>{
  if(!razorpay) return res.status(503).json({success:false,error:'Razorpay is not configured.'});
  try{
    const order=await razorpay.orders.create({amount:49900,currency:'INR',receipt:'mpeb_'+Date.now(),notes:{product:'MPEB Lifetime License'}});
    res.json({success:true,key_id:RZ_KEY_ID,order_id:order.id,amount:order.amount,currency:order.currency});
  }catch(e){ console.error(e); res.status(500).json({success:false,error:'Could not create Razorpay order.'}); }
});

app.post('/api/payment/verify', async (req,res)=>{
  if(!razorpay) return res.status(503).json({success:false,error:'Razorpay is not configured.'});
  const orderId=String(req.body.razorpay_order_id||''), paymentId=String(req.body.razorpay_payment_id||''), signature=String(req.body.razorpay_signature||'');
  if(!orderId||!paymentId||!signature) return res.status(400).json({success:false,error:'Missing payment information.'});
  const expected=crypto.createHmac('sha256',RZ_KEY_SECRET).update(orderId+'|'+paymentId).digest('hex');
  if(!safeEqual(expected,signature)) return res.status(400).json({success:false,error:'Payment signature verification failed.'});
  const client=await pool.connect();
  try{
    const existing=await client.query('SELECT id FROM licenses WHERE razorpay_payment_id=$1',[paymentId]);
    if(existing.rows.length) return res.status(409).json({success:false,error:'Payment already processed.'});
    const paid=await razorpay.payments.fetch(paymentId);
    if(paid.order_id!==orderId || Number(paid.amount)!==49900 || paid.currency!=='INR' || paid.status!=='captured') return res.status(400).json({success:false,error:'Payment could not be verified.'});
    const key=makeKey();
    await client.query('BEGIN');
    const lic=await client.query(`INSERT INTO licenses(key_hash,key_hint,type,status,razorpay_payment_id,razorpay_order_id,customer_name,customer_email,customer_phone) VALUES($1,$2,'lifetime','active',$3,$4,$5,$6,$7) RETURNING id,created_at`,[
      sha(key),key.slice(-8),paymentId,orderId,String(req.body.name||'').slice(0,120),String(req.body.email||'').slice(0,180),String(req.body.phone||'').slice(0,40)
    ]);
    await client.query(`INSERT INTO payments(razorpay_payment_id,razorpay_order_id,amount,currency,status,license_id,payload) VALUES($1,$2,49900,'INR',$3,$4,$5)`,[paymentId,orderId,paid.status,lic.rows[0].id,JSON.stringify(paid)]);
    await client.query('COMMIT');
    res.json({success:true,key,license:lic.rows[0]});
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); console.error(e); res.status(500).json({success:false,error:'Could not issue license.'}); }
  finally{ client.release(); }
});

app.post('/api/activate', async (req,res)=>{
  const key=String(req.body.key||'').trim().toUpperCase();
  const device=String(req.body.device_id||'').trim();
  if(!/^MPEB-[A-Z0-9-]{20,80}$/.test(key)||!validDevice(device)) return res.status(400).json({success:false,error:'Invalid license information.'});
  const keyHash=sha(key), deviceHash=sha(device), client=await pool.connect();
  try{
    await client.query('BEGIN');
    const q=await client.query('SELECT * FROM licenses WHERE key_hash=$1 FOR UPDATE',[keyHash]);
    if(!q.rows.length){ await client.query('ROLLBACK'); return res.status(404).json({success:false,error:'Invalid license key.'}); }
    const lic=q.rows[0];
    if(lic.status!=='active'){ await client.query('ROLLBACK'); return res.status(403).json({success:false,error:'License disabled.'}); }
    if(lic.expires_at && new Date(lic.expires_at)<=new Date()){ await client.query('ROLLBACK'); return res.status(403).json({success:false,error:'License expired.'}); }
    if(lic.type==='trial' && !lic.device_hash){
      const used=await client.query(`SELECT id FROM licenses WHERE type='trial' AND device_hash=$1 LIMIT 1`,[deviceHash]);
      if(used.rows.length){ await client.query('ROLLBACK'); return res.status(409).json({success:false,error:'1-day trial already used on this system.'}); }
    }
    if(lic.device_hash && lic.device_hash!==deviceHash){ await client.query('ROLLBACK'); return res.status(409).json({success:false,error:'This license is already activated on another system.'}); }
    await client.query(`UPDATE licenses SET device_hash=COALESCE(device_hash,$1),device_hint=COALESCE(device_hint,$2),activated_at=COALESCE(activated_at,NOW()),last_seen_at=NOW() WHERE id=$3`,[deviceHash,device.slice(0,32),lic.id]);
    await client.query('COMMIT');
    res.json({success:true,token:signLicense(lic.id,deviceHash,keyHash),license:{id:lic.id,type:lic.type,expires_at:lic.expires_at}});
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); console.error(e); res.status(500).json({success:false,error:'Activation failed.'}); }
  finally{ client.release(); }
});

app.post('/api/validate', async (req,res)=>{
  const token=String(req.body.token||''), device=String(req.body.device_id||'');
  if(!token||!validDevice(device)) return res.status(400).json({success:false,error:'Missing license information.'});
  const dh=sha(device), q=await pool.query('SELECT * FROM licenses WHERE device_hash=$1 LIMIT 1',[dh]);
  if(!q.rows.length) return res.status(401).json({success:false,error:'License not activated.'});
  const lic=q.rows[0];
  if(lic.status!=='active') return res.status(403).json({success:false,error:'License disabled.'});
  if(lic.expires_at && new Date(lic.expires_at)<=new Date()) return res.status(403).json({success:false,error:'License expired.'});
  if(!safeEqual(token,signLicense(lic.id,dh,lic.key_hash))) return res.status(401).json({success:false,error:'Invalid license token.'});
  await pool.query('UPDATE licenses SET last_seen_at=NOW() WHERE id=$1',[lic.id]);
  res.json({success:true,license:{id:lic.id,type:lic.type,expires_at:lic.expires_at}});
});

app.get('/api/admin/licenses',requireAdmin,async(req,res)=>{
  const r=await pool.query(`SELECT id,key_hint,type,status,expires_at,device_hint,activated_at,last_seen_at,razorpay_payment_id,razorpay_order_id,customer_name,customer_email,customer_phone,payment_mode,created_at FROM licenses ORDER BY id DESC LIMIT 2000`);
  res.json({success:true,licenses:r.rows});
});
app.post('/api/admin/licenses',requireAdmin,async(req,res)=>{
  const type=req.body.type==='trial'?'trial':(req.body.type==='annual'?'annual':'lifetime');
  const paymentMode=req.body.payment_mode==='cash'?'cash':'online';
  let expiry=req.body.expires_at?new Date(req.body.expires_at):null;
  if(type==='trial'&&!expiry) expiry=new Date(Date.now()+86400000);
  if(type==='annual'&&!expiry) expiry=new Date(Date.now()+365*86400000);
  if(expiry && Number.isNaN(expiry.getTime())) return res.status(400).json({success:false,error:'Invalid expiry date.'});
  const key=makeKey();
  const r=await pool.query(`INSERT INTO licenses(key_hash,key_hint,type,status,expires_at,payment_mode) VALUES($1,$2,$3,'active',$4,$5) RETURNING id,expires_at,created_at,payment_mode`,[sha(key),key.slice(-8),type,expiry,paymentMode]);
  res.json({success:true,key,license:r.rows[0]});
});
app.post('/api/admin/licenses/:id/reset',requireAdmin,async(req,res)=>{
  const r=await pool.query(`UPDATE licenses SET device_hash=NULL,device_hint=NULL,activated_at=NULL,last_seen_at=NULL WHERE id=$1 RETURNING id`,[req.params.id]);
  res.status(r.rows.length?200:404).json(r.rows.length?{success:true}:{success:false,error:'License not found.'});
});
app.post('/api/admin/licenses/:id/status',requireAdmin,async(req,res)=>{
  const status=req.body.status==='disabled'?'disabled':'active';
  const r=await pool.query('UPDATE licenses SET status=$1 WHERE id=$2 RETURNING id,status',[status,req.params.id]);
  res.status(r.rows.length?200:404).json(r.rows.length?{success:true,license:r.rows[0]}:{success:false,error:'License not found.'});
});
app.delete('/api/admin/licenses/:id',requireAdmin,async(req,res)=>{
  const r=await pool.query('DELETE FROM licenses WHERE id=$1 RETURNING id',[req.params.id]);
  res.status(r.rows.length?200:404).json(r.rows.length?{success:true}:{success:false,error:'License not found.'});
});
app.get('/api/admin/payments',requireAdmin,async(req,res)=>{
  const r=await pool.query(`SELECT id,razorpay_payment_id,razorpay_order_id,amount,currency,status,license_id,created_at FROM payments ORDER BY id DESC LIMIT 2000`);
  res.json({success:true,payments:r.rows});
});

app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('/license',(req,res)=>res.sendFile(path.join(__dirname,'public','license.html')));
app.get('/admin',requireAdmin,(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));

initDb().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log('MPEB License API listening on '+PORT))).catch(e=>{console.error(e);process.exit(1)});
