const express = require('express'), Database = require('better-sqlite3'), multer = require('multer');
const path = require('path'), fs = require('fs'), crypto = require('crypto');
const app = express(), db = new Database(path.join(__dirname, 'elan.db'));
const UP = path.join(__dirname, 'uploads'); fs.mkdirSync(UP, { recursive: true });
app.set('trust proxy', 1);

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  phone TEXT, salt TEXT NOT NULL, hash TEXT NOT NULL, is_admin INTEGER DEFAULT 0, banned INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ads(id INTEGER PRIMARY KEY AUTOINCREMENT, section TEXT NOT NULL, category TEXT, deal TEXT,
  title TEXT NOT NULL, description TEXT NOT NULL, price REAL, city TEXT, name TEXT, phone TEXT NOT NULL,
  attrs TEXT DEFAULT '{}', images TEXT DEFAULT '[]', views INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`);
for (const c of ["user_id INTEGER", "status TEXT DEFAULT 'active'", "reports INTEGER DEFAULT 0"])
  try { db.exec('ALTER TABLE ads ADD COLUMN ' + c); } catch {}

// ---- parollar və admin ----
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const checkPw = (pw, u) => crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
// Admin YALNIZ mühit dəyişənlərindən yaradılır: ADMIN_EMAIL və ADMIN_PASSWORD
if (process.env.ADMIN_EMAIL && (process.env.ADMIN_PASSWORD || '').length >= 8) {
  const email = process.env.ADMIN_EMAIL.toLowerCase(), salt = crypto.randomBytes(16).toString('hex');
  const h = hashPw(process.env.ADMIN_PASSWORD, salt);
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email))
    db.prepare('UPDATE users SET salt=?,hash=?,is_admin=1,banned=0 WHERE email=?').run(salt, h, email);
  else db.prepare('INSERT INTO users(email,name,salt,hash,is_admin) VALUES(?,?,?,?,1)').run(email, 'Admin', salt, h);
} else console.warn('DİQQƏT: ADMIN_EMAIL / ADMIN_PASSWORD (min 8 simvol) verilməyib, admin paneli işləməyəcək.');

// ---- sorğu limiti (spam qorunması) ----
const hits = new Map();
const limit = (name, max, ms) => (req, res, next) => {
  const k = name + ':' + (req.user?.id || req.ip), n = Date.now(), a = (hits.get(k) || []).filter(t => n - t < ms);
  if (a.length >= max && !req.user?.is_admin) return res.status(429).json({ error: 'Çox sorğu göndərdiniz. Bir az sonra yenidən cəhd edin.' });
  a.push(n); hits.set(k, a); next();
};
setInterval(() => hits.clear(), 3600e3);

app.use(express.json({ limit: '50kb' }));
app.use((req, res, next) => { // sessiya
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  if (m) req.user = db.prepare(`SELECT u.id,u.email,u.name,u.phone,u.is_admin FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token=? AND s.expires>? AND u.banned=0`).get(m[1], Date.now());
  next();
});
const need = (q, s, n) => q.user ? n() : s.status(401).json({ error: 'Əvvəlcə daxil olun.' });
const admin = (q, s, n) => q.user?.is_admin ? n() : s.status(403).json({ error: 'İcazə yoxdur.' });
const startSession = (req, res, id) => {
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(t, id, Date.now() + 30 * 864e5);
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${req.secure ? '; Secure' : ''}`);
};

// ---- hesab ----
app.post('/api/register', limit('reg', 5, 3600e3), (req, res) => {
  const { name = '', email = '', password = '', phone = '' } = req.body;
  if (name.trim().length < 2 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || password.length < 8 || !/^[+\d\s()-]{7,20}$/.test(phone))
    return res.status(400).json({ error: 'Ad, düzgün e-poçt, telefon və minimum 8 simvolluq parol daxil edin.' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email.toLowerCase()))
    return res.status(400).json({ error: 'Bu e-poçt artıq qeydiyyatdadır.' });
  const salt = crypto.randomBytes(16).toString('hex');
  const id = db.prepare('INSERT INTO users(email,name,phone,salt,hash) VALUES(?,?,?,?,?)')
    .run(email.toLowerCase(), name.trim().slice(0, 60), phone.trim(), salt, hashPw(password, salt)).lastInsertRowid;
  startSession(req, res, id); res.json({ ok: true });
});
app.post('/api/login', limit('login', 10, 15 * 60e3), (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(req.body.email || '').toLowerCase());
  if (!u || u.banned || !checkPw(String(req.body.password || ''), u)) return res.status(401).json({ error: 'E-poçt və ya parol səhvdir.' });
  startSession(req, res, u.id); res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  const m = /sid=([a-f0-9]+)/.exec(req.headers.cookie || ''); if (m) db.prepare('DELETE FROM sessions WHERE token=?').run(m[1]);
  res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); res.json({ ok: true });
});
app.get('/api/me', (req, res) => res.json({ user: req.user ? { ...req.user, is_admin: !!req.user.is_admin } : null }));

// ---- elanlar ----
const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };
const upload = multer({
  storage: multer.diskStorage({ destination: UP, filename: (r, f, cb) => cb(null, crypto.randomUUID() + EXT[f.mimetype]) }),
  limits: { fileSize: 5 * 1024 * 1024, files: 6 }, fileFilter: (r, f, cb) => cb(null, !!EXT[f.mimetype])
});
const parse = r => ({ ...r, attrs: JSON.parse(r.attrs || '{}'), images: JSON.parse(r.images || '[]') });
const PUB = 'id,section,category,deal,title,description,price,city,name,attrs,images,views,created_at,user_id';
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UP));

app.get('/api/ads', (req, res) => {
  const q = req.query, w = ["status='active'"], p = {};
  for (const k of ['section', 'category', 'deal', 'city']) if (q[k]) { w.push(`${k}=@${k}`); p[k] = q[k]; }
  if (q.q) { w.push('(title LIKE @q OR description LIKE @q)'); p.q = `%${q.q}%`; }
  if (q.min) { w.push('price>=@min'); p.min = +q.min; }
  if (q.max) { w.push('price<=@max'); p.max = +q.max; }
  for (const k of ['brand', 'model', 'body', 'fuel', 'gearbox', 'drive', 'color', 'market', 'damage', 'credit', 'barter', 'propType', 'rooms']) if (q[k]) { w.push(`json_extract(attrs,'$.${k}')=@${k}`); p[k] = q[k]; }
  for (const k of ['year', 'mileage', 'engine']) { // min / maks aralıqları
    if (q[k + 'Min']) { w.push(`CAST(json_extract(attrs,'$.${k}') AS REAL)>=@${k}Min`); p[k + 'Min'] = +q[k + 'Min']; }
    if (q[k + 'Max']) { w.push(`CAST(json_extract(attrs,'$.${k}') AS REAL)<=@${k}Max`); p[k + 'Max'] = +q[k + 'Max']; }
  }
  [].concat(q.extras || []).slice(0, 20).forEach((e, i) => { // seçilmiş bütün avadanlıqlar olmalıdır
    w.push(`EXISTS(SELECT 1 FROM json_each(attrs,'$.extras') WHERE value=@ex${i})`); p['ex' + i] = String(e); });
  const sort = { new: 'id DESC', cheap: 'price ASC', exp: 'price DESC' }[q.sort] || 'id DESC';
  p.off = ((parseInt(q.page) || 1) - 1) * 24;
  res.json(db.prepare(`SELECT ${PUB} FROM ads WHERE ${w.join(' AND ')} ORDER BY ${sort} LIMIT 24 OFFSET @off`).all(p).map(parse));
});
app.get('/api/ads/:id', (req, res) => {
  const r = db.prepare(`SELECT ${PUB} FROM ads WHERE id=? AND status='active'`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Elan tapılmadı' });
  db.prepare('UPDATE ads SET views=views+1 WHERE id=?').run(r.id); res.json(parse(r));
});
// telefon yalnız düyməyə basanda göstərilir (robotlara qarşı limitli)
app.get('/api/ads/:id/phone', limit('phone', 40, 3600e3), (req, res) => {
  const r = db.prepare("SELECT phone FROM ads WHERE id=? AND status='active'").get(req.params.id);
  r ? res.json(r) : res.status(404).json({ error: 'Elan tapılmadı' });
});
app.post('/api/ads/:id/report', limit('report', 10, 3600e3), (req, res) => {
  db.prepare('UPDATE ads SET reports=reports+1 WHERE id=?').run(req.params.id); res.json({ ok: true });
});
app.post('/api/ads', need, limit('post', 5, 3600e3), upload.array('images', 6), (req, res) => {
  const b = req.body;
  if (!['tap', 'avto', 'emlak'].includes(b.section) || !b.title?.trim() || !b.description?.trim() || !b.phone?.trim())
    return res.status(400).json({ error: 'Vacib sahələri doldurun.' });
  if (db.prepare("SELECT COUNT(*) c FROM ads WHERE user_id=? AND status!='deleted'").get(req.user.id).c >= 30 && !req.user.is_admin)
    return res.status(400).json({ error: 'Maksimum 30 aktiv elanınız ola bilər.' });
  let attrs = {}; try { attrs = JSON.parse(b.attrs || '{}'); } catch {}
  if (!attrs || typeof attrs !== 'object' || Array.isArray(attrs)) attrs = {};
  // real konum: yalnız Azərbaycan hüdudlarında olan rəqəmlər saxlanılır
  const la = Number(attrs.lat), lo = Number(attrs.lng);
  if (attrs.lat !== '' && attrs.lng !== '' && la >= 38 && la <= 42.5 && lo >= 44.5 && lo <= 51.5) { attrs.lat = la; attrs.lng = lo; }
  else { delete attrs.lat; delete attrs.lng; }
  for (const k of ['year', 'mileage', 'engine']) if (attrs[k] !== undefined) {
    const n = Number(attrs[k]); if (attrs[k] !== '' && isFinite(n) && n >= 0) attrs[k] = n; else delete attrs[k]; }
  if (Array.isArray(attrs.extras)) attrs.extras = attrs.extras.filter(x => typeof x === 'string' && x.length <= 40).slice(0, 30);
  else delete attrs.extras;
  const info = db.prepare(`INSERT INTO ads(user_id,section,category,deal,title,description,price,city,name,phone,attrs,images)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(req.user.id, b.section, b.category || '', b.deal || '', b.title.trim().slice(0, 120),
    b.description.trim().slice(0, 3000), b.price ? +b.price : null, b.city || '', req.user.name, b.phone.trim().slice(0, 30),
    JSON.stringify(attrs), JSON.stringify((req.files || []).map(f => f.filename)));
  res.status(201).json({ id: info.lastInsertRowid });
});
app.get('/api/my/ads', need, (req, res) =>
  res.json(db.prepare('SELECT * FROM ads WHERE user_id=? ORDER BY id DESC').all(req.user.id).map(parse)));
const own = (req, res, next) => {
  const a = db.prepare('SELECT * FROM ads WHERE id=?').get(req.params.id);
  if (!a || (a.user_id !== req.user.id && !req.user.is_admin)) return res.status(403).json({ error: 'İcazə yoxdur.' });
  req.ad = a; next();
};
app.patch('/api/ads/:id', need, own, (req, res) => {
  const { title, description, price } = req.body;
  db.prepare('UPDATE ads SET title=?,description=?,price=? WHERE id=?').run(
    (title || req.ad.title).slice(0, 120), (description || req.ad.description).slice(0, 3000),
    price === '' || price == null ? null : +price, req.ad.id);
  res.json({ ok: true });
});
app.delete('/api/ads/:id', need, own, (req, res) => {
  for (const f of JSON.parse(req.ad.images || '[]')) fs.unlink(path.join(UP, path.basename(f)), () => {});
  db.prepare('DELETE FROM ads WHERE id=?').run(req.ad.id); res.json({ ok: true });
});

// ---- admin paneli (yalnız admin hesabı) ----
app.get('/api/admin/stats', need, admin, (req, res) => res.json({
  users: db.prepare('SELECT COUNT(*) c FROM users').get().c, ads: db.prepare("SELECT COUNT(*) c FROM ads WHERE status='active'").get().c,
  hidden: db.prepare("SELECT COUNT(*) c FROM ads WHERE status='hidden'").get().c, reported: db.prepare('SELECT COUNT(*) c FROM ads WHERE reports>0').get().c }));
app.get('/api/admin/ads', need, admin, (req, res) => res.json(db.prepare(
  `SELECT a.*,u.email FROM ads a LEFT JOIN users u ON u.id=a.user_id ORDER BY (a.reports>0) DESC, a.reports DESC, a.id DESC LIMIT 300`).all().map(parse)));
app.post('/api/admin/ads/:id/status', need, admin, (req, res) => {
  db.prepare('UPDATE ads SET status=?,reports=0 WHERE id=?').run(req.body.status === 'hidden' ? 'hidden' : 'active', req.params.id); res.json({ ok: true });
});
app.get('/api/admin/users', need, admin, (req, res) => res.json(db.prepare(
  'SELECT id,email,name,phone,is_admin,banned,created_at,(SELECT COUNT(*) FROM ads WHERE user_id=users.id) ads FROM users ORDER BY id DESC LIMIT 300').all()));
app.post('/api/admin/users/:id/ban', need, admin, (req, res) => {
  const u = db.prepare('SELECT is_admin FROM users WHERE id=?').get(req.params.id);
  if (!u || u.is_admin) return res.status(400).json({ error: 'Admini bloklamaq olmaz.' });
  db.prepare('UPDATE users SET banned=? WHERE id=?').run(req.body.banned ? 1 : 0, req.params.id);
  if (req.body.banned) { db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.params.id); db.prepare("UPDATE ads SET status='hidden' WHERE user_id=?").run(req.params.id); }
  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log('Elan.az: http://localhost:3000'));
