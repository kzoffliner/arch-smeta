/** Minimal local backend for Archsmeta. Run: node server.js */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const root = __dirname;
const dbFile = path.join(root, 'archsmeta-db.json');
const sessions = new Map();
const readDb = () => {
  try { return JSON.parse(fs.readFileSync(dbFile, 'utf8')); }
  catch { return { users: [], state: null }; }
};
const writeDb = data => fs.writeFileSync(dbFile, JSON.stringify(data, null, 2), 'utf8');
const hash = password => new Promise((resolve, reject) => crypto.scrypt(password, 'archsmeta-v1', 64, (err, key) => err ? reject(err) : resolve(key.toString('hex'))));
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(x => x.trim().split('=')));
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); };
const userView = user => ({ id: user.id, email: user.email, name: user.name, avatar: user.avatar || '' });

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith('/api/')) {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 15_000_000) req.destroy(); });
    await new Promise(resolve => req.on('end', resolve));
    let payload = {};
    try { payload = body ? JSON.parse(body) : {}; } catch { return json(res, 400, { error: 'Некорректные данные' }); }
    const data = readDb();
    const token = cookies(req).archsmeta_session;
    const userId = sessions.get(token);
    if (url.pathname === '/api/auth/register' && req.method === 'POST') {
      const email = String(payload.email || '').trim().toLowerCase();
      if (!/^\S+@\S+\.\S+$/.test(email) || String(payload.password || '').length < 6) return json(res, 400, { error: 'Проверьте email и пароль (минимум 6 символов)' });
      if (data.users.some(u => u.email === email)) return json(res, 409, { error: 'Этот email уже зарегистрирован' });
      const user = { id: crypto.randomUUID(), email, name: email.split('@')[0], passwordHash: await hash(payload.password) };
      data.users.push(user); writeDb(data);
      const newToken = crypto.randomUUID(); sessions.set(newToken, user.id);
      res.setHeader('Set-Cookie', `archsmeta_session=${newToken}; HttpOnly; SameSite=Lax; Path=/`);
      return json(res, 201, { user: userView(user) });
    }
    if (url.pathname === '/api/auth/login' && req.method === 'POST') {
      const email = String(payload.email || '').trim().toLowerCase();
      const user = data.users.find(u => u.email === email);
      if (!user || user.passwordHash !== await hash(String(payload.password || ''))) return json(res, 401, { error: 'Неверная почта или пароль' });
      const newToken = crypto.randomUUID(); sessions.set(newToken, user.id);
      res.setHeader('Set-Cookie', `archsmeta_session=${newToken}; HttpOnly; SameSite=Lax; Path=/`);
      return json(res, 200, { user: userView(user) });
    }
    if (!userId) return json(res, 401, { error: 'Требуется вход' });
    if (url.pathname === '/api/state' && req.method === 'GET') return json(res, 200, { state: data.state });
    if (url.pathname === '/api/state' && req.method === 'PUT') { data.state = payload.state; writeDb(data); return json(res, 200, { ok: true }); }
    return json(res, 404, { error: 'Не найдено' });
  }
  const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  const full = path.resolve(root, file);
  if (!full.startsWith(root) || !fs.existsSync(full)) { res.writeHead(404); return res.end('Not found'); }
  const types = { '.html':'text/html; charset=utf-8', '.js':'application/javascript; charset=utf-8', '.css':'text/css; charset=utf-8' };
  res.writeHead(200, { 'Content-Type': types[path.extname(full)] || 'application/octet-stream' });
  fs.createReadStream(full).pipe(res);
}).listen(3000, '0.0.0.0', () => console.log('Archsmeta: http://0.0.0.0:3000'));
