// 잿빛 균열 — 게임 서버
// 계정 · 클라우드 저장 · 랭킹 · 경매장(REST) + 마을/파티/협동 던전(WebSocket)
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { WebSocketServer } = require('ws');

const PORT = +process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'game.db');
const PUBLIC = path.join(__dirname, 'public');
const MAX_BODY = 512 * 1024;
const AUCTION_HOURS = 48;
const AUCTION_FEE = 0.05;

/* ───────────── DB (SQLite 파일 또는 DATABASE_URL 이 있으면 PostgreSQL) ───────────── */
let DB, DB_TARGET = '', DB_STATE = 'connecting', DB_ERROR = '';
function errText(e) { if (!e) return '?'; const parts = [e.code, e.message].filter(Boolean); if (e.errors) for (const x of e.errors) parts.push(`[${x.code || ''} ${x.address || ''}:${x.port || ''} ${x.message || ''}]`); return parts.join(' ') || String(e); }
const SCHEMA_SQLITE = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, pw TEXT, created INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS users_name ON users(lower(name));
CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, uid INTEGER, created INTEGER, last INTEGER);
CREATE TABLE IF NOT EXISTS saves(uid INTEGER PRIMARY KEY, data TEXT, rev INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS records(board TEXT, uid INTEGER, value REAL, extra TEXT, updated INTEGER, PRIMARY KEY(board,uid));
CREATE INDEX IF NOT EXISTS rec_board ON records(board, value);
CREATE TABLE IF NOT EXISTS auctions(id INTEGER PRIMARY KEY, seller INTEGER, item TEXT, iuid TEXT, price INTEGER, slot TEXT, rar INTEGER, name TEXT, lv INTEGER, created INTEGER, status TEXT, buyer INTEGER);
CREATE INDEX IF NOT EXISTS auc_open ON auctions(status, created);
CREATE TABLE IF NOT EXISTS mail(id INTEGER PRIMARY KEY, uid INTEGER, gold INTEGER, item TEXT, note TEXT, created INTEGER, claimed INTEGER DEFAULT 0);`;
const SCHEMA_PG = `
CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, pw TEXT, created BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS users_name ON users(lower(name));
CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, uid BIGINT, created BIGINT, last BIGINT);
CREATE TABLE IF NOT EXISTS saves(uid BIGINT PRIMARY KEY, data TEXT, rev INTEGER, updated BIGINT);
CREATE TABLE IF NOT EXISTS records(board TEXT, uid BIGINT, value DOUBLE PRECISION, extra TEXT, updated BIGINT, PRIMARY KEY(board,uid));
CREATE INDEX IF NOT EXISTS rec_board ON records(board, value);
CREATE TABLE IF NOT EXISTS auctions(id BIGSERIAL PRIMARY KEY, seller BIGINT, item TEXT, iuid TEXT, price BIGINT, slot TEXT, rar INTEGER, name TEXT, lv INTEGER, created BIGINT, status TEXT, buyer BIGINT);
CREATE INDEX IF NOT EXISTS auc_open ON auctions(status, created);
CREATE TABLE IF NOT EXISTS mail(id BIGSERIAL PRIMARY KEY, uid BIGINT, gold BIGINT, item TEXT, note TEXT, created BIGINT, claimed INTEGER DEFAULT 0);`;
async function openDB() {
  if (process.env.DATABASE_URL) {
    const { Pool, types } = require('pg');
    types.setTypeParser(20, v => Number(v)); types.setTypeParser(1700, v => Number(v));
    // 복사할 때 섞여 들어간 psql '...', DATABASE_URL=, 따옴표, 줄바꿈/공백을 정리해요
    let url = process.env.DATABASE_URL.trim().replace(/^DATABASE_URL\s*=\s*/i, '').replace(/^psql\s+/, '').replace(/^['"]|['"]$/g, '').replace(/\s+/g, '');
    try { const u = new URL(url); u.searchParams.delete('channel_binding'); u.searchParams.delete('sslmode'); url = u.toString(); } catch {}
    const local = /@(localhost|127\.0\.0\.1)[:/]/.test(url);
    try { const u = new URL(url); DB_TARGET = `${u.protocol}//${u.username || '?'}:${u.password ? '(비밀번호 있음)' : '(비밀번호 없음!)'}@${u.hostname}:${u.port || 5432}${u.pathname}`; }
    catch { DB_TARGET = '(주소 형식이 올바르지 않아요: postgresql:// 로 시작해야 해요)'; }
    console.log('DB 접속 대상:', DB_TARGET);
    const pool = new Pool({ connectionString: url, ssl: local ? false : { rejectUnauthorized: false }, max: 5, connectionTimeoutMillis: 15000 });
    pool.on('error', e => console.error('DB 연결 오류:', errText(e)));
    const conv = sql => { let i = 0; return sql.replace(/\?/g, () => '$' + (++i)); };
    DB = {
      kind: 'PostgreSQL',
      get: async (sql, a) => (await pool.query(conv(sql), a)).rows[0],
      all: async (sql, a) => (await pool.query(conv(sql), a)).rows,
      run: async (sql, a) => { let t = conv(sql); const ins = /^\s*INSERT INTO (users|auctions|mail)\b/i.test(t); if (ins) t += ' RETURNING id'; const r = await pool.query(t, a); return { changes: r.rowCount, lastInsertRowid: ins && r.rows[0] ? r.rows[0].id : 0 }; },
    };
    await pool.query(SCHEMA_PG);
  } else {
    process.removeAllListeners('warning');
    const { DatabaseSync } = require('node:sqlite');
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    const db = new DatabaseSync(DB_PATH);
    db.exec(SCHEMA_SQLITE);
    DB = {
      kind: 'SQLite (' + DB_PATH + ')',
      get: async (sql, a) => db.prepare(sql).get(...a),
      all: async (sql, a) => db.prepare(sql).all(...a),
      run: async (sql, a) => { const r = db.prepare(sql).run(...a); return { changes: r.changes, lastInsertRowid: Number(r.lastInsertRowid) }; },
    };
  }
}
const q = sql => ({ get: (...a) => DB.get(sql, a), all: (...a) => DB.all(sql, a), run: (...a) => DB.run(sql, a) });
const now = () => Date.now();

/* ───────────── auth helpers ───────────── */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function hashPw(pw) { const salt = crypto.randomBytes(16).toString('hex'); return salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex'); }
function checkPw(pw, stored) { const [salt, h] = String(stored).split(':'); if (!salt || !h) return false; const a = crypto.scryptSync(pw, salt, 32), b = Buffer.from(h, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); }
async function newSession(uid) { const token = crypto.randomBytes(32).toString('base64url'); await q('INSERT INTO sessions VALUES(?,?,?,?)').run(sha(token), uid, now(), now()); return token; }
async function userFromToken(token) {
  if (!token || typeof token !== 'string') return null;
  const s = await q('SELECT uid FROM sessions WHERE th=?').get(sha(token)); if (!s) return null;
  await q('UPDATE sessions SET last=? WHERE th=?').run(now(), sha(token));
  return await q('SELECT id,name FROM users WHERE id=?').get(s.uid) || null;
}
const NAME_RE = /^[0-9A-Za-z가-힣_]{2,12}$/;

/* 간단한 IP별 속도 제한 */
const buckets = new Map();
function limited(key, perMin) {
  const t = now(); let b = buckets.get(key);
  if (!b || t - b.t > 60000) { b = { t, n: 0 }; buckets.set(key, b); }
  return ++b.n > perMin;
}
setInterval(() => { const t = now(); for (const [k, b] of buckets) if (t - b.t > 120000) buckets.delete(k); }, 60000).unref();

/* ───────────── records / boards ───────────── */
// time:<dungeonId>:<diffIndex> (낮을수록 좋음, 초) · tower (층, 높을수록) · level (레벨*1e9+누적경험, 높을수록)
const DUNGEON_IDS = ['ash', 'frost', 'void', 'raid', 'dune', 'sun'];
function boardSpec(board) {
  if (board === 'tower') return { asc: false, min: 1, max: 2000 };
  if (board === 'level') return { asc: false, min: 1, max: 1e12 };
  const m = /^time:([a-z]+):([0-3])$/.exec(board || '');
  if (m && DUNGEON_IDS.includes(m[1])) return { asc: true, min: 15, max: 3600 };
  return null;
}

/* ───────────── auction helpers ───────────── */
async function expireAuctions() {
  const cut = now() - AUCTION_HOURS * 3600e3;
  const rows = await q("SELECT * FROM auctions WHERE status='open' AND created<?").all(cut);
  for (const a of rows) {
    await q("UPDATE auctions SET status='expired' WHERE id=?").run(a.id);
    await q('INSERT INTO mail(uid,gold,item,note,created) VALUES(?,?,?,?,?)').run(a.seller, 0, a.item, `경매 기간 만료 · ${a.name}`, now());
  }
}
setInterval(() => expireAuctions().catch(e => console.error(e)), 5 * 60e3).unref();
function sanitizeItem(it) {
  if (!it || typeof it !== 'object' || Array.isArray(it)) return null;
  const s = JSON.stringify(it); if (s.length > 4000) return null;
  if (typeof it.name !== 'string' || typeof it.slot !== 'string' || typeof it.uid === 'undefined') return null;
  return JSON.parse(s);
}

/* ───────────── HTTP ───────────── */
// 넷리파이 등 다른 주소에서 게임을 열 때를 위한 CORS (ALLOWED_ORIGINS 로 제한 가능, 비우면 모두 허용)
const ALLOWED = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);
function corsFor(origin) { if (!ALLOWED.length) return '*'; return ALLOWED.includes(origin) ? origin : ALLOWED[0]; }
function send(res, code, obj) { const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': res.cors || '*', 'Vary': 'Origin' }); res.end(b); }
function readBody(req) {
  return new Promise((ok, bad) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { bad(new Error('too big')); req.destroy(); } else ch.push(c); });
    req.on('end', () => { try { ok(ch.length ? JSON.parse(Buffer.concat(ch).toString('utf8')) : {}); } catch (e) { bad(e); } });
    req.on('error', bad);
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.mp3': 'audio/mpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json' };
function serveStatic(req, res, p) {
  let rel = decodeURIComponent(p.split('?')[0]); if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('not found'); }
    const ext = path.extname(file);
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400' };
    // mp3 탐색(Range) 지원
    const range = req.headers.range;
    if (range && ext === '.mp3') {
      const m = /bytes=(\d*)-(\d*)/.exec(range); const start = m[1] ? +m[1] : 0, end = m[2] ? +m[2] : st.size - 1;
      res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${st.size}`, 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1 });
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
    res.writeHead(200, { ...headers, 'Content-Length': st.size, 'Accept-Ranges': 'bytes' });
    fs.createReadStream(file).pipe(res);
  });
}

const routes = {};
const route = (m, p, fn, auth = true) => { routes[m + ' ' + p] = { fn, auth }; };

route('GET', '/api/ping', async () => ({ ok: DB_STATE === 'ready', name: '잿빛 균열', online: online.size, db: DB_STATE, dbError: DB_ERROR || undefined }), false);

route('POST', '/api/register', async (b, u, req) => {
  if (limited('reg:' + req.ip, 8)) throw [429, '잠시 후 다시 시도해 주세요'];
  const name = String(b.name || '').trim(), pw = String(b.pw || '');
  if (!NAME_RE.test(name)) throw [400, '아이디는 한글·영문·숫자 2~12자예요'];
  if (pw.length < 4 || pw.length > 64) throw [400, '비밀번호는 4자 이상이에요'];
  if (await q('SELECT id FROM users WHERE lower(name)=lower(?)').get(name)) throw [409, '이미 있는 아이디예요'];
  const r = await q('INSERT INTO users(name,pw,created) VALUES(?,?,?)').run(name, hashPw(pw), now());
  return { token: await newSession(Number(r.lastInsertRowid)), name };
}, false);

route('POST', '/api/login', async (b, u, req) => {
  if (limited('login:' + req.ip, 20)) throw [429, '잠시 후 다시 시도해 주세요'];
  const row = await q('SELECT * FROM users WHERE lower(name)=lower(?)').get(String(b.name || '').trim());
  if (!row || !checkPw(String(b.pw || ''), row.pw)) throw [401, '아이디 또는 비밀번호가 달라요'];
  return { token: await newSession(row.id), name: row.name };
}, false);

route('POST', '/api/logout', async (b, u, req) => { await q('DELETE FROM sessions WHERE th=?').run(sha(req.token)); return { ok: true }; });

route('GET', '/api/me', async (b, u) => {
  const s = await q('SELECT rev,updated FROM saves WHERE uid=?').get(u.id);
  const mail = (await q('SELECT COUNT(*) n FROM mail WHERE uid=? AND claimed=0').get(u.id)).n;
  return { name: u.name, hasSave: !!s, rev: s ? s.rev : 0, updated: s ? s.updated : 0, mail };
});

route('GET', '/api/save', async (b, u) => {
  const s = await q('SELECT * FROM saves WHERE uid=?').get(u.id);
  return s ? { data: JSON.parse(s.data), rev: s.rev, updated: s.updated } : { data: null, rev: 0 };
});

route('PUT', '/api/save', async (b, u) => {
  if (!b.data || typeof b.data !== 'object') throw [400, '저장 데이터가 없어요'];
  const txt = JSON.stringify(b.data); if (txt.length > 400000) throw [413, '저장 데이터가 너무 커요'];
  const cur = await q('SELECT rev FROM saves WHERE uid=?').get(u.id);
  const curRev = cur ? cur.rev : 0;
  if (!b.force && (b.rev | 0) !== curRev) throw [409, '다른 기기에서 먼저 저장했어요', { rev: curRev }];
  const rev = curRev + 1;
  await q('INSERT INTO saves(uid,data,rev,updated) VALUES(?,?,?,?) ON CONFLICT(uid) DO UPDATE SET data=excluded.data,rev=excluded.rev,updated=excluded.updated').run(u.id, txt, rev, now());
  // 레벨 랭킹은 저장 때 자동 갱신
  // 캐릭터별 저장(chars) 중 가장 높은 캐릭터로 레벨 랭킹 갱신
  let top = { cls: b.data.cls, lv: +b.data.lv | 0, exp: +b.data.exp || 0 };
  for (const [cls, c] of Object.entries(b.data.chars || {})) { const lv = +(c && c.lv) | 0, exp = +(c && c.exp) || 0; if (lv > top.lv || (lv === top.lv && exp > top.exp)) top = { cls, lv, exp }; }
  if (top.lv > 0 && top.lv < 200) await upsertRecord('level', u.id, top.lv * 1e9 + Math.min(top.exp, 1e9 - 1), { cls: top.cls, lv: top.lv });
  return { rev };
});

async function upsertRecord(board, uid, value, extra) {
  const spec = boardSpec(board); const old = await q('SELECT value FROM records WHERE board=? AND uid=?').get(board, uid);
  const better = !old || (spec.asc ? value < old.value : value > old.value);
  if (better) await q('INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(board,uid) DO UPDATE SET value=excluded.value,extra=excluded.extra,updated=excluded.updated').run(board, uid, value, JSON.stringify(extra || {}), now());
  return better;
}
async function rankOf(board, uid) {
  const spec = boardSpec(board); const me = await q('SELECT value FROM records WHERE board=? AND uid=?').get(board, uid);
  if (!me) return null;
  const n = (await q(`SELECT COUNT(*) n FROM records WHERE board=? AND value ${spec.asc ? '<' : '>'} ?`).get(board, me.value)).n;
  return { rank: n + 1, value: me.value };
}

route('POST', '/api/record', async (b, u, req) => {
  if (limited('rec:' + u.id, 30)) throw [429, '너무 자주 보냈어요'];
  const spec = boardSpec(b.board); if (!spec || b.board === 'level') throw [400, '알 수 없는 랭킹이에요'];
  const v = +b.value; if (!isFinite(v) || v < spec.min || v > spec.max) throw [400, '기록 값이 올바르지 않아요'];
  const extra = { cls: String((b.extra || {}).cls || '').slice(0, 16), lv: +(b.extra || {}).lv | 0, grade: String((b.extra || {}).grade || '').slice(0, 2), adv: String((b.extra || {}).adv || '').slice(0, 16) };
  const best = await upsertRecord(b.board, u.id, v, extra);
  return { best, ...(await rankOf(b.board, u.id)) };
});

route('GET', '/api/rank', async (b, u, req) => {
  const board = req.query.get('board'); const spec = boardSpec(board); if (!spec) throw [400, '알 수 없는 랭킹이에요'];
  const rows = await q(`SELECT r.value, r.extra, u.name FROM records r JOIN users u ON u.id=r.uid WHERE r.board=? ORDER BY r.value ${spec.asc ? 'ASC' : 'DESC'}, r.updated ASC LIMIT 50`).all(board);
  return { board, top: rows.map(r => ({ name: r.name, value: r.value, ...JSON.parse(r.extra || '{}') })), me: await rankOf(board, u.id) };
});

route('GET', '/api/auction', async (b, u, req) => {
  await expireAuctions();
  const slot = req.query.get('slot'), sort = req.query.get('sort') || 'new', page = Math.max(0, +req.query.get('page') | 0);
  const qs = String(req.query.get('q') || '').slice(0, 20);
  let where = "a.status='open'", args = [];
  if (slot && slot !== 'all') { where += ' AND a.slot=?'; args.push(slot); }
  if (qs) { where += ' AND a.name LIKE ?'; args.push('%' + qs.replace(/[%_]/g, '') + '%'); }
  const order = sort === 'cheap' ? 'a.price ASC' : sort === 'rar' ? 'a.rar DESC, a.price ASC' : 'a.created DESC';
  const rows = await q(`SELECT a.id,a.item,a.price,a.created,a.seller,u.name seller_name FROM auctions a JOIN users u ON u.id=a.seller WHERE ${where} ORDER BY ${order} LIMIT 30 OFFSET ?`).all(...args, page * 30);
  const total = (await q(`SELECT COUNT(*) n FROM auctions a WHERE ${where}`).get(...args)).n;
  return { total, page, list: rows.map(r => ({ id: r.id, item: JSON.parse(r.item), price: r.price, created: r.created, seller: r.seller_name, mine: r.seller === u.id, left: r.created + AUCTION_HOURS * 3600e3 - now() })) };
});

route('GET', '/api/auction/mine', async (b, u) => {
  const rows = await q("SELECT id,item,price,created,status FROM auctions WHERE seller=? AND status='open' ORDER BY created DESC").all(u.id);
  return { list: rows.map(r => ({ id: r.id, item: JSON.parse(r.item), price: r.price, created: r.created, left: r.created + AUCTION_HOURS * 3600e3 - now() })) };
});

route('POST', '/api/auction/list', async (b, u) => {
  if (limited('auc:' + u.id, 20)) throw [429, '너무 자주 올렸어요'];
  const it = sanitizeItem(b.item); if (!it) throw [400, '올릴 수 없는 아이템이에요'];
  const price = Math.floor(+b.price); if (!(price >= 10 && price <= 99999999)) throw [400, '가격은 10 ~ 99,999,999 골드예요'];
  const open = (await q("SELECT COUNT(*) n FROM auctions WHERE seller=? AND status='open'").get(u.id)).n; if (open >= 10) throw [400, '한 번에 10개까지 올릴 수 있어요'];
  if (await q("SELECT id FROM auctions WHERE iuid=? AND status='open'").get(String(it.uid))) throw [409, '이미 올라가 있는 아이템이에요'];
  const r = await q("INSERT INTO auctions(seller,item,iuid,price,slot,rar,name,lv,created,status) VALUES(?,?,?,?,?,?,?,?,?,'open')")
    .run(u.id, JSON.stringify(it), String(it.uid), price, it.slot, +it.rar | 0, it.name.slice(0, 40), +it.ilvl | 0, now());
  broadcastAll({ t: 'sys', text: `경매장에 새 물건 · ${it.name}` }, u.id, 'town');
  return { id: Number(r.lastInsertRowid) };
});

route('POST', '/api/auction/buy', async (b, u) => {
  await expireAuctions();
  const a = await q('SELECT * FROM auctions WHERE id=?').get(+b.id | 0);
  if (!a || a.status !== 'open') throw [404, '이미 팔렸거나 내려간 물건이에요'];
  if (a.seller === u.id) throw [400, '내 물건은 살 수 없어요'];
  if (typeof b.gold === 'number' && b.gold < a.price) throw [400, '골드가 부족해요'];
  const r = await q("UPDATE auctions SET status='sold',buyer=? WHERE id=? AND status='open'").run(u.id, a.id);
  if (!r.changes) throw [409, '한발 늦었어요'];
  const earn = Math.floor(a.price * (1 - AUCTION_FEE));
  await q('INSERT INTO mail(uid,gold,item,note,created) VALUES(?,?,?,?,?)').run(a.seller, earn, null, `판매 완료 · ${a.name} (${a.price.toLocaleString()} G, 수수료 5%)`, now());
  notify(a.seller, { t: 'mail', text: `${a.name}이(가) 팔렸어요! 우편함을 확인하세요.` });
  return { item: JSON.parse(a.item), price: a.price };
});

route('POST', '/api/auction/cancel', async (b, u) => {
  const a = await q('SELECT * FROM auctions WHERE id=? AND seller=?').get(+b.id | 0, u.id);
  if (!a || a.status !== 'open') throw [404, '취소할 수 없는 물건이에요'];
  const r = await q("UPDATE auctions SET status='cancel' WHERE id=? AND status='open'").run(a.id);
  if (!r.changes) throw [409, '이미 팔렸어요'];
  return { item: JSON.parse(a.item) };
});

route('GET', '/api/mail', async (b, u) => {
  const rows = await q('SELECT id,gold,item,note,created FROM mail WHERE uid=? AND claimed=0 ORDER BY created DESC LIMIT 50').all(u.id);
  return { list: rows.map(r => ({ ...r, item: r.item ? JSON.parse(r.item) : null })) };
});

route('POST', '/api/mail/claim', async (b, u) => {
  const rows = b.id === 'all' ? await q('SELECT * FROM mail WHERE uid=? AND claimed=0').all(u.id) : await q('SELECT * FROM mail WHERE uid=? AND id=? AND claimed=0').all(u.id, +b.id | 0);
  let gold = 0; const items = [];
  const limit = Math.max(0, +b.room | 0); // 인벤토리 빈 칸 수
  for (const m of rows) {
    if (m.item && items.length >= limit) continue;
    const r = await q('UPDATE mail SET claimed=1 WHERE id=? AND claimed=0').run(m.id); if (!r.changes) continue;
    gold += m.gold; if (m.item) items.push(JSON.parse(m.item));
  }
  return { gold, items, left: (await q('SELECT COUNT(*) n FROM mail WHERE uid=? AND claimed=0').get(u.id)).n };
});

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  req.ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  req.query = url.searchParams;
  if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
  res.cors = corsFor(req.headers.origin || '');
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': res.cors, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS', 'Access-Control-Max-Age': '86400', 'Vary': 'Origin' }); return res.end(); }
  const r = routes[req.method + ' ' + url.pathname];
  if (!r) return send(res, 404, { error: '없는 주소예요' });
  if (DB_STATE !== 'ready' && url.pathname !== '/api/ping') return send(res, 503, { error: '서버가 준비 중이에요. 잠시 후 다시 시도해 주세요' });
  try {
    const auth = req.headers.authorization || ''; req.token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const user = await userFromToken(req.token);
    if (r.auth && !user) return send(res, 401, { error: '다시 로그인해 주세요' });
    const body = req.method === 'GET' ? {} : await readBody(req);
    send(res, 200, await r.fn(body, user, req));
  } catch (e) {
    if (Array.isArray(e)) return send(res, e[0], { error: e[1], ...(e[2] || {}) });
    console.error(e); send(res, 500, { error: '서버 오류가 났어요' });
  }
});

/* ───────────── 실시간 (WebSocket) ───────────── */
const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });
const online = new Map();   // uid → client
const parties = new Map();  // pid → { id, leader, members:Set<uid>, run:null|{host,kind,...} }
let pidSeq = 1;

function sendTo(c, msg) { if (c && c.ws.readyState === 1) c.ws.send(typeof msg === 'string' ? msg : JSON.stringify(msg)); }
function notify(uid, msg) { sendTo(online.get(uid), msg); }
function broadcastAll(msg, exceptUid, loc) { const s = JSON.stringify(msg); for (const c of online.values()) if (c.uid !== exceptUid && (!loc || c.loc === loc)) sendTo(c, s); }
function pub(c) { return { uid: c.uid, name: c.name, look: c.look, st: c.st, party: c.party || 0 }; }
function partyInfo(p) {
  if (!p) return null;
  return { id: p.id, leader: p.leader, run: !!p.run, members: [...p.members].map(uid => { const c = online.get(uid); return { uid, name: c ? c.name : '?', cls: c && c.look ? c.look.cls : '', lv: c && c.look ? c.look.lv : 0, loc: c ? c.loc : 'off', look: c ? c.look : null }; }) };
}
function pushParty(p) { const info = partyInfo(p); for (const uid of p.members) notify(uid, { t: 'party', party: info }); }
function leaveParty(c, reason) {
  const p = parties.get(c.party); if (!p) { c.party = 0; return; }
  p.members.delete(c.uid); c.party = 0; notify(c.uid, { t: 'party', party: null });
  if (p.run) {
    if (p.run.host === c.uid) { for (const uid of p.members) notify(uid, { t: 'g', k: 'hostgone' }); p.run = null; }
    else notify(p.run.host, { t: 'g', k: 'mategone', from: c.uid });
  }
  if (!p.members.size) { parties.delete(p.id); return; }
  if (p.leader === c.uid) p.leader = [...p.members][0];
  for (const uid of p.members) notify(uid, { t: 'sys', text: `${c.name}님이 파티를 ${reason || '떠났어요'}` });
  pushParty(p);
}
function setLoc(c, loc) {
  if (c.loc === loc) return;
  const was = c.loc; c.loc = loc;
  if (was === 'town') broadcastAll({ t: 'pl', uid: c.uid }, c.uid, 'town');
  if (loc === 'town') {
    broadcastAll({ t: 'pj', p: pub(c) }, c.uid, 'town');
    sendTo(c, { t: 'town', players: [...online.values()].filter(o => o !== c && o.loc === 'town').slice(0, 40).map(pub) });
  }
  const p = parties.get(c.party); if (p) pushParty(p);
}
function cleanText(s, n) { return String(s || '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, n); }

wss.on('connection', (ws, req, user) => {
  const old = online.get(user.id); if (old) { sendTo(old, { t: 'kicked', text: '다른 곳에서 접속했어요' }); old.ws.close(); }
  const c = { uid: user.id, name: user.name, ws, loc: 'menu', look: null, st: null, party: 0, alive: true };
  online.set(user.id, c);
  sendTo(c, { t: 'welcome', you: { uid: c.uid, name: c.name }, online: online.size });
  ws.on('pong', () => { c.alive = true; });
  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m.t !== 'string') return;
    const p = parties.get(c.party);
    switch (m.t) {
      case 'hello': {
        const L = m.look || {};
        c.look = { cls: cleanText(L.cls, 12), wear: L.wear && typeof L.wear === 'object' ? L.wear : {}, dye: L.dye && typeof L.dye === 'object' ? L.dye : {}, adv: cleanText(L.adv, 16), title: cleanText(L.title, 30), lv: +L.lv | 0 };
        if (JSON.stringify(c.look).length > 3000) c.look.dye = {};
        if (c.loc === 'town') broadcastAll({ t: 'pj', p: pub(c) }, c.uid, 'town');
        if (p) pushParty(p);
        break;
      }
      case 'loc': setLoc(c, ['town', 'play', 'menu'].includes(m.loc) ? m.loc : 'menu'); break;
      case 'st': {   // 내 캐릭터 상태 (초당 ~12회)
        const st = m.s; if (!st || typeof st !== 'object') return;
        c.st = st; const out = JSON.stringify({ t: 'st', uid: c.uid, s: st });
        if (c.loc === 'town') { for (const o of online.values()) if (o !== c && o.loc === 'town') sendTo(o, out); }
        else if (c.loc === 'play' && p && p.run) { for (const uid of p.members) if (uid !== c.uid) sendTo(online.get(uid), out); }
        break;
      }
      case 'chat': {
        if (limited('chat:' + c.uid, 20)) return sendTo(c, { t: 'sys', text: '채팅을 너무 빨리 보내고 있어요' });
        const text = cleanText(m.text, 120); if (!text) return;
        const msg = { t: 'chat', ch: m.ch === 'party' ? 'party' : 'town', from: c.name, uid: c.uid, text };
        if (msg.ch === 'party') { if (!p) return sendTo(c, { t: 'sys', text: '파티에 들어가 있지 않아요' }); for (const uid of p.members) notify(uid, msg); }
        else broadcastAll(msg, null, null);
        break;
      }
      case 'inv': {  // 파티 초대
        const to = [...online.values()].find(o => o.name.toLowerCase() === String(m.to || '').toLowerCase());
        if (!to || to === c) return sendTo(c, { t: 'sys', text: '접속 중인 사람을 찾지 못했어요' });
        if (to.party) return sendTo(c, { t: 'sys', text: `${to.name}님은 이미 파티 중이에요` });
        if (p && p.members.size >= 4) return sendTo(c, { t: 'sys', text: '파티는 4명까지예요' });
        if (p && p.run) return sendTo(c, { t: 'sys', text: '던전 진행 중에는 초대할 수 없어요' });
        to.invitedBy = c.uid; sendTo(to, { t: 'invite', from: c.name, uid: c.uid });
        sendTo(c, { t: 'sys', text: `${to.name}님에게 파티 초대를 보냈어요` });
        break;
      }
      case 'invAns': {
        const from = online.get(+m.uid); if (!from || c.invitedBy !== from.uid) return; c.invitedBy = 0;
        if (!m.ok) return sendTo(from, { t: 'sys', text: `${c.name}님이 초대를 거절했어요` });
        if (c.party) leaveParty(c);
        let fp = parties.get(from.party);
        if (!fp) { fp = { id: pidSeq++, leader: from.uid, members: new Set([from.uid]), run: null }; parties.set(fp.id, fp); from.party = fp.id; }
        if (fp.members.size >= 4 || fp.run) return sendTo(c, { t: 'sys', text: '파티에 들어갈 수 없어요 (가득 찼거나 진행 중)' });
        fp.members.add(c.uid); c.party = fp.id;
        for (const uid of fp.members) notify(uid, { t: 'sys', text: `${c.name}님이 파티에 들어왔어요` });
        pushParty(fp);
        break;
      }
      case 'leave': if (p) leaveParty(c); break;
      case 'kick': {
        if (!p || p.leader !== c.uid || p.run) return;
        const t = online.get(+m.uid); if (t && t.party === p.id && t !== c) leaveParty(t, '떠났어요 (추방)');
        break;
      }
      case 'run': {  // 파티장이 던전 시작 → 마을에 있는 파티원 모두 합류
        if (!p || p.leader !== c.uid) return;
        if (p.run) return;
        const members = [...p.members].filter(uid => { const o = online.get(uid); return o && (o.loc === 'town' || o === c); });
        if (members.length < 2) return sendTo(c, { t: 'sys', text: '마을에 있는 파티원이 없어요' });
        p.run = { host: c.uid, kind: m.kind === 'raid' ? 'raid' : 'normal', did: cleanText(m.did, 12), di: +m.di | 0, members, started: now() };
        const info = partyInfo(p);
        for (const uid of members) notify(uid, { t: 'run', run: p.run, party: info });
        break;
      }
      case 'g': {    // 협동 던전 데이터 중계 (호스트 → 모두 / 게스트 → 호스트)
        if (!p || !p.run) return;
        if (c.uid === p.run.host) {
          const out = JSON.stringify({ ...m, from: c.uid });
          if (m.to) notify(+m.to, out); else for (const uid of p.run.members) if (uid !== c.uid) sendTo(online.get(uid), out);
        } else notify(p.run.host, { ...m, from: c.uid });
        break;
      }
      case 'runEnd': {
        if (!p || !p.run) return;
        if (c.uid === p.run.host) { for (const uid of p.run.members) if (uid !== c.uid) notify(uid, { t: 'g', k: 'hostend' }); p.run = null; pushParty(p); }
        else { p.run.members = p.run.members.filter(u => u !== c.uid); notify(p.run.host, { t: 'g', k: 'mategone', from: c.uid }); }
        break;
      }
    }
  });
  ws.on('close', () => {
    if (online.get(c.uid) !== c) return;
    if (c.party) leaveParty(c, '떠났어요 (접속 종료)');
    if (c.loc === 'town') broadcastAll({ t: 'pl', uid: c.uid }, c.uid, 'town');
    online.delete(c.uid);
  });
});
setInterval(() => { for (const c of online.values()) { if (!c.alive) { c.ws.terminate(); continue; } c.alive = false; try { c.ws.ping(); } catch {} } }, 30000).unref();

server.on('upgrade', (req, sock, head) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname !== '/ws') return sock.destroy();
  if (ALLOWED.length && req.headers.origin && !ALLOWED.includes(req.headers.origin)) { sock.write('HTTP/1.1 403 Forbidden\r\n\r\n'); return sock.destroy(); }
  userFromToken(url.searchParams.get('token')).then(user => {
    if (!user) { sock.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return sock.destroy(); }
    wss.handleUpgrade(req, sock, head, ws => wss.emit('connection', ws, req, user));
  }).catch(() => sock.destroy());
});

// 포트를 먼저 열고(호스팅의 포트 검사 통과), DB는 뒤에서 연결·재시도해요
server.listen(PORT, () => {
  console.log(`잿빛 균열 서버 실행 중 → http://localhost:${PORT}`);
  const nets = require('node:os').networkInterfaces();
  for (const list of Object.values(nets)) for (const n of list || []) if (n.family === 'IPv4' && !n.internal) console.log(`  같은 와이파이의 폰에서 → http://${n.address}:${PORT}`);
});
(async function connectLoop(n = 1) {
  try { await openDB(); DB_STATE = 'ready'; DB_ERROR = ''; console.log(`저장소 연결 완료 [${DB.kind}]`); }
  catch (e) {
    DB_STATE = 'error'; DB_ERROR = errText(e);
    console.error(`DB 연결 실패 (${n}번째 시도): ${DB_ERROR}`);
    if (DB_TARGET) console.error('  접속 대상:', DB_TARGET, '— Render의 DATABASE_URL 값을 확인해 주세요');
    setTimeout(() => connectLoop(n + 1), Math.min(60000, 5000 * n));
  }
})();
