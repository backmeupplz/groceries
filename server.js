import { createServer } from 'node:http'
import { DatabaseSync } from 'node:sqlite'
import { scrypt, randomBytes, timingSafeEqual, createHash } from 'node:crypto'
import { promisify } from 'node:util'
import { readFileSync } from 'node:fs'
import { gzipSync, createGzip } from 'node:zlib'

const db = new DatabaseSync(process.env.DB || 'groceries.db')
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, hash TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user TEXT);
DELETE FROM sessions WHERE length(token) != 64; -- pre-hashing plaintext tokens
CREATE TABLE IF NOT EXISTS lists(id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE);
INSERT INTO lists(name) SELECT 'Grocery' WHERE NOT EXISTS (SELECT 1 FROM lists);`)
const q = sql => db.prepare(sql)

// "eggs x2" / "eggs 2x" / "eggs ×2" -> ["eggs", "x2"]: the quantity isn't part of the name (history, suggestions).
// Same regex lives in index.html.
const parse = s => { const m = /^(.+?)\s+(?:[x×*]\s*(\d+)|(\d+)\s*[x×*])$/i.exec(s); return m ? [m[1], 'x' + (m[2] || m[3])] : [s, ''] }
// Items are keyed by JS-lowercased name: SQLite NOCASE only folds ASCII, so "Молоко"/"молоко" would split.
const key = s => s.toLowerCase()
// Migrate older schemas (v1: single list; v2: name-keyed, quantity inside the name) to the current one.
const cols = q("SELECT name FROM pragma_table_info('items')").all().map(r => r.name)
if (!cols.includes('k')) {
  const old = cols.length ? q(`SELECT ${cols.includes('list') ? 'list' : '(SELECT MIN(id) FROM lists) list'}, name, done, rev FROM items ORDER BY rev`).all() : []
  db.exec(`BEGIN; DROP TABLE IF EXISTS items;
CREATE TABLE items(list INT, k TEXT, name TEXT, done INT, qty TEXT, rev INT, PRIMARY KEY(list, k));
CREATE INDEX items_rev ON items(rev);`)
  const ins = q('INSERT INTO items VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET name = excluded.name, done = excluded.done, qty = excluded.qty, rev = excluded.rev')
  for (const r of old) { const [name, qty] = parse(r.name); ins.run(r.list, key(name), name, r.done, r.done ? '' : qty, r.rev) }
  db.exec('COMMIT')
}
const userCount = q('SELECT COUNT(*) n FROM users')
const addUser = q('INSERT OR IGNORE INTO users VALUES(?, ?)')
const getUser = q('SELECT hash FROM users WHERE name = ?')
const addSession = q('INSERT INTO sessions VALUES(?, ?)')
const getSession = q('SELECT user FROM sessions WHERE token = ?')
const delSession = q('DELETE FROM sessions WHERE token = ?')
const listUsers = q('SELECT name FROM users ORDER BY name')
const delUser = q('DELETE FROM users WHERE name = ?')
const delSessions = q('DELETE FROM sessions WHERE user = ?')
const allLists = q('SELECT id, name FROM lists ORDER BY id')
const getList = q('SELECT 1 FROM lists WHERE id = ?')
const addList = q('INSERT OR IGNORE INTO lists(name) VALUES(?)')
const delList = q('DELETE FROM lists WHERE id = ?')
const delItems = q('DELETE FROM items WHERE list = ?')
// done: 0 = on the list, 1 = ticked (history), -1 = deleted (kept as a tombstone so cached clients drop it)
const put = q(`INSERT INTO items VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT DO UPDATE
  SET name = excluded.name, done = excluded.done, qty = excluded.qty, rev = excluded.rev RETURNING list, name, done, qty`)
// Ticking keeps the quantity; adding/re-adding sets it (re-add from history = no quantity). A deleted item re-added takes the new spelling.
const upsert = q(`INSERT INTO items VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET
  name = CASE WHEN done < 0 THEN excluded.name ELSE name END, done = excluded.done,
  qty = CASE WHEN excluded.done = 1 THEN qty ELSE excluded.qty END, rev = excluded.rev RETURNING list, name, done, qty`)
const getItem = q('SELECT name, done, qty FROM items WHERE list = ? AND k = ? AND done >= 0')
const rename = q('UPDATE items SET name = ?, qty = ?, rev = ? WHERE list = ? AND k = ? RETURNING list, name, done, qty')
const tomb = q('UPDATE items SET done = -1, rev = ? WHERE list = ? AND k = ? AND done >= 0 RETURNING list, name, done, qty')
const changes = q('SELECT list, name, done, qty FROM items WHERE rev > ? ORDER BY rev')
const snapshot = q('SELECT list, name, done, qty FROM items WHERE done >= 0 ORDER BY rev')
let rev = q('SELECT IFNULL(MAX(rev), 0) r FROM items').get().r
// Timestamp-based so rev never goes backwards across restarts, even after a list delete drops the newest rows.
const nextRev = () => rev = Math.max(rev + 1, Date.now())

// Async scrypt runs on the threadpool, so login attempts can't freeze the event loop.
const scryptAsync = promisify(scrypt)
const hash = async (p, salt = randomBytes(16).toString('hex')) => salt + ':' + (await scryptAsync(p, salt, 32)).toString('hex')
const verify = async (p, h) => timingSafeEqual(Buffer.from(await hash(p, h.split(':')[0])), Buffer.from(h))
const DUMMY = await hash(randomBytes(16).toString('hex')) // unknown users cost the same as known ones (no enumeration)
const sha = s => createHash('sha256').update(s).digest('hex') // sessions are stored hashed
const str = (s, max) => typeof s == 'string' && (s = s.trim()) && s.length <= max ? s : null
const okPassword = p => typeof p == 'string' && p.length >= 8 && p.length <= 200

// The first user comes from env; there is no open "first visitor becomes admin" setup.
if (!userCount.get().n) {
  const u = str(process.env.ADMIN_USER, 50), p = process.env.ADMIN_PASSWORD
  if (!u || !okPassword(p)) { console.error('No users yet: start with ADMIN_USER and ADMIN_PASSWORD (8+ chars) set'); process.exit(1) }
  addUser.run(u, await hash(p))
}

// Failed-login backoff per username: after 5 misses, wait 1s, 2s, 4s... up to 15 min.
// ponytail: in-memory, resets on restart; cleared wholesale if an attacker sprays >10k usernames.
const fails = new Map
const locked = u => { const f = fails.get(u); return f && f.n >= 5 && Date.now() < f.until }
const fail = u => {
  if (fails.size > 1e4) fails.clear()
  const f = fails.get(u) || { n: 0 }
  f.n++; f.until = Date.now() + 1000 * Math.min(2 ** Math.max(f.n - 5, 0), 900)
  fails.set(u, f)
}

const html = readFileSync(new URL('index.html', import.meta.url), 'utf8')
const scriptHash = createHash('sha256').update(/<script>([\s\S]*?)<\/script>/.exec(html)[1]).digest('base64')
const pageHeaders = {
  'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY',
  'content-security-policy': `default-src 'self'; img-src 'self' data:; script-src 'sha256-${scriptHash}'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
}
const clients = new Set()
// Every event carries the full (tiny) lists array, so list adds/deletes need no extra sync.
const event = (rows, full) => `id: ${rev}\ndata: ${JSON.stringify([rows.map(r => [r.list, r.name, r.done, r.qty]), full, allLists.all().map(l => [l.id, l.name])])}\n\n`
const broadcast = rows => clients.forEach(c => c.send(event(rows)))
setInterval(() => clients.forEach(c => c.send(':\n\n')), 25000)

const body = req => new Promise((ok, fail) => {
  let b = ''
  req.setEncoding('utf8')
  req.on('data', c => { if ((b += c).length > 1e4) { req.destroy(); fail(new Error('body too large')) } })
  req.on('end', () => ok(b)).on('error', fail)
})
// JSON API takes only application/json: a cross-origin page can't send that without a CORS preflight we never answer.
const json = async req => {
  if (!/^application\/json\b/.test(req.headers['content-type'])) return []
  try { const v = JSON.parse(await body(req)); return Array.isArray(v) ? v : [] } catch { return [] }
}

const handle = async (req, res) => {
  const url = new URL(req.url, 'http://x')
  const gzip = /gzip/.test(req.headers['accept-encoding'])
  // Behind an HTTPS proxy (e.g. Cloudflare) use a Secure, host-locked cookie.
  const secure = req.headers['x-forwarded-proto'] == 'https'
  const cookie = secure ? '__Host-groceries' : 'groceries'
  const token = new RegExp(`(?:^|; )${cookie}=(\\w+)`).exec(req.headers.cookie)?.[1]
  const sid = token && sha(token)
  const user = sid && getSession.get(sid)?.user
  const end = (code, headers = {}, b) => res.writeHead(code, { 'x-content-type-options': 'nosniff', ...headers }).end(b)
  const setCookie = (v, age) => `${cookie}=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${secure ? '; Secure' : ''}`

  if (req.method == 'GET' && url.pathname == '/health') return end(200, {}, 'ok')

  // CSRF: other apps on the same host (other ports) or sibling subdomains are "same-site", so SameSite=Lax isn't enough.
  // Browsers always send Sec-Fetch-Site (or at least Origin) on POST; non-browser clients send neither and aren't CSRF vectors.
  if (req.method == 'POST') {
    const site = req.headers['sec-fetch-site'], origin = req.headers.origin
    if (site ? site != 'same-origin' : origin && origin != 'null' && new URL(origin).host != req.headers.host) return end(403)
  }

  if (req.method == 'GET' && url.pathname == '/') {
    const page = html.replace('<body>', `<body class="${user ? 'app' : 'login'}${url.search == '?bad' ? ' bad' : ''}">`)
    return end(200, { ...pageHeaders, ...gzip && { 'content-encoding': 'gzip' } }, gzip ? gzipSync(page) : page)
  }

  if (req.method == 'POST' && url.pathname == '/login') {
    const f = new URLSearchParams(await body(req))
    const u = str(f.get('u'), 50), p = f.get('p') || ''
    if (!u || locked(u)) return end(303, { location: '/?bad' })
    const h = getUser.get(u)?.hash
    if (!(await verify(p, h || DUMMY)) || !h) { fail(u); return end(303, { location: '/?bad' }) }
    fails.delete(u)
    const t = randomBytes(24).toString('hex')
    addSession.run(sha(t), u)
    return end(303, { location: '/', 'set-cookie': setCookie(t, 31536000) })
  }

  if (!user) return end(401)

  if (req.method == 'POST' && url.pathname == '/logout') {
    delSession.run(sid)
    clients.forEach(c => c.sid == sid && c.end())
    return end(303, { location: '/', 'set-cookie': setCookie('', 0) })
  }

  if (url.pathname == '/events') {
    let since = +(req.headers['last-event-id'] ?? url.searchParams.get('since')) || 0
    if (since > rev) since = 0 // DB was reset, client cache is stale
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', ...gzip && { 'content-encoding': 'gzip' } })
    const out = gzip ? createGzip() : res
    if (gzip) out.pipe(res)
    const send = s => { out.write(s); gzip && out.flush() }
    send('retry: 2000\n' + event(since ? changes.all(since) : snapshot.all(), !since))
    const c = { user, sid, send, end: () => res.end() }
    clients.add(c)
    return req.on('close', () => clients.delete(c))
  }

  if (req.method == 'POST' && url.pathname == '/set') {
    const [list, text, done] = await json(req)
    const [name, qty] = parse(str(text, 200) || '')
    if (!name) return end(400)
    if (!Number.isInteger(list) || !getList.get(list)) return end(404)
    broadcast([upsert.get(list, key(name), name, done ? 1 : 0, qty, nextRev())])
    return end(204)
  }

  // Rename and/or change quantity. Renaming onto another existing item merges into it.
  if (req.method == 'POST' && url.pathname == '/edit') {
    const [list, old, text] = await json(req)
    const [name, qty] = parse(str(text, 200) || '')
    if (!name || typeof old != 'string' || !Number.isInteger(list)) return end(400)
    const it = getItem.get(list, key(old))
    if (!it) return end(404)
    if (key(name) == key(old)) broadcast([rename.get(name, qty, nextRev(), list, key(old))])
    else broadcast([tomb.get(nextRev(), list, key(old)), put.get(list, key(name), name, it.done, qty, nextRev())])
    return end(204)
  }

  if (req.method == 'POST' && url.pathname == '/delete') {
    const [list, name] = await json(req)
    if (!Number.isInteger(list) || typeof name != 'string') return end(400)
    const row = tomb.get(nextRev(), list, key(name))
    if (row) broadcast([row])
    return end(204)
  }

  if (req.method == 'POST' && url.pathname == '/lists') {
    const name = str((await json(req))[0], 50)
    if (!name) return end(400)
    const r = addList.run(name)
    if (!r.changes) return end(409)
    broadcast([])
    return end(200, {}, String(r.lastInsertRowid))
  }

  if (req.method == 'POST' && url.pathname == '/lists/delete') {
    const [id] = await json(req)
    if (!Number.isInteger(id) || allLists.all().length < 2) return end(400) // always keep one list
    delItems.run(id)
    delList.run(id)
    broadcast([])
    return end(204)
  }

  if (req.method == 'GET' && url.pathname == '/users')
    return end(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }, JSON.stringify([user, listUsers.all().map(r => r.name)]))

  if (req.method == 'POST' && url.pathname == '/users/delete') {
    const [name] = await json(req)
    if (typeof name != 'string' || name == user) return end(400) // can't delete yourself, so someone always remains
    delUser.run(name)
    delSessions.run(name)
    clients.forEach(c => c.user == name && c.end()) // kicks their live stream -> 401 -> login page
    return end(204)
  }

  if (req.method == 'POST' && url.pathname == '/users') {
    const [n, p] = await json(req)
    const name = str(n, 50)
    if (!name || !okPassword(p)) return end(400)
    return end(addUser.run(name, await hash(p)).changes ? 204 : 409)
  }

  end(404)
}

// One bad request (malformed URL, aborted upload, ...) must never take the process down.
createServer((req, res) => handle(req, res).catch(e => {
  console.error(e.message)
  res.headersSent ? res.destroy() : res.writeHead(400).end()
})).listen(process.env.PORT || 3000, () => console.log(`http://localhost:${process.env.PORT || 3000}`))
