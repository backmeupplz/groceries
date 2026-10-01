import { createServer } from 'node:http'
import { DatabaseSync } from 'node:sqlite'
import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { gzipSync, createGzip } from 'node:zlib'

const db = new DatabaseSync(process.env.DB || 'groceries.db')
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, hash TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user TEXT);
CREATE TABLE IF NOT EXISTS lists(id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE);
INSERT INTO lists(name) SELECT 'Grocery' WHERE NOT EXISTS (SELECT 1 FROM lists);`)
const q = sql => db.prepare(sql)
// v1 had one list: move its items into the first list
const v1 = q("SELECT 1 FROM pragma_table_info('items') WHERE name = 'name'").get() && !q("SELECT 1 FROM pragma_table_info('items') WHERE name = 'list'").get()
db.exec(`BEGIN;${v1 ? 'ALTER TABLE items RENAME TO items_v1; DROP INDEX items_rev;' : ''}
CREATE TABLE IF NOT EXISTS items(list INT, name TEXT COLLATE NOCASE, done INT, rev INT, PRIMARY KEY(list, name));
CREATE INDEX IF NOT EXISTS items_rev ON items(rev);
${v1 ? 'INSERT INTO items SELECT (SELECT MIN(id) FROM lists), name, done, rev FROM items_v1; DROP TABLE items_v1;' : ''}COMMIT`)
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
const upsert = q('INSERT INTO items VALUES(?, ?, ?, ?) ON CONFLICT DO UPDATE SET done = excluded.done, rev = excluded.rev RETURNING list, name, done')
const changes = q('SELECT list, name, done FROM items WHERE rev > ? ORDER BY rev')
let rev = q('SELECT IFNULL(MAX(rev), 0) r FROM items').get().r

const hash = (p, salt = randomBytes(16).toString('hex')) => salt + ':' + scryptSync(p, salt, 32).toString('hex')
const verify = (p, h) => !!h && timingSafeEqual(Buffer.from(hash(p, h.split(':')[0])), Buffer.from(h))
const str = (s, max) => typeof s == 'string' && (s = s.trim()) && s.length <= max ? s : null

const html = readFileSync(new URL('index.html', import.meta.url), 'utf8')
const clients = new Set()
// Every event carries the full (tiny) lists array, so list adds/deletes need no extra sync.
const event = (rows, full) => `id: ${rev}\ndata: ${JSON.stringify([rows.map(r => [r.list, r.name, r.done]), full, allLists.all().map(l => [l.id, l.name])])}\n\n`
const broadcast = rows => clients.forEach(c => c.send(event(rows)))
setInterval(() => clients.forEach(c => c.send(':\n\n')), 25000)

const body = req => new Promise((ok, fail) => {
  let b = ''
  req.on('data', c => (b += c).length > 1e4 && req.destroy())
  req.on('end', () => ok(b)).on('error', fail)
})
const json = async req => { try { return JSON.parse(await body(req)) } catch { return [] } }

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x')
  const gzip = /gzip/.test(req.headers['accept-encoding'])
  const token = /(?:^|; )s=(\w+)/.exec(req.headers.cookie)?.[1]
  const user = token && getSession.get(token)?.user
  const end = (code, headers = {}, b) => res.writeHead(code, headers).end(b)

  if (req.method == 'GET' && url.pathname == '/') {
    const cls = !userCount.get().n ? 'setup' : !user ? 'login' : 'app'
    const page = html.replace('<body>', `<body class="${cls}${url.search == '?bad' ? ' bad' : ''}">`)
    return end(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...gzip && { 'content-encoding': 'gzip' } }, gzip ? gzipSync(page) : page)
  }

  if (req.method == 'POST' && url.pathname == '/login') {
    const f = new URLSearchParams(await body(req))
    const u = str(f.get('u'), 50), p = f.get('p')
    // First visitor on an empty DB creates the first user.
    if (u && p && !userCount.get().n) addUser.run(u, hash(p))
    if (!u || !p || !verify(p, getUser.get(u)?.hash)) return end(303, { location: '/?bad' })
    const t = randomBytes(24).toString('hex')
    addSession.run(t, u)
    return end(303, { location: '/', 'set-cookie': `s=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000` })
  }

  if (!user) return end(401)

  if (req.method == 'POST' && url.pathname == '/logout') {
    delSession.run(token)
    return end(303, { location: '/', 'set-cookie': 's=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' })
  }

  if (url.pathname == '/events') {
    let since = +(req.headers['last-event-id'] ?? url.searchParams.get('since')) || 0
    if (since > rev) since = 0 // DB was reset, client cache is stale
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', ...gzip && { 'content-encoding': 'gzip' } })
    const out = gzip ? createGzip() : res
    if (gzip) out.pipe(res)
    const send = s => { out.write(s); gzip && out.flush() }
    send('retry: 2000\n' + event(changes.all(since), !since))
    const c = { user, send, end: () => res.end() }
    clients.add(c)
    return req.on('close', () => clients.delete(c))
  }

  if (req.method == 'POST' && url.pathname == '/set') {
    const [list, n, done] = await json(req)
    const name = str(n, 200)
    if (!name) return end(400)
    if (!Number.isInteger(list) || !getList.get(list)) return end(404)
    // Timestamp-based so rev never goes backwards across restarts, even after a list delete drops the newest rows.
    rev = Math.max(rev + 1, Date.now())
    broadcast([upsert.get(list, name, done ? 1 : 0, rev)])
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
    return end(200, { 'content-type': 'application/json' }, JSON.stringify([user, listUsers.all().map(r => r.name)]))

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
    if (!name || typeof p != 'string' || !p) return end(400)
    return end(addUser.run(name, hash(p)).changes ? 204 : 409)
  }

  end(404)
}).listen(process.env.PORT || 3000, () => console.log(`http://localhost:${process.env.PORT || 3000}`))
