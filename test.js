// node test.js — boots the server on a temp DB and checks the core flows
import { spawn } from 'node:child_process'
import assert from 'node:assert'
import { tmpdir } from 'node:os'
import { DatabaseSync } from 'node:sqlite'
import { connect } from 'node:net'

const PORT = 3999, base = `http://localhost:${PORT}`, DB = `${tmpdir()}/groceries-test-${Date.now()}.db`
// start from a v1 (single list) DB to exercise the migration
new DatabaseSync(DB).exec(`CREATE TABLE items(name TEXT PRIMARY KEY COLLATE NOCASE, done INT, rev INT); CREATE INDEX items_rev ON items(rev); INSERT INTO items VALUES('Bread', 1, 1)`)
const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT, DB, ADMIN_USER: 'me', ADMIN_PASSWORD: 'password1' }, stdio: 'inherit' })
await new Promise(r => setTimeout(r, 500))

const login = async (u, p) => {
  const r = await fetch(base + '/login', { method: 'POST', body: new URLSearchParams({ u, p }), redirect: 'manual' })
  return [r.headers.get('location'), r.headers.get('set-cookie')?.split(';')[0]]
}
try {
  const page = await fetch(base)
  assert.match(await page.text(), /class="login"/)
  assert.match(page.headers.get('content-security-policy'), /script-src 'sha256-/)
  assert.equal(page.headers.get('x-frame-options'), 'DENY')
  assert.equal(await (await fetch(base + '/health')).text(), 'ok')
  const [, cookie] = await login('me', 'password1') // seeded from env
  assert.match(cookie, /^groceries=\w+$/)
  assert.equal((await login('me', 'nope'))[0], '/?bad')
  assert.equal((await fetch(base + '/events')).status, 401)
  const headers = { cookie, 'content-type': 'application/json' }
  const post = (path, body, extra) => fetch(base + path, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(body) })

  // CSRF: same-site sibling app (other port) can't post, even text/plain bodies that happen to be valid JSON
  assert.equal((await post('/users', ['evil', 'password1'], { 'sec-fetch-site': 'same-site' })).status, 403)
  assert.equal((await post('/users', ['evil', 'password1'], { origin: 'http://localhost:1234' })).status, 403)
  assert.equal((await post('/users', ['evil', 'password1'], { 'content-type': 'text/plain' })).status, 400)
  assert.equal((await post('/users', ['evil', 'password1'], { 'sec-fetch-site': 'same-origin', origin: base })).status, 204)

  // crash attempts: server must survive all of these
  for (const b of [null, 5, {}, '"x"']) assert.equal((await post('/set', b)).status, 400)
  await new Promise(ok => { const s = connect(PORT, 'localhost', () => s.end('GET //[ HTTP/1.1\r\nHost: x\r\n\r\n')); s.on('data', () => {}).on('close', ok) })
  await new Promise(ok => { const s = connect(PORT, 'localhost', () => { s.write('POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc'); setTimeout(() => s.destroy(), 100) }); s.on('close', ok) })
  await new Promise(r => setTimeout(r, 200))
  assert.equal((await fetch(base + '/health')).status, 200)

  assert.equal((await post('/users', ['wife', 'short'])).status, 400) // < 8 chars
  assert.equal((await post('/users', ['wife', 'password2'])).status, 204)
  assert.equal((await post('/users', ['wife', 'password3'])).status, 409)
  const [, wifeCookie] = await login('wife', 'password2')
  assert.ok(wifeCookie)
  assert.deepEqual(await (await fetch(base + '/users', { headers })).json(), ['me', ['evil', 'me', 'wife']])
  assert.equal((await post('/users/delete', ['me'])).status, 400)
  assert.equal((await post('/users/delete', ['wife'])).status, 204)
  assert.equal((await fetch(base + '/events', { headers: { cookie: wifeCookie } })).status, 401)
  assert.equal((await login('wife', 'password2'))[0], '/?bad')

  // brute force: after 5 misses even the right password is refused for a while
  for (let i = 0; i < 5; i++) await login('evil', 'wrong')
  assert.equal((await login('evil', 'password1'))[0], '/?bad')
  // sessions are stored hashed
  assert.ok(new DatabaseSync(DB).prepare('SELECT token FROM sessions').all().every(r => r.token.length == 64 && !cookie.includes(r.token)))

  assert.equal(await (await post('/lists', ['Sometime'])).text(), '2')
  assert.equal((await post('/lists', ['sometime'])).status, 409)
  await post('/set', [1, 'Milk', 0])
  await post('/set', [1, 'milk', 1]) // same item, case-insensitive; keeps "Milk"
  await post('/set', [2, 'Milk', 0]) // same name, separate list
  assert.equal((await post('/set', [9, 'Eggs', 0])).status, 404)
  assert.equal((await post('/set', [{}, 'Eggs', 0])).status, 404)

  const events = async since => {
    const ac = new AbortController(), reader = (await fetch(`${base}/events?since=${since}`, { headers, signal: ac.signal })).body.pipeThrough(new TextDecoderStream()).getReader()
    let buf = ''
    while (!buf.includes('\n\n')) buf += (await reader.read()).value
    ac.abort()
    return [+/id: (\d+)/.exec(buf)[1], JSON.parse(/data: (.*)/.exec(buf)[1])]
  }
  const lists = [[1, 'Grocery'], [2, 'Sometime']]
  const [rev, all] = await events(0)
  assert.deepEqual(all, [[[1, 'Bread', 1], [1, 'Milk', 1], [2, 'Milk', 0]], true, lists])
  assert.deepEqual((await events(rev - 1))[1], [[[2, 'Milk', 0]], false, lists])
  assert.deepEqual((await events(rev + 1))[1], all) // stale cache -> full resync

  assert.equal((await post('/lists/delete', [2])).status, 204)
  assert.equal((await post('/lists/delete', [1])).status, 400) // last list stays
  assert.deepEqual((await events(0))[1], [[[1, 'Bread', 1], [1, 'Milk', 1]], true, [[1, 'Grocery']]])
  assert.equal((await fetch(base + '/logout', { method: 'POST', headers, redirect: 'manual' })).status, 303)
  assert.equal((await fetch(base + '/events', { headers })).status, 401)
  console.log('ok')
} finally { srv.kill() }
