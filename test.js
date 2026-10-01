// node test.js — boots the server on a temp DB and checks the core flows
import { spawn } from 'node:child_process'
import assert from 'node:assert'
import { tmpdir } from 'node:os'
import { DatabaseSync } from 'node:sqlite'

const PORT = 3999, base = `http://localhost:${PORT}`, DB = `${tmpdir()}/groceries-test-${Date.now()}.db`
// start from a v1 (single list) DB to exercise the migration
new DatabaseSync(DB).exec(`CREATE TABLE items(name TEXT PRIMARY KEY COLLATE NOCASE, done INT, rev INT); CREATE INDEX items_rev ON items(rev); INSERT INTO items VALUES('Bread', 1, 1)`)
const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT, DB }, stdio: 'inherit' })
await new Promise(r => setTimeout(r, 500))

const login = async (u, p) => {
  const r = await fetch(base + '/login', { method: 'POST', body: new URLSearchParams({ u, p }), redirect: 'manual' })
  return [r.headers.get('location'), r.headers.get('set-cookie')?.split(';')[0]]
}
try {
  assert.match(await (await fetch(base)).text(), /class="setup"/)
  const [, cookie] = await login('me', 'pw')
  assert.ok(cookie)
  assert.equal((await login('me', 'nope'))[0], '/?bad')
  assert.equal((await fetch(base + '/events')).status, 401)
  const headers = { cookie }
  const post = (path, body) => fetch(base + path, { method: 'POST', headers, body: JSON.stringify(body) })

  assert.equal((await post('/users', ['wife', 'pw2'])).status, 204)
  assert.equal((await post('/users', ['wife', 'x'])).status, 409)
  const [, wifeCookie] = await login('wife', 'pw2')
  assert.ok(wifeCookie)
  assert.deepEqual(await (await fetch(base + '/users', { headers })).json(), ['me', ['me', 'wife']])
  assert.equal((await post('/users/delete', ['me'])).status, 400)
  assert.equal((await post('/users/delete', ['wife'])).status, 204)
  assert.equal((await fetch(base + '/events', { headers: { cookie: wifeCookie } })).status, 401)
  assert.equal((await login('wife', 'pw2'))[0], '/?bad')

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
