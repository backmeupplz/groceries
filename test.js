// node test.js — boots the server on a temp DB and checks the core flows
import { spawn } from 'node:child_process'
import assert from 'node:assert'
import { tmpdir } from 'node:os'

const PORT = 3999, base = `http://localhost:${PORT}`
const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT, DB: `${tmpdir()}/groceries-test-${Date.now()}.db` }, stdio: 'inherit' })
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

  await post('/set', ['Milk', 0])
  await post('/set', ['milk', 1]) // same item, case-insensitive; keeps "Milk"
  await post('/set', ['Eggs', 0])

  const events = async since => {
    const ac = new AbortController(), reader = (await fetch(`${base}/events?since=${since}`, { headers, signal: ac.signal })).body.pipeThrough(new TextDecoderStream()).getReader()
    let buf = ''
    while (!buf.includes('\n\n')) buf += (await reader.read()).value
    ac.abort()
    return [+/id: (\d+)/.exec(buf)[1], JSON.parse(/data: (.*)/.exec(buf)[1])]
  }
  assert.deepEqual(await events(0), [3, [[['Milk', 1], ['Eggs', 0]], true]])
  assert.deepEqual(await events(2), [3, [[['Eggs', 0]], false]])
  assert.deepEqual(await events(99), [3, [[['Milk', 1], ['Eggs', 0]], true]]) // stale cache -> full resync
  assert.equal((await fetch(base + '/logout', { method: 'POST', headers, redirect: 'manual' })).status, 303)
  assert.equal((await fetch(base + '/events', { headers })).status, 401)
  console.log('ok')
} finally { srv.kill() }
