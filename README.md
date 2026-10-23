# groceries

Shared shopping lists (tabs on top, all shared between users). Tap to tick, tap a ticked item (or a suggestion) to re-add. Live sync between everyone logged in.

Zero dependencies, Node 22.13+ (uses built-in `node:sqlite`). The whole frontend is ~2.5KB gzipped.

```sh
ADMIN_USER=me ADMIN_PASSWORD=change-me-please node server.js   # http://localhost:3000
node test.js                                                    # tests
```

`ADMIN_USER` / `ADMIN_PASSWORD` create the first user on an empty database (ignored afterwards). Add more users from the users icon in the top bar. `PORT` and `DB` (SQLite path) are optional.

## Docker

```sh
docker run -d -p 3000:3000 -v groceries:/data -e ADMIN_USER=me -e ADMIN_PASSWORD=change-me-please ghcr.io/backmeupplz/groceries
```

Images for amd64 and arm64 are published to GitHub Container Registry by Forgejo Actions on every release published on [git.borodutch.com](https://git.borodutch.com/backmeupplz/groceries) (`tea release create --repo backmeupplz/groceries --tag vX.Y.Z --title vX.Y.Z`).

Also available as an app on [MyGround](https://myground.online).

## Security notes

- Every user is an equal admin: anyone logged in can add/remove users and lists.
- Behind an HTTPS proxy, pass `X-Forwarded-Proto: https` so the session cookie becomes `Secure`/`__Host-`.
- On plain-http `host:port` setups, browsers share cookies across ports, so other apps on the same host can see the session cookie. Give it its own hostname if you don't trust the neighbours.
