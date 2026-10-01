# groceries

Shared shopping lists (tabs on top, all shared between users). Tap to tick, tap a ticked item (or a suggestion) to re-add. Live sync between everyone logged in.

Zero dependencies, Node 22.13+ (uses built-in `node:sqlite`). The whole frontend is 2.3KB gzipped.

```sh
node server.js          # http://localhost:3000
PORT=8080 DB=/path/to/groceries.db node server.js
node test.js            # smoke test
```

First visit creates the first user. Add more users from "Add user" at the bottom of the list.
