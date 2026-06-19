# secret-share

Share secrets with one-time, expiring links.

Paste any text, pick a lifetime, and get a link. Whoever opens it sees the secret
**once**, and it's deleted on first view (and on expiry).

## How it works

Every secret is **zero-knowledge**: the AES-256-GCM key is generated in your
browser, the plaintext is encrypted client-side, and only ciphertext is sent to
the server.
The key lives in the URL fragment and **never reaches the server**,
which stores ciphertext it cannot read.

Retrieval is a single **one-time burn**: the secret is read and deleted
atomically (exactly-once even under concurrent reads), behind a "click to reveal"
step so link-unfurlers (Slack/Outlook, which issue GET) don't trigger the burn.
A background sweeper purges anything that reaches its expiry.

## Quick start (dev)

Requires Go 1.26+ and Bun.

```sh
make frontend                 # build the embedded SPA once
make dev                      # runs serve with dev/config.yaml (bbolt)
# in another terminal, optional live-reload UI on :5173 (proxies /api to :8080):
cd frontend && bun run dev
```

The UI is at http://localhost:3000

## Build & run (production)

```sh
make build
cp secret-share.example.yaml secret-share.yaml # then edit it
./bin/secret-share serve --config secret-share.yaml

```

For TLS, either terminate it in a reverse proxy (set `server.behind_tls_proxy:
true`) or let secret-share serve HTTPS itself via `server.tls.mode`: `manual`
(your PEM cert + key), `self` (in-memory self-signed, dev/internal), or `acme`
(Let's Encrypt). See the `server.tls` block in `secret-share.example.yaml`.

### Docker

```sh
docker build -t secret-share .
docker run -p 3000:3000 \
  -v secret-share-data:/var/lib/secret-share \
  -e SHARE_DATABASE_PATH=/var/lib/secret-share/secret-share.db \
  secret-share
```

## Configuration

YAML or `SHARE_*` env vars (`section.key` → `SHARE_SECTION_KEY`). See
[`secret-share.example.yaml`](./secret-share.example.yaml) for every option.
Validation runs at boot, so misconfiguration fails fast.

## Security notes

- The decryption key travels only in the URL fragment -
  the server never sees it, so a database breach exposes no plaintext.

