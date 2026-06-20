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

## Private mode (auth)

By default is open. For org-internal deployments you can turn on
**private mode** to require sign-in and stop strangers from using the server to
host arbitrary content. Auth is an orthogonal access gate - secrets stay
zero-knowledge, the server still only ever holds ciphertext it can't read.

Two gate modes (`auth.gate`):

- **`create`** (default) - you must sign in to *create* a secret, but anyone with
  a link can still open it. Best when sharing with people outside the org. In this
  mode the create form also offers a **per-secret Public/Private** choice: a
  *private* secret requires the opener to sign in (an anonymous visitor is bounced
  to the login page), while a *public* secret stays openable by anyone with the link.
- **`all`** - sign-in is also required to preview and reveal.

Sign-in methods: **local accounts** (email + password, with optional TOTP 2FA and
passkeys) and **OIDC SSO** (one or more providers - Google Workspace, Microsoft
Entra, or any standard OIDC issuer; one button each on the login page). Admins
manage users in-app at `/users`; everyone self-manages 2FA/passkeys at `/account`.

```sh
# Minimal private-mode setup: seed an admin, then run.
export SHARE_AUTH_ENABLED=true
export SHARE_AUTH_SESSION_SECRET=$(openssl rand -hex 32)   # >= 32 chars
export SHARE_AUTH_BOOTSTRAP_ADMIN_EMAIL=admin@acme.com
export SHARE_AUTH_BOOTSTRAP_ADMIN_PASSWORD=change-me-please
./bin/secret-share serve
# or create users out-of-band (server stopped):
./bin/secret-share user create admin@acme.com --role admin
```

See the `auth` block in [`secret-share.example.yaml`](./secret-share.example.yaml)
for OIDC providers and all options. (GitHub is OAuth2-only and isn't supported as
an OIDC issuer; use Google/Microsoft/your IdP.)

## Configuration

YAML or `SHARE_*` env vars (`section.key` → `SHARE_SECTION_KEY`). See
[`secret-share.example.yaml`](./secret-share.example.yaml) for every option.
Validation runs at boot, so misconfiguration fails fast. OIDC providers (a list)
can be set in the YAML file or entirely via env vars
(`SHARE_AUTH_OIDC_PROVIDERS=google,entra` + `SHARE_AUTH_OIDC_<ID>_*` per field) —
see the `auth.oidc` block in the example config.

## Security notes

- The decryption key travels only in the URL fragment -
  the server never sees it, so a database breach exposes no plaintext.

