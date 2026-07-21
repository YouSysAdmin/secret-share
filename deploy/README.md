# Deployment examples

Both examples run the published image (`ghcr.io/yousysadmin/secret-share`) with
the bbolt database on a persistent volume. Configuration is entirely via
`SHARE_*` env vars (see `secret-share.example.yaml` at the repo root for every
key and its env name).

## docker-compose

```sh
cd deploy/docker-compose
docker compose up -d
```

Serves plain HTTP on `127.0.0.1:3000`. Put a TLS-terminating reverse proxy in
front (then set `SHARE_SERVER_BEHIND_TLS_PROXY=true` and list the proxy in
`SHARE_SERVER_TRUSTED_PROXIES`), or enable built-in TLS with
`SHARE_SERVER_TLS_MODE`.

## Kubernetes

```sh
kubectl apply -f deploy/kubernetes/
```

Creates a PVC, a single-replica Deployment (bbolt is single-writer: keep
`replicas: 1` and `strategy: Recreate`), and a ClusterIP Service. Health probes
use `GET /healthz`. Add your own Ingress/HTTPRoute in front, uncomment the env
blocks in the manifest for private mode (auth) and Prometheus metrics.
