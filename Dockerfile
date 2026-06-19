# syntax=docker/dockerfile:1

# build UI.
FROM oven/bun:1 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/bun.lock* ./
RUN bun install --frozen-lockfile || bun install
COPY frontend/ ./
RUN bun run build

# build the static Go binary.
FROM golang:1.26 AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

COPY --from=frontend /src/frontend/dist ./frontend/dist
ARG VERSION=docker
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X github.com/YouSysAdmin/secret-share/pkg/version.Version=${VERSION}" \
    -o /out/secret-share ./cmd/secret-share

# minimal runtime.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend /out/secret-share /secret-share
USER nonroot:nonroot
EXPOSE 3000
ENTRYPOINT ["/secret-share"]
CMD ["serve"]
