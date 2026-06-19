// Package secretshareui hosts the //go:embed of the prerendered Svelte frontend.
// `make frontend` runs `bun run build` in frontend/ to populate frontend/dist/.
package secretshareui

import "embed"

// Frontend is the embedded Svelte build.
//
//go:embed all:frontend/dist
var Frontend embed.FS
