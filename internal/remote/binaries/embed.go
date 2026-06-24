// Package binaries embeds the prebuilt linux scanner binaries shipped for
// agentless remote delivery. Files are placed under dist/ by the release build.
package binaries

import "embed"

// FS holds the bundled binaries, accessed as "dist/houndoom-linux-<arch>".
//
//go:embed dist
var FS embed.FS
