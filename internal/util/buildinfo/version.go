// Package buildinfo carries build-time information.
package buildinfo

// Version is the release version, set at build time with -ldflags -X. It is
// "dev" in local builds.
var Version = "dev"
