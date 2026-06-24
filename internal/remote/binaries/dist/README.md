# Bundled scanner binaries

Release builds place `houndoom-linux-amd64` and `houndoom-linux-arm64` here
before the control-plane binary is built (see `.github/workflows/release.yml`).
These artifacts are git-ignored; this README keeps the directory present so the
`//go:embed dist` directive compiles in local/dev builds.
