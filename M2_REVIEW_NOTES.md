# M2 Publishing Review Notes

## Changes prepared in this working copy

- Bounded inspector stdout and stderr independently; either overflow now cancels the child process and is returned as `ErrProtocolViolation`.
- Reject relative inspector executable paths, including paths under `crates/.../target`, to avoid resolving an executable from an attacker-controlled working directory.
- Use a platform-neutral `pg-tor-inspector` default name; Windows companion lookup still checks the `.exe` suffix.
- Add regression tests for output-limit cancellation and rejection of repository-relative executable paths.
- Add a root README, update the architecture and CLI references to describe the actual M2 scope and boundaries, and add a security reporting policy.
- Update the MIT copyright attribution to `48sh1xbh` as explicitly confirmed by the maintainer.

## Validation limitations

The source was formatted with `gofmt`. Full Go tests could not be executed in this review environment because it has Go 1.23.2 while `go.mod` requires Go 1.26.5, and the environment cannot reach the Go module proxy to fetch `gopkg.in/yaml.v3`. Rust/Cargo are not installed in this environment. Therefore this review copy is **not approved for publication yet**.

Before publishing, run on a machine with the declared toolchains:

```bash
gofmt -w internal/tor/inspector_bridge.go internal/tor/inspector_test.go
go test -race -count=1 ./...
go vet ./...
cargo fmt --manifest-path crates/pg-tor-inspector/Cargo.toml --check
cargo test --manifest-path crates/pg-tor-inspector/Cargo.toml
cargo build --manifest-path crates/pg-tor-inspector/Cargo.toml --release
git diff --check
```

Also verify on native Linux and against a live Tor daemon before describing those environments as validated. Do not commit generated binaries, `.env` files, Rust `target/` directories, logs, reports, or `.git/` metadata.
