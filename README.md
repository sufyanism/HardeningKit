# HardeningKit — Linux Security Baseline Scanner

**Brand promise:** a single-binary, read-only Linux security baseline scanner with a clean, colorized ANSI compliance-style report. Target runtime is around 3 seconds on typical hosts; the actual time depends on the machine, permissions, and environment.

## Checks
- SSH root-login and password-authentication directives (main config only)
- Firewall signals for UFW, firewalld, and nftables
- World-writable temporary directories without sticky bit
- Sampled SUID inventory in common binary directories
- IPv4 TCP listening socket count
- Package-manager metadata signal (not update freshness)

## Build and run
Requires Go 1.22+ to build. The deployed program is a single executable.

```sh
go test ./...
go build -trimpath -ldflags="-s -w" -o hardeningkit ./cmd/hardeningkit
./hardeningkit
sudo ./hardeningkit
./hardeningkit --no-color
sudo ./hardeningkit -json reports/audit.json
./hardeningkit -version
```

Before publishing, replace `YOUR_USERNAME` in `go.mod` and the import path in `cmd/hardeningkit/main.go` with your GitHub username.

## Exit codes
- `0`: no HIGH or CRITICAL findings
- `1`: report output error
- `2`: one or more HIGH or CRITICAL findings

## Scope and limitations
This is a lightweight baseline scanner, not a compliance certification or a replacement for CIS benchmarks or a professional security review. Checks are heuristic and may produce false positives or negatives. SSH Include files/effective settings are not evaluated; firewall rule quality is not assessed; SUID inventory is limited to common binary directories; listening sockets cover IPv4 TCP only; package update freshness is not checked. The `-timeout` flag is a best-effort check budget, not a hard process timeout. Run with appropriate privileges for more complete visibility.

Use only on systems you own or are authorized to audit. HardeningKit is read-only and does not automatically modify host configuration.

## License
MIT. See `LICENSE`.
