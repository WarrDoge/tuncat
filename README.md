# tuncat

Universal tunnel managment utility in pure Go. Inspired by netcat and rclone.

`tuncat` is a Go VPN client for Cisco AnyConnect-compatible gateways. It embeds the VPN core in-process and keeps the legacy CLI/config contract intact.

## What stays the same

- same CLI flags (`-server`, `-username`, `-password`, `-pfx-path`, `-pfx-password`, `-base-mtu`, `-config`, `-verbose`)
- same YAML fields (`server`, `username`, `password`, `pfx_path`, `pfx_password`, `base_mtu`, `split_routes`, `dns_domains`, etc.)
- same `tuncat obscure` workflow for secret values
- cert + password auth is mandatory

When a config file contains plaintext `password` or `pfx_password`, `tuncat` now rewrites them to `obscured:...` automatically after a successful connection. CLI-provided secrets are not written back.

## Runtime Notes

- Linux: root privileges and `/dev/net/tun`
- macOS: administrator privileges to configure the tunnel, routes, and DNS
  Known exception: interface address setup still invokes the system `ifconfig` binary.
- Windows: Administrator privileges to configure the tunnel, routes, and DNS

No external `openconnect` or `openssl` runtime binaries are required.

## Quick Start

By default, `tuncat` searches config in this order:

- `./tuncat/config.yaml`
- `./.tuncat/config.yaml`
- `./config.yaml` (legacy fallback)
- `~/tuncat/config.yaml`
- `~/.tuncat/config.yaml`

Create `./tuncat/config.yaml` (same schema as before):

```yaml
server: "vpn.example.com/external"
username: "<USERNAME>"
password: "obscured:<HASH>"
pfx_path: "denys.dudko.pfx"
pfx_password: "obscured:<HASH>"
base_mtu: 1200

split_routes:
  - "10.0.0.0/8"

dns_domains:
  - "example.internal"
  - "group.example.internal"
  - "external.example.internal"

verify_url: "https://intranet.example.internal/health"
```

Generate obscured values:

```sh
tuncat obscure
```

Connect:

```sh
sudo tuncat -config ./tuncat/config.yaml
```

Disconnect with `Ctrl+C`.

## Usage

```sh
$ tuncat --help

Usage of tuncat:
  -base-mtu int
        base MTU value
  -config string
        path to config file
  -password string
        login password
  -pfx-password string
        password for .pfx file
  -pfx-path string
        path to .pfx certificate file
  -server string
        VPN server address
  -username string
        login username
  -verbose
        enable verbose VPN core logs
  -version
        show version
```

## Config Example

See `config.example.yml`.

Legacy fields are still accepted:

- `protocol`
- `user_agent`
- `server_cert`
- `openconnect_path` (kept for compatibility; ignored by embedded runtime)

`verify_url` is optional. When set, `tuncat` performs a post-connect DNS lookup and HTTP probe and logs the structured result. Probe failure is treated as a failed connection attempt.

## Development

Install the pinned local toolchain with `aqua`:

```sh
aqua i
```

This installs the repo-pinned Go toolchain from `go.mod` plus:

- `act`
- `lefthook`
- `gitleaks`
- `actionlint`
- `golangci-lint`

Install local git hooks once per clone:

```sh
aqua exec -- lefthook install
```

The local hooks use the same task surface as CI:

- `pre-commit`: formats staged Go files with `gofmt`
- `pre-push`: runs `act workflow_dispatch -j lint`, `act workflow_dispatch -j test`, and `act workflow_dispatch -j secrets`

GitHub Actions is the task surface now. Run jobs locally with `act`:

```sh
act -l
act -j build
act -j test
act -j lint
act -j secrets
act -j cross-build
```

`act` requires Docker. The repo-local `.actrc` provides the default workflow directory and container architecture.
For repository secret scans, the `secrets` job runs `gitleaks git .`, which avoids false positives from ignored local files such as personal configs or certificates.
