# ProofLab Action (Quantum Aether) — MVP

Prove a post-quantum TLS change works **before** it reaches production.

ProofLab scans your repository for TLS server configs, proposes a minimal change that enables the
**X25519MLKEM768** hybrid key exchange (ML-KEM-768 + X25519) while keeping classical groups as a fallback,
then runs the **original and the patched config side by side in throwaway Docker containers** on your CI runner
and writes a verifiable report to the job summary.

Nothing is deployed. Your code stays in your GitHub/CI. The only optional write is a pull request from a new
`prooflab/*` branch (`open-pr: true`); the action never pushes to your default branch.

## What it does

1. **Discover**: nginx (`*.conf` with `server {}` + `ssl`), Caddy (`Caddyfile*`) and HAProxy (`*.cfg` with `bind … ssl`),
   plus `Dockerfile` base images (the runtime `FROM`) to learn which TLS library the server ships.
2. **Propose**, with evidence (file, line, diff):
   - nginx: `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (adds `TLSv1.3` to `ssl_protocols` if missing). Needs OpenSSL ≥ 3.5.
   - HAProxy: `ssl-default-bind-curves X25519MLKEM768:X25519:P-256` (or the `curves` bind option). Needs OpenSSL ≥ 3.5.
   - Caddy: X25519MLKEM768 is on by default from Caddy 2.10; an explicit `curves` list gets `x25519mlkem768` added, and a
     `FROM caddy:<2.10` is bumped.
   - If the repository's base image has an older OpenSSL, the `FROM` line is bumped to an image that has OpenSSL ≥ 3.5
     (see *Images* below). The report prints the library version actually found in each image.
3. **Test in isolated containers** (a private Docker network, a self-signed test certificate made for the run):
   - config valid (`nginx -t`, `caddy validate`, `haproxy -c`)
   - handshake with a **PQ-only client** (`openssl s_client -groups X25519MLKEM768`, OpenSSL 3.5)
   - handshake with a **classical-only client** (`-groups X25519:prime256v1`): the fallback still works
   - which group a **modern client** (offering both) actually gets
   - **handshake time** (median of N handshakes) and **handshake bytes** read/written, PQ vs classical
4. **Report**: patch diff, pass/fail table, measurements, rollback steps, verdict — in the job summary and in a Markdown file.

## Usage

```yaml
name: prooflab
on: [pull_request, workflow_dispatch]
permissions:
  contents: read
jobs:
  prooflab:
    runs-on: ubuntu-latest   # needs Docker (GitHub-hosted Ubuntu runners have it)
    steps:
      - uses: actions/checkout@v4
      - uses: moncef00327-cloud/prooflab-action@v0.1.0
        with:
          path: .            # where your configs live
          # open-pr: true    # optional; then grant contents: write and pull-requests: write
```

For `open-pr: true` the job needs `permissions: {contents: write, pull-requests: write}` and the repository setting
*Settings → Actions → General → Allow GitHub Actions to create and approve pull requests*. The PR is opened only when
every check of the patched config passed, from a new `prooflab/x25519mlkem768-<run id>` branch.

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan (inside the repo) |
| `test-run` | `true` | Run the container tests. `false` = only propose the config patch |
| `open-pr` | `false` | Open a PR with the patch from a new `prooflab/*` branch, only if every check passed |
| `fail-on-error` | `true` | Fail the job if the patched config fails a check |
| `iterations` | `20` | Handshakes per timing measurement |
| `github-token` | `github.token` | Used only for `open-pr` |

### Outputs

`configs-found`, `patched-pass`, `original-post-quantum`, `report-path`, `pr-url`.

## Images

| Role | Image | Why |
|---|---|---|
| Test client | `alpine:3.22` + `openssl` | Ships OpenSSL 3.5 with `X25519MLKEM768` |
| nginx (patched) | `nginx:1.29` / `nginx:1.29-alpine` | Built with OpenSSL 3.5 (the `-alpine` variant is picked when your image was Alpine) |
| HAProxy (patched) | `haproxy:3.2` / `haproxy:3.2-alpine` | OpenSSL 3.5 |
| Caddy (patched) | `caddy:2.10-alpine` | Go TLS; X25519MLKEM768 on by default |

Measured by the `image-probe` CI job on 2026-11-14: `nginx:1.27` ships OpenSSL 3.0 (no ML-KEM), `nginx:1.29` and
`nginx:1.29-alpine` OpenSSL 3.5, `haproxy:2.8` OpenSSL 3.5 (Debian rebuild), `caddy:2.8` no ML-KEM, `caddy:2.10` yes,
client `alpine:3.22` OpenSSL 3.5. Image contents change over time, so every report prints the version it actually found.

The original config runs on the runtime image from your Dockerfile when it is an official `nginx`, `caddy` or
`haproxy` image; otherwise on the image above. The CI job `image-probe` prints the library versions of these images.

## Honest scope (MVP)

- nginx, Caddy and HAProxy only; at most 6 configs per run.
- It tests TLS protocol behaviour of your config, not your application, upstreams or real certificates.
  Certificate paths are rewritten to a test certificate for the run (listed in the report, never part of the patch);
  upstream hostnames resolve to 127.0.0.1 inside the container.
- Timings include the client process start-up; compare original vs patched, not absolute numbers.
- Configs split over many `include` files may need `path` pointed at the directory that holds the main file.
- Nothing reaches production without your explicit approval (merging the PR is your decision).

## Examples and CI

`examples/nginx`, `examples/caddy` and `examples/haproxy` are small fixture repositories whose original configs do **not**
negotiate X25519MLKEM768. The `test` workflow runs the action on each and asserts that the patched config passes every
check and that the checkout is left untouched.

Part of [Quantum Aether ProofLab](https://ather-quantum.com/prooflab) — free pilot on one repository.
Related: [Post-quantum TLS check action](https://github.com/marketplace/actions/post-quantum-tls-check-quantum-aether)
for live sites.

## License

MIT
