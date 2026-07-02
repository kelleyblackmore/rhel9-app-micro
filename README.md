# SecureLedger — micro-base application layer (Rust / axum)

The same *SecureLedger* secure task & audit API as
[`rhel9-app-full`](https://github.com/kelleyblackmore/rhel9-app-full), implemented
in **Rust (axum)** as a **fully static musl binary** on the distroless
[`rhel9-micro-hardened-base`](https://github.com/kelleyblackmore/rhel9-micro-hardened-base)
image — and run through the **same CVE check the micro base uses**.

## What the app does

- **JWT auth** (`POST /api/auth/login`) with Argon2-hashed, seeded users.
- **RBAC**: `user` vs `admin` enforced in axum extractors.
- **Task CRUD** (`/api/tasks`) with validation, owner enforcement, paging.
- **Append-only audit log** (`/api/audit`, admin-only) on every mutation.
- **Rate limiting** (governor) → HTTP 429.
- **Persistence**: **SQLite** via `rusqlite` (bundled — compiled in, static).
- **Observability**: Prometheus `/metrics`; `tracing` JSON logs.
- **OpenAPI**: `utoipa` → `/swagger-ui`, `/api-docs/openapi.json`.
- **Health**: `/healthz`, `/readyz`.

## Image

Multi-stage: a `rust:1-alpine` builder produces a **static musl** binary (rustls,
no OpenSSL); the runtime stage is `FROM ghcr.io/kelleyblackmore/rhel9-micro-hardened-base:latest`
(no shell, no package manager) and just `COPY`s the binary in. Runs as non-root
UID 10001 with an exec-form entrypoint.

```bash
docker build -t secureledger-micro .
docker run --rm -p 8080:8080 secureledger-micro
# http://localhost:8080/healthz
```

## CI (all in GitHub Actions)

| Workflow | What it does |
|---|---|
| [`build.yml`](.github/workflows/build.yml) | `cargo test` (+ fmt/clippy) |
| [`cve-scan.yml`](.github/workflows/cve-scan.yml) | Trivy on the app image; **gate: 0 fixable CVEs**; total (incl. unfixed) reported |
| [`stig-dast-scan.yml`](.github/workflows/stig-dast-scan.yml) | **DISA API SRG** + **DISA ASD STIG** black-box scans against the running app (`stig-api-scanner` + `stig-asd-scanner`); SARIF → Security tab, CRITICAL-gated |
| [`stig-checklist.yml`](.github/workflows/stig-checklist.yml) | Consolidated **`.ckl` + `.cklb`** checklist (API SRG + ASD STIG) for **STIG Manager / STIG Viewer** — weekly + manual. (No RHEL 9 OS STIG here — the base is distroless.) |

> STIG is **not** run here, matching the micro base: DISA STIG content targets a
> full OS and cannot be evaluated inside a distroless image with no shell/rpm.
> The base's minimalism *is* the hardening.

## Automation

Weekly **Renovate** ([`renovate.json`](renovate.json)) updates Cargo crates, the
pinned base-image digest, and GitHub Actions (requires the Mend Renovate App).
