# Design Decisions

This document records the architectural and design decisions of sysdhardener. Open research questions remain explicitly marked.

## Reference environment and tooling

- Use one Ubuntu Server LTS reference VM under headless QEMU/KVM and libvirt.
- Provision it with a reproducible cloud-init/NoCloud seed.
- Nix and direnv reproduce user-space tooling; the host supplies KVM, libvirt, networking, and kernel capabilities.
- Keep both flake and non-flake entry points on the same dependency expression.

The reference VM was verified on 2026-08-22 as Ubuntu 26.04 LTS (resolute), x86_64, kernel `7.0.0-28-generic`, systemd 259, and cgroup v2. The image and host validation details are in [`validation.md`](validation.md).

## Packaging and privilege boundary

sysdhardener is a self-contained CLI binary with integrated observation and analysis. It is strictly an on-demand profiler, not a permanent background service or daemon. Root is the expected execution mode; non-root execution is allowed but must warn and mark visibility degraded. Root does not guarantee complete observation. The tool never applies hardening.

Observation operates exclusively via two implemented models:
1. `ExecStart=` launch or transient spawn (`observe`);
2. Direct side-channel attachment (`attach` via ptrace or cgroup via eBPF).

## Evidence model

- Syscalls are the primary evidence source.
- Supplementary low-level sources are permitted only to resolve a syscall blind spot and must retain provenance.
- Evidence is stored as recommendation-local, deduplicated aggregates. There is no shared evidence index or persistent aggregate cache.
- Coverage and event-loss metadata are never discarded.
- Absence produces a provisional validation candidate, never proof of non-use.

## Output contract

The output has two linked views: a detailed findings file and a concise recommended-settings file. The concise file starts with exactly one warning line and contains settings only afterwards. JSON is optional. Selected sinks run independently: successful outputs are preserved, failures are reported, and any failed selected sink produces a non-zero result.

## Compatibility and provenance

Compatibility records use `directive`, `introduced_in`, `support_status`, `source_ref`, and `verification_status`, with exception fields only when needed. `source_ref` uses stable `SRC-NN` identifiers from [`research.md`](research.md). Unknown or unverified facts remain explicitly unknown.

## eBPF outcome semantics

The cgroup sockaddr hook runs before the operation returns, so eBPF events do not claim syscall success. For `RestrictAddressFamilies=`, an attempted family is treated as needed: `Success` and `Unknown` outcomes remain in the allow-list; only a known `Error` excludes a family and records a contradiction.

## Validation strategy

Validation is deterministic-first: typed unit/mapping tests, scenario fixtures, golden output, live ptrace tests, and eBPF loader tests. CI runs formatting, Clippy, all-feature tests, source-size checks, dependency checks, and repository consistency checks.

## Status of implementation and boundaries
 
The CLI implementation resolves:
- Reference baseline: verified on Ubuntu 26.04 LTS, kernel 7.0, systemd 259, cgroup v2.
- Runtime observation: both `ExecStart=` / transient launch (`observe`) and direct side-channel attachment (`attach` / eBPF cgroup) are implemented and verified.
- Dynamic compatibility: the host's systemd version is probed at runtime to gate directives.
- Filesystem sandboxing: implemented with both ptrace fallback (path string capture via procfs / `process_vm_readv`) and eBPF wire event bridge, deriving `ProtectSystem=`, `ProtectHome=`, `ProtectControlGroups=`, and prefix-clustered `ReadWritePaths=`.
- Evidence aggregation: in-memory recommendation-local aggregates per CLI run.
- Operational model: strictly on-demand CLI profiling; permanent background daemonization is explicitly out of scope.
