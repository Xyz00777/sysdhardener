# Validation and Reference Environment

## Validation strategy

The project uses deterministic-first validation: typed parsing and mapping tests, adversarial fixtures, golden output, live ptrace/attach tests, eBPF loader tests, and CLI end-to-end tests. CI runs these through `scripts/ci.sh` alongside formatting, Clippy, dependency, source-size, and consistency checks.

## Reference host boundary

Nix supplies user-space tools only. The host must supply hardware virtualization, `/dev/kvm`, libvirt or virtqemud, networking, and appropriate permissions. Checks are read-only:

```sh
grep -m1 -o -E 'vmx|svm' /proc/cpuinfo
ls -l /dev/kvm
lsmod | grep -E '^kvm'
command -v virsh
systemctl is-active virtqemud.socket
ip route show default
id
```

The reference VM was verified on 2026-08-22 as Ubuntu 26.04 LTS (resolute), x86_64, kernel `7.0.0-28-generic`, systemd `259.5-0ubuntu3`, and cgroup v2. The image checksum was verified against the Ubuntu `SHA256SUMS`; SSH uses a cloud-init-seeded key, disabled password/root login, and loopback-only host forwarding.

## Performance findings

The release fixture pipeline scales linearly at roughly 2 microseconds per event. The 1M-event case took about 1.96 seconds and peaked at about 561 MB RSS. Parsing dominates runtime; aggregation, recommendation, projection, and serialization operate on the small per-family aggregate and are effectively constant-size after parsing.

TRACE logging is bounded by `--max-trace-events` (alias `--max-raw-events`) and routed to a dedicated debug file; at 100K events, the measured full-cap trace run was about 2.5 times the default INFO run. The current scope does not require optimization, but streaming/one-pass parsing is the main future performance opportunity.

## Limitations

The implementation is recommendation-only. It does not apply systemd settings, provide service deployment packaging, or claim complete syscall, path, LSM, or capability coverage.
