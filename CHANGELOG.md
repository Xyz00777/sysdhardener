# Changelog

## [0.3.0]

- Add automated demo and evaluation harness with web frontend simulation for university portal scenarios.
- Add comprehensive Redis client tests for fragmented socket responses, timeouts, and error handling.
- Expand filesystem sandboxing directives and regression tests for `ProtectHome=read-only` and `ReadWritePaths=`.
- Harden demo execution scripts (`demo/setup_demo.sh`, `demo/run_test.sh`) with startup connection retries and verified drop-in evaluation.

## [0.2.0]

- Add automated release metadata checks for pull requests.
- Publish a tested Linux x86-64 command-line binary and checksum with GitHub Releases.
