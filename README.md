# Rootless Docker 29.1.3 DNS persistence reproduction

A standalone, synthetic reproduction of Docker converting three `HostConfig`
fields from explicit `null` to empty lists when loading an existing container:
`Dns`, `DnsOptions`, and `DnsSearch`.

This repository contains no application deployment, user data, credentials, or
external server inventory. It uses a fresh standard GitHub-hosted Ubuntu 24.04
x86-64 runner, an isolated rootless Engine, and tiny BusyBox fixtures.

## What is tested

1. Create two synthetic containers on an internal network with no published ports.
2. Materialize their initial stopped state with harmless `/bin/true` setup runs.
3. Stop the dedicated Engine. Initialize the new control container with three
   explicit empty DNS lists; retain its pre-initialization snapshot and exact
   setup diff. Take its accepted baseline only after this synthetic setup.
4. Seed exactly three legacy `null` DNS values in the test fixture. Capture full
   Config, HostConfig, MountPoints, attachment maps and raw fingerprints for both.
5. Start the same Engine once and compare readback against a separate expected
   map applying only Docker's three explicit DNS null-to-empty defaults. Preserve
   the original unmodified Engine baseline and record those projected paths.
   Perform one harmless fixture checkpoint and stop the Engine again.
6. Accept only the exact three-field transition for Docker 29.1.3. Keep raw
   before/after snapshots and hashes distinct. All other fields, full attachment maps,
   the created internal network and the control container must remain exact.
7. Verify shutdown, empty runtime cgroups/processes, unavailable Engine socket,
   and removal of temporary service activation.

The audit module rejects partial DNS transitions, different Engine versions,
missing full snapshots, altered hashes, actual DNS changes and unrelated drift.
The standard-library unit tests run before native setup. A unit PASS does not
substitute for the native result.

## Execution and boundaries

Use **Actions → Docker 29.1.3 rootless DNS persistence reproduction → Run workflow**.
The workflow is manual-only, uses a standard `ubuntu-24.04` runner and has a
15-minute job limit. No cache or artifact-upload actions are used; a small
synthetic receipt is written to the job log and summary. Complete synthetic
before/after snapshots and their hashes are retained in the log for independent
verification after the runner is disposed.

The harness refuses non-hosted/non-CI environments and existing fixture paths
or accounts. It installs a pinned standalone Docker into a dedicated path and
creates one isolated fixture user. Host package prerequisites are installed only
on the disposable runner. No SSH, public application ports, host firewall edits,
VPN daemon or default-route changes are part of this reproduction.

Do not run the native harness on an existing server or workstation. Its root
setup is designed exclusively for a disposable GitHub-hosted Linux runner.

## Pins and evidence

- Engine: Docker 29.1.3, official static archives verified by SHA256.
- Fixture: BusyBox 1.37.0, pinned Linux/amd64 manifest.
- The exact byte-level source pins are in `pins.json` and `SHA256SUMS`.
- Upstream behavior: [Moby InitDNSHostConfig](https://github.com/moby/moby/blob/docker-v29.1.3/daemon/container/container.go#L619-L633).

A successful result proves this synthetic Engine behavior on Ubuntu 24.04. It
does not establish any application's authorization, data recovery, deployment,
or compatibility with other OS packaging. Failed attempts remain in Actions.

## Verified native run

[Run 43517035955](https://github.com/Worldy-Out/docker-rootless-dns-repro/actions/runs/43517035955),
source `ae561ff403330422bf66b6bf6cce924a7d77fe70`: **PASS**.
The 27 regression tests passed; native Docker reproduced exactly the three
fixture DNS transitions. Control raw spec, other fixture fields, complete
attachments and network snapshot matched. Engine shutdown and cleanup passed.

Full synthetic snapshots and the [receipt](evidence/43517035955/result.json)
are retained in `evidence/43517035955/`; `SHA256SUMS` verifies their bytes. The
control's explicit-empty initialization and the fixture's legacy-null seed are
disclosed setup operations before the accepted disk baseline, not historical
rollback evidence.

Three earlier diagnostic failures remain in Actions:
[43515041327](https://github.com/Worldy-Out/docker-rootless-dns-repro/actions/runs/43515041327),
[43515566257](https://github.com/Worldy-Out/docker-rootless-dns-repro/actions/runs/43515566257),
[43516266514](https://github.com/Worldy-Out/docker-rootless-dns-repro/actions/runs/43516266514).
Each confirmed safe cleanup. They led to complete readback diagnostics, an
explicit derived cold-Engine expectation, and corrected synthetic control setup;
the strict disk-audit module was not broadened.
