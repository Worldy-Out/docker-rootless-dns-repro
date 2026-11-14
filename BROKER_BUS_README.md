# Root sandbox and an existing user bus

This is a standalone synthetic test for an explicitly opted-in, disposable
GitHub-hosted Ubuntu 24.04 runner. It does not run on a production host, import
application code, start a container engine, change firewall or routes, enable
linger, modify a user-manager unit, or contact an external service.

The harness creates one dedicated account and starts its existing `user@UID`
manager once. Its home contains a disabled, inert `docker.service` surrogate
whose `ExecStart` is `sleep`; that service is **never started**. A successful
query must report loaded, disabled, inactive, MainPID=0, and
ExecMainStartTimestampMonotonic=0 before and after every case.

The original root sandbox includes `ProtectHome=yes`, `NoNewPrivileges=yes`,
an explicit bounded capability set, `ProtectSystem=strict`, and the other
directives listed in `sandbox()`. The first native case attempts the actual
`runuser ... systemctl --user show` command and requires a hidden-bus failure.
An identical query outside the sandbox must succeed before and after the case.

The candidate changes only:

- `ProtectHome=tmpfs`;
- one fixed-UID `BindReadOnlyPaths=/run/user/UID/bus` socket bind.

It does not expose the complete runtime directory. The native proof checks the
socket's exact host device/inode/UID/GID/mode, the kernel's read-only mount flag,
and that the visible runtime directory contains only `bus`. The synthetic
home, an owned root-home marker, and another synthetic runtime directory must
remain hidden. Complete effective systemd properties are recorded. The bind
property's presentation is retained verbatim; it is not normalized into proof.

Two negative bindings expose an empty directory or a socket owned by root in
place of the expected user socket. They must be rejected before the user query.
After all four probes, the one owned manager is stopped once. Both the manager
and runtime-directory service must be inactive, its runtime path absent, and
the UID process inventory empty. The bus is then confirmed absent without a
manager restart. No test performs a service start over the user bus.

Cleanup checks exact account identity, owned file inode/hash/permissions and
directory identities before deletion. A foreign generation, partial setup,
unknown start/stop acknowledgement, unexpected process, or unreadable state
preserves the remaining fixture and reports FAIL. There are no automatic
start/stop retries or recursive deletion of an arbitrary home directory.
The scenario and cleanup have separate 300/90-second limits; the free standard
runner job has an eight-minute cap.

## Run and interpretation

Run only the dedicated **Synthetic broker user-bus sandbox** workflow. It checks
`BROKER_BUS_SHA256SUMS`, runs offline failure tests, then executes this one new
native scenario. No other reproduction or accepted test is dispatched.

`PASS` means these kernel/systemd primitives worked on the recorded Ubuntu
24.04 runner versions. It does not prove behavior on a different distro or
systemd version, a production root helper, privileged network configuration,
container lifecycle, or real credentials. The fixture captures no private
inventory or deployment data. A native FAIL is retained as evidence, never
rewritten by the offline tests. No native result exists at preparation time.

The exact publication allowlist is the source, offline test, this README,
`BROKER_BUS_SHA256SUMS`, and `.github/workflows/broker-bus.yml`. All values,
names, accounts and paths are synthetic; no project source is copied.
