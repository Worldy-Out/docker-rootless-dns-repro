# Root broker sandbox: isolated systemd reproduction

This generic fixture validates a real Linux systemd socket-activated root broker
with kernel `SO_PEERCRED` authentication. It contains no application code,
deployment configuration, credentials, or external network destinations.

Only use a new disposable standard GitHub Actions Ubuntu runner. Python 3,
systemd, `runuser`, shadow account tools and procps are required. No package
installation is performed. Set the job timeout to **8 minutes**.

```sh
python3 -I -B test_broker_repro.py
sudo env GITHUB_ACTIONS=true CI=true RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT" RUN_BROKER_REPRO=yes python3 -I -B broker_repro.py --output results
```

The fixture requires `RUNNER_ENVIRONMENT=github-hosted` and systemd as PID 1,
and refuses existing names, paths, UIDs or GIDs. It creates two temporary
synthetic users and one group, its own root-owned files, and five uniquely named
systemd units. Only its socket and watchdog timer are enabled. Communication is
local AF_UNIX only. The permitted operation executes fixed `id -u` commands as
root and as the dedicated unprivileged account; it accepts no command or path
from a caller.

Native checks cover the following:

- Socket activation with root ownership, dedicated group and mode `0660`.
- Exact kernel peer UID/GID; another UID in the same permitted group and root
  are both rejected by the application authorization check.
- One complete newline-terminated JSON frame with EOF, at most 256 bytes and
  a three-second receive deadline; malformed, extra, oversized and stalled
  requests are rejected. A subsequent valid request must still work.
- Effective `NoNewPrivileges`, exact bounding/effective capabilities, and no
  ambient capabilities. A fixed identity-drop command must work within them.
- `ProtectSystem=strict` makes the source location read-only (specifically
  `EROFS`), while the explicitly permitted synthetic state directories work.
- An actual systemd timer observes a stale monotonic heartbeat and records a
  single harmless stop intent. It never starts a daemon. A separate sentinel
  service must remain inactive and its start marker must remain absent.

The watchdog fixture does **not** stop a real service or model a VPN lease. It
proves timer execution, sandbox compatibility, and the absence of a start action
in this bounded synthetic workload. It does not prove production authorization,
network policy, reboot recovery, storage safety, or daemon supervision semantics.

Cleanup stops only fixture units, verifies their stopped state and fixture user
process absence, removes only owned unchanged files, and deletes only the newly
created synthetic users/group and empty directories. Unknown or changed state
causes cleanup FAIL and preserves remaining resources. Overall PASS requires
cleanup PASS. Results contain only synthetic identities, selected sandbox
properties, outcomes and timing. The native execution is not performed by the
local unit tests. The first native run reached the correctly owned socket but
rejected the first authorized probe; its response omitted the precise probe
stage, so that cause remains unknown. Cleanup also failed because `userdel`
automatically removed the empty same-name group. Both failures are preserved.
The revised fixture records a bounded fixed-stage diagnostic and accepts group
absence only after checking both its owned name and GID. It has not yet passed a
native run; sandbox privileges and acceptance checks have not been relaxed.
The diagnostic iteration found only `CAP_SETUID` missing from permitted and
effective sets despite the exact requested bounding set. The no-site Python
child inherited that loss and the fixed `runuser` command failed. No file
capabilities or restrictive LSM label explained the difference. These results
remain FAIL; diagnostics never waive the capability check.

The official systemd [v255 execution path](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c#L4431-L4489)
and [v259 execution path](https://github.com/systemd/systemd/blob/v259/src/core/exec-invoke.c#L5531-L5594)
contain a conditional capability drop for an explicit user together with
seccomp restrictions. This supports a causal hypothesis, not yet a native
confirmation for the distribution build. A controlled variant omits only the
redundant `User=root` line from the broker and watchdog **system** services:

```sh
sudo env GITHUB_ACTIONS=true CI=true RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT" RUN_BROKER_REPRO=yes python3 -I -B broker_repro.py --implicit-system-root --output results-implicit
```

Use a fresh disposable runner per variant. The default command remains the
explicit-user baseline. All other unit directives, including `Group=root`,
`NoNewPrivileges`, address-family restrictions and the capability bounding set,
are byte-identical. No ambient capabilities are added. Both variants require
actual real/effective UID zero, the exact permitted/effective/bounding sets,
zero ambient capabilities, and successful fixed identity-drop commands.
The receipt records the variant, unit hashes and effective properties. The
variant has not yet passed native execution. It changes no production service.

Public source allowlist: `README.md`, `broker_repro.py`, `test_broker_repro.py`.
No private modules are imported or copied. No IP address, private account,
host inventory, SSH key, token, receipt, database data, or repository history is
included. Generated results require a separate privacy review before publishing.
