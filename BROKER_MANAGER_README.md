# Synthetic systemd 259 private-manager socket reproduction

This standalone fixture runs only on an explicitly opted-in, disposable GitHub-hosted Ubuntu 26.04 runner. It requires both the installed `systemctl` client and PID 1 to report systemd major 259 before creating anything. It records full versions, including the user manager. The current runner may supply a later 259 stable release; this is **not an exact 259.5 native acceptance claim** and proves nothing about a production installation.

The fixture contains generic code and synthetic identities only. It imports no application modules and uses no credentials, real inventory, private evidence or externally reachable service. It does not invoke a container engine, make external requests, pull images, configure a firewall, change routes, enable linger, modify user-manager units or launch other workflows. The older 255 fixture remains separate and unchanged.

## Primary-source mechanism

In [systemd v259.5 systemctl-show.c](https://github.com/systemd/systemd/blob/v259.5/src/systemctl/systemctl-show.c#L2292), `show` requests the manager bus. [systemctl-util.c](https://github.com/systemd/systemd/blob/v259.5/src/systemctl/systemctl-util.c#L40) passes that request to the manager transport. [bus-util.c](https://github.com/systemd/systemd/blob/v259.5/src/shared/bus-util.c#L247) connects to `$XDG_RUNTIME_DIR/systemd/private`. Its local-user branch falls back to the session bus only when XDG_RUNTIME_DIR is absent (`ENOMEDIUM`), not when the private socket is missing (`ENOENT`).

[v255](https://github.com/systemd/systemd/blob/v255/src/shared/bus-util.c#L217) instead falls back after any failed private-socket connection. This makes a session-bus-only bind an insufficient regression on 255. The complete `bus_connect_user_systemd` and `bus_connect_transport_systemd` function bytes were independently compared between upstream tags [v259.5](https://github.com/systemd/systemd/blob/v259.5/src/shared/bus-util.c) and [v259.9](https://github.com/systemd/systemd/blob/v259.9/src/shared/bus-util.c): identical, with SHA256 respectively `5f2eba4c0e4e64b795f922e5968137def0de1ead23363abce1e14a913e99d80f` and `be9f917aa2cf023b32c40efb4b940cc8b7d8ac936b4900ce909acea6a1cb06df`. This establishes source-level equivalence for those functions, not equivalence of every distribution patch or native component.

## Native cases

The harness creates one dedicated account (UID/GID 16064), private fixture directories and a disabled `docker.service` surrogate whose only possible executable is `sleep`. The surrogate is **never started**; the name does not refer to Docker. Its loaded/inactive/PID0/disabled state and `ExecMainStartTimestampMonotonic=0` are checked before and after every case. One known user-manager generation is started and later stopped once.

Five bounded transient root probes use identical capability, NoNewPrivileges, ProtectSystem, address-family and lifetime restrictions:

1. `ProtectHome=yes`: the private socket is hidden and the fixed query must return the exact upstream C-locale privilege-denied diagnostic with its fixed advisory. Root may observe the mount as empty while the dropped UID cannot traverse it.
2. `ProtectHome=tmpfs` with a read-only bind of only the session `/bus`: that socket must match the host inode, while the private socket is absent and the distinct exact C-locale missing-file diagnostic must occur.
3. `ProtectHome=tmpfs` with a read-only bind of only `/run/user/16064/systemd/private`: the fixed query must succeed. The probe also submits one fixed `stop` for the already inactive surrogate and proves it remained never started.
4. Missing private socket: reject before the user command.
5. Foreign-owned private socket: reject before the user command.

Successful private-socket access requires the host socket's exact device/inode/owner/mode, a kernel read-only mount, and no other files beneath the namespace's synthetic runtime directory except `systemd/private`. The session socket, fixture home, root marker and another UID's runtime directory remain hidden. Both environment variables stay set in every query; no forced-session-bus workaround is used.

A final owned-manager stop must remove its runtime directory and both sockets, with no remaining UID processes. Account, group, probe processes and exact owned fixture files must be absent before cleanup is PASS. Unknown start/stop acknowledgements, foreign generations, identity changes and partial setup remain FAIL with preserved state; there is no automatic retry, broad deletion or guessed cleanup.

## Running and publication scope

The manual `broker-manager-259.yml` workflow uses the standard free `ubuntu-26.04` runner, contents-read permission and an eight-minute job limit. Native execution has a five-minute scenario bound plus a 90-second cleanup bound. The workflow verifies checksums and offline contracts first, then prints bounded synthetic JSON. No package installation or old DNS scenario is run.

Only these five files are publishable:

- `broker_manager_repro.py`
- `test_broker_manager_repro.py`
- `BROKER_MANAGER_README.md`
- `BROKER_MANAGER_SHA256SUMS`
- `.github/workflows/broker-manager-259.yml`

Offline tests validate failure classification, exact version gates, socket identity, positive-query-before-stop ordering, post-stop never-started readback and cleanup latches. They are not native systemd acceptance. A native failure preserves its actual diagnostic and must not be rewritten as PASS.

The first 259 native run stopped at the original-sandbox classifier: the hidden socket produced the upstream privilege-denied branch, whereas the initial fixture incorrectly required missing-file there. Cleanup succeeded; that run remains FAIL, and no candidate success is claimed from it. This revision distinguishes those two source-defined branches and records bounded synthetic stderr before asserting. Unknown text, extra lines, wrong branch or an unexpectedly successful negative query still fail. No sandbox property, fixed command or cleanup scope changed.
