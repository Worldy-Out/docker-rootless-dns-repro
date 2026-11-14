# Synthetic cold and warm systemd user-manager lifecycle

**Prepared, not yet executed natively.** This independent fixture contains no
application code or deployment inventory. It exercises a new disposable account
on a standard GitHub-hosted `ubuntu-24.04` runner. Actual OS, systemd and kernel
versions are recorded; this is not evidence of Ubuntu 26.04 compatibility.

The separate manual-only `user-manager.yml` workflow does not invoke any DNS,
Docker, broker, or network test. It installs no packages and uses no cache,
uploaded artifacts, secrets, custom runner, or additional paid resource.

```sh
python3 -I -B test_user_manager_repro.py
sudo env CI=true GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted RUN_USER_MANAGER_REPRO=yes python3 -I -B user_manager_repro.py --output manager-results
```

Native scope is one fresh synthetic account, no linger, only its own bounded
synthetic PAM session, no SSH configuration and no external network. A single exact disabled canary is
installed under its private home. Its source, ancestry and lack of enablement
are checked offline before starting the manager; `systemctl --user` is only
used after a real bus exists. Global distribution user services are not modified.
The experiment is not a substitute for an application-specific offline startup
graph and source allowlist, which require their own production-code tests.

The experiment has two explicit manager starts and a separate PAM-created manager observation:

1. Prove missing bus and inactive manager/runtime-dir before any `runuser` call.
   Run `systemctl start --no-block user@16067.service` once, wait at most 30 seconds
   for its actual PID, InvocationID and Unix bus, then prove the canary is disabled,
   inactive and PID zero. A 12-second observation records the direct manager with
   zero login sessions and linger off; this is not an indefinite hold proof. An
   injected failure after this online proof tests
   ownership-qualified cleanup.
2. Recreate the manager once as a separate synthetic case. Its InvocationID must
   change while the canary source seal stays identical. An inner warm consumer
   must issue zero starts/stops and preserve this exact manager generation. The
   outer harness then stops only the manager it owns.
3. A bounded synthetic system service uses `User=manager-fixture`, `PAMName=login`
   and `sleep 15` to create a real login session. The inner warm consumer again
   makes zero starts/stops. After the session ends naturally, the harness observes
   manager/bus state for 30 seconds without changing linger or logind policy.
   Survival or disappearance is recorded as a factual distribution behavior.
   Neither outcome proves an indefinite manager hold or application safety. Only
   the outer disposable harness cleans up its own session-created generation.

Cleanup first verifies current boot, manager and runtime-dir generation, bus
inode, no foreign sessions and no unexpected active user service or scope. Only then
may it stop its owned manager. The post-stop runtime-dir/bus state is observed;
if the runtime-dir remains active, only its unchanged owned generation may be
stopped separately. `/run/user` is never manually created or deleted. The new
account, group and exact unchanged canary files are removed only after confirmed
cold state and process absence. Any unknown state is FAIL and leaves ambiguous
resources for disposal with the disposable runner. It never kills all user
processes or stops a preexisting manager.

The script has a 180-second working deadline and a separate 60-second cleanup
budget; every command is bounded;
the workflow is capped at eight minutes. This does not prove safe recovery from
SIGKILL or a host crash. The hosted runner is disposable; do not run the fixture
on a workstation, shared Linux host or a deployment server.

Local fake-adapter tests separately cover missing bus, failed reads, cold/warm
branching, exactly one attempted start when its acknowledgement becomes unknown, identity drift, foreign
sessions/services, and runtime-dir ownership. They make no native claim. An
unknown start acknowledgement blocks retry and guessed rollback; the native
failure case is explicitly **after a successful online ownership proof**.

Public allowlist for this addition: `user_manager_repro.py`,
`test_user_manager_repro.py`, `USER_MANAGER_README.md`, `USER_MANAGER_SHA256SUMS`,
and `.github/workflows/user-manager.yml`. No existing reproduction is modified.
Review the synthetic result before publishing it. PASS requires all native
checks plus confirmed cleanup; it says nothing about application authorization,
Docker, VPN connectivity, database safety, or production startup.
