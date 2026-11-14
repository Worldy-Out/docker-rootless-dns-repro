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

## First native result and bounded cleanup correction

The first native run (workflow run `43620220396`, source `8ad29fc`) remains FAIL.
On Ubuntu 24.04.5 / systemd 255.4 it proved cold missing bus, a new online manager,
the disabled canary and 12.175 seconds of direct-manager observation. It then
reported `Incomplete manager cleanup`; no second stop was issued and the account
was preserved. The final teardown snapshot was not captured, so this does not
prove whether the bus was genuinely still present or was read before later
systemd state changed. No successful cleanup is inferred retrospectively.

The corrected read-only wait requires coherent before/after unit and filesystem
observations. Cold units alone are insufficient: the bus and runtime directory
must also be absent, with no processes or sessions. Intermediate teardown is
polled within the original 30-second deadline; the sole optional runtime-dir
stop still requires the exact originally owned active generation. There is no
additional manager stop or automatic retry. Bounded stop observations and a
failure snapshot are now recorded. Fake-adapter regression exercises lingering
bus, lingering directory, inconsistent read boundaries and deadline failure.
These corrections have not yet passed a new native run.

## Accepted direct cases and isolated PAM diagnostic

Run `43620948588` (source `49c0b61`) natively passed the direct cold startup,
post-online failure cleanup, second cold startup, warm zero-mutation consumer,
and complete second manager/runtime-directory cleanup. It recorded intermediate teardown followed by
coherent cold units and absent bus/runtime directory. Those accepted direct
cases need not be repeated while their code is unchanged.

The same run remains overall FAIL: the later PAM scenario reached its ten-second
online deadline. The failure snapshot showed a live manager, bus and login
session, but the transient system service properties were not retained. Its
precise readiness failure is therefore unproven. Unknown PAM ownership correctly
prevented further stop or account deletion; no successful PAM cleanup is claimed.

Use the separate manual workflow input `phase: pam-only` for the next diagnostic.
It creates a fresh synthetic account and executes no direct manager start cases.
The receipt explicitly labels this limited scope and `directCases: NOT_RUN_IN_PAM_ONLY`.
The default `all` phase preserves the original sequence. The PAM phase now saves
at most 24 changed service/manager observations, including fixed systemd service
state, Type, MainPID/ExecMainPID, InvocationID, result, job and monotonic timestamps,
plus the original readiness booleans. It reads no authentication log, environment
or unrestricted journal. Readiness still requires the original active service
and manager, bus and login session; no new service state or zero PID is accepted.
The diagnostic result is recorded below; the strict readiness criterion was not relaxed.

## Optional PAM result: inconclusive post-session behavior

Run `43621692444` (source `7aa9de4`, phase `pam-only`) remains **FAIL**, with
`directCases: NOT_RUN_IN_PAM_ONLY`. Its verified result SHA256 is
`4ac01ddcc0a157be046c5f88b86f809772a6bab5e6b4fc8bc53db80309bd54a6`.
No accepted direct cold/warm case was repeated in this run.

From 0.415 through 10.106 seconds, the manager, bus and login session were
observed active, while the owned transient service remained
`Type=exec`, `ActiveState=activating`, `SubState=start`, with unchanged
InvocationID, `MainPID=ExecMainPID=2256` and pending job `1388`.
The interim `Result=success` property does not establish completed activation:
`ownServiceActive` remained false. The exact readiness check correctly reached
`PAM online deadline`. No cause for the pending activation is inferred.

The post-session observation phase was never reached. Therefore manager survival
after PAM session termination remains **INCONCLUSIVE**, not PASS or evidence of
an indefinite hold. Cleanup stayed **FAIL / UNKNOWN_PAM_START_PRESERVED**;
unknown ownership was not converted into permission to stop or delete the
synthetic account. Both this result and the earlier overall FAILs are retained.
No further PAM changes or retries are planned in this fixture.

The accepted direct cold-start, disabled-canary, warm zero-mutation and owned
manager/runtime-directory cleanup evidence from run `43620948588` remains
separate and unchanged. It is not a successful whole-fixture cleanup or a
production installer acceptance. An independent direct-manager/explicit-linger
implementation still needs its own real post-session-disconnect readback of
manager generation and linger before starting workloads. Neither this optional
PAM experiment nor the Ubuntu 24.04 runner proves that acceptance on another OS.
