# Named declarations and anonymous nft JSON expressions

This independent synthetic experiment runs only on an explicitly enabled,
standard GitHub-hosted Ubuntu 26.04 runner with nftables 1.1.6. It does not import
application code or use production inventory, credentials, addresses, or receipts.
Only documentation IPv4 space and inert example ports are used.

One `unshare --net` child creates one table with a finite named IPv4 set and two
anonymous port-set expressions. Its chain has **no hook**: it handles no traffic.
The outer process stays in its original network namespace. There is no Docker,
SSH, service, account, package-install, DNS, or host ruleset operation.

The native assertions distinguish two JSON contexts:

* A top-level `nftables` row `set` is a named declaration object with an exact
  identity, `flags: ["timeout"]`, and integer seconds.
* A rule's anonymous port expression is `{"set": [...]}`. Its array, order and
  every member remain intact. It is not a named declaration.

The experiment captures exact raw JSON before inserting a single finite element,
while active, and after natural expiry. It compares all static fields, retaining
handles, and normalizes only validated lease elements and counter-expression
values. Rate-limit fields are not discarded. It records the text printer's
default-timeout flag elision separately; JSON flags are still required.

Upstream primary source for this representation is nftables 1.1.6:
[`src/json.c`](https://git.netfilter.org/nftables/tree/src/json.c?h=v1.1.6)
(`set_expr_json`, `set_ref_expr_json`, `set_print_json`) and
[`src/rule.c`](https://git.netfilter.org/nftables/tree/src/rule.c?h=v1.1.6)
(default-timeout text printer). The
[official source release](https://www.netfilter.org/projects/nftables/files/nftables-1.1.6.tar.xz)
was inspected separately; this workflow uses the runner's installed executable
and reports its complete version, kernel and Python versions.

Cleanup requires the accepted full empty snapshot, compares every static field
again, validates the table identity and positive integer handle, then executes
`delete table inet handle N` once, proves the namespace ruleset is empty, and
waits for the namespace child to exit. Unknown cleanup stays FAIL. There is no
name-based fallback or mutation retry. All remaining namespace objects disappear
with the owned child. The job deadline is eight minutes; the experiment itself
has a 45-second outer deadline. Output is bounded, synthetic and shareable.

This is a serialization/finite-element regression. It does **not** prove traffic
filtering, established-flow cutoff, an application's parser, or production cleanup.
Existing networking and DNS experiments are not run by this workflow.

Run offline tests with `python3 -I -B test_nft_json_repro.py`. Native execution is
manual-workflow-only; do not run it on a personal server or self-hosted runner.
