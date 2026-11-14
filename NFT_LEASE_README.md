# Timed kernel TCP gate: isolated reproduction

This standalone synthetic fixture tests whether an expiring nftables IPv4 set
can block both new TCP connections and traffic on an already established TCP
connection. A separate ungated connection must continue throughout the same
measurement. No application, account, credentials, external destination, or
production server is involved.

Run only on a disposable standard GitHub Actions Linux runner with Python 3,
iproute2 and nftables. Root is required exclusively for two newly created network
namespaces. The script refuses ordinary machines without all explicit CI flags.

```sh
python3 -I -B test_nft_lease_repro.py
sudo env GITHUB_ACTIONS=true CI=true RUN_NFT_LEASE_REPRO=yes python3 -I -B nft_lease_repro.py --output results
```

`results` must not already exist. The three cases are sequential and run once:

1. **Unsafe ordering:** `ct state established,related accept` precedes the gate.
   The fixture must reproduce continued traffic on the established connection
   after the lease expires, while new connections fail.
2. **Gate first:** input destination-port and output source-port gates precede
   conntrack acceptance. Both established traffic and new connections must stop.
3. **Renewal:** one atomic delete/add transaction extends the fixed test address
   lease. The original connection must survive the original deadline, then stop
   when the renewed lease expires. No automatic renewal runs afterward.

Every positive case requires live fixture processes, unchanged original TCP
connections, continuing ungated control bytes, failed new gated connections and
kernel drop counters in both directions. An unrelated target close, dead control,
missing counters, or short observation interval fails the fixture. The observation
lasts two seconds after a 700 ms allowance for packets already in flight.

Raw `nft -j` snapshots preserve table comments and timed element `timeout` and
`expires` fields before/after renewal and expiration. They contain synthetic data
only. The script saves a separate cleanup result and never reports overall PASS
when cleanup is unconfirmed. It deletes only its unique namespace handles after
verifying ownership, inode and absence of remaining processes. Host firewall,
SSH, routes and existing namespaces are not configured. Unknown resources are
preserved for inspection; no broad process kill or namespace cleanup is used.

This is an IPv4/TCP kernel containment test, not VPN authentication, per-user
revocation, TLS, IPv6, or a production cutoff SLA. Local Python tests exercise
adversarial verdict and cleanup logic; only a successful native run demonstrates
the kernel behavior. Native execution has not yet been performed for this candidate.

Public source allowlist: `README.md`, `nft_lease_repro.py`,
`test_nft_lease_repro.py`. Generated evidence should be reviewed separately before
publication. Do not copy deployment configuration or private evidence here.
