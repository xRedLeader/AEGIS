# Ubuntu installation package

This package installs the existing trusted assessment controller/gateway, the
untrusted delegated decision adapter, and the durable notification receiver as
separate non-root systemd services. The optional external provider runner uses
the trusted operator identity and needs a separate enable marker. Installing the
package does not authorize an engagement or approve a release.

Supported native hosts are Ubuntu 22.04 and 24.04 with systemd, unprivileged user
namespaces, mount namespaces, and libseccomp. Ubuntu 24.04 requires the included
named `aegis-supervisor` AppArmor profile. The installer never disables AppArmor
or changes global namespace policy. A failed kernel probe stops the gateway;
there is no unrestricted fallback. WSL can run the development regression suite
when its kernel and mounts support it, but is not a substitute for native-host
service evidence. Windows and macOS operators should use a dedicated Ubuntu VM
or remote Ubuntu host and transfer the same verified release artifact.

## Review and install

Use a reviewed source archive, verify `SHA256SUMS.txt` and its complete file set,
and independently obtain the exact commit and SHA-256 of the manifest. A commit
label alone does not authenticate downloaded bytes. The installer pins all file
bytes to the separately selected manifest digest; it does not fetch releases,
run repository hooks, or install application dependencies.

Create a dedicated root-owned Python virtual environment outside every code,
policy, evidence, scratch, and assessed-source tree. Install the exact versions
in `deployment/requirements.lock`; the installer rejects version drift and
non-root-owned or group/world-writable runtime files. The operating system and
Python interpreter are also part of the host's independently maintained trust
base. For example, on the disposable host chosen for installation:

```sh
sudo apt-get install python3-venv libseccomp2 apparmor apparmor-utils
sudo python3 -m venv /opt/aegis-runtime
sudo /opt/aegis-runtime/bin/pip install -r deployment/requirements.lock
sudo /opt/aegis-runtime/bin/pip uninstall -y setuptools
```

Copy `deployment/install.example.json` to an operator-controlled file. Select
explicit unused account names, numeric UIDs/GIDs, shared socket groups, source
roots and absolute paths. Select `apparmor_profile: "none"` only on 22.04;
24.04 requires `"aegis-supervisor"`. Set the reviewed commit and manifest digest.
Keep `configured: false` while reviewing the dry run:

```sh
/opt/aegis-runtime/bin/python aegis_install.py \
  --config /secure/operator/install.json --source /secure/reviewed-release
```

After reviewing the identities and paths, set `configured: true` and repeat the
plan, then explicitly apply it:

```sh
sudo /opt/aegis-runtime/bin/python aegis_install.py \
  --config /secure/operator/install.json --source /secure/reviewed-release --apply
```

The installer refuses existing conflicting accounts, paths, active AEGIS units,
source changes, or mutable runtime custody. Code goes in a root-owned immutable
release directory selected by commit. A root-owned receipt records source and
configuration hashes, every unit hash, and exact dependency versions. Receipts
and earlier release directories are retained. Units remain disabled and stopped.

The fixed launcher runs with Python isolation and imports only the selected
protected release. It verifies its effective UID, GID, supplementary groups,
source bytes and read-only mounts before accepting work. The controller also
performs the existing complete kernel-isolation probe inside its actual service
environment before binding the socket. Services have bounded CPU, memory, tasks
and file descriptors, no ambient capabilities, no new privileges, no core dumps,
read-only system/code/policy/source trees, and private temporary directories.
Their writable paths are restricted to each role's required private state.
`PrivateUsers` and `RestrictNamespaces` are deliberately absent: remapping peer
UIDs or blocking nested namespaces would break AEGIS's existing enforcement.
`ProtectKernelModules` is also omitted: its locked child mount beneath `/usr`
prevents the worker's deliberately nonrecursive read-only runtime bind. Module
changes remain denied by the empty capability sets, no-new-privileges setting
and worker syscall policy. The package does not import host submounts or weaken
the worker's namespace restrictions to accommodate systemd.

## Supply separate signed authority

Installation generates no signing keys and no enabled example engagement.
Provision each role's files into its root-owned policy directory, owned by that
role's UID/GID with mode `0400`. Keep signing authority outside the untrusted
adapter and outside assessed repositories. Paths and engagement IDs below must
agree with the selected installation configuration and independently signed scope.
The role directories themselves are root-owned, use that role's private group,
and have mode `0550`; this permits protected directory reads without exposing
another role's files or granting directory writes.

| Role directory | Required files |
| --- | --- |
| `operator/` | `scope.yaml`, detached raw `scope.sig`, `trust.json`, referenced scope public key, `assessment.json`, `delegation.json`, referenced delegation public key |
| `receiver/` | `receiver.json`, with receiver state path, operator sender UID, engagement IDs and configured receiver socket/group |
| `agent/` | `client.pem`, `grant.json`, detached raw `grant.sig`, created by the existing operator grant flow |

The gateway socket is `<run_root>/gateway/agent.sock`; the receiver socket is
`<run_root>/receiver/receiver.sock`. Their directories are owned by the relevant
service UID, mode `0710`, with the configured shared group. Sockets are `0660`.
The notification sender uses nofollow `O_PATH` directory traversal, so it can
verify socket custody through the group's search permission without directory
read access. Parent/file ownership and mode checks still apply.
The gateway admits only the configured adapter UID, and the receiver admits only
the configured operator UID. Unix group access does not replace these peer checks.

The operator's assessment policy must refer to approved fixed steps; signed
authority still controls every action. For notification steps, provision a
protected notification policy referencing the receiver socket and UID. Root
then explicitly starts the two services:

```sh
sudo /opt/aegis-runtime/bin/python aegis_install.py \
  --config /secure/operator/install.json --source /secure/reviewed-release \
  --action enable --apply
```

This writes a commit/configuration-bound enable marker and starts the receiver
and gateway. Their own preflight must succeed before any listener accepts work.
Inspect `systemctl status` and the `AEGIS_INSTALLED_PREFLIGHT` journal record;
a started process alone is not acceptance evidence. Boot activation is a separate
operator choice: `systemctl enable aegis-gateway aegis-receiver` after validation.
The adapter is a bounded oneshot: place only a supported JSON decision in
`<agent_state_root>/decision.json`, owned by the adapter UID, mode `0600`, then
start `aegis-agent.service`. It has no signing authority beyond its existing
explicit delegation grant. Replayed requests and mismatched proposed steps fail.

For the optional provider, follow `PROVIDER_RUNNER.md` and provision
`operator/provider-runner.json`, its protected role keys, and (for real Claude)
the protected API credential file. Select `<runner_root>` as its private run
directory. Its code, role policy and credentials are read-only inside the unit;
only the existing ledger, reports and separate runner scratch are writable.
After reviewing that authority, root may copy `enabled` to `provider-enabled`
with mode `0444`, then start `aegis-provider.service`. It is a trusted operator
service, distinct from the delegated adapter. A nonzero result requires inspection
of durable runner state before retry; no automatic oneshot restart is configured.

## Recovery, upgrades and removal

Graceful stops allow listeners to unlink their own sockets. After a crash the
launcher removes only a socket with the exact expected custody, only when a
connection proves no live listener exists, and only while the retained directory
and inode match. Regular files, symlinks, live listeners and uncertain failures
are rejected. The receiver commits notices before acknowledging them; a sender
that lost an ACK can retry and obtain an acknowledgment without a second receipt.

Before an upgrade, explicitly stop/disable the services using the installed
configuration and verified source. Install the newly reviewed commit with the
same selected identities and data paths, then review/re-enable the engagement.
Installation removes the old enable marker and preserves all role policies,
keys, reports, ledgers, receiver records, runner accounting, receipts and earlier
code directories. Changing identities or data custody requires a separately
planned migration; the installer will not silently chown existing evidence.

```sh
sudo /opt/aegis-runtime/bin/python aegis_install.py \
  --config /secure/operator/install.json --source /secure/reviewed-release \
  --action disable --apply
```

Use `--action uninstall --apply` to stop/disable services and remove only the
matching generated unit files. Modified units are preserved by refusing the
operation. Accounts, runtime, AppArmor profile, tmpfiles policy, code, policies,
credentials and all evidence remain for recovery or separately reviewed cleanup.
The package never recursively deletes deployment data. Retain and independently
verify off-host audit checkpoints before any operator-selected evidence cleanup.

## Acceptance evidence

`.github/workflows/packaged-deployment.yml` installs these actual units on fresh
native Ubuntu 22.04 and 24.04 runners. Its synthetic source-only engagement tests
disabled installation, real effective identities and privilege limits, immutable
mounts, kernel probes, exact socket group/modes, signed adapter execution,
wrong-peer and replay rejection, durable sender retry, and lost-ACK receiver
crash/restart recovery. Its JSON artifact binds results to the exact commit,
source manifest, configuration and runtime versions. CI requires no provider
credential and makes no requests to the user's live application.

Run the existing `aegis_host_acceptance.py` diagnostic in each intended service's
actual installed environment and retain the corresponding configuration, unit
receipt and signed evidence. Package CI is engineering evidence, not approval of
an operator's deployment. The named host, real authorized application pilot,
independent review, staging/recovery exercises, off-host retention verification,
and release owner's decision remain separate gates.
