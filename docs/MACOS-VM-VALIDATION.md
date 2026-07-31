# macOS VM validation pass

How to validate the macOS parity work (P0 fail-closed + P1 proxy scaffold) in a
SIP/AMFI-relaxed VM. Prereqs: the VM is set up per `docs/MACOS-DEV.md` (SIP off,
`amfi_get_out_of_my_way=0x1`, `systemextensionsctl developer on`, rebooted) and
`mac-leash/devtools/esprobe/run.sh` returns `0`.

## 0. Build & deploy

Two artifacts must reach the VM:

1. **`Leash.app`** (extensions) — build + ad-hoc sign on the host:
   ```bash
   cd mac-leash
   xcodebuild -project Leash.xcodeproj -scheme Leash -configuration Debug clean build
   # (the Ad-hoc Sign phase runs automatically)
   ```
   Zip with `ditto -c -k --keepParent .../Debug/Leash.app Leash.zip`, copy to the VM,
   unzip with `ditto -x -k Leash.zip .`, move to `/Applications/`.

2. **`leash` Go binary** (daemon + `--darwin exec`) — needs the Control UI embedded:
   ```bash
   make build-ui      # writes internal/ui/dist (or: mkdir -p internal/ui/dist && echo '<html></html>' > internal/ui/dist/index.html  for a throwaway)
   make build         # produces the leash binary
   ```
   Copy `leash` into the VM (on PATH). `leash --darwin exec` expects the companion CLI
   at `/Applications/Leash.app/Contents/Resources/leashcli`.

Stream logs in a second terminal throughout:
```bash
log stream --style compact --level debug --predicate 'subsystem == "com.strongdm.leash"'
```

## 1. Activate extensions

1. Open `Leash.app` → Activate **Endpoint Security** and **Network Filter**; approve in
   System Settings. Grant **Full Disk Access** to LeashES.
2. Confirm: `systemextensionsctl list` shows both `[activated enabled]`.
3. System Settings → Network → VPN & Filters → "Leash Network Filter" is green/Enabled.

---

## Tier 1 — P0 fail-closed (the core; fully ready)

Enforcement applies only to leash-tracked PID lineage, so denials can't brick the host.

### 1a. Baseline (permissive policy → everything allowed)
With no `LEASH_POLICY` set, the bootstrap policy is permissive. Confirm a workload runs:
```bash
leash --darwin exec -- curl -sSI https://example.com
leash --darwin exec -- ls /etc
```
Both should succeed. Log shows `ALLOW`.

### 1b. Exec default-deny
Write a tightened policy that allows only a couple of binaries:
```
# tight.cedar
permit (principal, action == Action::"ProcessExec", resource)
  when { resource in [ File::"/bin/ls", File::"/usr/bin/curl" ] };
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
  when { resource in [ Dir::"/" ] };
permit (principal, action == Action::"NetworkConnect", resource)
  when { resource in [ Host::"*" ] };
```
Run the daemon with it: `LEASH_POLICY=$PWD/tight.cedar leash --darwin exec -- bash -c 'ls; whoami'`
- **Expected:** `ls` ALLOWED, `whoami` (i.e. `/usr/bin/whoami`, not listed) **DENIED** (killed).
- Log: `No policy match … → DENY (default-deny)`. **This is the P0 exec win.**

### 1c. File default-deny
Restrict file opens to a directory, then read outside it:
```
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
  when { resource in [ Dir::"/tmp/" ] };
permit (principal, action == Action::"ProcessExec", resource) when { resource in [ Dir::"/" ] };
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"*" ] };
```
`leash --darwin exec -- cat /etc/hosts` → **DENIED**; `cat /tmp/x` (after `echo hi >/tmp/x`) → allowed.

### 1d. Network default-deny + DNS exemption
Allow only one host:
```
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"example.com" ] };
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource) when { resource in [ Dir::"/" ] };
permit (principal, action == Action::"ProcessExec", resource) when { resource in [ Dir::"/" ] };
```
- `leash --darwin exec -- curl -sSI https://example.com` → **allowed**.
- `leash --darwin exec -- curl -sSI https://www.google.com` → **DENIED** (flow dropped).
- **DNS still resolves** (name lookups aren't dropped) — the denial is the TCP connect,
  not resolution. Confirm curl fails at connect, not DNS. **This is the network fail-closed + DNS-exemption win.**

### 1e. CIDR matching (was a stub returning false)
```
permit (principal, action == Action::"NetworkConnect", resource) when { resource in [ Host::"93.184.216.0/24" ] };
... (permit file + exec as above) ...
```
Connect to an IP inside the range → allowed; outside → denied. Confirms `isIPInRange` works.

### 1f. Domain persistence across restart
1. Under a hostname policy, make a request so a domain→IP mapping is learned.
2. Confirm `~/Library/Application Support/com.strongdm.leash/resolved-domains.json` exists and has entries.
3. Toggle the Network Filter off/on (or reboot). Log shows `Restored N resolved domains from disk`.

### 1g. Fail-open degrade (daemon down)
Stop the daemon (`leash --darwin stop`) while a tracked workload is mid-run, or before policy
loads. Tracked processes should **degrade to allow + log** (not brick) — the "not
--require-lsm" behavior. (Hard-fail-when-required is a separate unshipped P0 item.)

---

## Tier 2 — P1 transparent proxy (scaffold; smoke test only)

**Not end-to-end yet.** `TransparentProxyManager.activate()` isn't wired into the app UI,
and the provider relays *all* TCP flows (tracked-PID gating stubbed). So:

- **Buildable/embed check (done on host):** the `LeashProxy.systemextension` is embedded and
  ad-hoc signed with `app-proxy-provider`.
- **Smoke test (VM):** if activation is triggered, `systemextensionsctl list` should show
  `com.strongdm.leash.LeashProxy [activated enabled]`, and the darwind proxy (`:18000`) should
  log PROXY-protocol connections when a flow is relayed. Watch category `transparent-proxy`.
- **Blocked until:** activate() is called from the app lifecycle, tracked-PID gating lands, and
  the darwin CA path is confirmed for `leashcli` injection. See `docs/MACOS-P1-PROXY.md`.

To make P1 testable, the next host-side change is wiring `TransparentProxyManager.activate()`
into the app (alongside the existing `NetworkFilterManager.activate()` call) + the PID gate.

---

## Recording results

For each Tier 1 check, note: policy used, command, observed decision (log line), pass/fail.
File issues for any divergence. The NEMachServiceName caveat (#19) is worth an explicit check:
confirm the **network filter registers at all** under ad-hoc (empty team prefix) — if it doesn't,
that's the prime suspect.

---

## Debug logging (transparent proxy)

Verbose per-flow diagnostics for the transparent proxy are gated behind
`LEASH_MAC_DEBUG` on the **daemon**. Off by default; toggling it is a daemon
restart — no extension re-activation.

Enable:

```
pkill -f "leash --darwin"        # stop the managed daemon
LEASH_MAC_DEBUG=1 leash --darwin exec -- true   # restart it with debug on
```

The daemon pushes the flag to each extension over the websocket on connect
(message `mac.debug`), and the transparent-proxy provider emits to the daemon
log (readable via the `--log`/`LEASH_LOG` file):

- `event=proxy.start status=started relay=127.0.0.1:18000` — `startProxy` result.
- `event=proxy.pids count=N` — each tracked-PID update the provider receives.
- `event=proxy.flow pid=… tracked=yes|no tracked_count=N dest="ip:port"` — every
  process-attributed flow offered to `handleNewFlow` and how PID gating resolved.

This is the fastest way to diagnose "the proxy isn't intercepting": confirm the
flow reaches the provider (`proxy.flow`), that its PID is tracked (`tracked=yes`),
and the destination resolves. Leave `LEASH_MAC_DEBUG` unset in normal use — the
per-flow events are suppressed at the source.
