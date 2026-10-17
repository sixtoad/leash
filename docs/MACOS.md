# Leash on macOS

Leash on macOS can run natively with a companion app that installs two system extensions:

- Endpoint Security (ES) extension for exec/file monitoring
- Network Extension (NE) filter for per‑directory network policy

This is a native alternative to the Linux container path and does not launch the local HTTP MITM proxy on macOS. Leash on macOS does not use `sandbox-exec`. Native `--darwin` mode is still highly experimental.

## Requirements

- macOS 14+ (Sonoma or newer)
- Administrator approval to activate system extensions

## Install & Activate

1. Open `Leash.app`.
2. In the app window, activate both extensions:
   - Endpoint Security -> “Activate”
   - Network Filter -> “Activate”
3. Approve the prompts in System Settings when macOS asks for permission.

## Verify Status

Start with `leash doctor`, which grades the whole macOS stack in one shot and
exits `0` (enforcing), `3` (running, but not fully enforcing) or `1` (cannot
enforce). `leash doctor --json` emits the same facts as a machine-readable
document — see [API contracts](api-contracts-leash-core.md#node-readiness--leash-doctor---json)
for the `darwin` section's fields.

```console
$ leash doctor
macOS enforcement: DEGRADED (runs, not fully enforcing)
  ES extension:     active
  content filter:   active
  proxy extension:  missing
  full disk access: granted
  daemon:           up (127.0.0.1:18080)
  connected:        leash.es, leash.netfilter
```

It checks the three system extensions' activation, whether each is actually
*connected* to the daemon (an activated extension that never connected holds no
rules and enforces nothing), Full Disk Access, the daemon on `:18080`, and the
companion `leashcli` binary.

If it reports **"a connected client that does not identify itself"**, the
installed extensions predate the `component` field in `client.hello` (through
Leash.app `1.1.0/20251027.1`): they register as `unknown`, so doctor can see that
something is connected but not which extension. Rebuild and re-activate the
extensions from this tree to get a per-extension answer. Two flags cover the development seams:
`--leash-cli-path` for a locally built `leashcli`, `--darwin-daemon` for a daemon
on another port.

The panes below are what doctor is reading, when you want to check by eye:

1. System Settings -> General -> Login Items & Extensions -> Extensions
   - Network Extensions -> “Leash (Leash Network Filter)”
   - Endpoint Security Extensions -> “Leash (LeashES)”
   - On macOS 15+, change the view to “By Category” to find them quickly.
2. System Settings -> Network -> VPN & Filters -> “Leash Network Filter” should show a green indicator and “Enabled”.

## Full Disk Access

The ES extension needs Full Disk Access to observe events:

System Settings -> Privacy & Security -> Full Disk Access -> enable for “LeashES”.

Without it, `es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`,
LeashES reports the failure to the daemon and exits — so the extension looks
activated while delivering no file events at all. macOS exposes no API for
reading another process's TCC grant, so `leash doctor` relays LeashES's own
verdict from the daemon rather than guessing.

LeashES advertises the grant as a `full-disk-access` capability in every
`client.hello`, so it re-arrives on each reconnect and survives a daemon restart.
It also emits `es.full_disk_access.ready` at startup, which covers its very first
connection. If doctor still reports `unknown` — which never counts as ready —
either the extension has not reconnected since the daemon started (wait a few
seconds), or it predates the capability and Leash.app needs rebuilding.

## Darwin-Specific Commands

### Start the Darwin Server

```bash
leash --darwin exec <your_command>
```

This automatically starts the WebSocket API server and web interface at [localhost:18080](http://localhost:18080), if they are not already running.

### Stop the Darwin Server

```bash
leash --darwin stop
```

Stops the running server.

## Remove / Uninstall

Deleting `Leash.app` should delete the system extensions, but you can also use the the app UI (each section has a “Remove” button). You can also remove from the terminal:

```bash
systemextensionsctl uninstall W5HSYBBJGA com.strongdm.leash.LeashES
systemextensionsctl uninstall W5HSYBBJGA com.strongdm.leash.LeashNetworkFilter
```

## Troubleshooting

### Stream Logs

```bash
log stream --style compact --level debug --predicate 'subsystem == "com.strongdm.leash"'
```

Examples:
- Only network filter logs: add `AND category == "network-filter"`
- Watch a specific leash PID: pipe to `grep "leash=<PID>"`

### Console.app

- Open Console.app -> Start
- Search for `com.strongdm.leash` and switch the filter to “Subsystem”

## Known Limitations

- No HTTP header injection or rewrite on macOS: the local MITM proxy is not launched; enforcement is via the Network Extension only.
- MCP logging is not emitted on macOS today.
- IP range (CIDR) matching is not implemented yet; hostnames and single IPs are supported.
- Default network behavior is fail‑open for flows missing PID metadata; enable “Enforce rules for untracked processes” in Settings to evaluate them.
- `leash --darwin exec …` expects the companion CLI at `/Applications/Leash.app/Contents/Resources/leashcli`; moving the app can break launches.
- Requires macOS 14+ for extension activation.
- Only supports connecting to the server at `localhost:18080`

## Enforcement preflight (native mode)

Native `--darwin` enforcement is the Endpoint Security (ES) and Network
Extension (NE) system extensions. There is no second layer behind them on
macOS, so leash **refuses to start** unless both are activated: `leash --darwin
exec` (in the terminal, before the daemon is started) and the daemon itself
query `systemextensionsctl list` and stop with the per-extension state and the
activation steps. There is no opt-out and no degraded mode: the old
`LEASH_REQUIRE_ENFORCEMENT` switch is gone because refusing is now the only
behaviour. A `systemextensionsctl` that cannot be run (for example exit 69,
`EX_NOPERM`) counts as "not active", and its error is printed.

The match is on the bundle-id column exactly, so a sibling extension whose id
starts with leash's cannot make leash look enforced.

Full Disk Access and "is the extension actually receiving rules" are answered by
`leash doctor` rather than by this preflight — see [Verify Status](#verify-status).
Both come from the running daemon (`GET /health/darwin`), because neither can be
observed from outside the processes that hold them.

## Not supported in native macOS mode

- `--inject-service` (and its `authz=` plugin authorization socket, #152) is
  refused by `leash --darwin exec`: darwind serves no plugin authorization
  socket and there is no box to bind a plugin's socket into. Use the Linux
  runtime (container or native Linux) for plugins.
