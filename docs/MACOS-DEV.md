# Developing the mac-leash Swift extensions without an Apple entitlement grant

The macOS native path (`mac-leash/`) ships two system extensions that need
**restricted, Apple-approved entitlements**:

- `com.apple.developer.endpoint-security.client` (LeashES)
- `com.apple.developer.networking.networkextension` = `content-filter-provider` (LeashNetworkFilter)

These are only honored when they come from an Apple-issued provisioning profile
bound to your Team ID. The production build uses team `W5HSYBBJGA`. To iterate on
the Swift **without** a paid account / entitlement grant / notarization, you run
in a **VM with SIP and AMFI relaxed**, and self-sign.

> Local development never needs notarization. Notarization only matters for
> distributing to other machines.

## 1. A macOS VM you can lower security on (Apple Silicon)

macOS guests on Apple Silicon run only under Virtualization.framework. Use a tool
that can boot the guest into **Recovery** (required to disable SIP):

- **VirtualBuddy** (free, purpose-built, easiest) — `brew install --cask virtualbuddy`
- UTM, Tart, or Parallels also work.

Create the VM from a macOS restore image (the tool downloads it). Give it ~4 CPUs,
8 GB RAM, 60+ GB disk.

## 2. Relax SIP + AMFI (two reboots)

The order matters — `boot-args` is SIP-protected, so it can only be written once
SIP is *actually* off, which needs a reboot.

1. Boot the guest into **Recovery**, open Terminal:
   ```
   csrutil disable          # confirm y, authenticate
   ```
2. **Reboot fully into the normal guest.** Verify:
   ```
   csrutil status           # must say: disabled
   ```
3. Now set the AMFI boot-arg (makes the OS accept self-signed restricted entitlements):
   ```
   sudo nvram boot-args="amfi_get_out_of_my_way=0x1"
   ```
   If this still says `not permitted` with SIP confirmed disabled, you hit the
   Apple-Silicon boot-args restriction — lower the guest to Permissive Security in
   Recovery via `bputil` (`bputil --disable-boot-args-restriction`), then retry.
4. **Reboot again** for the boot-arg to take effect.

## 3. Prove the entitlement is honored (go/no-go gate)

Before building anything, run the probe in `mac-leash/devtools/esprobe/`:

```
sh mac-leash/devtools/esprobe/run.sh
```

Read the result code:

| Code | Meaning | Action |
|------|---------|--------|
| `0`  | SUCCESS | fully working — proceed to build |
| `3`  | NOT_ENTITLED | **bypass failed** — VM route is dead, use a fallback |
| `4`  | NOT_PERMITTED | run with `sudo` |
| `5`  | NOT_PRIVILEGED | bypass works; grant Full Disk Access to the terminal, rerun |

If you get `3` even with SIP disabled and the boot-arg set, this VM cannot host an
un-granted ES entitlement. Fallbacks: disable SIP on a **spare physical Mac**, or
request the **paid Apple ES entitlement grant** (which removes the need to relax
anything).

## 4. Build / sign / run loop

1. **Patch the Team-ID trust anchor first.** `Shared/LeashIdentifiers.swift` pins
   team `W5HSYBBJGA`, and the ES extension authorizes `leashcli` by matching
   `team_id`. Ad-hoc binaries have **no** team ID, so this check fails silently and
   execs won't be authorized. For dev builds, match on `signing_id`/cdhash instead.
2. Set the Xcode targets to ad-hoc / manual signing (or your own team).
3. Build, then ad-hoc sign each target with its entitlements:
   ```
   codesign --force --sign - --entitlements <target>.entitlements --options runtime <binary>
   ```
4. Enable developer mode so self-signed sysexts load from anywhere:
   ```
   systemextensionsctl developer on
   ```
5. Launch `Leash.app`, activate both extensions, approve the NE content filter in
   System Settings, grant Full Disk Access to LeashES.
6. Iterate — with developer mode on, changed extensions reload without the full
   uninstall dance.

## Security note

Disabling SIP + AMFI removes real OS protections. Do this **only in a throwaway VM**,
never on a machine you care about.
