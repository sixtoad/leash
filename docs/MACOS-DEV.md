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

**No source patch is needed for ad-hoc signing.** The ES extension's `leashcli`
trust check (`LeashES/LeashMonitor+Handlers.swift` `isLeashExecutable`) already
degrades correctly: it trusts the binary at `/Leash.app/Contents/Resources/leashcli`
by path (no signing check), and when matching by `signing_id` it skips the team
comparison if the process has no `team_id` — which is exactly the ad-hoc case. The
hardcoded `W5HSYBBJGA` in `Shared/LeashIdentifiers.swift` is only a last-resort
default (overridable via `LEASH_TEAM_IDENTIFIER`, or auto-derived from the app's
`AppIdentifierPrefix` when signed with a real team). So:

1. The targets are already configured for this: **manual signing**, `CODE_SIGN_IDENTITY
   = "-"` (ad-hoc / "Sign to Run Locally"), empty `DEVELOPMENT_TEAM` /
   `PROVISIONING_PROFILE_SPECIFIER`, and the existing `com.strongdm.leash.*` bundle
   identifiers are kept (avoids needing the IDs registered to your team). Do not
   switch to automatic signing — that forces a team + a bundle-ID change.
2. Build the `Leash` scheme in **Debug**. Note that Xcode will *not* ad-hoc sign the
   restricted ES / NetworkExtension entitlements inline — with a real identity it
   demands a provisioning profile ("`LeashES requires a provisioning profile`"). The
   project works around this **only in Debug**: `CODE_SIGNING_ALLOWED = NO` lets the
   build finish unsigned, then an **"Ad-hoc Sign (local, no account)"** run-script
   phase invokes `mac-leash/adhoc-sign.sh` to re-sign the app and nested extensions
   bottom-up **with** their entitlements. (`ENABLE_USER_SCRIPT_SANDBOXING = NO` in
   Debug lets that script run.) The result is a one-shot Debug build that produces a
   fully ad-hoc-signed `Leash.app`; the relaxed VM then honors the entitlements
   (proven by the esprobe result of `0`). You can also run `adhoc-sign.sh` standalone
   against an already-built `.app`. The **Release** config is untouched and still
   expects real signing for when a team/provisioning is available again.
3. Enable developer mode so ad-hoc sysexts load without notarization / matching team:
   ```
   systemextensionsctl developer on
   ```
4. Launch `Leash.app`, activate both extensions, approve the NE content filter in
   System Settings, grant Full Disk Access to LeashES.
5. Iterate — with developer mode on, changed extensions reload without the full
   uninstall dance. leashcli launched from the embedded Resources path is trusted
   by ES on the path rule, so exec authorization works with no team ID.

## Security note

Disabling SIP + AMFI removes real OS protections. Do this **only in a throwaway VM**,
never on a machine you care about.
