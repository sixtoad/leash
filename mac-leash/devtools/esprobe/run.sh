#!/bin/sh
# Build, ad-hoc sign, and run the EndpointSecurity entitlement probe.
# Run this inside a SIP/AMFI-relaxed dev VM. See docs/MACOS-DEV.md.
set -eu

cd "$(dirname "$0")"

echo "== compiling =="
# Full Xcode ships EndpointSecurity as a .framework; Command Line Tools ship it
# as a plain library (headers in usr/include, stub in usr/lib). Try both so the
# probe builds under either toolchain without needing full Xcode / an Apple ID.
if ! clang -o esprobe esprobe.c -framework EndpointSecurity 2>/dev/null; then
    clang -o esprobe esprobe.c -lEndpointSecurity
fi

echo "== ad-hoc signing with ES entitlement =="
codesign --force --sign - --entitlements es.entitlements esprobe

echo "== running (needs root) =="
status=0
sudo ./esprobe || status=$?

cat <<'EOF'

--------------------------------------------------------------------
Result codes:
  0  SUCCESS         -> fully working. Green light.
  3  NOT_ENTITLED    -> bypass FAILED. VM route is dead; use a fallback.
  4  NOT_PERMITTED   -> run it with sudo.
  5  NOT_PRIVILEGED  -> bypass WORKS; just grant Full Disk Access to your
                        terminal (System Settings > Privacy & Security >
                        Full Disk Access), then rerun. Should flip to 0.
--------------------------------------------------------------------
EOF

# Propagate the probe's result code so callers/CI can branch on it.
exit "$status"
