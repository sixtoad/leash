#!/bin/sh
# Build, ad-hoc sign, and run the EndpointSecurity entitlement probe.
# Run this inside a SIP/AMFI-relaxed dev VM. See docs/MACOS-DEV.md.
set -eu

cd "$(dirname "$0")"

echo "== compiling =="
clang -o esprobe esprobe.c -framework EndpointSecurity

echo "== ad-hoc signing with ES entitlement =="
codesign --force --sign - --entitlements es.entitlements esprobe

echo "== running (needs root) =="
sudo ./esprobe || true

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
