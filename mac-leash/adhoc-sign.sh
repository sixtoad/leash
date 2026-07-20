#!/bin/bash
# Ad-hoc re-sign the built Leash.app so its system extensions carry their
# restricted entitlements. For local dev on a SIP-disabled / AMFI-relaxed VM
# (no paid Apple Developer account). Run after an unsigned build:
#   xcodebuild ... CODE_SIGNING_ALLOWED=NO
#   ./adhoc-sign.sh [/path/to/Leash.app]
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
APP="${1:-$(ls -d /Volumes/sixto_dev/.devcache/DerivedData/Leash-*/Build/Products/Debug/Leash.app | head -1)}"

ES_ENT="$SRC/LeashES/LeashES.entitlements"
NF_ENT="$SRC/LeashNetworkFilter/LeashNetworkFilter.entitlements"
PROXY_ENT="$SRC/LeashProxy/LeashProxy.entitlements"
APP_ENT="$SRC/Leash/leash.entitlements"

echo ">> Signing app: $APP"

sign() { codesign --force --timestamp=none --options runtime=0 --sign - "$@"; }

# 1. Sparkle framework and all its nested helpers (no entitlements)
codesign --force --deep --sign - "$APP/Contents/Frameworks/Sparkle.framework"

# 2. Bundled CLI (bare mach-o, fixed identifier, no entitlements)
codesign --force --sign - -i com.strongdm.leash.cli "$APP/Contents/Resources/leashcli"

# 3. Endpoint Security system extension (restricted entitlement)
codesign --force --sign - --entitlements "$ES_ENT" \
  "$APP/Contents/Library/SystemExtensions/com.strongdm.leash.LeashES.systemextension"

# 4. Network Filter system extension (restricted entitlement)
codesign --force --sign - --entitlements "$NF_ENT" \
  "$APP/Contents/Library/SystemExtensions/com.strongdm.leash.LeashNetworkFilter.systemextension"

# 5. Transparent Proxy system extension (restricted entitlement), if present.
PROXY_EXT="$APP/Contents/Library/SystemExtensions/com.strongdm.leash.LeashProxy.systemextension"
if [ -d "$PROXY_EXT" ]; then
  codesign --force --sign - --entitlements "$PROXY_ENT" "$PROXY_EXT"
fi

# 6. Outer app (network extension + system-extension install entitlements)
codesign --force --sign - --entitlements "$APP_ENT" "$APP"

echo ">> Verifying..."
codesign --verify --verbose=2 "$APP"
echo ">> Entitlements on LeashES:"
codesign -d --entitlements - "$APP/Contents/Library/SystemExtensions/com.strongdm.leash.LeashES.systemextension" 2>/dev/null
echo ">> Done."
