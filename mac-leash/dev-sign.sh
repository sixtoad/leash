#!/bin/bash
# Re-sign a built Leash.app with an Apple Development identity and the team's
# Mac Development provisioning profiles, so it runs on a registered Mac with
# SIP enabled (#2). The restricted entitlements (Endpoint Security, Network
# Extension, system-extension install) are honoured only because each bundle
# embeds a profile that grants them.
#
# Unlike adhoc-sign.sh this needs the team's development certificate in the
# keychain and a "macOS App Development" profile per App ID that lists this
# Mac. Run after a Debug build (which ad-hoc signs first; this replaces it):
#   xcodebuild -project Leash.xcodeproj -scheme Leash -configuration Debug build
#   ./dev-sign.sh [/path/to/Leash.app]
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
APP="${1:-$(ls -d /Volumes/sixto_dev/.devcache/DerivedData/Leash-*/Build/Products/Debug/Leash.app | head -1)}"
TEAM="${LEASH_TEAM_IDENTIFIER:-9884BZY594}"
BUNDLE="${LEASH_BUNDLE_IDENTIFIER:-com.sixtoad.leash}"
PROFILES="${LEASH_PROFILES_DIR:-$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles}"
EXT="$APP/Contents/Library/SystemExtensions"

IDENTITY="${LEASH_SIGN_IDENTITY:-$(security find-identity -v -p codesigning |
  sed -n "s/.*\"\(Apple Development: .*\)\"/\1/p" | head -1)}"
[ -n "$IDENTITY" ] || { echo "no Apple Development identity in the keychain" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# profile_for <bundle id>: the newest development profile (one that lists
# devices) for exactly that App ID.
profile_for() {
  local want="$TEAM.$1" best="" best_date="" f plist appid date
  for f in "$PROFILES"/*.provisionprofile; do
    plist="$WORK/p.plist"
    security cms -D -i "$f" > "$plist" 2>/dev/null || continue
    appid="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$plist" 2>/dev/null)" || continue
    [ "$appid" = "$want" ] || continue
    /usr/libexec/PlistBuddy -c 'Print :ProvisionedDevices' "$plist" >/dev/null 2>&1 || continue
    date="$(/usr/libexec/PlistBuddy -c 'Print :CreationDate' "$plist" | xargs -I{} date -j -f '%a %b %d %T %Z %Y' '{}' +%s)"
    if [ -z "$best" ] || [ "$date" -gt "$best_date" ]; then best="$f"; best_date="$date"; fi
  done
  [ -n "$best" ] || { echo "no development profile for $want in $PROFILES" >&2; exit 1; }
  echo "$best"
}

# entitlements_for <source entitlements> <bundle id>: the target's
# entitlements plus the identifiers a profile-signed binary must carry.
entitlements_for() {
  local out="$WORK/$2.entitlements"
  cp "$1" "$out"
  /usr/libexec/PlistBuddy -c "Add :com.apple.application-identifier string $TEAM.$2" "$out"
  /usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string $TEAM" "$out"
  echo "$out"
}

sign() { codesign --force --timestamp=none --options runtime --sign "$IDENTITY" "$@"; }

# sign_bundle <bundle path> <bundle id> <source entitlements>
sign_bundle() {
  # Debug builds split the code into Contents/MacOS/*.debug.dylib (and
  # __preview.dylib); with the hardened runtime dyld refuses one whose team
  # differs from the executable's, so they must be re-signed too.
  find "$1/Contents/MacOS" -maxdepth 1 -name '*.dylib' -print0 |
    while IFS= read -r -d '' lib; do sign "$lib"; done
  cp "$(profile_for "$2")" "$1/Contents/embedded.provisionprofile"
  sign --entitlements "$(entitlements_for "$3" "$2")" "$1"
}

echo ">> Signing $APP as \"$IDENTITY\""

# 1. Sparkle framework and its nested helpers (no entitlements)
codesign --force --deep --timestamp=none --options runtime --sign "$IDENTITY" \
  "$APP/Contents/Frameworks/Sparkle.framework"

# 2. Bundled CLI (bare mach-o, fixed identifier, no restricted entitlements)
sign -i "$BUNDLE.cli" "$APP/Contents/Resources/leashcli"

# 3-5. System extensions. The Debug build is compiled unsigned, so
# $(TeamIdentifierPrefix) left the filter's Mach service name unprefixed; a
# team-signed content filter must carry the team prefix to register (#19).
NF_PLIST="$EXT/$BUNDLE.LeashNetworkFilter.systemextension/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :NetworkExtension:FilterDataProvider:NEMachServiceName $TEAM.$BUNDLE.LeashNetworkFilter" "$NF_PLIST"
sign_bundle "$EXT/$BUNDLE.LeashES.systemextension" "$BUNDLE.LeashES" "$SRC/LeashES/LeashES.entitlements"
sign_bundle "$EXT/$BUNDLE.LeashNetworkFilter.systemextension" "$BUNDLE.LeashNetworkFilter" "$SRC/LeashNetworkFilter/LeashNetworkFilter.entitlements"
if [ -d "$EXT/$BUNDLE.LeashProxy.systemextension" ]; then
  sign_bundle "$EXT/$BUNDLE.LeashProxy.systemextension" "$BUNDLE.LeashProxy" "$SRC/LeashProxy/LeashProxy.entitlements"
fi

# 6. Outer app
sign_bundle "$APP" "$BUNDLE" "$SRC/Leash/leash.entitlements"

echo ">> Verifying..."
codesign --verify --deep --strict --verbose=2 "$APP"
for b in "$APP" "$EXT"/*.systemextension; do
  echo ">> $(basename "$b"): $(codesign -dv "$b" 2>&1 | grep -E '^TeamIdentifier' )"
done
echo ">> Done."
