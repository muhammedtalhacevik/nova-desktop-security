#!/usr/bin/env bash
set -euo pipefail

RID="${1:-osx-arm64}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/publish/$RID"
APP="$ROOT/publish/Nova Desktop Security.app"
VERSION="1.2.2"

dotnet publish "$ROOT/src/Nova.Desktop/Nova.Desktop.csproj" \
  -c Release -r "$RID" --self-contained true -p:UseAppHost=true -p:DebugType=none -o "$OUT"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -R "$OUT/." "$APP/Contents/MacOS/"
cp "$ROOT/src/Nova.Desktop/Assets/nova.icns" "$APP/Contents/Resources/nova.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Nova Desktop Security</string>
  <key>CFBundleDisplayName</key><string>Nova Desktop Security</string>
  <key>CFBundleIdentifier</key><string>com.perasoft.novadesktopsecurity</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleExecutable</key><string>NovaDesktopSecurity</string>
  <key>CFBundleIconFile</key><string>nova.icns</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSLocationWhenInUseUsageDescription</key><string>Nova, baÄŸlÄ± Wi-Fi aÄŸÄ±nÄ±n adÄ±nÄ± ve gÃ¼venlik tÃ¼rÃ¼nÃ¼ gÃ¶stermek iÃ§in konum iznine ihtiyaÃ§ duyar.</string>
  <key>NSLocationUsageDescription</key><string>Nova, baÄŸlÄ± Wi-Fi aÄŸÄ±nÄ±n adÄ±nÄ± ve gÃ¼venlik tÃ¼rÃ¼nÃ¼ gÃ¶stermek iÃ§in konum iznine ihtiyaÃ§ duyar.</string>
  <key>NSAppleEventsUsageDescription</key><string>Nova, oturum aÃ§ma Ã¶ÄŸelerini listelemek iÃ§in System Events'e eriÅŸir.</string>
</dict>
</plist>
PLIST

chmod +x "$APP/Contents/MacOS/NovaDesktopSecurity"
codesign --force --deep --sign - "$APP" || true

echo ""
echo "HazÄ±r: $APP"
