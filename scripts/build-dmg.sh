#!/usr/bin/env bash
# Build dudelogs.app + dudelogs-<versi>-<arch>.dmg (macOS).
# Hasil: dist/dudelogs.app dan dist/dudelogs-<versi>-<arch>.dmg
set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="dudelogs"
BUNDLE_ID="sh.dudelogs.app"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
ARCH="$(uname -m)"
DIST="dist"
APP="$DIST/$APP_NAME.app"
STAGE="$DIST/dmg-root"

if ! command -v hdiutil >/dev/null 2>&1; then
  echo "hdiutil tidak ditemukan — script ini hanya untuk macOS" >&2
  exit 1
fi

echo "==> build release ($ARCH)"
cargo build --release

echo "==> susun $APP_NAME.app"
rm -rf "$DIST"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "target/release/$APP_NAME" "$APP/Contents/MacOS/$APP_NAME"
cp playbook.toml dudelogs.example.toml "$APP/Contents/Resources/" 2>/dev/null || true
cp README.md "$APP/Contents/Resources/" 2>/dev/null || true

ICON_LINE=""
if [ -f assets/AppIcon.icns ]; then
  cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
  ICON_LINE="  <key>CFBundleIconFile</key><string>AppIcon</string>"
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$APP_NAME</string>
  <key>CFBundleDisplayName</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
$ICON_LINE
</dict>
</plist>
PLIST

echo "==> code sign (ad-hoc)"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "==> buat dmg"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
# ikon volume dmg (kalau SetFile tersedia dari Xcode CLT)
if [ -f assets/AppIcon.icns ] && command -v SetFile >/dev/null 2>&1; then
  cp assets/AppIcon.icns "$STAGE/.VolumeIcon.icns"
  SetFile -a C "$STAGE"
fi
DMG="$DIST/$APP_NAME-$VERSION-$ARCH.dmg"
hdiutil create -quiet -volname "$APP_NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
rm -rf "$STAGE"

echo
echo "selesai:"
echo "  $APP"
echo "  $DMG"
echo "install: buka dmg, drag $APP_NAME ke Applications."
