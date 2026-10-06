#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
case "$MODE" in
  run|--debug|--logs|--telemetry|--verify|--build-only) ;;
  *) echo "Usage: $0 [--verify|--build-only|--debug|--logs|--telemetry]" >&2; exit 2 ;;
esac

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="NativeForensics"
BUNDLE_ID="io.github.pornmongkolnano.nativeforensics"
APP_BUNDLE="$ROOT_DIR/dist/$APP_NAME.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"

# Stop only this checkout's app, never another copy or Autopsy.
python3 - "$APP_BINARY" "$APP_NAME" <<'PY'
import os, signal, subprocess, sys, time
binary, name = sys.argv[1:]
result = subprocess.run(['/usr/bin/pgrep', '-x', name], capture_output=True, text=True)
for item in result.stdout.split():
    pid = int(item)
    command = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'comm='], capture_output=True, text=True).stdout.strip()
    if command != binary:
        continue
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        try: os.kill(pid, 0)
        except ProcessLookupError: break
        time.sleep(0.1)
    else:
        raise SystemExit('This checkout app did not stop; close it before rebuilding.')
PY

cd "$ROOT_DIR"
swift build --product "$APP_NAME"
BUILD_DIR="$(swift build --show-bin-path)"
mkdir -p "$ROOT_DIR/dist"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
cp "$BUILD_DIR/$APP_NAME" "$APP_BINARY"
chmod +x "$APP_BINARY"

cat > "$APP_BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>NativeForensics</string>
  <key>CFBundleIdentifier</key><string>io.github.pornmongkolnano.nativeforensics</string>
  <key>CFBundleName</key><string>NativeForensics</string>
  <key>CFBundleDisplayName</key><string>Native Forensics</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>CFBundleDocumentTypes</key><array><dict>
    <key>CFBundleTypeName</key><string>Native Forensics Case</string>
    <key>CFBundleTypeRole</key><string>Editor</string>
    <key>LSItemContentTypes</key><array><string>io.github.pornmongkolnano.nativeforensics.case</string></array>
    <key>LSTypeIsPackage</key><true/>
  </dict></array>
  <key>UTExportedTypeDeclarations</key><array><dict>
    <key>UTTypeIdentifier</key><string>io.github.pornmongkolnano.nativeforensics.case</string>
    <key>UTTypeDescription</key><string>Native Forensics Case</string>
    <key>UTTypeConformsTo</key><array><string>com.apple.package</string></array>
    <key>UTTypeTagSpecification</key><dict><key>public.filename-extension</key><array><string>nativecase</string></array></dict>
  </dict></array>
</dict></plist>
PLIST

/usr/bin/codesign --force --sign - "$APP_BUNDLE"
/usr/bin/codesign --verify --strict "$APP_BUNDLE"

case "$MODE" in
  --build-only) echo "Built: $APP_BUNDLE" ;;
  run) /usr/bin/open -n "$APP_BUNDLE" ;;
  --debug) /usr/bin/lldb -- "$APP_BINARY" ;;
  --logs)
    /usr/bin/open -n "$APP_BUNDLE"
    /usr/bin/log stream --info --style compact --predicate 'process == "NativeForensics"'
    ;;
  --telemetry)
    /usr/bin/open -n "$APP_BUNDLE"
    /usr/bin/log stream --info --style compact --predicate 'subsystem == "io.github.pornmongkolnano.nativeforensics"'
    ;;
  --verify)
    /usr/bin/open -n "$APP_BUNDLE"
    python3 - "$APP_BINARY" "$APP_NAME" <<'PY'
import subprocess, sys, time
binary, name = sys.argv[1:]
for _ in range(50):
    result = subprocess.run(['/usr/bin/pgrep', '-x', name], capture_output=True, text=True)
    for item in result.stdout.split():
        command = subprocess.run(['/bin/ps', '-p', item, '-o', 'comm='], capture_output=True, text=True).stdout.strip()
        if command == binary:
            print('Launched this checkout app successfully (PID ' + item + ')')
            raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit('App process did not appear within 5 seconds.')
PY
    ;;
esac
