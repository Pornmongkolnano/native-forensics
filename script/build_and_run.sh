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
BUILD_CONFIGURATION="release"
if [[ "$MODE" == "--debug" ]]; then BUILD_CONFIGURATION="debug"; fi

cd "$ROOT_DIR"
python3 ./script/build_native_engine.py
swift build -c "$BUILD_CONFIGURATION" --product "$APP_NAME"
swift build -c "$BUILD_CONFIGURATION" --product NFDocumentDecoder
BUILD_DIR="$(swift build -c "$BUILD_CONFIGURATION" --show-bin-path)"
# Fully stage/sign/verify before asking the running app to drain its work.
STAGED_APP="$(python3 ./script/package_app.py --stage "$BUILD_DIR/$APP_NAME")"
cleanup_stage() {
  if [[ -n "${STAGED_APP:-}" && -d "$(dirname "$STAGED_APP")" ]]; then
    rm -rf "$(dirname "$STAGED_APP")"
  fi
}
trap cleanup_stage EXIT

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
    for _ in range(300):
        try: os.kill(pid, 0)
        except ProcessLookupError: break
        time.sleep(0.1)
    else:
        raise SystemExit('This checkout app is still finishing work; the verified stage was not published.')
PY

python3 ./script/package_app.py --publish "$STAGED_APP"
STAGED_APP=""

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
