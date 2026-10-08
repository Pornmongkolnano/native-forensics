#!/bin/zsh
# Original NativeForensics installer. Never changes Gatekeeper/quarantine policy.
emulate -LR zsh
set -euo pipefail
setopt EXTENDED_GLOB
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
task_package=${0:A:h}
task_parent=${HOME}/Applications
task_replace=0
task_verify_only=0
task_stage=''

task_report_stage_candidate() {
  local task_exit_status=$?
  if [[ -n $task_stage ]]; then
    # A stage or ancestor can be renamed after creation. Keep every stage;
    # a lexical path never authorizes removing the directory now at that name.
    print -u2 -- "Stage path candidate for manual review (no automatic cleanup): $task_stage" || true
  fi
  return "$task_exit_status"
}

task_fail() { print -u2 -- "Install failed: $*"; exit 1; }
task_no_links() {
  local task_path=$1 task_cursor=/ task_component
  [[ $task_path = /* ]] || task_fail 'Use an absolute destination folder.'
  for task_component in ${(s:/:)task_path}; do
    [[ -n $task_component && $task_component != . && $task_component != .. ]] || continue
    task_cursor=${task_cursor%/}/$task_component
    [[ ! -L $task_cursor ]] || task_fail 'A package/destination ancestor is a symbolic link.'
  done
}
while (( $# )); do
  case $1 in
    --destination) (( $# >= 2 )) || task_fail 'Missing destination folder.'; task_parent=$2; shift 2 ;;
    --replace) task_replace=1; shift ;;
    --verify-only) task_verify_only=1; shift ;;
    *) task_fail 'Usage: Install.command [--destination /absolute/owned/folder] [--replace] [--verify-only]' ;;
  esac
done
[[ $task_parent = /* ]] || task_fail 'Use an absolute destination folder.'
task_parent=${task_parent:a}
task_no_links "$task_package"
task_no_links "$task_parent"
[[ -d $task_package && -f $task_package/SHA256SUMS && ! -L $task_package/SHA256SUMS ]] || task_fail 'Incomplete package.'
cd -- "$task_package"

# Check both the listed bytes and the complete inventory. Extra files, aliases,
# devices and traversal names are not silently ignored by shasum.
typeset -A task_expected
while IFS=' ' read -r task_digest task_name; do
  [[ $task_digest = [0-9a-f]## && ${#task_digest} = 64 ]] || task_fail 'Invalid hash record.'
  [[ $task_name = [A-Za-z0-9._/-]## && $task_name != /* && $task_name != *'../'* && $task_name != */.. && $task_name != . && $task_name != *'//'* ]] || task_fail 'Invalid inventory path.'
  [[ -z ${task_expected[$task_name]-} ]] || task_fail 'Duplicate inventory path.'
  [[ -f $task_name && ! -L $task_name ]] || task_fail 'A package file is missing or linked.'
  task_expected[$task_name]=$task_digest
done < SHA256SUMS
(( ${#task_expected} > 0 )) || task_fail 'Empty package inventory.'
task_count=0
for task_file in **/*(DN); do
  [[ ! -L $task_file ]] || task_fail 'Package contains a symbolic link.'
  if [[ -f $task_file ]]; then
    [[ $task_file = SHA256SUMS || -n ${task_expected[$task_file]-} ]] || task_fail 'Package contains an unlisted file.'
    (( task_count += 1 ))
  elif [[ ! -d $task_file ]]; then
    task_fail 'Package contains a special file.'
  fi
done
(( task_count == ${#task_expected} + 1 )) || task_fail 'Incomplete inventory.'
/usr/bin/shasum -a 256 -c SHA256SUMS >/dev/null
/usr/bin/codesign --verify --strict ./InstallSupport
/usr/bin/codesign --verify --deep --strict ./NativeForensics.app

task_identity=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' NativeForensics.app/Contents/Info.plist)
[[ $task_identity = io.github.pornmongkolnano.nativeforensics ]] || task_fail 'Unexpected app identity.'
task_arch=$(/usr/bin/lipo -archs NativeForensics.app/Contents/MacOS/NativeForensics)
[[ " $task_arch " = *" $(/usr/bin/uname -m) "* ]] || task_fail 'This package does not support the current CPU architecture.'
task_min=$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' NativeForensics.app/Contents/Info.plist)
task_os=$(/usr/bin/sw_vers -productVersion)
task_min_parts=(${(s:.:)task_min})
task_os_parts=(${(s:.:)task_os})
(( ${#task_min_parts} >= 1 && ${#task_min_parts} <= 3 && ${#task_os_parts} >= 1 && ${#task_os_parts} <= 3 )) || task_fail 'Invalid macOS version declaration.'
for task_component in $task_min_parts $task_os_parts; do
  [[ $task_component = <-> ]] || task_fail 'Invalid macOS version declaration.'
done
task_supported=0
for task_index in 1 2 3; do
  task_host_component=${task_os_parts[$task_index]:-0}
  task_min_component=${task_min_parts[$task_index]:-0}
  (( task_host_component >= task_min_component )) || task_fail "Requires macOS $task_min or later."
  if (( task_host_component > task_min_component )); then task_supported=1; break; fi
done
if (( task_verify_only )); then
  print -- 'Package hashes, code signatures, architecture and minimum macOS: verified.'
  print -- 'Verification does not establish notarization, Gatekeeper acceptance or clean-machine coverage.'
  exit 0
fi

if [[ ! -d $task_parent ]]; then
  [[ $task_parent = ${HOME}/Applications ]] || task_fail 'Create the destination folder before using --destination.'
  /bin/mkdir -m 755 -- "$task_parent"
fi
[[ -d $task_parent && -O $task_parent && -w $task_parent ]] || task_fail 'Destination must be a writable folder owned by this user; do not use sudo.'
[[ $task_parent != $task_package && $task_parent != $task_package/* && $task_package != $task_parent/NativeForensics.app/* ]] || task_fail 'Destination overlaps the package/source app.'
task_target=$task_parent/NativeForensics.app
if [[ -e $task_target || -L $task_target ]]; then
  (( task_replace )) || task_fail 'An app already exists. Quit it and rerun with --replace to retain a backup and replace it.'
  [[ -d $task_target && ! -L $task_target ]] || task_fail 'Existing target is not a real app directory.'
  task_old_identity=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$task_target/Contents/Info.plist")
  [[ $task_old_identity = io.github.pornmongkolnano.nativeforensics ]] || task_fail 'Existing app has another identity and was preserved.'
fi
task_stage=$(/usr/bin/mktemp -d "$task_parent/.nativeforensics-install-stage.XXXXXXXX")
trap 'task_report_stage_candidate' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
# Preserve copied extended attributes including quarantine. No xattr removal.
/usr/bin/ditto --rsrc --extattr ./NativeForensics.app "$task_stage/NativeForensics.app"
for task_copied in "$task_stage/NativeForensics.app"/**/*(DN); do
  [[ ! -L $task_copied ]] || task_fail 'Staged app contains a symbolic link.'
  if [[ -f $task_copied ]]; then
    task_name=${task_copied#$task_stage/}
    [[ -n ${task_expected[$task_name]-} ]] || task_fail 'Staged app contains an unlisted file.'
  elif [[ ! -d $task_copied ]]; then
    task_fail 'Staged app contains a special file.'
  fi
done
for task_name task_digest in ${(kv)task_expected}; do
  if [[ $task_name = NativeForensics.app/* ]]; then
    task_copied=$task_stage/$task_name
    [[ -f $task_copied && ! -L $task_copied ]] || task_fail 'Staged app is incomplete.'
    task_actual=$(/usr/bin/shasum -a 256 "$task_copied")
    [[ ${task_actual[1,64]} = $task_digest ]] || task_fail 'Staged app differs from the verified package.'
  fi
done
/usr/bin/codesign --verify --deep --strict "$task_stage/NativeForensics.app"
task_publish_args=("$task_stage/NativeForensics.app" "$task_target")
(( task_replace == 0 )) || task_publish_args+=(--replace)
./InstallSupport "${task_publish_args[@]}"
print -- "Installed: $task_target"
print -- 'Open the app through Finder. macOS trust checks remain enabled.'
print -- 'Keep this original ZIP/Source/Relink/Licenses package with the installed app.'
print -- 'Development packages are ad hoc signed; this installer does not bypass a trust-policy refusal.'
