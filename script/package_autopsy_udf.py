#!/usr/bin/env python3
"""Add the original bounded UDF logical-export helper to an audited portable Autopsy package."""
import argparse
import hashlib
import json
import io
import plistlib
import shutil
import subprocess
import tarfile
from pathlib import Path


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def run(args):
    subprocess.run([str(value) for value in args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True, help='Generated synthetic UDF self-test image')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--addons', type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    base, helper, output = args.base.resolve(), args.helper.resolve(), args.output.absolute()
    if output.exists() or output.is_symlink():
        raise SystemExit('Output already exists; select a new directory.')
    if not (base / 'SHA256SUMS').is_file() or not helper.is_file():
        raise SystemExit('An audited base package and built helper are required.')
    subprocess.run(['/usr/bin/shasum', '-a', '256', '-c', 'SHA256SUMS'],
                   cwd=base, check=True, stdout=subprocess.DEVNULL)
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', base / 'Autopsy ARM64.app'])
    run(['/usr/bin/ditto', '--norsrc', '--noextattr', base, output])
    app = output / 'Autopsy ARM64.app'
    contents = app / 'Contents'
    bundled = contents / 'Helpers/AutopsyUDFExport'
    shutil.copy2(helper, bundled)
    bundled.chmod(0o755)
    run(['/usr/bin/codesign', '--force', '--sign', '-', bundled])
    fixture = contents / 'Resources/fixtures/synthetic-udf.dd'
    shutil.copy2(args.fixture, fixture)
    self_test = contents / 'Resources/verification/SelfTest.command'
    self_test.write_text(self_test.read_text() + '''
"$task_contents/Helpers/AutopsyUDFExport" --self-test "$task_contents/Resources/fixtures/synthetic-udf.dd"
''')
    info_path = contents / 'Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info['CFBundleVersion'] = '20261007.2'
    info['CFBundleDisplayName'] = 'Autopsy ARM64 UDF'
    info_path.write_bytes(plistlib.dumps(info))
    wrapper = '''#!/bin/bash
set -euo pipefail
task_package="$(cd -- "$(dirname -- "$0")" && pwd -P)"
task_app="$task_package/Autopsy ARM64.app"
/usr/bin/codesign --verify --deep --strict "$task_app"
exec "$task_app/Contents/Helpers/AutopsyUDFExport" --interactive "$@"
'''
    (output / 'Import UDF.command').write_text(wrapper)
    (output / 'Import UDF.command').chmod(0o755)
    installer_path = output / 'Install.command'
    installer = installer_path.read_text().replace(
        'task_destination="$HOME/Applications/Autopsy ARM64 Fixed.app"',
        'task_destination="$HOME/Applications/Autopsy ARM64 UDF.app"')
    shortcut_function = '''
# Publish a per-application shortcut without overwriting an existing user file.
task_udf_shortcut() {
  local task_shortcut task_shortcut_stage task_bundle_name
  task_bundle_name="$(/usr/bin/basename "$task_destination")"
  task_shortcut="$(/usr/bin/dirname "$task_destination")/${task_bundle_name%.app} - Import UDF.command"
  task_shortcut_stage="$(/usr/bin/mktemp "$(/usr/bin/dirname "$task_destination")/.autopsy-udf-command.XXXXXX")"
  {
    printf '#!/bin/bash\\nset -euo pipefail\\n'
    printf 'task_parent="$(cd -- "$(dirname -- "$0")" && pwd -P)"\\n'
    printf 'task_bundle_name=%q\\n' "$task_bundle_name"
    printf 'task_app="$task_parent/$task_bundle_name"\\n'
    printf '/usr/bin/codesign --verify --deep --strict "$task_app"\\n'
    printf 'exec "$task_app/Contents/Helpers/AutopsyUDFExport" --interactive "$@"\\n'
  } > "$task_shortcut_stage"
  /bin/chmod 755 "$task_shortcut_stage"
  if [ -e "$task_shortcut" ] || [ -L "$task_shortcut" ]; then
    if ! /usr/bin/cmp -s "$task_shortcut_stage" "$task_shortcut"; then
      printf 'Existing UDF shortcut was preserved: %s\\n' "$task_shortcut"
    fi
    /bin/rm -f "$task_shortcut_stage"
  elif ! "$task_source/Contents/Helpers/Publish" "$task_shortcut_stage" "$task_shortcut"; then
    /bin/rm -f "$task_shortcut_stage"
    printf 'Shortcut could not be published; use Import UDF.command in the original package.\\n'
  fi
  printf 'UDF import shortcut: %s\\n' "$task_shortcut"
}
'''
    installer = installer.replace('trap task_finish EXIT', shortcut_function + '\ntrap task_finish EXIT')
    installer = installer.replace("printf '\\nThis exact build is already installed: %s\\n' \"$task_destination\"\n    exit 0",
                                  "printf '\\nThis exact build is already installed: %s\\n' \"$task_destination\"\n    task_udf_shortcut\n    exit 0")
    installer += '\ntask_udf_shortcut\n'
    installer_path.write_text(installer)
    installer_path.chmod(0o755)
    sources = output / 'Sources'
    shutil.copy2(installer_path, sources / 'Install.command')
    shutil.copy2(output / 'Import UDF.command', sources / 'Import UDF.command')
    shutil.copy2(Path(__file__), sources / Path(__file__).name)
    source_archive = sources / 'AutopsyUDFExport-source.tar.gz'
    def neutral_source_metadata(item):
        item.uid = item.gid = 0
        item.uname = item.gname = ''
        return item
    with tarfile.open(source_archive, 'w:gz') as archive:
        for directory in ['Sources/ForensicsCore', 'Sources/AutopsyUDFExport']:
            for path in sorted((repo / directory).rglob('*.swift')):
                archive.add(path, arcname=str(path.relative_to(repo)), recursive=False, filter=neutral_source_metadata)
        test_source = repo / 'Tests/ForensicsCoreTests/UDFHistoryTests.swift'
        archive.add(test_source, arcname='Tests/ForensicsCoreTests/UDFHistoryTests.swift',
                    recursive=False, filter=neutral_source_metadata)
        package = b'''// swift-tools-version: 6.1
import PackageDescription
let package = Package(name: "AutopsyUDFExport", platforms: [.macOS(.v14)],
    products: [.executable(name: "AutopsyUDFExport", targets: ["AutopsyUDFExport"])],
    targets: [.target(name: "ForensicsCore"),
        .executableTarget(name: "AutopsyUDFExport", dependencies: ["ForensicsCore"]),
        .testTarget(name: "ForensicsCoreTests", dependencies: ["ForensicsCore"])])
'''
        item = tarfile.TarInfo('Package.swift')
        item.size = len(package)
        item.mode = 0o644
        archive.addfile(item, io.BytesIO(package))
    (sources / 'UDF-Export-Build-Notes.txt').write_text('''Original Swift UDF logical-export helper; no third-party runtime library is embedded in this executable.
Build the included standalone source archive using Xcode/Swift 6.1 or later on macOS:
  swift build -c release --product AutopsyUDFExport
Run synthetic UDF parser/export regressions:
  swift test --filter UDFHistoryTests
Generate the exact synthetic distribution fixture into a new existing parent:
  NF_UDF_SHARE_FIXTURE_OUTPUT=/absolute/new-fixture.dd swift test --filter UDFHistoryTests.autopsyLogicalImport
The shared binary needs only macOS system frameworks; developer tools are not required to run it.
The helper is a derived logical-file export adapter. It does not modify Autopsy/TSK filesystem dispatch.
''')
    if args.addons:
        for folder in ['Sources', 'LICENSES']:
            if (args.addons / folder).is_dir():
                shutil.copytree(args.addons / folder, output / folder, dirs_exist_ok=True)
    guide = (repo / 'docs/AUTOPSY-UDF-SHARING-TH.md').read_text()
    (output / 'UDF-GUIDE-TH.md').write_text(guide)
    readme = (output / 'README-TH.txt').read_text()
    readme = readme.replace('Revision 20261007.1 — Fixed', 'Revision 20261007.2 — UDF logical import')
    readme = readme.replace('Autopsy ARM64 Fixed.app', 'Autopsy ARM64 UDF.app')
    readme += '\n\nCD/UDF: เปิด Import UDF.command เลือก image และโฟลเดอร์ปลายทาง แล้วนำ LogicalFiles เข้า Autopsy ตาม UDF-GUIDE-TH.md\n'
    readme += 'ตัวช่วยเพิ่มการส่งออก UDF/VAT; ไม่ได้เปลี่ยน Sleuth Kit ให้เป็นตัวอ่าน UDF โดยตรง และต้องดูเวลา/สถานะเดิมจาก Reports\n'
    readme += 'หลังติดตั้งมี shortcut “Autopsy ARM64 UDF - Import UDF.command” ใน ~/Applications ใช้ได้แม้ลบโฟลเดอร์ที่แตก ZIP\n'
    (output / 'README-TH.txt').write_text(readme)
    for name in ['REGRESSION-VALIDATION.json', 'DELIVERY-VALIDATION.json']:
        if (output / name).is_file():
            (output / name).rename(output / ('BASE-' + name))
    metadata = json.loads((output / 'PACKAGE.json').read_text())
    metadata['package_revision'] = '20261007.2'
    metadata['udf_logical_import'] = {
        'method': 'Original Swift bounded UDF/VAT reader; verified derived logical-file export',
        'helper_sha256': sha(bundled),
        'source_archive_sha256': sha(source_archive),
        'synthetic_fixture_sha256': sha(fixture),
        'upstream_udf_filesystem_support_changed': False,
        'source_evidence_included': False,
        'device_tested': 'Apple M2 / macOS 27.0.1',
        'M5_tested': False,
    }
    (output / 'PACKAGE.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
    run(['/usr/bin/codesign', '--force', '--deep', '--sign', '-', app])
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
    entries = []
    for path in sorted(output.rglob('*')):
        if path.is_file() and not path.is_symlink() and path != output / 'SHA256SUMS':
            entries.append(f'{sha(path)}  {path.relative_to(output)}\n')
    (output / 'SHA256SUMS').write_text(''.join(entries))
    print(json.dumps({'package': str(output), 'helper_sha256': sha(bundled), 'checksummed_files': len(entries)}, indent=2))


if __name__ == '__main__':
    main()
