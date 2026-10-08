import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

/// A separate-language producer/OS oracle constructs both volumes before the
/// application receives the image. Identical paths deliberately carry different
/// bytes, so choosing a convenient first volume cannot satisfy both oracles.
@Suite("Independent APFS multi-volume selection", .serialized)
struct APFSMultiVolumeFixtureOracle {
    private static let enabled = ProcessInfo.processInfo.environment["NF_APFS_INTEGRATION"] == "1"

    @Test("Discovery and explicit stable UUID selection keep two distinct shared.txt payloads separate",
          .enabled(if: APFSMultiVolumeFixtureOracle.enabled))
    func explicitVolumeSelection() async throws {
        let fixture = try APFSMultiVolumeSyntheticFixture()
        defer { try? fixture.cleanup() }
        let before = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        #expect(before.sha256 == fixture.receipt.containerSHA256)
        #expect(before.byteCount == fixture.receipt.containerByteCount)
        let evidence = EvidenceRecord(sourcePath: fixture.image.path, byteCount: before.byteCount,
            sha256: before.sha256, container: before.container, filesystemHint: before.filesystemHint)
        let adapter = APFSMountedImageAdapter(scratchRoot: fixture.adapterScratch) { event in
            if case .mounted = event { fixture.auditSelectedMount() }
        }
        let catalog = try await adapter.discoverVolumes(evidence: evidence)
        #expect(catalog.evidenceID == evidence.id && catalog.containerSHA256 == before.sha256)
        #expect(catalog.containerByteCount == before.byteCount && catalog.hashScope == FileHashScope.selectedFileBytes)
        #expect(catalog.containerEncryption == .none)
        #expect(catalog.volumeGroupInventoryAvailable)
        #expect(catalog.volumes.count == 2)
        #expect(Set(catalog.volumes.map(\.volumeUUID)) == Set(fixture.receipt.volumes.map(\.volumeUUID)))
        for volume in fixture.receipt.volumes {
            let actual = try #require(catalog.volumes.first { $0.volumeUUID == volume.volumeUUID })
            #expect(actual.name == volume.name && actual.containerUUID == volume.containerUUID)
            #expect(actual.roles.isEmpty && actual.volumeGroupUUID == nil && !actual.encrypted && !actual.locked)
        }
        let catalogJSON = String(decoding: try JSONEncoder().encode(catalog), as: UTF8.self)
        #expect(!catalogJSON.contains(fixture.root.path) && !catalogJSON.contains("/dev/disk") && !catalogJSON.contains("/Volumes/"))
        try fixture.requireEmptyAdapterScratch()
        await #expect(throws: (any Error).self) { _ = try await adapter.inspect(evidence: evidence) }
        try fixture.requireEmptyAdapterScratch()
        let unknown: UUID = {
            var candidate = UUID()
            while fixture.receipt.volumes.contains(where: { $0.volumeUUID == candidate }) { candidate = UUID() }
            return candidate
        }()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence, options: APFSReadOptions(selectedVolumeUUID: unknown))
        }
        try fixture.requireEmptyAdapterScratch()
        var returnedBytes: [Data] = []
        for volume in fixture.receipt.volumes.sorted(by: { $0.name < $1.name }) {
            let expected = try #require(fixture.expected[volume.name])
            #expect(volume.sha256 == APFSMultiVolumeSyntheticFixture.hash(expected))
            fixture.expectSelectedMount(volume.volumeUUID)
            let inspection = try await adapter.inspect(evidence: evidence,
                options: APFSReadOptions(selectedVolumeUUID: volume.volumeUUID))
            #expect(inspection.volumeUUID == volume.volumeUUID && inspection.options.selectedVolumeUUID == volume.volumeUUID)
            #expect(inspection.containerSHA256 == before.sha256 && inspection.containerByteCount == before.byteCount)
            #expect(inspection.coverage == .completeAllocatedView)
            let entry = try #require(inspection.entries.first { $0.relativePath == "shared.txt" })
            #expect(entry.kind == .regular && entry.byteCount == Int64(expected.count))
            #expect(entry.sha256 == APFSMultiVolumeSyntheticFixture.hash(expected))
            try fixture.requireEmptyAdapterScratch()
            fixture.expectSelectedMount(volume.volumeUUID)
            let content = try await adapter.readVerifiedFile(evidence: evidence, inspection: inspection, entry: entry)
            #expect(content.data == expected && content.sha256 == APFSMultiVolumeSyntheticFixture.hash(expected))
            #expect(content.relativePath == "shared.txt" && content.volumeUUID == volume.volumeUUID)
            #expect(content.containerSHA256 == before.sha256)
            returnedBytes.append(content.data)
            try fixture.requireEmptyAdapterScratch()
        }
        #expect(returnedBytes.count == 2 && returnedBytes[0] != returnedBytes[1])
        try fixture.requireSuccessfulMountAudits(expectedCount: 4)
        let after = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        #expect(after.sha256 == before.sha256 && after.byteCount == before.byteCount)
        #expect(after.sourceIdentity == before.sourceIdentity)
        try fixture.cleanup()
    }
}

private struct APFSMultiVolumeOracleReceipt: Decodable {
    let containerSHA256: String
    let containerByteCount: Int64
    let volumes: [Volume]
    let volumeGroupInventoryAvailable: Bool
    let sourceAndPrivateHashesIdentitiesUnchanged: Bool
    let cleanupDetached: Bool
    let ownedLeafPaths: [String]
    struct Volume: Decodable {
        let volumeUUID: UUID
        let containerUUID: UUID
        let name: String
        let sha256: String
        let exactKnownBytes: Bool
        let readOnly: Bool
        let nonSelectedVolumeUnmounted: Bool
    }
}

/// Mutable audit state is locked. Each serialized job sets its expected UUID;
/// the synchronous test lifecycle callback checks actual mounted OS metadata.
private final class APFSMultiVolumeSyntheticFixture: @unchecked Sendable {
    let root: URL
    let image: URL
    let adapterScratch: URL
    let receipt: APFSMultiVolumeOracleReceipt
    let expected: [String: Data] = [
        "Primary": Data("PRIMARY volume bytes\nSame filename; first independently known payload.\n".utf8),
        "Secondary": Data("SECONDARY volume bytes\nไฟล์คนละ volume e\u{301}\n".utf8)
    ]
    private let lock = NSLock()
    private var selectedUUID: UUID?
    private var auditCount = 0
    private var auditFailed = false
    private var auditFailureStages: [String] = []
    private var identities: [String: (dev_t, ino_t, mode_t)] = [:]
    private var cleaned = false

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("APFSMultiVolume-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        image = root.appendingPathComponent("two-plain-apfs-volumes.dmg")
        adapterScratch = root.appendingPathComponent("adapter-scratch", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: adapterScratch, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        _ = try Self.run("/usr/bin/python3", ["-c", Self.pythonBuilder, root.path])
        receipt = try JSONDecoder().decode(APFSMultiVolumeOracleReceipt.self, from: Data(contentsOf: root.appendingPathComponent("receipt.json")))
        try #require(receipt.volumes.count == 2 && Set(receipt.volumes.map(\.volumeUUID)).count == 2)
        try #require(receipt.volumeGroupInventoryAvailable && receipt.sourceAndPrivateHashesIdentitiesUnchanged && receipt.cleanupDetached)
        for volume in receipt.volumes {
            try #require(volume.exactKnownBytes && volume.readOnly && volume.nonSelectedVolumeUnmounted)
        }
        for relative in receipt.ownedLeafPaths {
            try #require(!relative.hasPrefix("/") && !relative.split(separator: "/").contains(".."))
            var metadata = stat()
            try #require(Darwin.lstat(root.appendingPathComponent(relative).path, &metadata) == 0)
            identities[relative] = (metadata.st_dev, metadata.st_ino, metadata.st_mode & S_IFMT)
        }
    }

    func expectSelectedMount(_ uuid: UUID) {
        lock.lock(); selectedUUID = uuid; lock.unlock()
    }
    func auditSelectedMount() {
        lock.lock(); let expected = selectedUUID; lock.unlock()
        var stage = "unexpected-mount"
        do {
            guard let expected else { throw ForensicsError.io("Unexpected mounted discovery or unspecified-selection job.") }
            stage = "audit-process"
            let expectedVolumes = receipt.volumes.map { $0.volumeUUID.uuidString }.sorted()
            let data = try Self.run("/usr/bin/python3", ["-c", Self.pythonMountedAudit, adapterScratch.path,
                expected.uuidString] + expectedVolumes + [receipt.volumes[0].containerUUID.uuidString])
            stage = "audit-result"
            let observation = try JSONDecoder().decode(MountedAuditReceipt.self, from: data)
            guard Self.mountedAuditStages.contains(observation.stage) else { throw ForensicsError.io("Invalid mounted audit stage.") }
            stage = observation.stage
            guard observation.ok else { throw ForensicsError.io("Mounted APFS oracle rejected the selected view.") }
            lock.lock(); auditCount += 1; lock.unlock()
        } catch {
            lock.lock()
            auditFailed = true
            let report = auditFailureStages.count < 4
            if report { auditFailureStages.append(stage) }
            lock.unlock()
            // Only fixed, allowlisted stages reach test output. Private paths,
            // raw command output and credentials never enter this diagnostic.
            if report { print("APFS_MULTI_VOLUME_MOUNT_AUDIT_FAILED stage=\(stage)") }
        }
    }
    func requireSuccessfulMountAudits(expectedCount: Int) throws {
        lock.lock(); let count = auditCount, failed = auditFailed, stages = auditFailureStages.joined(separator: ","); lock.unlock()
        try #require(!failed && count == expectedCount,
            "Mounted APFS oracle stages: \(stages); completed \(count) of \(expectedCount) audits.")
    }
    private struct MountedAuditReceipt: Decodable { let ok: Bool; let stage: String }
    private static let mountedAuditStages: Set<String> = [
        "scratch-root", "private-directory", "image-descriptor", "view-descriptor", "image-inventory",
        "image-alias", "image-entities", "image-ownership", "root-entity", "root-partitions", "physical-store",
        "container-entity", "container-list", "container-identity", "container-stores", "expected-volumes",
        "volume-nodes", "volume-info", "volume-association", "volume-filesystem", "selected-view", "mount-alias",
        "descriptor-readonly", "descriptor-fsid", "sibling-unmounted", "selected-count", "held-identities", "complete"
    ]
    func requireEmptyAdapterScratch() throws {
        try #require(try FileManager.default.contentsOfDirectory(atPath: adapterScratch.path).isEmpty)
    }
    func cleanup() throws {
        if cleaned { return }
        // Fresh exact image-path ownership checks precede every detach. A retained
        // production image is deliberately left intact, never traversed/deleted.
        for imageName in ["oracle-private-image.dmg", "two-plain-apfs-volumes.dmg"] {
            _ = try Self.run("/usr/bin/python3", ["-c", Self.pythonDetachKnownImage, root.appendingPathComponent(imageName).path])
        }
        try requireEmptyAdapterScratch()
        var observed: Set<String> = []
        func verifyDirectory(_ directory: URL, prefix: String) throws {
            for child in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
                let relative = prefix.isEmpty ? child.lastPathComponent : prefix + "/" + child.lastPathComponent
                let identity = try #require(identities[relative])
                var metadata = stat()
                try #require(Darwin.lstat(child.path, &metadata) == 0)
                try #require(metadata.st_dev == identity.0 && metadata.st_ino == identity.1 && metadata.st_mode & S_IFMT == identity.2)
                observed.insert(relative)
                if identity.2 == S_IFDIR { try verifyDirectory(child, prefix: relative) }
            }
        }
        try verifyDirectory(root, prefix: "")
        try #require(observed == Set(receipt.ownedLeafPaths))
        for relative in observed.sorted(by: { $0.split(separator: "/").count > $1.split(separator: "/").count }) {
            let path = root.appendingPathComponent(relative).path
            if identities[relative]?.2 == S_IFDIR { try #require(Darwin.rmdir(path) == 0) }
            else { try #require(Darwin.unlink(path) == 0) }
        }
        try #require(Darwin.rmdir(root.path) == 0)
        cleaned = true
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    private static func run(_ executable: String, _ arguments: [String]) throws -> Data {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("APFSMultiVolume-command-\(UUID().uuidString)")
        let stdoutURL = base.appendingPathExtension("stdout"), stderrURL = base.appendingPathExtension("stderr")
        try #require(FileManager.default.createFile(atPath: stdoutURL.path, contents: nil, attributes: [.posixPermissions: 0o600]))
        try #require(FileManager.default.createFile(atPath: stderrURL.path, contents: nil, attributes: [.posixPermissions: 0o600]))
        let output = try FileHandle(forWritingTo: stdoutURL), errors = try FileHandle(forWritingTo: stderrURL)
        defer { try? output.close(); try? errors.close(); try? FileManager.default.removeItem(at: stdoutURL); try? FileManager.default.removeItem(at: stderrURL) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = errors
        try process.run()
        let clock = ContinuousClock(), deadline = ContinuousClock().now + .seconds(180)
        while process.isRunning && clock.now < deadline { usleep(20_000) }
        if process.isRunning { process.terminate(); usleep(100_000); if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) } }
        process.waitUntilExit(); try output.synchronize(); try errors.synchronize()
        guard process.terminationStatus == 0 else { throw ForensicsError.io("Owned APFS multi-volume fixture command failed or timed out.") }
        let attributes = try FileManager.default.attributesOfItem(atPath: stdoutURL.path)
        try #require(((attributes[.size] as? NSNumber)?.intValue ?? Int.max) <= 1_048_576)
        return try Data(contentsOf: stdoutURL)
    }

    private static let pythonDetachKnownImage = #"""
import plistlib,re,subprocess,sys
image=sys.argv[1]
def call(args):
 r=subprocess.run(['/usr/bin/hdiutil',*args],input=b'',capture_output=True,timeout=30)
 assert r.returncode==0
 return r.stdout
rows=plistlib.loads(call(['info','-plist']))['images']
owned=[row for row in rows if row.get('image-path')==image]
assert len(owned)<=1
if owned:
 nodes=[e for e in owned[0]['system-entities'] if re.fullmatch(r'/dev/disk[0-9]+',e.get('dev-entry',''))]
 nodes.sort(key=lambda e:e.get('content-hint')!='GUID_partition_scheme')
 assert nodes
 current=[row for row in plistlib.loads(call(['info','-plist']))['images'] if row.get('image-path')==image]
 assert len(current)==1 and any(e.get('dev-entry')==nodes[0]['dev-entry'] for e in current[0]['system-entities'])
 call(['detach',nodes[0]['dev-entry']])
 assert not [row for row in plistlib.loads(call(['info','-plist']))['images'] if row.get('image-path')==image]
"""#
    private static let pythonMountedAudit = #"""
from pathlib import Path
import json,os,plistlib,re,stat,subprocess,sys
stage='scratch-root'
held=[]
def require(condition, fixed_stage):
 global stage
 stage=fixed_stage
 assert condition
def identity(fd):
 value=os.fstat(fd)
 return (value.st_dev,value.st_ino,stat.S_IFMT(value.st_mode))
def open_held(path, flags, parent=None):
 descriptor=os.open(path,flags|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
 held.append(descriptor)
 return descriptor
def call(tool,args):
 r=subprocess.run([tool,*args],input=b'',capture_output=True,timeout=30)
 assert r.returncode==0
 return plistlib.loads(r.stdout)
def alias_matches(reported, expected, expected_fd, directory_fd, is_directory):
 # /var and /private/var are legitimate aliases. Canonical equality alone
 # is insufficient: pin the reported leaf without following a leaf symlink,
 # then compare it and its parent to the already held known descriptors.
 assert isinstance(reported,str) and reported.startswith('/') and '\x00' not in reported
 path=Path(reported)
 assert path.resolve(strict=True)==expected.resolve(strict=True)
 parent=open_held(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 assert identity(parent)==identity(directory_fd)
 descriptor=open_held(path.name,os.O_RDONLY|(os.O_DIRECTORY if is_directory else 0),parent)
 assert identity(descriptor)==identity(expected_fd)
 leaf=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
 assert (leaf.st_dev,leaf.st_ino,stat.S_IFMT(leaf.st_mode))==identity(expected_fd)
 return descriptor
def owned_entities(required_devices=()):
 global stage
 stage='image-inventory'
 images=call('/usr/bin/hdiutil',['info','-plist'])['images']
 owned=[]
 for row in images:
  reported=row.get('image-path')
  if isinstance(reported,str) and reported.startswith('/') and '\x00' not in reported:
   path=Path(reported)
   # Do not resolve unrelated host/user image paths from the inventory.
   if path.name=='image.dmg' and path.parent.name==candidates[0] and path.resolve(strict=True)==image.resolve(strict=True):
    owned.append(row)
 require(len(owned)==1,'image-inventory')
 stage='image-alias'
 alias_matches(owned[0]['image-path'],image,image_fd,directory_fd,False)
 entities=owned[0]['system-entities']
 require(isinstance(entities,list) and 0<len(entities)<=64,'image-entities')
 mapped={entity.get('dev-entry') for entity in entities}
 require(all(device in mapped for device in required_devices),'image-ownership')
 return entities,mapped
try:
 scratch=Path(sys.argv[1]).resolve(strict=True); selected=sys.argv[2].upper()
 root_fd=open_held(scratch,os.O_RDONLY|os.O_DIRECTORY)
 root_identity=identity(root_fd)
 require(root_identity[2]==stat.S_IFDIR,'scratch-root')
 names=os.listdir(root_fd)
 candidates=[name for name in names if re.fullmatch(r'\.native-apfs-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',name)]
 require(len(names)==1 and len(candidates)==1,'private-directory')
 directory=scratch/candidates[0]
 directory_fd=open_held(candidates[0],os.O_RDONLY|os.O_DIRECTORY,root_fd)
 directory_identity=identity(directory_fd)
 require(directory_identity[2]==stat.S_IFDIR,'private-directory')
 stage='image-descriptor'
 image=directory/'image.dmg'
 image_fd=open_held('image.dmg',os.O_RDONLY,directory_fd)
 image_identity=identity(image_fd)
 require(image_identity[2]==stat.S_IFREG,'image-descriptor')
 stage='view-descriptor'
 view=directory/'view'
 view_fd=open_held('view',os.O_RDONLY|os.O_DIRECTORY,directory_fd)
 view_identity=identity(view_fd)
 require(view_identity[2]==stat.S_IFDIR,'view-descriptor')
 expected_volumes={sys.argv[3].upper(),sys.argv[4].upper()}; expected_container=sys.argv[5].upper()
 require(len(sys.argv)==6 and len(expected_volumes)==2 and selected in expected_volumes,'expected-volumes')
 entities,mapped=owned_entities()
 # hdiutil info caches attach-time annotations and may omit volume-kind.
 # Use its backing-identity proof for device ownership, then obtain fresh
 # volume metadata through the one owned physical store/container chain.
 roots=[e['dev-entry'] for e in entities if e.get('content-hint')=='GUID_partition_scheme'
        and re.fullmatch(r'/dev/disk[0-9]+',e.get('dev-entry',''))]
 require(len(roots)==1,'root-entity'); root_device=roots[0]
 owned_entities([root_device])
 stage='root-partitions'
 disks=call('/usr/sbin/diskutil',['list','-plist',root_device])['AllDisksAndPartitions']
 require(len(disks)==1 and '/dev/'+disks[0]['DeviceIdentifier']==root_device
         and disks[0]['Content']=='GUID_partition_scheme','root-partitions')
 partitions=disks[0]['Partitions']
 stores=[p for p in partitions if p.get('Content')=='Apple_APFS']
 require(len(partitions)==1 and len(stores)==1,'physical-store')
 physical='/dev/'+stores[0]['DeviceIdentifier']
 require(physical in mapped and re.fullmatch(re.escape(root_device)+r's[0-9]+',physical) is not None,'physical-store')
 owned_entities([root_device,physical])
 stage='physical-store'
 store_info=call('/usr/sbin/diskutil',['info','-plist',physical])
 require('/dev/'+store_info['DeviceIdentifier']==physical
         and '/dev/'+store_info['ParentWholeDisk']==root_device,'physical-store')
 reference=store_info['APFSContainerReference']; container_device='/dev/'+reference
 require(re.fullmatch(r'disk[0-9]+',reference) is not None and container_device in mapped
         and container_device!=root_device,'container-entity')
 owned_entities([root_device,physical,container_device])
 stage='container-list'
 containers=call('/usr/sbin/diskutil',['apfs','list',container_device,'-plist'])['Containers']
 require(len(containers)==1,'container-list'); container=containers[0]
 require(container['ContainerReference']==reference and container['APFSContainerUUID'].upper()==expected_container,'container-identity')
 physical_stores=container['PhysicalStores']
 root_partitions={'/dev/'+p['DeviceIdentifier'] for p in partitions}
 require(len(physical_stores)==1 and {'/dev/'+p['DeviceIdentifier'] for p in physical_stores}=={physical}
         and all('/dev/'+p['DeviceIdentifier'] in root_partitions for p in physical_stores),'container-stores')
 volumes=container['Volumes']
 require(len(volumes)==2 and {v['APFSVolumeUUID'].upper() for v in volumes}==expected_volumes,'expected-volumes')
 devices=['/dev/'+v['DeviceIdentifier'] for v in volumes]
 require(len(set(devices))==2 and all(re.fullmatch(re.escape(container_device)+r's[0-9]+',d) for d in devices),'volume-nodes')
 mounted=[]
 for volume in volumes:
  owned_entities([root_device,physical,container_device])
  stage='volume-info'
  device='/dev/'+volume['DeviceIdentifier']
  info=call('/usr/sbin/diskutil',['info','-plist',device])
  require('/dev/'+info['DeviceIdentifier']==device and info['ParentWholeDisk']==reference
          and info['APFSContainerReference']==reference
          and info['VolumeUUID'].upper()==volume['APFSVolumeUUID'].upper()
          and {'/dev/'+p['APFSPhysicalStore'] for p in info['APFSPhysicalStores']}=={physical},'volume-association')
  require(info['FilesystemType']=='apfs','volume-filesystem')
  uuid=info['VolumeUUID'].upper(); point=info['MountPoint']
  if uuid==selected:
   require(bool(point) and info['WritableVolume'] is False,'selected-view')
   stage='mount-alias'
   reported_view_fd=alias_matches(point,view,view_fd,directory_fd,True)
   require(bool(os.fstatvfs(view_fd).f_flag & os.ST_RDONLY) and bool(os.fstatvfs(reported_view_fd).f_flag & os.ST_RDONLY),'descriptor-readonly')
   known_fs,reported_fs=os.fstatvfs(view_fd),os.fstatvfs(reported_view_fd)
   if hasattr(known_fs,'f_fsid') and hasattr(reported_fs,'f_fsid'):
    require(known_fs.f_fsid==reported_fs.f_fsid,'descriptor-fsid')
   mounted.append(uuid)
  else:
   require(point=='','sibling-unmounted')
 require(mounted==[selected],'selected-count')
 owned_entities([root_device,physical,container_device])
 require(identity(root_fd)==root_identity and identity(directory_fd)==directory_identity and identity(image_fd)==image_identity and identity(view_fd)==view_identity,'held-identities')
 for leaf,descriptor,parent in [('image.dmg',image_fd,directory_fd),('view',view_fd,directory_fd),(candidates[0],directory_fd,root_fd)]:
  value=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
  require((value.st_dev,value.st_ino,stat.S_IFMT(value.st_mode))==identity(descriptor),'held-identities')
 print(json.dumps({'ok':True,'stage':'complete'}))
except Exception:
 print(json.dumps({'ok':False,'stage':stage}))
finally:
 for descriptor in reversed(held):
  os.close(descriptor)
"""#
    private static let pythonBuilder = #"""
#!/usr/bin/env python3
"""Two-volume synthetic APFS selection oracle, scoped to owned images only."""
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import subprocess
import sys
import time

ROOT = Path(sys.argv[1]).resolve()
BASE = ROOT.parent
ROOT.mkdir(mode=0o700, exist_ok=True)
IMAGE = ROOT / "two-plain-apfs-volumes.dmg"
PRIVATE = ROOT / "oracle-private-image.dmg"
KNOWN_IMAGES = {str(IMAGE), str(PRIVATE)}
EXPECTED = {
    "Primary": b"PRIMARY volume bytes\nSame filename; first independently known payload.\n",
    "Secondary": "SECONDARY volume bytes\nไฟล์คนละ volume e\u0301\n".encode(),
}
SEED = ROOT / "seed-primary"
SEED.mkdir(mode=0o700)
(SEED / "shared.txt").write_bytes(EXPECTED["Primary"])


def run(tool, args, require=True):
    result = subprocess.run([tool, *args], input=b"", capture_output=True,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}, timeout=60)
    if require and result.returncode:
        (ROOT / "last-failed-command-output.txt").write_bytes(result.stdout + b"\n" + result.stderr)
        raise RuntimeError("Synthetic multi-volume command failed: " + args[0] + "; exit=" + str(result.returncode))
    return result


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path):
    value = path.stat()
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def owned(image):
    info = plistlib.loads(run("/usr/bin/hdiutil", ["info", "-plist"]).stdout)
    images = [row for row in info["images"] if row.get("image-path") == str(image)]
    assert len(images) <= 1
    return images[0] if images else None


def assert_device(image, device):
    row = owned(image)
    assert row
    if any(entity.get("dev-entry") == device for entity in row["system-entities"]):
        return
    # DiskImages retains its attach-time entity list while fixture construction
    # adds partitions/volumes. Resolve fresh descendants from the known whole
    # image device, with scoped diskutil results; never a global host inventory.
    whole = next(e["dev-entry"] for e in row["system-entities"] if re.fullmatch(r"/dev/disk[0-9]+", e.get("dev-entry", "")))
    disk_list = plistlib.loads(run("/usr/sbin/diskutil", ["list", "-plist", whole]).stdout)
    disks = disk_list["AllDisksAndPartitions"]
    assert len(disks) == 1 and "/dev/" + disks[0]["DeviceIdentifier"] == whole
    partitions = disks[0].get("Partitions", [])
    if any("/dev/" + p["DeviceIdentifier"] == device for p in partitions):
        return
    physical = next(p["DeviceIdentifier"] for p in partitions if p.get("Content") == "Apple_APFS")
    store_info = plistlib.loads(run("/usr/sbin/diskutil", ["info", "-plist", physical]).stdout)
    reference = store_info["APFSContainerReference"]
    apfs = plistlib.loads(run("/usr/sbin/diskutil", ["apfs", "list", reference, "-plist"]).stdout)
    containers = apfs["Containers"]
    assert len(containers) == 1 and any(p["DeviceIdentifier"] == physical for p in containers[0]["PhysicalStores"])
    assert device == "/dev/" + containers[0]["ContainerReference"] or any(device == "/dev/" + v["DeviceIdentifier"] for v in containers[0]["Volumes"])


def detach(image):
    row = owned(image)
    if row is None:
        return
    entities = row["system-entities"]
    candidates = [e for e in entities if re.fullmatch(r"/dev/disk[0-9]+", e.get("dev-entry", ""))]
    candidates.sort(key=lambda e: e.get("content-hint") != "GUID_partition_scheme")
    whole = candidates[0]["dev-entry"]
    assert_device(image, whole)
    run("/usr/bin/hdiutil", ["detach", whole])
    assert owned(image) is None


def info(device, filename):
    output = run("/usr/sbin/diskutil", ["info", "-plist", device]).stdout
    (ROOT / filename).write_bytes(output)
    return plistlib.loads(output)


def scoped_list(image, container, filename):
    assert_device(image, "/dev/" + container)
    output = run("/usr/sbin/diskutil", ["apfs", "list", container, "-plist"]).stdout
    (ROOT / filename).write_bytes(output)
    result = plistlib.loads(output)
    assert len(result["Containers"]) == 1
    assert result["Containers"][0]["ContainerReference"] == container
    return result["Containers"][0]


try:
    # An entirely new sparse zero-filled RAW file avoids DiskImages' one-volume
    # APFS formatting recipe and any pre-existing filesystem metadata.
    with IMAGE.open("xb") as blank:
        blank.truncate(1024 * 1024 * 1024)
    attach = run("/usr/bin/hdiutil", ["attach", str(IMAGE), "-imagekey", "diskimage-class=CRawDiskImage", "-readwrite", "-nomount", "-nobrowse", "-noautoopen", "-noautofsck", "-noverify", "-plist"]).stdout
    (ROOT / "construction-attach.plist").write_bytes(attach)
    entities = plistlib.loads(attach)["system-entities"]
    whole = next(e["dev-entry"] for e in entities if re.fullmatch(r"/dev/disk[0-9]+", e.get("dev-entry", "")))
    assert_device(IMAGE, whole)
    run("/usr/sbin/diskutil", ["partitionDisk", "-noEFI", whole, "GPT", "%Apple_HFS%", "%noformat%", "0b"])
    disk_list = plistlib.loads(run("/usr/sbin/diskutil", ["list", "-plist", whole]).stdout)
    physical_store = "/dev/" + next(p["DeviceIdentifier"] for p in disk_list["AllDisksAndPartitions"][0]["Partitions"] if p.get("Content") == "Apple_HFS")
    assert_device(IMAGE, physical_store)
    run("/usr/sbin/diskutil", ["apfs", "createContainer", physical_store])
    store_info = info(physical_store, "construction-physical-store.plist")
    container = store_info["APFSContainerReference"]
    assert_device(IMAGE, "/dev/" + container)
    run("/usr/sbin/diskutil", ["apfs", "addVolume", container, "APFS", "Primary", "-nomount"])
    assert_device(IMAGE, "/dev/" + container)
    run("/usr/sbin/diskutil", ["apfs", "addVolume", container, "APFS", "Secondary", "-nomount"])
    volumes = scoped_list(IMAGE, container, "construction-apfs-list.plist")["Volumes"]
    assert len(volumes) == 2
    primary_row = next(v for v in volumes if v["Name"] == "Primary")
    primary_device = "/dev/" + primary_row["DeviceIdentifier"]
    primary_mount = ROOT / "construction-primary"
    primary_mount.mkdir(mode=0o700)
    assert_device(IMAGE, primary_device)
    run("/usr/sbin/diskutil", ["mount", "nobrowse", "-mountPoint", str(primary_mount), primary_device])
    assert not (os.statvfs(primary_mount).f_flag & os.ST_RDONLY)
    (primary_mount / "shared.txt").write_bytes(EXPECTED["Primary"])
    secondary_row = next(v for v in volumes if v["Name"] == "Secondary")
    secondary_device = "/dev/" + secondary_row["DeviceIdentifier"]
    secondary_info = info(secondary_device, "construction-secondary-info.plist")
    assert secondary_info["MountPoint"] == "" and secondary_info["APFSContainerReference"] == container
    secondary_mount = ROOT / "construction-secondary"
    secondary_mount.mkdir(mode=0o700)
    assert_device(IMAGE, secondary_device)
    run("/usr/sbin/diskutil", ["mount", "nobrowse", "-mountPoint", str(secondary_mount), secondary_device])
    assert not (os.statvfs(secondary_mount).f_flag & os.ST_RDONLY)
    (secondary_mount / "shared.txt").write_bytes(EXPECTED["Secondary"])
    assert (primary_mount / "shared.txt").read_bytes() == EXPECTED["Primary"]
    assert (secondary_mount / "shared.txt").read_bytes() == EXPECTED["Secondary"]
    detach(IMAGE)
    source_sha, source_identity = sha(IMAGE), identity(IMAGE)
    shutil.copy2(IMAGE, PRIVATE)
    private_identity = identity(PRIVATE)
    readonly_attach = run("/usr/bin/hdiutil", ["attach", str(PRIVATE), "-readonly", "-nomount", "-noverify", "-noautofsck", "-nobrowse", "-noautoopen", "-plist"]).stdout
    (ROOT / "readonly-attach.plist").write_bytes(readonly_attach)
    readonly_entities = plistlib.loads(readonly_attach)["system-entities"]
    apfs_node = next(e["dev-entry"] for e in readonly_entities if e.get("volume-kind") == "apfs")
    selected_info = info(apfs_node, "readonly-initial-info.plist")
    readonly_container = selected_info["APFSContainerReference"]
    catalog = scoped_list(PRIVATE, readonly_container, "readonly-apfs-list.plist")
    assert len(catalog["Volumes"]) == 2
    assert_device(PRIVATE, "/dev/" + readonly_container)
    groups_result = run("/usr/sbin/diskutil", ["apfs", "listVolumeGroups", readonly_container, "-plist"], require=False)
    assert groups_result.returncode == 0
    groups = plistlib.loads(groups_result.stdout)
    (ROOT / "readonly-volume-groups.plist").write_bytes(groups_result.stdout)
    observations = []
    for row in sorted(catalog["Volumes"], key=lambda row: row["Name"]):
        assert row["Name"] in EXPECTED
        device = "/dev/" + row["DeviceIdentifier"]
        mount = ROOT / ("readonly-" + row["Name"])
        mount.mkdir(mode=0o700)
        for sibling in catalog["Volumes"]:
            sibling_info = info("/dev/" + sibling["DeviceIdentifier"], "readonly-before-" + row["Name"] + "-" + sibling["Name"] + ".plist")
            assert sibling_info["MountPoint"] == ""
        assert_device(PRIVATE, device)
        run("/usr/sbin/diskutil", ["mount", "readOnly", "nobrowse", "-mountOptions", "noexec,nosuid,nodev", "-mountPoint", str(mount), device])
        mounted_info = info(device, "readonly-mounted-" + row["Name"] + ".plist")
        assert mounted_info["VolumeUUID"] == row["APFSVolumeUUID"]
        assert mounted_info["WritableVolume"] is False
        assert os.statvfs(mount).f_flag & os.ST_RDONLY
        actual = (mount / "shared.txt").read_bytes()
        assert actual == EXPECTED[row["Name"]]
        try:
            descriptor = os.open(mount / "must-not-write", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError as error:
            assert error.errno == errno.EROFS
        else:
            os.close(descriptor)
            raise AssertionError("Selected readonly volume accepted a write")
        sibling = next(v for v in catalog["Volumes"] if v["APFSVolumeUUID"] != row["APFSVolumeUUID"])
        sibling_info = info("/dev/" + sibling["DeviceIdentifier"], "readonly-nonselected-" + row["Name"] + ".plist")
        assert sibling_info["MountPoint"] == ""
        observations.append({"volumeUUID": row["APFSVolumeUUID"], "name": row["Name"], "containerUUID": catalog["APFSContainerUUID"],
                             "relativePath": "shared.txt", "byteCount": len(actual), "sha256": hashlib.sha256(actual).hexdigest(),
                             "exactKnownBytes": True, "readOnly": True, "writeDeniedErrno": errno.EROFS,
                             "nonSelectedVolumeUnmounted": True, "roles": row.get("Roles"), "encrypted": row.get("Encryption"), "locked": row.get("Locked")})
        assert_device(PRIVATE, device)
        run("/usr/sbin/diskutil", ["unmount", device])
    detach(PRIVATE)
    assert source_sha == sha(IMAGE) == sha(PRIVATE)
    assert source_identity == identity(IMAGE) and private_identity == identity(PRIVATE)
    receipt = {"schemaVersion": 1, "synthetic": True, "profile": "two-plain-APFS-volumes-one-owned-UDIF",
               "containerSHA256": source_sha, "containerByteCount": IMAGE.stat().st_size,
               "volumes": observations, "distinctFileBytesForSamePath": True,
               "volumeGroupInventoryAvailable": True, "volumeGroupInventory": groups,
               "sourceAndPrivateHashesIdentitiesUnchanged": True, "cleanupDetached": True}
    receipt["ownedLeafPaths"] = sorted(str(path.relative_to(ROOT)) for path in ROOT.rglob("*")) + ["receipt.json"]
    (ROOT / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2))
    print(json.dumps({"result": "passed", "receipt": str((ROOT / "receipt.json").relative_to(BASE)), "volumeCount": 2, "exactDifferentFileOracles": 2}))
finally:
    for image in [PRIVATE, IMAGE]:
        try:
            detach(image)
        except Exception:
            pass

"""#
}
