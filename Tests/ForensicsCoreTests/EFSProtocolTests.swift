import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Bounded EFS credential transport")
struct EFSProtocolTests {
    @Test("Binary DER segments survive real short writes, EINTR, EAGAIN and pipe pressure")
    func segmentedCredentials() async throws {
        let fixture = try EFSProtocolFixture(large: true); defer { fixture.remove() }
        let clears = EFSProtocolClears()
        let key = try await fixture.material(clears: clears)
        let helper = try fixture.helper(mode: "normal")
        let writes = EFSProtocolWrites()
        let receipt = try await EngineClient(helperURL: helper, timeouts: Self.timeouts,
            inputWriteForTesting: { writes.write($0, bytes: $1) })
            .extractDecrypted(imageURL: fixture.source, file: fixture.file, outputURL: fixture.output,
                keyMaterial: key, expectedSourceHashes: [fixture.source.path: EFSProtocolFixture.abcHash])
        #expect(key.isConsumed)
        #expect(clears.counts.sorted() == [65_536, 131_072])
        #expect(clears.allZero)
        #expect(writes.shortWrites > 0)
        #expect(writes.injectedInterrupts == 1)
        #expect(writes.injectedWouldBlock == 1)
        #expect(writes.maximumRequested <= 65_536)
        #expect(receipt.outputPath == fixture.output.path)
        #expect(receipt.sha256 == EFSProtocolFixture.abcHash)
        #expect(receipt.byteCount == 3)
        #expect(receipt.contentStatus == "decrypted-content")
        #expect(receipt.decryption?.recipientRole == .ddf)
        // Independent Python hashlib oracle over this synthetic public DER.
        #expect(receipt.decryption?.certificateSHA1 == "976c4e94f01800cb51ec5ad4ca4dd8354a2dd821")
        #expect(receipt.decryption?.ciphertextBytes == 512)
        #expect(receipt.decryption?.authenticatedPlaintext == false)
        #expect(receipt.warnings == [ExtractionDecryptionReceipt.unauthenticatedPlaintextWarning])
        #expect(try Data(contentsOf: fixture.output) == Data("abc".utf8))
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
        let report = try fixture.report()
        #expect(report.privateBytes == 65_536 && report.certificateBytes == 131_072)
        #expect(report.privateMatched && report.certificateMatched)
        #expect(report.transportFields == ["certificateBytes", "privateKeyBytes", "profile"])
        #expect(report.privatePathInHeader == false && report.certificatePathInHeader == false)
        #expect(report.privatePathInArgumentsOrEnvironment == false)
        #expect(report.certificatePathInArgumentsOrEnvironment == false)
        #expect(report.operation == "extract-efs")
        #expect(report.attributeName == "")
        #expect(try FileAccess.identity(at: fixture.source) == fixture.sourceIdentity)
    }

    @Test("Cancellation during a partial DER segment closes stdin and never injects JSON into key bytes")
    func partialCredentialCancellation() async throws {
        let fixture = try EFSProtocolFixture(large: true); defer { fixture.remove() }
        let clears = EFSProtocolClears(), cancellation = EFSProtocolCancellation()
        let material = try await fixture.material(clears: clears)
        let helper = try fixture.helper(mode: "partial-cancel")
        let task = Task {
            try await EngineClient(helperURL: helper, timeouts: Self.timeouts,
                inputWriteForTesting: { Darwin.write($0, $1.baseAddress, min(257, $1.count)) })
                .extractDecrypted(imageURL: fixture.source, file: fixture.file, outputURL: fixture.output,
                    keyMaterial: material, progress: { if $0.stage == "credential-prefix" { cancellation.cancel() } })
        }
        cancellation.install(task)
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        let report = try fixture.cancellationReport()
        #expect(report.readBytes > 0 && report.readBytes < 196_608)
        #expect(report.cancelFrameDetected == false)
        #expect(report.stdinEOF)
        #expect(material.isConsumed && clears.allZero)
        #expect(clears.counts.sorted() == [65_536, 131_072])
        #expect(!FileManager.default.fileExists(atPath: fixture.output.path))
        #expect(try FileAccess.identity(at: fixture.source) == fixture.sourceIdentity)
        try fixture.expectNoStagingDirectory()
    }

    @Test("A complete binary key stream retains cooperative same-job JSON cancellation")
    func completedCredentialCancellation() async throws {
        let fixture = try EFSProtocolFixture(); defer { fixture.remove() }
        let cancellation = EFSProtocolCancellation(), material = try await fixture.material()
        let helper = try fixture.helper(mode: "full-cancel")
        let task = Task {
            try await EngineClient(helperURL: helper, timeouts: Self.timeouts)
                .extractDecrypted(imageURL: fixture.source, file: fixture.file, outputURL: fixture.output,
                    keyMaterial: material, progress: { if $0.stage == "credentials-ready" { cancellation.cancel() } })
        }
        cancellation.install(task)
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        let report = try fixture.cancellationReport()
        #expect(report.readBytes == 192)
        #expect(report.cancelFrameDetected && report.sameJob)
        #expect(material.isConsumed)
        #expect(!FileManager.default.fileExists(atPath: fixture.output.path))
        try fixture.expectNoStagingDirectory()
    }

    @Test("Helper death and diagnostic reflection cannot publish bytes or expose credential diagnostics", arguments: ["crash", "failed-diagnostic"])
    func failedCredentialJobs(_ mode: String) async throws {
        let fixture = try EFSProtocolFixture(large: true); defer { fixture.remove() }
        let clears = EFSProtocolClears(), material = try await fixture.material(clears: clears)
        let helper = try fixture.helper(mode: mode)
        do {
            _ = try await EngineClient(helperURL: helper, timeouts: Self.timeouts)
                .extractDecrypted(imageURL: fixture.source, file: fixture.file, outputURL: fixture.output, keyMaterial: material)
            Issue.record("A failed EFS helper was accepted.")
        } catch {
            #expect(!error.localizedDescription.contains("synthetic-private-diagnostic"))
        }
        #expect(material.isConsumed && clears.allZero)
        #expect(clears.counts.sorted() == [65_536, 131_072])
        #expect(!FileManager.default.fileExists(atPath: fixture.output.path))
        #expect(try FileAccess.identity(at: fixture.source) == fixture.sourceIdentity)
        try fixture.expectNoStagingDirectory()
    }

    @Test("EFS receipts cannot inherit legacy logical-content success", arguments: [
        "missing-decryption", "wrong-status", "missing-status", "empty-warnings", "missing-warnings",
        "wrong-profile", "unknown-role", "authenticated", "wrong-unit", "wrong-ciphertext-count", "upper-hash",
        "bad-certificate-hash", "wrong-certificate", "absent-capability", "wrong-output-hash", "wrong-output-size"
    ])
    func strictDecryptionReceipts(_ mode: String) async throws {
        let fixture = try EFSProtocolFixture(); defer { fixture.remove() }
        let material = try await fixture.material(), helper = try fixture.helper(mode: mode)
        if mode == "absent-capability" {
            await #expect(throws: EngineError.protocolViolation("The native engine does not advertise the required EFS key profile.")) {
                _ = try await EngineClient(helperURL: helper, timeouts: Self.timeouts)
                    .extractDecrypted(imageURL: fixture.source, file: fixture.file, outputURL: fixture.output, keyMaterial: material)
            }
        } else {
            await #expect(throws: EngineError.self) {
                _ = try await EngineClient(helperURL: helper, timeouts: Self.timeouts)
                    .extractDecrypted(imageURL: fixture.source, file: fixture.file, outputURL: fixture.output, keyMaterial: material)
            }
        }
        if mode != "absent-capability" {
            // An unrelated early script failure cannot satisfy a negative:
            // prove exact credentials first, then a fully emitted receipt.
            let credentialReport = try fixture.report()
            #expect(credentialReport.privateMatched && credentialReport.certificateMatched)
            #expect(credentialReport.privateBytes == fixture.privateCount && credentialReport.certificateBytes == fixture.certificateCount)
            #expect(credentialReport.operation == "extract-efs")
            #expect(credentialReport.transportFields == ["certificateBytes", "privateKeyBytes", "profile"])
            #expect(credentialReport.attributeName == "")
            try fixture.verifyReceiptEmission(mode: mode)
        }
        #expect(material.isConsumed)
        #expect(!FileManager.default.fileExists(atPath: fixture.output.path))
        try fixture.expectNoStagingDirectory()
    }

    @Test("Ordinary extraction rejects unsolicited decrypted-content provenance")
    func ordinaryContradiction() async throws {
        let fixture = try EFSProtocolFixture(); defer { fixture.remove() }
        let helper = try fixture.helper(mode: "ordinary-decryption")
        await #expect(throws: EngineError.self) {
            _ = try await EngineClient(helperURL: helper, timeouts: Self.timeouts)
                .extract(imageURL: fixture.source, file: fixture.file, outputURL: fixture.output)
        }
        try fixture.verifyReceiptEmission(mode: "ordinary-decryption")
        #expect(!FileManager.default.fileExists(atPath: fixture.output.path))
    }

    @Test("Legacy entries and receipts omit encryption fields while named DATA does not establish EFS eligibility")
    func optionalLegacyFields() throws {
        let legacy = FilesystemEntry(id: "f", path: "/f", name: "f", fsOffsetBytes: 0, metaAddress: 1,
            size: 3, isDirectory: false, isDeleted: false)
        let entryData = try JSONEncoder().encode(legacy)
        let entryObject = try #require(try JSONSerialization.jsonObject(with: entryData) as? [String: Any])
        #expect(entryObject["encryptionStatus"] == nil && entryObject["attributeName"] == nil)
        #expect(try JSONDecoder().decode(FilesystemEntry.self, from: entryData) == legacy)
        let receipt = ExtractionResult(outputPath: "/synthetic", byteCount: 3, sha256: EFSProtocolFixture.abcHash)
        let receiptData = try JSONEncoder().encode(receipt)
        let receiptObject = try #require(try JSONSerialization.jsonObject(with: receiptData) as? [String: Any])
        #expect(receiptObject["decryption"] == nil)
        #expect(try JSONDecoder().decode(ExtractionResult.self, from: receiptData) == receipt)
        let named = FilesystemEntry(id: "named", path: "/f:notes", name: "f:notes", fsOffsetBytes: 0,
            metaAddress: 1, attributeType: 128, attributeID: 4, size: 3, isDirectory: false, isDeleted: false, attributeName: "notes")
        try EngineValidation.file(named)
        #expect(named.encryptionStatus == nil)
    }

    @Test("Ciphertext unit counts and tag hashes remain strict at arithmetic boundaries")
    func receiptArithmetic() throws {
        let valid = ExtractionDecryptionReceipt(profile: "ntfs-efs-rsa-pkcs1-aes256-der", recipientRole: .drf,
            metadataSHA256: String(repeating: "a", count: 64), certificateSHA1: String(repeating: "c", count: 40),
            ciphertextSHA256: String(repeating: "b", count: 64), ciphertextBytes: 1_024, unitBytes: 512, authenticatedPlaintext: false)
        try EngineValidation.decryption(valid, plaintextBytes: 513)
        #expect(throws: EngineError.self) { try EngineValidation.decryption(valid, plaintextBytes: Int64.max) }
        #expect(throws: EngineError.self) { try EngineValidation.decryption(valid, plaintextBytes: -1) }
    }

    @Test("Listing string budgets charge attributeName once and exclude typed encryption tags")
    func attributeNameStringBudget() throws {
        func entry(name: String?, encrypted: Bool) -> FilesystemEntry {
            FilesystemEntry(id: "f", path: "/f", name: "f", fsOffsetBytes: 0, metaAddress: 1,
                attributeType: 128, attributeID: 3, size: 3, isDirectory: false, isDeleted: false,
                encryptionStatus: encrypted ? .ntfsEFSEncrypted : nil, attributeName: name)
        }
        func result(_ file: FilesystemEntry) -> EnumerationResult {
            EnumerationResult(engineVersion: "synthetic", patchDigest: "test", sourcePaths: ["/synthetic.dd"],
                sourceFileHashes: ["/synthetic.dd": EFSProtocolFixture.abcHash], options: EngineOptions(hashLogicalImage: false),
                image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512, imagePaths: ["/synthetic.dd"]),
                volumes: [], files: [file], warnings: [], status: .completed)
        }
        let baseline = try FilesystemListingStringCost.measure(result(entry(name: nil, encrypted: false))).rawUTF8Bytes
        let stream = "e\u{301}資料"
        #expect(try FilesystemListingStringCost.measure(result(entry(name: stream, encrypted: false))).rawUTF8Bytes == baseline + stream.utf8.count)
        #expect(try FilesystemListingStringCost.measure(result(entry(name: "", encrypted: true))).rawUTF8Bytes == baseline)
    }

    @Test("Credential oversize and missing candidate provenance fail before any helper launch")
    func preflightGuards() async throws {
        let fixture = try EFSProtocolFixture(); defer { fixture.remove() }
        try Data(EFSProtocolFixture.der(total: 65_537, byte: 0x55)).write(to: fixture.key)
        await #expect(throws: EFSKeyInputError.invalidKeyFile) { _ = try await fixture.material() }
        try Data(EFSProtocolFixture.der(total: 64, byte: 0x55)).write(to: fixture.key)
        let material = try await fixture.material()
        let helper = try fixture.helper(mode: "normal")
        let legacy = FilesystemEntry(id: "legacy", path: "/legacy", name: "legacy", fsOffsetBytes: 0,
            metaAddress: 1, attributeType: 128, attributeID: 3, size: 3, isDirectory: false, isDeleted: false)
        await #expect(throws: EngineError.self) {
            _ = try await EngineClient(helperURL: helper).extractDecrypted(imageURL: fixture.source,
                file: legacy, outputURL: fixture.output, keyMaterial: material)
        }
        #expect(material.isConsumed)
        #expect(!FileManager.default.fileExists(atPath: fixture.reportURL.path))
    }

    @Test("Existing destinations and wrong source hashes discard credentials without publishing")
    func sourceAndPublicationGuards() async throws {
        let fixture = try EFSProtocolFixture(); defer { fixture.remove() }
        let helper = try fixture.helper(mode: "normal")
        let wrongSourceKey = try await fixture.material()
        await #expect(throws: EngineError.sourceChanged) {
            _ = try await EngineClient(helperURL: helper).extractDecrypted(imageURL: fixture.source,
                file: fixture.file, outputURL: fixture.output, keyMaterial: wrongSourceKey,
                expectedSourceHashes: [fixture.source.path: String(repeating: "0", count: 64)])
        }
        #expect(wrongSourceKey.isConsumed)
        try Data("preserve".utf8).write(to: fixture.output)
        let existingKey = try await fixture.material()
        await #expect(throws: EngineError.self) {
            _ = try await EngineClient(helperURL: helper).extractDecrypted(imageURL: fixture.source,
                file: fixture.file, outputURL: fixture.output, keyMaterial: existingKey)
        }
        #expect(existingKey.isConsumed)
        #expect(try Data(contentsOf: fixture.output) == Data("preserve".utf8))
        #expect(!FileManager.default.fileExists(atPath: fixture.reportURL.path))
    }

    private static let timeouts = EngineTimeouts(startup: 10, inactivity: 10, cancellationGrace: 0.3, terminationGrace: 0.3)
}

private struct EFSProtocolFixture: Sendable {
    static let abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    let directory: URL, source: URL, key: URL, certificate: URL, output: URL, reportURL: URL
    let sourceIdentity: SourceIdentity
    let privateCount: Int, certificateCount: Int
    var file: FilesystemEntry {
        FilesystemEntry(id: "efs-allocated", path: "/encrypted.txt", name: "encrypted.txt", fsOffsetBytes: 0,
            metaAddress: 31, attributeType: 128, attributeID: 3, size: 3, isDirectory: false, isDeleted: false,
            encryptionStatus: .ntfsEFSEncrypted, attributeName: "")
    }
    init(large: Bool = false) throws {
        // The production credential reader deliberately rejects symlinked
        // ancestors, including macOS /var aliases. Use an owned ignored repo
        // directory and establish its identity with no-follow descriptors.
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let local = try FileAccess.localURL(repository).appendingPathComponent("local", isDirectory: true)
        if Darwin.mkdir(local.path, mode_t(0o700)) != 0 && errno != EEXIST {
            throw FileAccess.posixError("Cannot create synthetic EFS fixture parent")
        }
        // An existing shared local directory retains its permissions. Verify
        // its held identity and owner instead of silently accepting an alias.
        let localFD = Darwin.open(local.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard localFD >= 0 else { throw FileAccess.posixError("Cannot open synthetic EFS fixture parent") }
        defer { Darwin.close(localFD) }
        var parentHeld = stat(), parentNamed = stat()
        guard Darwin.fstat(localFD, &parentHeld) == 0, Darwin.lstat(local.path, &parentNamed) == 0,
              parentHeld.st_mode & S_IFMT == S_IFDIR, parentHeld.st_uid == Darwin.getuid(),
              parentHeld.st_dev == parentNamed.st_dev, parentHeld.st_ino == parentNamed.st_ino else {
            throw EFSKeyInputError.invalidSelection
        }
        directory = local.appendingPathComponent("EFS Protocol \(UUID().uuidString)", isDirectory: true)
        guard Darwin.mkdirat(localFD, directory.lastPathComponent, mode_t(0o700)) == 0 else { throw FileAccess.posixError("Cannot create synthetic EFS fixture") }
        let directoryFD = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { throw FileAccess.posixError("Cannot verify synthetic EFS fixture") }
        defer { Darwin.close(directoryFD) }
        var held = stat(), named = stat()
        guard Darwin.fstat(directoryFD, &held) == 0, Darwin.lstat(directory.path, &named) == 0,
              held.st_mode & S_IFMT == S_IFDIR, held.st_mode & 0o777 == 0o700,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
            throw EFSKeyInputError.invalidSelection
        }
        source = directory.appendingPathComponent("source.dd")
        key = directory.appendingPathComponent("synthetic private.der")
        certificate = directory.appendingPathComponent("synthetic certificate.der")
        output = directory.appendingPathComponent("decrypted.bin")
        reportURL = directory.appendingPathComponent("transport-observations.json")
        privateCount = large ? 65_536 : 64; certificateCount = large ? 131_072 : 128
        try Data("abc".utf8).write(to: source)
        try Data(Self.der(total: privateCount, byte: 0x55)).write(to: key)
        try Data(Self.der(total: certificateCount, byte: 0xaa)).write(to: certificate)
        sourceIdentity = try FileAccess.identity(at: source)
    }
    func material(clears: EFSProtocolClears? = nil) async throws -> EFSKeyMaterial {
        guard let clears else { return try await EFSKeyMaterial.read(privateKeyURL: key, certificateURL: certificate) }
        return try await EFSKeyMaterial.readForTesting(privateKeyURL: key, certificateURL: certificate,
            hooks: EFSKeyReadHooks(read: { try FileAccess.read($0, into: $1, count: $2) }, afterRead: { _ in },
                descriptorClosed: {}, bufferCleared: { clears.observe($0) }, uptime: { ProcessInfo.processInfo.systemUptime }))
    }
    func report() throws -> EFSWireReport { try JSONDecoder().decode(EFSWireReport.self, from: Data(contentsOf: reportURL)) }
    func cancellationReport() throws -> EFSCancelReport { try JSONDecoder().decode(EFSCancelReport.self, from: Data(contentsOf: directory.appendingPathComponent("cancellation.json"))) }
    func verifyReceiptEmission(mode: String) throws {
        let emission = try JSONDecoder().decode(EFSReceiptEmission.self,
            from: Data(contentsOf: directory.appendingPathComponent("receipt-emitted.json")))
        #expect(emission.mode == mode)
        let frameBytes = Data(emission.extractedFrame.utf8)
        #expect(frameBytes.count <= 16_384)
        #expect(frameBytes.last == 10)
        let observedDigest = SHA256.hash(data: frameBytes).map { String(format: "%02x", $0) }.joined()
        #expect(observedDigest == emission.emittedReceiptSHA256)
        let frame = try #require(try JSONSerialization.jsonObject(with: frameBytes) as? [String: Any])
        #expect(frame["type"] as? String == "extracted")
        #expect(frame["sequence"] as? Int == 2)
    }
    func expectNoStagingDirectory() throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(names.allSatisfy { !$0.hasPrefix(".native-extract-") })
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    static func der(total: Int, byte: UInt8) -> [UInt8] {
        if total < 130 { return [0x30, UInt8(total - 2)] + Array(repeating: byte, count: total - 2) }
        if total - 4 <= 65_535 {
            let length = total - 4
            return [0x30, 0x82, UInt8(length >> 8), UInt8(length & 0xff)] + Array(repeating: byte, count: length)
        }
        let length = total - 5
        return [0x30, 0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xff), UInt8(length & 0xff)] + Array(repeating: byte, count: length)
    }
    func helper(mode: String) throws -> URL {
        let helper = directory.appendingPathComponent("transport helper.py")
        let script = """
        #!/usr/bin/python3
        import os,sys,json,time,signal,hashlib
        mode=\(Self.literal(mode))
        report_path=\(Self.literal(reportURL.path))
        cancel_path=\(Self.literal(directory.appendingPathComponent("cancellation.json").path))
        key_path=\(Self.literal(key.path))
        certificate_path=\(Self.literal(certificate.path))
        receipt_emitted_path=\(Self.literal(directory.appendingPathComponent("receipt-emitted.json").path))
        canonical_warning=\(Self.literal(ExtractionDecryptionReceipt.unauthenticatedPlaintextWarning))
        def read_line():
            line=bytearray()
            while len(line)<=1048576:
                b=os.read(0,1)
                if not b: return bytes(line)
                line.extend(b)
                if b==b'\\n': return bytes(line)
            raise RuntimeError('bounded-header')
        header=read_line(); request=json.loads(header); sequence=0
        def emit(kind,**values):
            global sequence
            frame=dict(protocolVersion=1,jobID=request['jobID'],sequence=sequence,type=kind)
            frame.update(values); sequence+=1
            wire=json.dumps(frame)+'\\n'
            sys.stdout.write(wire);sys.stdout.flush()
            return wire
        emit('hello',engineVersion='synthetic-efs-wire',patchDigest='synthetic-only',capabilities=[] if mode=='absent-capability' else ['ntfs-efs-rsa-aes256-der'])
        def read_exact(count):
            output=bytearray()
            while len(output)<count:
                piece=os.read(0,min(733,count-len(output)))
                if not piece: raise RuntimeError('truncated-segment')
                output.extend(piece)
                if count>1024: time.sleep(.001)
            return bytes(output)
        def der(total,byte):
            if total<130: return bytes([48,total-2])+bytes([byte])*(total-2)
            if total-4<=65535:
                n=total-4; return bytes([48,130,n>>8,n&255])+bytes([byte])*n
            n=total-5; return bytes([48,131,n>>16,(n>>8)&255,n&255])+bytes([byte])*n
        if mode=='partial-cancel':
            signal.signal(signal.SIGTERM,lambda *_:None)
            prefix=os.read(0,1)
            emit('progress',stage='credential-prefix',completed=1,unit='bytes')
            count=len(prefix); rolling=b'';found=False
            while True:
                piece=os.read(0,4096)
                if not piece: break
                count+=len(piece);rolling=(rolling+piece)[-8192:]
                found=found or b'"operation":"cancel"' in rolling
            with open(cancel_path,'x') as f: json.dump(dict(readBytes=count,cancelFrameDetected=found,stdinEOF=True,sameJob=False),f)
            emit('cancelled',fileCount=0);sys.exit(2)
        if mode=='crash':
            os.read(0,1);sys.stderr.write('synthetic-private-diagnostic');sys.stderr.flush();os._exit(73)
        if request['operation']=='extract-efs':
            transport=request['credentialTransport'];private=read_exact(transport['privateKeyBytes']);certificate=read_exact(transport['certificateBytes'])
            environment='\\n'.join(os.environ.values())
            observations=dict(operation=request['operation'],transportFields=sorted(transport),privateBytes=len(private),certificateBytes=len(certificate),
                privateMatched=private==der(len(private),85),certificateMatched=certificate==der(len(certificate),170),
                privatePathInHeader=key_path.encode() in header,certificatePathInHeader=certificate_path.encode() in header,
                privatePathInArgumentsOrEnvironment=key_path in environment or key_path in sys.argv,
                certificatePathInArgumentsOrEnvironment=certificate_path in environment or certificate_path in sys.argv,
                attributeName=request['file'].get('attributeName'))
            with open(report_path,'x') as f:json.dump(observations,f)
        if mode=='full-cancel':
            emit('progress',stage='credentials-ready',completed=len(private)+len(certificate),unit='bytes')
            cancellation=json.loads(read_line())
            with open(cancel_path,'x') as f:json.dump(dict(readBytes=len(private)+len(certificate),cancelFrameDetected=cancellation.get('operation')=='cancel',sameJob=cancellation.get('jobID')==request['jobID'],stdinEOF=False),f)
            emit('cancelled',fileCount=0);sys.exit(2)
        if mode=='failed-diagnostic':
            sys.stderr.write('synthetic-private-diagnostic');sys.stderr.flush()
            emit('error',code='synthetic-private-diagnostic',message='synthetic-private-diagnostic');emit('failed',fileCount=0);sys.exit(1)
        emit('image',imageType='raw',logicalSize=3,sectorSize=512,logicalSha256='\(Self.abcHash)',imagePaths=request['imagePaths'])
        with open(request['outputPath'],'xb') as f:f.write(b'abc')
        receipt=dict(outputPath=request['outputPath'],byteCount=3,sha256='\(Self.abcHash)',contentStatus='decrypted-content',warnings=[canonical_warning],
            decryption=dict(profile='ntfs-efs-rsa-pkcs1-aes256-der',recipientRole='ddf',metadataSHA256='a'*64,certificateSHA1=hashlib.sha1(certificate).hexdigest() if request['operation']=='extract-efs' else 'c'*40,ciphertextSHA256='b'*64,ciphertextBytes=512,unitBytes=512,authenticatedPlaintext=False))
        if mode=='missing-decryption':receipt.pop('decryption')
        if mode=='wrong-status':receipt['contentStatus']='logical-content'
        if mode=='missing-status':receipt.pop('contentStatus')
        if mode=='empty-warnings':receipt['warnings']=[]
        if mode=='missing-warnings':receipt.pop('warnings')
        if mode=='wrong-profile':receipt['decryption']['profile']='unrecognized'
        if mode=='unknown-role':receipt['decryption']['recipientRole']='owner'
        if mode=='authenticated':receipt['decryption']['authenticatedPlaintext']=True
        if mode=='wrong-unit':receipt['decryption']['unitBytes']=16
        if mode=='wrong-ciphertext-count':receipt['decryption']['ciphertextBytes']=3
        if mode=='upper-hash':receipt['decryption']['metadataSHA256']='A'*64
        if mode=='bad-certificate-hash':receipt['decryption']['certificateSHA1']='c'*64
        if mode=='wrong-certificate':receipt['decryption']['certificateSHA1']='0'*40
        if mode=='wrong-output-hash':receipt['sha256']='0'*64
        if mode=='wrong-output-size':receipt['byteCount']=4
        previous_handler=signal.signal(signal.SIGTERM,signal.SIG_IGN)
        extracted_wire=emit('extracted',**receipt)
        with open(receipt_emitted_path,'x') as f:
            json.dump(dict(mode=mode,extractedFrame=extracted_wire,emittedReceiptSHA256=hashlib.sha256(extracted_wire.encode('utf-8')).hexdigest()),f)
        signal.signal(signal.SIGTERM,previous_handler)
        emit('completed',fileCount=0)
        """
        try Data(script.utf8).write(to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        return helper
    }
    private static func literal(_ value: String) -> String {
        let encoder = JSONEncoder()
        // A JSON escape for slash is not a Python string escape. Preserve
        // exact synthetic path spellings when embedding the literal in code.
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: try! encoder.encode(value), as: UTF8.self)
    }
}

private struct EFSReceiptEmission: Decodable { let mode: String, extractedFrame: String, emittedReceiptSHA256: String }

private struct EFSWireReport: Decodable {
    let operation: String, transportFields: [String], privateBytes: Int, certificateBytes: Int
    let privateMatched: Bool, certificateMatched: Bool, privatePathInHeader: Bool, certificatePathInHeader: Bool
    let privatePathInArgumentsOrEnvironment: Bool, certificatePathInArgumentsOrEnvironment: Bool
    let attributeName: String?
}
private struct EFSCancelReport: Decodable {
    let readBytes: Int, cancelFrameDetected: Bool, stdinEOF: Bool, sameJob: Bool
}
private final class EFSProtocolClears: @unchecked Sendable {
    private let lock = NSLock(); private var cleared: [Int] = []; private var zero = true
    func observe(_ bytes: UnsafeRawBufferPointer) { lock.lock(); cleared.append(bytes.count); zero = zero && bytes.allSatisfy { $0 == 0 }; lock.unlock() }
    var counts: [Int] { lock.lock(); defer { lock.unlock() }; return cleared }
    var allZero: Bool { lock.lock(); defer { lock.unlock() }; return zero }
}
private final class EFSProtocolWrites: @unchecked Sendable {
    private let lock = NSLock(); private var calls = 0, short = 0, interrupts = 0, blocks = 0, maximum = 0
    func write(_ descriptor: Int32, bytes: UnsafeRawBufferPointer) -> Int {
        lock.lock(); calls += 1; let call = calls; maximum = max(maximum, bytes.count)
        if call == 1 { interrupts += 1; lock.unlock(); errno = EINTR; return -1 }
        if call == 3 { blocks += 1; lock.unlock(); errno = EAGAIN; return -1 }
        lock.unlock()
        let count = Darwin.write(descriptor, bytes.baseAddress, min(257, bytes.count))
        if count > 0 && count < bytes.count { lock.lock(); short += 1; lock.unlock() }
        return count
    }
    var shortWrites: Int { lock.lock(); defer { lock.unlock() }; return short }
    var injectedInterrupts: Int { lock.lock(); defer { lock.unlock() }; return interrupts }
    var injectedWouldBlock: Int { lock.lock(); defer { lock.unlock() }; return blocks }
    var maximumRequested: Int { lock.lock(); defer { lock.unlock() }; return maximum }
}
private final class EFSProtocolCancellation: @unchecked Sendable {
    private let lock = NSLock(); private var task: Task<ExtractionResult, Error>?; private var requested = false
    func install(_ task: Task<ExtractionResult, Error>) { lock.lock(); self.task = task; let cancel = requested; lock.unlock(); if cancel { task.cancel() } }
    func cancel() { lock.lock(); requested = true; let target = task; lock.unlock(); target?.cancel() }
}
