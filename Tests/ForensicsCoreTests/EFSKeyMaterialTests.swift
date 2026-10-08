import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Single-use EFS key material", .serialized)
struct EFSKeyMaterialTests {
    @Test("Direct read preserves exact bytes and consumes the pair once without paths or digests")
    func exactSingleUse() async throws {
        let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
        let observations = EFSKeyReadObservations()
        let material = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
            hooks: observations.hooks())
        #expect(material.privateKeyByteCount == fixture.keyBytes.count)
        #expect(material.certificateByteCount == fixture.certificateBytes.count)
        #expect(!material.isConsumed && observations.closedCount == 2)
        let counts = try material.consume { key, certificate in
            #expect(Array(key) == fixture.keyBytes && Array(certificate) == fixture.certificateBytes)
            #expect(material.isConsumed)
            return (key.count, certificate.count)
        }
        #expect(counts.0 == fixture.keyBytes.count && counts.1 == fixture.certificateBytes.count)
        #expect(material.isConsumed && observations.clearedCounts == [fixture.keyBytes.count, fixture.certificateBytes.count])
        #expect(observations.everyClearWasZero)
        #expect(throws: EFSKeyInputError.alreadyConsumed) { try material.consume { _, _ in () } }
        material.discard()
        #expect(observations.clearedCounts.count == 2)
        #expect(!EFSKeyInputError.invalidKeyFile.localizedDescription.contains(fixture.key.path))
    }

    @Test("Throwing consumers and explicit discard release both owned allocations")
    func releaseOnError() async throws {
        let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
        let observations = EFSKeyReadObservations()
        let material = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
            hooks: observations.hooks())
        #expect(throws: EFSKeyInputError.invalidSelection) {
            try material.consume { _, _ in throw EFSKeyInputError.invalidSelection }
        }
        #expect(observations.clearedCounts.count == 2 && observations.everyClearWasZero)
        let discarded = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
            hooks: observations.hooks())
        discarded.discard()
        #expect(discarded.isConsumed && observations.clearedCounts.count == 4)
    }

    @Test("Exact independent limits accept complete DER envelopes; over-cap inputs are never read")
    func inputBoundaries() async throws {
        let fixture = try EFSKeyMaterialFixture(
            keyBytes: EFSKeyMaterialFixture.envelope(totalBytes: 65_536),
            certificateBytes: EFSKeyMaterialFixture.envelope(totalBytes: 131_072))
        defer { fixture.remove() }
        let material = try await EFSKeyMaterial.read(privateKeyURL: fixture.key, certificateURL: fixture.certificate)
        #expect(material.privateKeyByteCount == 65_536 && material.certificateByteCount == 131_072)
        material.discard()
        try Data(EFSKeyMaterialFixture.envelope(totalBytes: 65_537)).write(to: fixture.key)
        let observations = EFSKeyReadObservations()
        do {
            _ = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
                hooks: observations.hooks())
            Issue.record("An oversized private key was accepted.")
        } catch { #expect(error as? EFSKeyInputError == .invalidKeyFile) }
        #expect(observations.readCount == 0 && observations.closedCount == 1)
    }

    @Test("Symlink leaves, symlink ancestors, directories and FIFOs fail before reading")
    func rejectsRedirectedAndSpecialFiles() async throws {
        let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
        let leaf = fixture.directory.appendingPathComponent("key-link.der")
        try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: fixture.key)
        let aliasDirectory = fixture.directory.appendingPathComponent("ancestor-link")
        try FileManager.default.createSymbolicLink(at: aliasDirectory, withDestinationURL: fixture.directory)
        let fifo = fixture.directory.appendingPathComponent("key-fifo.der")
        #expect(Darwin.mkfifo(fifo.path, 0o600) == 0)
        let observations = EFSKeyReadObservations()
        for rejected in [leaf, aliasDirectory.appendingPathComponent(fixture.key.lastPathComponent), fixture.directory, fifo] {
            do {
                _ = try await EFSKeyMaterial.readForTesting(privateKeyURL: rejected, certificateURL: fixture.certificate,
                    hooks: observations.hooks())
                Issue.record("A redirected or special credential file was accepted.")
            } catch { #expect(error as? EFSKeyInputError == .invalidSelection) }
        }
        #expect(observations.readCount == 0)
    }

    @Test("Same-size mutation and pathname replacement invalidate the pinned credential read")
    func changedCredential() async throws {
        for replace in [false, true] {
            let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
            let observations = EFSKeyReadObservations()
            let hooks = observations.hooks(afterRead: { _ in
                if replace {
                    let new = fixture.directory.appendingPathComponent("replacement.der")
                    try Data(fixture.keyBytes).write(to: new)
                    #expect(Darwin.rename(new.path, fixture.key.path) == 0)
                } else {
                    let fd = Darwin.open(fixture.key.path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
                    guard fd >= 0 else { throw EFSKeyInputError.invalidSelection }
                    defer { Darwin.close(fd) }
                    var changed: UInt8 = 0x56
                    #expect(Darwin.pwrite(fd, &changed, 1, 4) == 1)
                }
            })
            do {
                _ = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate, hooks: hooks)
                Issue.record("A changed credential file was accepted.")
            } catch { #expect(error as? EFSKeyInputError == .sourceChanged) }
            #expect(observations.closedCount == 1 && observations.clearedCounts.count == 1 && observations.everyClearWasZero)
        }
    }

    @Test("Mid-read I/O failure cannot return a partial private key")
    func midReadFailure() async throws {
        let fixture = try EFSKeyMaterialFixture(keyBytes: EFSKeyMaterialFixture.envelope(totalBytes: 32_768))
        defer { fixture.remove() }
        let observations = EFSKeyReadObservations()
        let hooks = observations.hooks(read: { descriptor, bytes, count in
            if observations.readCount > 1 { throw EFSKeyInputError.invalidKeyFile }
            #expect(fcntl(descriptor, F_GETFL) & O_ACCMODE == O_RDONLY)
            #expect(fcntl(descriptor, F_GETFD) & FD_CLOEXEC == FD_CLOEXEC)
            return try FileAccess.read(descriptor, into: bytes, count: count)
        })
        do {
            _ = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate, hooks: hooks)
            Issue.record("A partial read was accepted.")
        } catch { #expect(error as? EFSKeyInputError == .invalidKeyFile) }
        #expect(observations.readCount == 2 && observations.closedCount == 1)
        #expect(observations.clearedCounts == [32_768] && observations.everyClearWasZero)
    }

    @Test("Cancellation awaits the reader's held descriptor and clears bytes before returning")
    func cancellationDrains() async throws {
        let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
        let gate = EFSKeyReaderGate(), observations = EFSKeyReadObservations()
        let task = Task {
            defer { observations.markCompleted() }
            return try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
                hooks: observations.hooks(afterRead: { _ in try gate.pause() }))
        }
        defer { task.cancel(); gate.release() }
        do { try await gate.waitEntered() }
        catch { task.cancel(); gate.release(); _ = try? await task.value; throw error }
        task.cancel()
        try await Task.sleep(nanoseconds: 30_000_000)
        #expect(!observations.completed)
        #expect(observations.closedCount == 0 && observations.clearedCounts.isEmpty)
        gate.release()
        do { _ = try await task.value; Issue.record("A cancelled key reader returned material.") }
        catch { #expect(error is CancellationError) }
        #expect(observations.closedCount == 1 && observations.clearedCounts == [fixture.keyBytes.count])
        #expect(observations.everyClearWasZero)
        #expect(observations.closedAtCompletion == 1 && observations.clearedAtCompletion == 1)
    }

    @Test("Certificate limits, framing and I/O failures clear the already-read private key")
    func certificateFailures() async throws {
        for mode in 0...2 {
            let certificate: [UInt8] = mode == 0 ? EFSKeyMaterialFixture.envelope(totalBytes: 131_073)
                : (mode == 1 ? [0x30, 0x02, 0x01] : [0x30, 0x03, 0x02, 0x01, 0x01])
            let fixture = try EFSKeyMaterialFixture(certificateBytes: certificate); defer { fixture.remove() }
            let observations = EFSKeyReadObservations()
            let hooks = observations.hooks(read: { descriptor, bytes, count in
                if mode == 2 && observations.readCount == 2 { throw EFSKeyInputError.invalidCertificateFile }
                return try FileAccess.read(descriptor, into: bytes, count: count)
            })
            do {
                _ = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate, hooks: hooks)
                Issue.record("An invalid certificate input was accepted.")
            } catch { #expect(error as? EFSKeyInputError == .invalidCertificateFile) }
            #expect(observations.closedCount == 2 && observations.everyClearWasZero)
            #expect(observations.clearedCounts.contains(fixture.keyBytes.count))
            #expect(observations.clearedCounts.count == (mode == 0 ? 1 : 2))
            #expect(observations.readCount == (mode == 0 ? 1 : 2))
        }
    }

    @Test("Cancellation during certificate read drains and clears both owned buffers")
    func certificateCancellation() async throws {
        let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
        let observations = EFSKeyReadObservations(), gate = EFSKeyReaderGate()
        let task = Task {
            defer { observations.markCompleted() }
            return try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
                hooks: observations.hooks(afterRead: { _ in if observations.readCount == 2 { try gate.pause() } }))
        }
        defer { task.cancel(); gate.release() }
        do { try await gate.waitEntered() }
        catch { task.cancel(); gate.release(); _ = try? await task.value; throw error }
        task.cancel(); try await Task.sleep(nanoseconds: 30_000_000)
        #expect(!observations.completed && observations.closedCount == 1)
        gate.release()
        do { _ = try await task.value; Issue.record("A cancelled certificate reader returned material.") }
        catch { #expect(error is CancellationError) }
        #expect(observations.closedCount == 2 && observations.clearedCounts.count == 2 && observations.everyClearWasZero)
        #expect(observations.closedAtCompletion == 2 && observations.clearedAtCompletion == 2)
    }

    @Test("The monotonic read deadline rejects expired work and clears the current allocation")
    func readDeadline() async throws {
        let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
        let observations = EFSKeyReadObservations()
        do {
            _ = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
                hooks: observations.hooks(uptime: { observations.readCount == 0 ? 0 : 10 }))
            Issue.record("Expired key read work returned material.")
        } catch { #expect(error as? EFSKeyInputError == .readTimedOut) }
        #expect(observations.closedCount == 1 && observations.clearedCounts == [fixture.keyBytes.count])
        #expect(observations.everyClearWasZero)
    }

    @Test("PEM, incomplete and nonminimal outer DER framing are rejected without leaking bytes")
    func framing() async throws {
        for invalid in [Array("-----BEGIN RSA PRIVATE KEY-----".utf8), [0x30, 0x81, 0x01, 0x00], [0x30, 0x80, 0x00, 0x00], [0x30, 0x02, 0x01]] {
            let fixture = try EFSKeyMaterialFixture(keyBytes: invalid); defer { fixture.remove() }
            do {
                _ = try await EFSKeyMaterial.read(privateKeyURL: fixture.key, certificateURL: fixture.certificate)
                Issue.record("Invalid DER framing was accepted.")
            } catch { #expect(error as? EFSKeyInputError == .invalidKeyFile) }
        }
    }

    @Test("Borrowed callbacks release the state lock; concurrent discard cannot clear active bytes")
    func borrowAndConcurrentDiscard() async throws {
        for throwsAfterBorrow in [false, true] {
            let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
            let observations = EFSKeyReadObservations(), gate = EFSKeyReaderGate(), response = EFSKeyConcurrentResponse()
            let material = try await EFSKeyMaterial.readForTesting(privateKeyURL: fixture.key, certificateURL: fixture.certificate,
                hooks: observations.hooks())
            let borrow = Task.detached {
                try material.consume { key, certificate in
                    #expect(Array(key) == fixture.keyBytes && Array(certificate) == fixture.certificateBytes)
                    try gate.pause()
                    #expect(Array(key) == fixture.keyBytes && Array(certificate) == fixture.certificateBytes)
                    if throwsAfterBorrow { throw EFSKeyInputError.invalidSelection }
                }
            }
            defer { gate.release() }
            do { try await gate.waitEntered() }
            catch { gate.release(); _ = try? await borrow.value; throw error }
            let state = Task.detached {
                material.discard()
                response.finish(isConsumed: material.isConsumed)
            }
            let responsive = await response.waitForCompletion(seconds: 3)
            #expect(responsive && response.isConsumed)
            #expect(observations.clearedCounts.isEmpty)
            if responsive {
                #expect(throws: EFSKeyInputError.alreadyConsumed) { try material.consume { _, _ in () } }
            }
            gate.release()
            do {
                try await borrow.value
                #expect(!throwsAfterBorrow)
            } catch { #expect(throwsAfterBorrow && error as? EFSKeyInputError == .invalidSelection) }
            await state.value
            #expect(observations.clearedCounts.count == 2 && observations.everyClearWasZero)
            material.discard()
            #expect(observations.clearedCounts.count == 2)
        }
    }

    @Test("An early source-open failure cannot strand the bounded key reader gate")
    func failedReadGateIsBounded() async throws {
        let fixture = try EFSKeyMaterialFixture(); defer { fixture.remove() }
        let gate = EFSKeyReaderGate()
        let missing = fixture.directory.appendingPathComponent("missing-private.der")
        let task = Task {
            try await EFSKeyMaterial.readForTesting(privateKeyURL: missing, certificateURL: fixture.certificate,
                hooks: .init(read: nil, afterRead: { _ in try gate.pause() }, descriptorClosed: {}, bufferCleared: { _ in },
                    uptime: { ProcessInfo.processInfo.systemUptime }))
        }
        do {
            try await gate.waitEntered(maximumSeconds: 0.1)
            Issue.record("The deliberately unentered reader gate unexpectedly opened.")
        } catch { #expect(error as? EFSKeyTestFailure == .gateDeadline) }
        gate.release()
        do { _ = try await task.value; Issue.record("A missing source returned key material.") }
        catch { #expect(error as? EFSKeyInputError == .invalidSelection) }
    }
}

private struct EFSKeyMaterialFixture: Sendable {
    let directory: URL
    let key: URL
    let certificate: URL
    let keyBytes: [UInt8]
    let certificateBytes: [UInt8]
    init(keyBytes: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x00], certificateBytes: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]) throws {
        directory = try Self.newOwnedDirectory()
        key = directory.appendingPathComponent("synthetic-private.der")
        certificate = directory.appendingPathComponent("synthetic-certificate.der")
        self.keyBytes = keyBytes; self.certificateBytes = certificateBytes
        try Data(keyBytes).write(to: key); try Data(certificateBytes).write(to: certificate)
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    private static func newOwnedDirectory() throws -> URL {
        // Foundation can preserve /var's alias after resolution on macOS 27.
        // Use a fresh private ignored repository child, retaining no-follow
        // ancestor and held-vs-path identity checks before fixture writes.
        let local = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("local", isDirectory: true)
        guard Darwin.mkdir(local.path, 0o700) == 0 || errno == EEXIST else { throw EFSKeyTestFailure.fixtureDirectory }
        let parent = try openDirectory(local.path); defer { Darwin.close(parent) }
        var base = stat()
        guard Darwin.fstat(parent, &base) == 0, base.st_uid == geteuid() else { throw EFSKeyTestFailure.fixtureDirectory }
        let leaf = "efs-key-input-\(UUID().uuidString)"
        guard Darwin.mkdirat(parent, leaf, 0o700) == 0 else { throw EFSKeyTestFailure.fixtureDirectory }
        let url = local.appendingPathComponent(leaf, isDirectory: true)
        let descriptor = Darwin.openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw EFSKeyTestFailure.fixtureDirectory }
        defer { Darwin.close(descriptor) }
        var held = stat(), named = stat()
        guard Darwin.fstat(descriptor, &held) == 0, Darwin.lstat(url.path, &named) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_uid == geteuid(),
              held.st_mode & S_IFMT == S_IFDIR, held.st_mode & 0o7777 == 0o700 else { throw EFSKeyTestFailure.fixtureDirectory }
        return url
    }
    private static func openDirectory(_ path: String) throws -> Int32 {
        var parent = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw EFSKeyTestFailure.fixtureDirectory }
        for name in path.split(separator: "/") {
            let next = Darwin.openat(parent, String(name), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            Darwin.close(parent)
            guard next >= 0 else { throw EFSKeyTestFailure.fixtureDirectory }
            parent = next
        }
        return parent
    }
    static func envelope(totalBytes: Int) -> [UInt8] {
        if totalBytes < 130 { return [0x30, UInt8(totalBytes - 2)] + Array(repeating: 0x5a, count: totalBytes - 2) }
        if totalBytes - 4 <= 65_535 {
            let payload = totalBytes - 4
            return [0x30, 0x82, UInt8(payload >> 8), UInt8(payload & 0xff)] + Array(repeating: 0x5a, count: payload)
        }
        let payload = totalBytes - 5
        return [0x30, 0x83, UInt8(payload >> 16), UInt8((payload >> 8) & 0xff), UInt8(payload & 0xff)] + Array(repeating: 0x5a, count: payload)
    }
}

private final class EFSKeyReadObservations: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0, closed = 0
    private var clears: [Int] = []
    private var allZero = true
    private var didComplete = false
    private var completedClosed = 0, completedCleared = 0
    var readCount: Int { lock.lock(); defer { lock.unlock() }; return reads }
    var closedCount: Int { lock.lock(); defer { lock.unlock() }; return closed }
    var clearedCounts: [Int] { lock.lock(); defer { lock.unlock() }; return clears }
    var everyClearWasZero: Bool { lock.lock(); defer { lock.unlock() }; return allZero }
    var completed: Bool { lock.lock(); defer { lock.unlock() }; return didComplete }
    var closedAtCompletion: Int { lock.lock(); defer { lock.unlock() }; return completedClosed }
    var clearedAtCompletion: Int { lock.lock(); defer { lock.unlock() }; return completedCleared }
    func markCompleted() { lock.lock(); didComplete = true; completedClosed = closed; completedCleared = clears.count; lock.unlock() }
    func hooks(read: (@Sendable (Int32, UnsafeMutableRawBufferPointer, Int) throws -> Int)? = nil,
               afterRead: @escaping @Sendable (Int) throws -> Void = { _ in },
               uptime: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) -> EFSKeyReadHooks {
        EFSKeyReadHooks(read: { descriptor, bytes, count in
            self.lock.lock(); self.reads += 1; self.lock.unlock()
            return try read?(descriptor, bytes, count) ?? FileAccess.read(descriptor, into: bytes, count: count)
        }, afterRead: afterRead, descriptorClosed: {
            self.lock.lock(); self.closed += 1; self.lock.unlock()
        }, bufferCleared: { bytes in
            self.lock.lock(); self.clears.append(bytes.count); self.allZero = self.allZero && bytes.allSatisfy { $0 == 0 }; self.lock.unlock()
        }, uptime: uptime)
    }
}

private final class EFSKeyReaderGate: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var entered = false
    private var hasEntered: Bool { lock.lock(); defer { lock.unlock() }; return entered }
    func pause() throws {
        lock.lock(); entered = true; lock.unlock()
        guard semaphore.wait(timeout: .now() + 10) == .success else { throw EFSKeyTestFailure.gateDeadline }
    }
    func waitEntered(maximumSeconds: TimeInterval = 5) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + maximumSeconds
        while !hasEntered {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw EFSKeyTestFailure.gateDeadline }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }
    func release() { semaphore.signal() }
}

private enum EFSKeyTestFailure: Error, Equatable { case fixtureDirectory, gateDeadline }
private final class EFSKeyConcurrentResponse: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false, consumed = false
    var isConsumed: Bool { lock.lock(); defer { lock.unlock() }; return consumed }
    private var isComplete: Bool { lock.lock(); defer { lock.unlock() }; return completed }
    func finish(isConsumed: Bool) { lock.lock(); consumed = isConsumed; completed = true; lock.unlock() }
    func waitForCompletion(seconds: TimeInterval) async -> Bool {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while !isComplete && ProcessInfo.processInfo.systemUptime < deadline { try? await Task.sleep(nanoseconds: 10_000_000) }
        return isComplete
    }
}
