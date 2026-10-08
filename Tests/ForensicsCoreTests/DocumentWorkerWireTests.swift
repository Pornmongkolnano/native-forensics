import Darwin
import Foundation
import Security
import Testing
@testable import ForensicsCore

struct DocumentWorkerWireTests {
    @Test func framesReadDeclaredBytesWithoutWaitingForEOF() throws {
        let pipe = Pipe()
        defer { try? pipe.fileHandleForReading.close(); try? pipe.fileHandleForWriting.close() }
        let first = Data("first framed payload".utf8), second = Data("next frame".utf8)
        try pipe.fileHandleForWriting.write(contentsOf: DocumentWorkerWire.encodeFrame(first))
        try pipe.fileHandleForWriting.write(contentsOf: DocumentWorkerWire.encodeFrame(second))
        // The writer stays open. Each read must stop at its frame boundary.
        #expect(try DocumentWorkerWire.readFrame(pipe.fileHandleForReading) == first)
        #expect(try DocumentWorkerWire.readFrame(pipe.fileHandleForReading) == second)
    }

    @Test func truncatedAndOversizedFramesFailBeforeUnboundedAllocation() throws {
        let pipe = Pipe()
        defer { try? pipe.fileHandleForReading.close(); try? pipe.fileHandleForWriting.close() }
        try pipe.fileHandleForWriting.write(contentsOf: Data([0,0,0,10, 1,2]))
        try pipe.fileHandleForWriting.close()
        #expect(throws: DocumentAnalysisError.invalidInput) { try DocumentWorkerWire.readFrame(pipe.fileHandleForReading) }
        #expect(throws: DocumentAnalysisError.outputLimit) {
            try DocumentWorkerWire.encodeFrame(Data(repeating: 0, count: DocumentXPCWire.maximumControlBytes + 1))
        }
        let oversized = Pipe()
        defer { try? oversized.fileHandleForReading.close(); try? oversized.fileHandleForWriting.close() }
        try oversized.fileHandleForWriting.write(contentsOf: Data([255,255,255,255]))
        #expect(throws: DocumentAnalysisError.outputLimit) { try DocumentWorkerWire.readFrame(oversized.fileHandleForReading) }
    }

    @Test func inheritedWorkerAllowsOnlyTwoExactBooleanEntitlements() throws {
        let minimal: [String: Any] = ["com.apple.security.app-sandbox": true, "com.apple.security.inherit": true]
        try DocumentWorkerExecutableConfiguration.validateEntitlements([kSecCodeInfoEntitlementsDict as String: minimal])
        for rejected in [NSNumber(value: 1), NSNumber(value: 1.0), "true", false] as [Any] {
            var values = minimal; values["com.apple.security.inherit"] = rejected
            #expect(throws: DocumentAnalysisError.sandboxUnavailable) {
                try DocumentWorkerExecutableConfiguration.validateEntitlements([kSecCodeInfoEntitlementsDict as String: values])
            }
        }
        var expanded = minimal; expanded["com.apple.security.network.client"] = true
        #expect(throws: DocumentAnalysisError.sandboxUnavailable) {
            try DocumentWorkerExecutableConfiguration.validateEntitlements([kSecCodeInfoEntitlementsDict as String: expanded])
        }
    }

    @Test func registeredProcessObserverTracksPhysicalExitAcrossExec() throws {
        let owned = DocumentObserverOwnedTestProcess()
        let input = Pipe()
        owned.process.executableURL = URL(fileURLWithPath: "/bin/sh")
        owned.process.arguments = ["-c", "read owned_gate; exec /usr/bin/true"]
        owned.process.standardInput = input
        owned.process.standardOutput = FileHandle.nullDevice
        owned.process.standardError = FileHandle.nullDevice
        try owned.process.run()
        defer { try? input.fileHandleForWriting.close(); owned.process.waitUntilExit() }
        let observer = DocumentProcessExitObserver(processIdentifier: owned.process.processIdentifier) {
            guard owned.process.isRunning else { throw DocumentAnalysisError.invalidResponse }
        }
        try observer.awaitTrustedRegistration(deadline: DocumentXPCTransport.uptime() + 2, cancellation: DocumentCancellation())
        #expect(!observer.hasExited)
        // exec changes the kernel audit identity version; the registered process
        // source must still report the physical end of our same owned process.
        try input.fileHandleForWriting.write(contentsOf: Data("owned\n".utf8))
        try observer.waitUntilExited(deadline: DocumentXPCTransport.uptime() + 2)
        owned.process.waitUntilExit()
        #expect(observer.hasExited && owned.process.terminationStatus == 0)
    }

    @Test func unverifiedRegistrationNeverTreatsSyntheticExitAsProof() throws {
        let observer = DocumentProcessExitObserver(processIdentifier: Int32.max) {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        #expect(throws: DocumentAnalysisError.sandboxUnavailable) {
            try observer.awaitTrustedRegistration(deadline: DocumentXPCTransport.uptime() + 2, cancellation: DocumentCancellation())
        }
        #expect(!observer.hasExited)
        #expect(throws: DocumentAnalysisError.cleanupFailed) {
            try observer.waitUntilExited(deadline: DocumentXPCTransport.uptime() + 2)
        }
    }
}

private final class DocumentObserverOwnedTestProcess: @unchecked Sendable {
    let process = Process()
}
