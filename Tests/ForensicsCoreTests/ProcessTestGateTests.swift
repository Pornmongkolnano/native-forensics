import Darwin
import Testing

struct ProcessTestGateTests {
    @Test("The held unrelated process cannot inherit an unprotected parent pipe writer")
    func heldProcessDescriptorIsolation() throws {
        var descriptors: [Int32] = [-1, -1]
        try #require(Darwin.pipe(&descriptors) == 0)
        defer { Darwin.close(descriptors[0]) }
        let writer = Darwin.fcntl(descriptors[1], F_DUPFD, 128)
        Darwin.close(descriptors[1])
        try #require(writer >= 0)
        var ownsWriter = true
        defer { if ownsWriter { Darwin.close(writer) } }
        try #require(Darwin.fcntl(writer, F_SETFD, 0) == 0)
        let flags = Darwin.fcntl(descriptors[0], F_GETFL)
        try #require(flags >= 0 && Darwin.fcntl(descriptors[0], F_SETFL, flags | O_NONBLOCK) == 0)
        let held = try HeldOpenTestProcess()
        defer { held.close() }
        let child = held.process.processIdentifier
        #expect(held.process.isRunning)
        Darwin.close(writer); ownsWriter = false
        // Spawn has returned after exec. EOF must already be observable while
        // the sentinel is alive; an inherited writer instead produces EAGAIN.
        var byte: UInt8 = 0
        #expect(Darwin.read(descriptors[0], &byte, 1) == 0)
        #expect(held.process.isRunning)
        held.close()
        let stopped = Darwin.kill(child, 0), stoppedErrno = errno
        #expect(stopped == -1)
        #expect(stoppedErrno == ESRCH)
    }
}
