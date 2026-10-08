import Darwin
import Testing
@testable import ForensicsCore

@Suite("Document worker spawn C-string ownership")
struct DocumentWorkerCStringLifetimeTests {
    @Test("UTF-8 argv0 and the fixed environment stay owned throughout the synchronous operation", arguments: [false, true])
    func scopedOwnership(_ throwFromOperation: Bool) throws {
        let ownership = WorkerCStringOwnership()
        let path = "/owned-synthetic/worker-ก😀"
        let variables = ["PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"]
        var called = false
        do {
            let value = try DocumentWorkerProcess.withSpawnCStringVectors(executablePath: path, environmentStrings: variables,
                allocate: ownership.allocate, release: ownership.release) { executable, argv, environment in
                called = true
                #expect(ownership.live.count == 4 && ownership.releases == 0)
                #expect(String(cString: executable) == path)
                #expect(argv[0] == UnsafeMutablePointer(mutating: executable) && argv[1] == nil)
                for (offset, expected) in variables.enumerated() {
                    let pointer = try #require(environment[offset])
                    #expect(String(cString: pointer) == expected)
                    #expect(ownership.live.contains(UInt(bitPattern: pointer)))
                }
                #expect(environment[variables.count] == nil)
                if throwFromOperation { throw WorkerCStringFailure.operation }
                return 41
            }
            #expect(!throwFromOperation && value == 41)
        } catch WorkerCStringFailure.operation { #expect(throwFromOperation) }
        #expect(called && ownership.allocations == 4)
        #expect(ownership.live.isEmpty && ownership.releases == 4 && ownership.doubleReleases == 0)
    }

    @Test("Every partial strdup failure prevents spawn and frees all successful copies", arguments: [0, 1, 2, 3])
    func partialAllocationFailure(_ failAt: Int) {
        let ownership = WorkerCStringOwnership(failAt: failAt)
        var called = false
        #expect(throws: DocumentAnalysisError.launchFailed) {
            try DocumentWorkerProcess.withSpawnCStringVectors(executablePath: "/owned-synthetic/worker",
                environmentStrings: ["PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"],
                allocate: ownership.allocate, release: ownership.release) { _, _, _ in called = true }
        }
        #expect(!called && ownership.allocations == 4)
        #expect(ownership.live.isEmpty && ownership.releases == 3 && ownership.doubleReleases == 0)
    }
}

private enum WorkerCStringFailure: Error { case operation }

/// Per-test allocator accounting; it never launches or changes a process.
private final class WorkerCStringOwnership {
    private let failAt: Int?
    private(set) var allocations = 0, releases = 0, doubleReleases = 0
    private(set) var live: Set<UInt> = []
    init(failAt: Int? = nil) { self.failAt = failAt }
    func allocate(_ value: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>? {
        let offset = allocations; allocations += 1
        guard offset != failAt else { return nil }
        guard let pointer = Darwin.strdup(value) else { Issue.record("Synthetic strdup unexpectedly failed"); return nil }
        live.insert(UInt(bitPattern: pointer)); return pointer
    }
    func release(_ pointer: UnsafeMutablePointer<CChar>) {
        guard live.remove(UInt(bitPattern: pointer)) != nil else { doubleReleases += 1; return }
        releases += 1; Darwin.free(pointer)
    }
    deinit { for address in live { Darwin.free(UnsafeMutableRawPointer(bitPattern: address)) } }
}
