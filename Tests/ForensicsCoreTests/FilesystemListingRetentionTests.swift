import Foundation
import Testing
@testable import ForensicsCore

struct FilesystemListingRetentionTests {
    @Test("Two-listing admission evicts the least recently selected UUID")
    func listingCountAndSelectionOrder() throws {
        let a = UUID(), b = UUID(), c = UUID(), absent = UUID()
        var retention = FilesystemListingRetention(maximumStringBytes: 100)
        #expect(retention.insert(evidenceID: a, cost: try cost(10)).retained)
        #expect(retention.insert(evidenceID: b, cost: try cost(20)).retained)
        let touched = retention.touch(a)
        let touchedAbsent = retention.touch(absent)
        #expect(touched)
        #expect(!touchedAbsent)
        let inserted = retention.insert(evidenceID: c, cost: try cost(30))
        #expect(inserted.retained && inserted.removedEvidenceIDs == [b])
        #expect(retention.leastRecentlyUsedEvidenceIDs == [a, c])
        #expect(retention.retainedEvidenceIDs == [a, c])
        #expect(retention.count == 2 && retention.totalStringBytes == 40)
    }

    @Test("The aggregate byte budget may evict both older listings")
    func aggregateBudget() throws {
        let a = UUID(), b = UUID(), c = UUID()
        var retention = FilesystemListingRetention(maximumStringBytes: 10)
        retention.insert(evidenceID: a, cost: try cost(7))
        retention.insert(evidenceID: b, cost: try cost(3))
        #expect(retention.totalStringBytes == 10)
        retention.touch(a)
        let inserted = retention.insert(evidenceID: c, cost: try cost(4))
        #expect(inserted.removedEvidenceIDs == [b, a])
        #expect(retention.retainedEvidenceIDs == [c])
        #expect(retention.totalStringBytes == 4)
    }

    @Test("Production defaults admit one exact 64 MiB logical string payload")
    func productionBoundary() throws {
        let a = UUID(), b = UUID()
        var retention = FilesystemListingRetention()
        #expect(retention.maximumListings == 2)
        #expect(retention.maximumStringBytes == 67_108_864)
        #expect(retention.insert(evidenceID: a, cost: try cost(67_108_864)).retained)
        #expect(retention.totalStringBytes == 67_108_864)
        let oversized = retention.insert(evidenceID: b, cost: try cost(67_108_865))
        #expect(!oversized.retained && oversized.removedEvidenceIDs.isEmpty)
        #expect(retention.retainedEvidenceIDs == [a])
        #expect(retention.totalStringBytes == 67_108_864)
    }

    @Test("A rejected replacement removes its stale generation without evicting other UUIDs")
    func rejectedReplacement() throws {
        let a = UUID(), b = UUID()
        var retention = FilesystemListingRetention(maximumStringBytes: 10)
        retention.insert(evidenceID: a, cost: try cost(4))
        retention.insert(evidenceID: b, cost: try cost(3))
        let replaced = retention.insert(evidenceID: a, cost: try cost(11))
        #expect(!replaced.retained && replaced.removedEvidenceIDs == [a])
        #expect(retention.retainedEvidenceIDs == [b])
        #expect(retention.totalStringBytes == 3)
    }

    @Test("A retained replacement updates accounting and becomes most recently used")
    func retainedReplacementAndRemoval() throws {
        let a = UUID(), b = UUID()
        var retention = FilesystemListingRetention(maximumStringBytes: 10)
        retention.insert(evidenceID: a, cost: try cost(4))
        retention.insert(evidenceID: b, cost: try cost(3))
        let replaced = retention.insert(evidenceID: a, cost: try cost(6))
        #expect(replaced.retained && replaced.removedEvidenceIDs.isEmpty)
        #expect(retention.leastRecentlyUsedEvidenceIDs == [b, a])
        #expect(retention.totalStringBytes == 9)
        let removed = retention.remove(b)
        let removedAgain = retention.remove(b)
        #expect(removed)
        #expect(!removedAgain)
        #expect(retention.totalStringBytes == 6)
        retention.removeAll()
        #expect(retention.count == 0 && retention.totalStringBytes == 0)
        #expect(retention.leastRecentlyUsedEvidenceIDs.isEmpty)
    }

    @Test("A one-listing or zero-byte policy preserves its declared bounds")
    func smallerPolicy() throws {
        let a = UUID(), b = UUID()
        var one = FilesystemListingRetention(maximumListings: 1, maximumStringBytes: 10)
        one.insert(evidenceID: a, cost: try cost(0))
        #expect(one.insert(evidenceID: b, cost: try cost(0)).removedEvidenceIDs == [a])
        var zero = FilesystemListingRetention(maximumStringBytes: 0)
        #expect(zero.insert(evidenceID: a, cost: try cost(0)).retained)
        #expect(!zero.insert(evidenceID: b, cost: try cost(1)).retained)
        #expect(zero.retainedEvidenceIDs == [a] && zero.totalStringBytes == 0)
    }

    private func cost(_ bytes: Int) throws -> FilesystemListingStringCost {
        try FilesystemListingStringCost(rawUTF8Bytes: bytes)
    }
}
