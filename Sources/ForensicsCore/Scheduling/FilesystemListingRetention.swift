import Foundation

/// Tracks listing admission and LRU order without retaining the listings.
/// The UI owner applies removedEvidenceIDs to its in-memory result dictionary;
/// persisted artifacts and evidence sources are outside this model's scope.
public struct FilesystemListingRetention: Sendable {
    public static let defaultMaximumListings = 2
    public static let defaultMaximumStringBytes = 64 * 1_048_576

    public struct Insertion: Sendable, Equatable {
        public let retained: Bool
        public let removedEvidenceIDs: [UUID]
    }

    public let maximumListings: Int
    public let maximumStringBytes: Int
    public private(set) var totalStringBytes = 0
    private var costs: [UUID: FilesystemListingStringCost] = [:]
    private var leastRecentlyUsedFirst: [UUID] = []

    public init(maximumListings: Int = FilesystemListingRetention.defaultMaximumListings,
                maximumStringBytes: Int = FilesystemListingRetention.defaultMaximumStringBytes) {
        precondition((1...Self.defaultMaximumListings).contains(maximumListings))
        precondition((0...Self.defaultMaximumStringBytes).contains(maximumStringBytes))
        self.maximumListings = maximumListings
        self.maximumStringBytes = maximumStringBytes
    }

    public var retainedEvidenceIDs: Set<UUID> { Set(costs.keys) }
    public var leastRecentlyUsedEvidenceIDs: [UUID] { leastRecentlyUsedFirst }
    public var count: Int { costs.count }

    /// Replacement removes the old generation before admission is evaluated.
    /// A rejected replacement therefore cannot leave a stale listing behind.
    @discardableResult
    public mutating func insert(evidenceID: UUID, cost: FilesystemListingStringCost) -> Insertion {
        let replaced = remove(evidenceID)
        guard cost.rawUTF8Bytes <= maximumStringBytes else {
            return Insertion(retained: false, removedEvidenceIDs: replaced ? [evidenceID] : [])
        }

        var removed: [UUID] = []
        while costs.count >= maximumListings || cost.rawUTF8Bytes > maximumStringBytes - totalStringBytes {
            guard let oldest = leastRecentlyUsedFirst.first else { break }
            remove(oldest)
            removed.append(oldest)
        }
        costs[evidenceID] = cost
        leastRecentlyUsedFirst.append(evidenceID)
        totalStringBytes += cost.rawUTF8Bytes
        return Insertion(retained: true, removedEvidenceIDs: removed)
    }

    /// Selection makes a retained listing the most recently used listing.
    @discardableResult
    public mutating func touch(_ evidenceID: UUID) -> Bool {
        guard costs[evidenceID] != nil else { return false }
        leastRecentlyUsedFirst.removeAll { $0 == evidenceID }
        leastRecentlyUsedFirst.append(evidenceID)
        return true
    }

    @discardableResult
    public mutating func remove(_ evidenceID: UUID) -> Bool {
        guard let cost = costs.removeValue(forKey: evidenceID) else { return false }
        totalStringBytes -= cost.rawUTF8Bytes
        leastRecentlyUsedFirst.removeAll { $0 == evidenceID }
        return true
    }

    public mutating func removeAll() {
        costs.removeAll()
        leastRecentlyUsedFirst.removeAll()
        totalStringBytes = 0
    }
}
