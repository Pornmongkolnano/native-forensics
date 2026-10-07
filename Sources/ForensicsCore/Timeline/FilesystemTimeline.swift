import Foundation

public enum FilesystemTimeline {
    /// Uses recorded engine epochs only. It does not reread metadata, infer a
    /// deletion time, or increase the precision missing from engine protocol v1.
    public static func make(caseID: UUID, evidence: EvidenceRecord, result: EnumerationResult, historical: Bool) throws -> TimelineReport {
        let binding = try TimelineSourceBinding.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        var events: [TimelineEvent] = [], estimatedBytes = 4096
        for file in result.files {
            try Task.checkCancellation()
            let stamps: [(TimelineEventKind, Int64?, Int32)] = [
                (.filesystemCreated, file.createdEpoch, file.createdNanoseconds),
                (.filesystemModified, file.modifiedEpoch, file.modifiedNanoseconds),
                (.filesystemAccessed, file.accessedEpoch, file.accessedNanoseconds),
                (.filesystemChanged, file.changedEpoch, file.changedNanoseconds)]
            for (kind, epoch, nanos) in stamps {
                guard let epoch else { continue }
                guard events.count < TimelineLimits.maximumFilesystemEvents else { throw TimelineError.limitExceeded("Filesystem timeline exceeds 200,000 events.") }
                let estimated = file.path.utf8.count * 6 + file.name.utf8.count * 6 + file.id.utf8.count * 6 + 2048
                guard estimated <= TimelineLimits.maximumReportBytes - estimatedBytes else { throw TimelineError.limitExceeded("Filesystem timeline exceeds its 64 MiB report budget.") }
                estimatedBytes += estimated
                let stamp = TimelineTimestamp.unix(seconds: epoch, nanos: nanos,
                    precision: "engine seconds/nanoseconds; original precision unavailable",
                    timezoneAssumption: "Engine evidence timezone: \(result.options.timezone); original per-field offset/raw civil value unavailable")
                let id = try TimelineCoding.digest([binding.snapshotSHA256, file.id, kind.rawValue, String(epoch), String(nanos)])
                events.append(TimelineEvent(id: id, kind: kind, timestamp: stamp, fileID: file.id, evidencePath: file.path,
                    title: file.name, detail: "Recorded filesystem timestamp; fsOffsetBytes=\(file.fsOffsetBytes), metaAddress=\(file.metaAddress), attributeType=\(file.attributeType.map(String.init) ?? "none"), attributeID=\(file.attributeID.map(String.init) ?? "none")",
                    isDeleted: file.isDeleted, parser: "filesystem-engine-epochs.v1", recordID: file.id))
            }
        }
        let sorted = sort(events)
        var warnings = ["Recorded metadata is not fresh source-byte verification. Snapshot time is not a file timestamp.",
                        "Protocol v1 exposes normalized epochs and nanosecond fields; original filesystem civil values, resolution and per-field timezone offsets are unavailable.",
                        "Deleted entry state does not establish a deletion time; no deletion event is inferred."]
        if historical { warnings.append("Historical/offline snapshot: metadata may no longer match the current source.") }
        if result.status == .partial { warnings.append("Partial filesystem listing: missing files/timestamps are outside this timeline's coverage.") }
        return TimelineReport(binding: binding, events: sorted, warnings: warnings,
            coverage: "\(result.files.count) recorded filesystem entries; \(events.count) non-missing timestamps; status=\(result.status.rawValue). No artifact or unallocated-data coverage unless explicitly imported.")
    }

    public static func sort(_ events: [TimelineEvent]) -> [TimelineEvent] {
        events.sorted {
            if $0.timestamp.epochSeconds != $1.timestamp.epochSeconds {
                if let lhs = $0.timestamp.epochSeconds, let rhs = $1.timestamp.epochSeconds { return lhs < rhs }
                return $0.timestamp.epochSeconds != nil
            }
            if $0.timestamp.nanoseconds != $1.timestamp.nanoseconds { return $0.timestamp.nanoseconds < $1.timestamp.nanoseconds }
            return $0.id < $1.id
        }
    }
}

public struct TimelineFilter: Sendable {
    public let query: String
    public let from: Date?
    public let through: Date?
    public let includeUnresolved: Bool
    public init(query: String = "", from: Date? = nil, through: Date? = nil, includeUnresolved: Bool = true) {
        self.query = query; self.from = from; self.through = through; self.includeUnresolved = includeUnresolved
    }
    public func apply(to events: [TimelineEvent]) throws -> [TimelineEvent] {
        guard query.utf8.count <= 4096, events.count <= TimelineLimits.maximumFilesystemEvents + TimelineLimits.maximumBrowserEvents,
              from.map({ $0.timeIntervalSince1970.isFinite }) ?? true,
              through.map({ $0.timeIntervalSince1970.isFinite }) ?? true,
              from == nil || through == nil || from! <= through! else { throw TimelineError.invalidInput("Invalid timeline query or date range.") }
        let needle = query.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
        var matches: [TimelineEvent] = []
        for event in events {
            try Task.checkCancellation()
            if let seconds = event.timestamp.epochSeconds {
                let time = Double(seconds) + Double(event.timestamp.nanoseconds) / 1_000_000_000
                if let from, time < from.timeIntervalSince1970 { continue }
                if let through, time > through.timeIntervalSince1970 { continue }
            } else if !includeUnresolved { continue }
            if !needle.isEmpty {
                let haystack = (event.title + "\n" + event.evidencePath + "\n" + event.detail + "\n" + event.kind.rawValue)
                    .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
                if !haystack.contains(needle) { continue }
            }
            matches.append(event)
        }
        return matches
    }
}
