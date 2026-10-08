import Foundation

/// App-side milestones only. None of these stages establishes display presentation.
public enum UIInteractionStage: String, Codable, Sendable, CaseIterable {
    case bindingReceived
    case scheduled
    case workerStarted
    case workerFinished
    case rowsPublished
}

public enum UIInteractionOutcome: String, Codable, Sendable, CaseIterable {
    case published
    case cancelled
    case superseded
    case failed
}

public struct UIInteractionStageSample: Codable, Sendable, Equatable {
    public let stage: UIInteractionStage
    public let uptimeSeconds: TimeInterval
}

/// Numeric metadata from one explicitly associated native input dispatch.
/// Clock validation and responder identity remain the caller's responsibility.
public struct UIInteractionInputReceipt: Codable, Sendable, Equatable {
    public let sequence: UInt64
    public let eventUptimeSeconds: TimeInterval
    public let quartzEventUptimeSeconds: TimeInterval
    public let dispatchReceiptUptimeSeconds: TimeInterval
    public let dispatchEndUptimeSeconds: TimeInterval
    public let machBracketStartSeconds: TimeInterval
    public let coreAnimationSampleSeconds: TimeInterval
    public let machBracketEndSeconds: TimeInterval

    public init(sequence: UInt64, eventUptimeSeconds: TimeInterval,
                quartzEventUptimeSeconds: TimeInterval, dispatchReceiptUptimeSeconds: TimeInterval,
                dispatchEndUptimeSeconds: TimeInterval, machBracketStartSeconds: TimeInterval,
                coreAnimationSampleSeconds: TimeInterval, machBracketEndSeconds: TimeInterval) {
        self.sequence = sequence
        self.eventUptimeSeconds = eventUptimeSeconds
        self.quartzEventUptimeSeconds = quartzEventUptimeSeconds
        self.dispatchReceiptUptimeSeconds = dispatchReceiptUptimeSeconds
        self.dispatchEndUptimeSeconds = dispatchEndUptimeSeconds
        self.machBracketStartSeconds = machBracketStartSeconds
        self.coreAnimationSampleSeconds = coreAnimationSampleSeconds
        self.machBracketEndSeconds = machBracketEndSeconds
    }
}

/// Stable numeric codes. No event characters, queries or control labels are retained.
public enum UIInteractionInputRejection: UInt8, Codable, Sendable, CaseIterable {
    case notFocused = 1
    case noChange = 2
    case ambiguous = 3
    case unsupported = 4
    case invalidClock = 5
    case staleEvent = 6
    case futureEvent = 7
    case replay = 8
    case missingTrial = 9
    case alreadyAssociated = 10
    case suspended = 11
    case sequenceExhausted = 12
}

/// Bounded, saturating counters for the opt-in native input association path.
public struct UIInteractionInputDiagnostics: Codable, Sendable, Equatable {
    public private(set) var associatedInputCount: UInt64
    public private(set) var reservedInputSequenceCount: UInt64
    public private(set) var rejectionCounts: [UInt8: UInt64]

    public init(associatedInputCount: UInt64 = 0, reservedInputSequenceCount: UInt64 = 0,
                rejectionCounts: [UInt8: UInt64] = [:]) {
        self.associatedInputCount = associatedInputCount
        self.reservedInputSequenceCount = reservedInputSequenceCount
        self.rejectionCounts = rejectionCounts.filter {
            UIInteractionInputRejection(rawValue: $0.key) != nil
        }
    }

    private enum CodingKeys: String, CodingKey {
        case associatedInputCount, reservedInputSequenceCount, rejectionCounts
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(associatedInputCount: try values.decode(UInt64.self, forKey: .associatedInputCount),
                  reservedInputSequenceCount: try values.decode(UInt64.self, forKey: .reservedInputSequenceCount),
                  rejectionCounts: try values.decode([UInt8: UInt64].self, forKey: .rejectionCounts))
    }

    mutating func recordAssociation() { Self.increment(&associatedInputCount) }
    mutating func recordReservation() { Self.increment(&reservedInputSequenceCount) }
    mutating func recordRejection(_ code: UIInteractionInputRejection) {
        var count = rejectionCounts[code.rawValue, default: 0]
        Self.increment(&count)
        rejectionCounts[code.rawValue] = count
    }

    private static func increment(_ value: inout UInt64) {
        if value != UInt64.max { value += 1 }
    }
}

public struct UIInteractionTrial: Codable, Sendable, Equatable {
    public let id: UInt64
    /// Explicit, caller-validated input metadata; absent for normal binding-only trials.
    public fileprivate(set) var inputEventUptimeSeconds: TimeInterval?
    public fileprivate(set) var inputReceipt: UIInteractionInputReceipt? = nil
    public fileprivate(set) var stages: [UIInteractionStageSample]
    public fileprivate(set) var outcome: UIInteractionOutcome?
    public fileprivate(set) var completedUptimeSeconds: TimeInterval?

    public var bindingToPublicationSeconds: TimeInterval? {
        guard outcome == .published, let first = stages.first,
              let published = stages.last, published.stage == .rowsPublished else { return nil }
        return published.uptimeSeconds - first.uptimeSeconds
    }
}

public struct UIInteractionTraceReport: Codable, Sendable, Equatable {
    public let trials: [UIInteractionTrial]
    public let evictedTrialCount: UInt64
    public let rejectedMutationCount: UInt64
    public let inputDiagnostics: UIInteractionInputDiagnostics?

    public init(trials: [UIInteractionTrial] = [], evictedTrialCount: UInt64 = 0,
                rejectedMutationCount: UInt64 = 0,
                inputDiagnostics: UIInteractionInputDiagnostics? = nil) {
        self.trials = trials
        self.evictedTrialCount = evictedTrialCount
        self.rejectedMutationCount = rejectedMutationCount
        self.inputDiagnostics = inputDiagnostics
    }
}

/// A bounded numeric receipt store, safe to call from UI and worker threads.
/// IDs increase for this instance's lifetime and are never recycled after eviction.
public final class UIInteractionTrace: @unchecked Sendable {
    public static let maximumTrials = 256
    public static let maxStagesPerTrial = 8
    /// Diagnostic policy limits, rather than AppKit delivery guarantees.
    public static let maximumInputEventAgeSeconds: TimeInterval = 1
    public static let maximumInputBindingAgeSeconds: TimeInterval = 1
    public static let maximumInputQuartzClockDifferenceSeconds: TimeInterval = 0.000_001
    public static let maximumInputMachBracketToleranceSeconds: TimeInterval = 0.000_000_001

    private let lock = NSLock()
    private let capacity: Int
    private var trials: [UIInteractionTrial] = []
    private var nextID: UInt64 = 1
    private var identifiersExhausted = false
    private var evictedTrialCount: UInt64 = 0
    private var rejectedMutationCount: UInt64 = 0
    private var inputDiagnostics: UIInteractionInputDiagnostics?
    private var nextInputSequence: UInt64 = 1
    private var inputSequencesExhausted = false
    private var lastAttemptedInputSequence: UInt64 = 0
    private var lastAcceptedInputEventSeconds: TimeInterval?

    public init(capacity: Int = UIInteractionTrace.maximumTrials) {
        self.capacity = min(max(1, capacity), Self.maximumTrials)
    }

    /// Begins a binding receipt. Optional event time must already use this uptime epoch.
    @discardableResult
    public func begin(at uptimeSeconds: TimeInterval,
                      inputEventUptimeSeconds: TimeInterval? = nil) -> UInt64? {
        lock.withLock {
            guard Self.isValidUptime(uptimeSeconds), !identifiersExhausted else {
                reject(); return nil
            }
            if let eventTime = inputEventUptimeSeconds,
               !Self.isValidUptime(eventTime) || eventTime > uptimeSeconds {
                reject(); return nil
            }
            let id = nextID
            if nextID == UInt64.max { identifiersExhausted = true }
            else { nextID += 1 }
            if trials.count == capacity {
                trials.removeFirst()
                Self.increment(&evictedTrialCount)
            }
            trials.append(UIInteractionTrial(id: id, inputEventUptimeSeconds: inputEventUptimeSeconds,
                stages: [UIInteractionStageSample(stage: .bindingReceived, uptimeSeconds: uptimeSeconds)],
                outcome: nil, completedUptimeSeconds: nil))
            return id
        }
    }

    /// Accepts the worker path or the synchronous binding-to-publication path.
    /// Duplicate, skipped worker, stale and terminal callbacks cannot rewrite a receipt.
    @discardableResult
    public func record(_ stage: UIInteractionStage, trialID: UInt64,
                       at uptimeSeconds: TimeInterval) -> Bool {
        lock.withLock {
            guard let index = trials.firstIndex(where: { $0.id == trialID }),
                  trials[index].outcome == nil,
                  let previous = trials[index].stages.last,
                  Self.isValidUptime(uptimeSeconds), uptimeSeconds >= previous.uptimeSeconds,
                  trials[index].stages.count < Self.maxStagesPerTrial,
                  Self.canAdvance(from: previous.stage, to: stage) else {
                reject(); return false
            }
            trials[index].stages.append(UIInteractionStageSample(stage: stage, uptimeSeconds: uptimeSeconds))
            return true
        }
    }

    @discardableResult
    public func finish(_ outcome: UIInteractionOutcome, trialID: UInt64,
                       at uptimeSeconds: TimeInterval) -> Bool {
        lock.withLock {
            guard let index = trials.firstIndex(where: { $0.id == trialID }),
                  trials[index].outcome == nil,
                  let previous = trials[index].stages.last,
                  Self.isValidUptime(uptimeSeconds), uptimeSeconds >= previous.uptimeSeconds,
                  (outcome == .published) == (previous.stage == .rowsPublished) else {
                reject(); return false
            }
            trials[index].outcome = outcome
            trials[index].completedUptimeSeconds = uptimeSeconds
            return true
        }
    }

    /// Reserves a trace-local identifier. Identifiers survive trial eviction and never recycle.
    public func reserveInputEventSequence() -> UInt64? {
        lock.withLock {
            ensureInputDiagnostics()
            guard !inputSequencesExhausted else {
                rejectInput(.sequenceExhausted); return nil
            }
            let sequence = nextInputSequence
            if sequence == UInt64.max { inputSequencesExhausted = true }
            else { nextInputSequence += 1 }
            inputDiagnostics?.recordReservation()
            return sequence
        }
    }

    /// Records a caller-side input rejection without changing legacy trial mutation counters.
    public func recordInputRejection(_ code: UIInteractionInputRejection) {
        lock.withLock { rejectInput(code) }
    }

    /// Attaches after dispatch, including after a trial completed, without changing milestones.
    /// A reserved sequence permits one attempt; rejected receipts cannot be corrected and reused.
    /// A valid numeric receipt does not itself prove responder identity or physical input origin.
    @discardableResult
    public func associateInputEvent(_ receipt: UIInteractionInputReceipt, trialID: UInt64) -> Bool {
        lock.withLock {
            let sequenceWasReserved = receipt.sequence > 0
                && (inputSequencesExhausted || receipt.sequence < nextInputSequence)
            guard sequenceWasReserved, receipt.sequence > lastAttemptedInputSequence else {
                rejectInput(.replay); return false
            }
            // A reserved dispatch has one association attempt, even if its target or clocks fail.
            // Invalid or unreserved identifiers cannot consume the reserved sequence range.
            lastAttemptedInputSequence = receipt.sequence
            guard let index = trials.firstIndex(where: { $0.id == trialID }),
                  let binding = trials[index].stages.first?.uptimeSeconds else {
                rejectInput(.missingTrial); return false
            }
            guard trials[index].inputReceipt == nil, trials[index].inputEventUptimeSeconds == nil else {
                rejectInput(.alreadyAssociated); return false
            }
            let times = [receipt.eventUptimeSeconds, receipt.quartzEventUptimeSeconds,
                         receipt.dispatchReceiptUptimeSeconds, receipt.dispatchEndUptimeSeconds,
                         receipt.machBracketStartSeconds, receipt.coreAnimationSampleSeconds,
                         receipt.machBracketEndSeconds]
            guard times.allSatisfy({ $0.isFinite && $0 > 0 }),
                  receipt.dispatchReceiptUptimeSeconds <= receipt.dispatchEndUptimeSeconds,
                  receipt.machBracketStartSeconds <= receipt.machBracketEndSeconds,
                  abs(receipt.eventUptimeSeconds - receipt.quartzEventUptimeSeconds)
                    <= Self.maximumInputQuartzClockDifferenceSeconds,
                  abs(receipt.dispatchReceiptUptimeSeconds - receipt.coreAnimationSampleSeconds)
                    <= Self.maximumInputMachBracketToleranceSeconds,
                  receipt.coreAnimationSampleSeconds
                    >= receipt.machBracketStartSeconds - Self.maximumInputMachBracketToleranceSeconds,
                  receipt.coreAnimationSampleSeconds
                    <= receipt.machBracketEndSeconds + Self.maximumInputMachBracketToleranceSeconds else {
                rejectInput(.invalidClock); return false
            }
            guard receipt.eventUptimeSeconds <= receipt.dispatchReceiptUptimeSeconds,
                  receipt.dispatchReceiptUptimeSeconds <= binding else {
                rejectInput(.futureEvent); return false
            }
            guard binding <= receipt.dispatchEndUptimeSeconds else {
                rejectInput(.ambiguous); return false
            }
            guard receipt.dispatchReceiptUptimeSeconds - receipt.eventUptimeSeconds
                    <= Self.maximumInputEventAgeSeconds,
                  binding - receipt.dispatchReceiptUptimeSeconds <= Self.maximumInputBindingAgeSeconds else {
                rejectInput(.staleEvent); return false
            }
            if let previous = lastAcceptedInputEventSeconds, receipt.eventUptimeSeconds <= previous {
                rejectInput(.replay); return false
            }
            trials[index].inputEventUptimeSeconds = receipt.eventUptimeSeconds
            trials[index].inputReceipt = receipt
            lastAcceptedInputEventSeconds = receipt.eventUptimeSeconds
            ensureInputDiagnostics()
            inputDiagnostics?.recordAssociation()
            return true
        }
    }

    public func snapshot() -> UIInteractionTraceReport {
        lock.withLock {
            UIInteractionTraceReport(trials: trials, evictedTrialCount: evictedTrialCount,
                                     rejectedMutationCount: rejectedMutationCount,
                                     inputDiagnostics: inputDiagnostics)
        }
    }

    private static func canAdvance(from previous: UIInteractionStage, to next: UIInteractionStage) -> Bool {
        switch (previous, next) {
        case (.bindingReceived, .scheduled), (.scheduled, .workerStarted),
             (.workerStarted, .workerFinished), (.workerFinished, .rowsPublished),
             (.bindingReceived, .rowsPublished): true
        default: false
        }
    }

    private static func isValidUptime(_ value: TimeInterval) -> Bool { value.isFinite && value >= 0 }
    private static func increment(_ value: inout UInt64) { if value != UInt64.max { value += 1 } }
    private func reject() { Self.increment(&rejectedMutationCount) }
    private func ensureInputDiagnostics() {
        if inputDiagnostics == nil { inputDiagnostics = UIInteractionInputDiagnostics() }
    }
    private func rejectInput(_ code: UIInteractionInputRejection) {
        ensureInputDiagnostics()
        inputDiagnostics?.recordRejection(code)
    }
}
