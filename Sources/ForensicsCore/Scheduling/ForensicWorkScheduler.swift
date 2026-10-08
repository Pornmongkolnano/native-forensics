import Foundation

/// These values carry no source path, file name, examiner text or credentials.
public enum ForensicWorkKind: String, Sendable, Codable, CaseIterable {
    case imageInspection, filesystemAnalysis, extraction, batchExport
    case documentPreview, contentIndex, recovery, opticalHistory, apfsRead
    case timeline, integrityAudit, historyRead
}

public enum ForensicEnergyMode: String, Sendable, Codable, CaseIterable {
    case automatic, conserveEnergy
}

public enum ForensicPowerSource: String, Sendable, Codable { case externalPower, battery, unknown }
public enum ForensicThermalState: String, Sendable, Codable { case nominal, fair, serious, critical, unknown }

public struct ForensicEnergyContext: Sendable, Codable, Equatable {
    public let powerSource: ForensicPowerSource
    public let lowPowerMode: Bool
    public let thermalState: ForensicThermalState
    public init(powerSource: ForensicPowerSource = .unknown, lowPowerMode: Bool = false,
                thermalState: ForensicThermalState = .unknown) {
        self.powerSource = powerSource; self.lowPowerMode = lowPowerMode; self.thermalState = thermalState
    }
}

public enum ForensicWorkPriority: String, Sendable, Codable { case userInitiated, utility
    public var taskPriority: TaskPriority { self == .userInitiated ? .userInitiated : .utility }
}

public enum ForensicEnergyReason: String, Sendable, Codable {
    case explicitConservation, batteryPower, unknownPower, lowPowerMode, elevatedThermal, unknownThermal
}

/// A policy decision is frozen only when a workflow is actually admitted.
/// This controls admission priority, not evidence limits or a child's deadline.
public struct ForensicWorkPolicy: Sendable, Codable, Equatable {
    public let mode: ForensicEnergyMode
    public let context: ForensicEnergyContext
    public let priority: ForensicWorkPriority
    public let reasons: [ForensicEnergyReason]
    public let maximumActiveHeavyWorkflows: Int

    public static func decide(mode: ForensicEnergyMode, context: ForensicEnergyContext) -> Self {
        var reasons: [ForensicEnergyReason] = []
        if mode == .conserveEnergy { reasons.append(.explicitConservation) }
        switch context.powerSource {
        case .battery: reasons.append(.batteryPower)
        case .unknown: reasons.append(.unknownPower)
        case .externalPower: break
        }
        if context.lowPowerMode { reasons.append(.lowPowerMode) }
        switch context.thermalState {
        case .nominal: break
        case .unknown: reasons.append(.unknownThermal)
        case .fair, .serious, .critical: reasons.append(.elevatedThermal)
        }
        return Self(mode: mode, context: context, priority: reasons.isEmpty ? .userInitiated : .utility,
            reasons: reasons, maximumActiveHeavyWorkflows: 1)
    }
}

public struct ForensicWorkAdmission: Sendable, Equatable {
    public let id: UUID
    public let kind: ForensicWorkKind
    public let policy: ForensicWorkPolicy
    /// Monotonic elapsed time in the application queue, before operation deadlines.
    public let queuedSeconds: TimeInterval
}

public struct ForensicSchedulerState: Sendable, Equatable {
    public let isClosed: Bool
    public let active: ForensicWorkAdmission?
    public let queuedKinds: [ForensicWorkKind]
    public let maximumQueuedWorkflows: Int
    public let nextPolicy: ForensicWorkPolicy
}

public enum ForensicSchedulingError: Error, Sendable, Equatable, LocalizedError {
    case closed, busy, queueFull, nestedAdmission
    public var errorDescription: String? {
        switch self {
        case .closed: "The application is closing. No new forensic workflow was started."
        case .busy: "Another window owns the forensic workflow slot. Finish or cancel that workflow, then try again."
        case .queueFull: "The application work queue is full. No new forensic workflow was started."
        case .nestedAdmission: "A workflow already owns this scheduler. Inner operations must use that admission."
        }
    }
}

/// A release is idempotent. It must happen only after the owner has drained its
/// helper, scratch cleanup and publication, including the throwing path.
public struct ForensicWorkPermit: Sendable {
    public let admission: ForensicWorkAdmission
    private let scheduler: ForensicWorkScheduler
    fileprivate init(admission: ForensicWorkAdmission, scheduler: ForensicWorkScheduler) {
        self.admission = admission; self.scheduler = scheduler
    }
    @discardableResult public func release() async -> Bool { await scheduler.release(admission.id) }

    /// Runs an admitted worker at the actual sampled policy priority. The owner
    /// still retains its permit across any later writer/publication step.
    /// Cancellation is forwarded; the worker is always awaited through cleanup.
    public func run<Value: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        try await scheduler.runAdmitted(admission, operation: operation)
    }

    /// Explicit atomic publication boundary. Parent cancellation is checked
    /// immediately before the owned detached worker is created. Once created,
    /// that worker runs to completion without parent cancellation forwarding,
    /// and its result is awaited through publication and cleanup. The owner
    /// must retain this permit until all later cleanup has also drained.
    /// Use ordinary run for cancellable inspection, decoding and extraction.
    public func runToCompletion<Value: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        try await scheduler.runAdmittedToCompletion(admission, operation: operation)
    }
}

private enum ForensicAdmissionScope {
    @TaskLocal static var schedulerID: UUID?
}

/// Read before creating a detached inner worker, which does not inherit task
/// locals. Unscheduled development callers retain the existing default.
public enum ForensicWorkExecutionContext {
    @TaskLocal public static var requestedPriority: ForensicWorkPriority?
    public static var requestedTaskPriority: TaskPriority { (requestedPriority ?? .userInitiated).taskPriority }
}

/// One shared instance admits a single heavy foreground workflow across all
/// windows. Serial is the only whole-pipeline policy measured at this revision.
/// This is an overlap bound, not a measured process RSS ceiling.
public actor ForensicWorkScheduler {
    public static let shared = ForensicWorkScheduler()
    private let id = UUID()
    private let maximumQueuedWorkflows: Int
    private var mode: ForensicEnergyMode = .automatic
    private var context = ForensicEnergyContext()
    private var active: ForensicWorkAdmission?
    private var queued: [Waiter] = []
    private var isClosed = false

    public init(maximumQueuedWorkflows: Int = 32) {
        precondition((1...128).contains(maximumQueuedWorkflows))
        self.maximumQueuedWorkflows = maximumQueuedWorkflows
    }

    /// Sampling/setting the policy never signals or cancels the active owner.
    public func updatePolicy(mode: ForensicEnergyMode, context: ForensicEnergyContext) {
        self.mode = mode; self.context = context
    }

    public func state() -> ForensicSchedulerState {
        .init(isClosed: isClosed, active: active, queuedKinds: queued.map(\.kind),
            maximumQueuedWorkflows: maximumQueuedWorkflows, nextPolicy: .decide(mode: mode, context: context))
    }

    /// Only application termination closes the shared scheduler. Closing one
    /// window cancels its queued task; it must not close work for other windows.
    public func close() {
        guard !isClosed else { return }
        isClosed = true
        let waiting = queued; queued.removeAll(keepingCapacity: false)
        for waiter in waiting { waiter.continuation.resume(throwing: ForensicSchedulingError.closed) }
    }

    /// Credential-bearing workflows must not wait while retaining a copied
    /// password. Obtain this permit first, then construct single-use credentials.
    /// Existing queued non-secret work is not bypassed.
    public func acquireImmediately(_ kind: ForensicWorkKind) throws -> ForensicWorkPermit {
        try Task.checkCancellation()
        guard ForensicAdmissionScope.schedulerID != id else { throw ForensicSchedulingError.nestedAdmission }
        guard !isClosed else { throw ForensicSchedulingError.closed }
        guard active == nil && queued.isEmpty else { throw ForensicSchedulingError.busy }
        let admission = admit(id: UUID(), kind: kind, enqueuedAt: ProcessInfo.processInfo.systemUptime)
        return ForensicWorkPermit(admission: admission, scheduler: self)
    }

    /// Acquire before creating password Data or opening/materializing large
    /// inputs. The queue contains only typed kinds, IDs and continuations.
    public nonisolated func acquire(_ kind: ForensicWorkKind) async throws -> ForensicWorkPermit {
        let schedulerID = id
        guard ForensicAdmissionScope.schedulerID != schedulerID else { throw ForensicSchedulingError.nestedAdmission }
        let waiterID = UUID()
        let admission = try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await enqueue(id: waiterID, kind: kind)
        } onCancel: { Task { await self.cancelQueued(waiterID) } }
        do {
            try Task.checkCancellation()
            return ForensicWorkPermit(admission: admission, scheduler: self)
        } catch {
            _ = await release(admission.id)
            throw error
        }
    }

    /// Preferred owner boundary. Release is awaited exactly once on every exit;
    /// cancellation after a successful publication does not fabricate a failure.
    /// The operation itself must await all of its owned cleanup before returning.
    public nonisolated func withPermit<Value: Sendable>(
        _ kind: ForensicWorkKind,
        operation: @escaping @Sendable (ForensicWorkAdmission) async throws -> Value
    ) async throws -> Value {
        let permit = try await acquire(kind), schedulerID = id
        do {
            let value = try await ForensicAdmissionScope.$schedulerID.withValue(schedulerID) {
                try await ForensicWorkExecutionContext.$requestedPriority.withValue(permit.admission.policy.priority) {
                    try Task.checkCancellation()
                    return try await operation(permit.admission)
                }
            }
            _ = await permit.release()
            return value
        } catch {
            _ = await permit.release()
            throw error
        }
    }

    /// Complete non-UI workflow boundary. The detached worker has its own
    /// priority rather than inheriting a user-initiated main-actor task's QoS.
    public nonisolated func run<Value: Sendable>(
        _ kind: ForensicWorkKind,
        operation: @escaping @Sendable (ForensicWorkAdmission) async throws -> Value
    ) async throws -> Value {
        try await withPermit(kind) { admission in
            try await self.runAdmitted(admission) { try await operation(admission) }
        }
    }

    fileprivate nonisolated func runAdmitted<Value: Sendable>(
        _ admission: ForensicWorkAdmission,
        operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        let schedulerID = id
        guard await state().active?.id == admission.id else { throw ForensicSchedulingError.closed }
        let worker = Task.detached(priority: admission.policy.priority.taskPriority) {
            try await ForensicAdmissionScope.$schedulerID.withValue(schedulerID) {
                try await ForensicWorkExecutionContext.$requestedPriority.withValue(admission.policy.priority) {
                    try Task.checkCancellation()
                    return try await operation()
                }
            }
        }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }

    fileprivate nonisolated func runAdmittedToCompletion<Value: Sendable>(
        _ admission: ForensicWorkAdmission,
        operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        let schedulerID = id
        guard await state().active?.id == admission.id else { throw ForensicSchedulingError.closed }
        // There is no suspension between this check and worker construction.
        // After this boundary, the explicit atomic publisher owns completion.
        try Task.checkCancellation()
        let worker = Task.detached(priority: admission.policy.priority.taskPriority) {
            try await ForensicAdmissionScope.$schedulerID.withValue(schedulerID) {
                try await ForensicWorkExecutionContext.$requestedPriority.withValue(admission.policy.priority) {
                    try await operation()
                }
            }
        }
        // Awaiting an owned task does not automatically propagate cancellation.
        // A late parent cancellation must not fabricate a failed publication.
        return try await worker.value
    }

    private func enqueue(id: UUID, kind: ForensicWorkKind) async throws -> ForensicWorkAdmission {
        try Task.checkCancellation()
        guard !isClosed else { throw ForensicSchedulingError.closed }
        if active == nil && queued.isEmpty { return admit(id: id, kind: kind, enqueuedAt: ProcessInfo.processInfo.systemUptime) }
        guard queued.count < maximumQueuedWorkflows else { throw ForensicSchedulingError.queueFull }
        let enqueuedAt = ProcessInfo.processInfo.systemUptime
        return try await withCheckedThrowingContinuation { continuation in
            queued.append(Waiter(id: id, kind: kind, enqueuedAt: enqueuedAt, continuation: continuation))
        }
    }

    fileprivate func release(_ permitID: UUID) -> Bool {
        guard active?.id == permitID else { return false }
        active = nil
        guard !isClosed, !queued.isEmpty else { return true }
        let waiter = queued.removeFirst()
        let admission = admit(id: waiter.id, kind: waiter.kind, enqueuedAt: waiter.enqueuedAt)
        waiter.continuation.resume(returning: admission)
        return true
    }

    private func cancelQueued(_ waiterID: UUID) {
        guard let index = queued.firstIndex(where: { $0.id == waiterID }) else { return }
        let waiter = queued.remove(at: index)
        waiter.continuation.resume(throwing: CancellationError())
    }

    private func admit(id: UUID, kind: ForensicWorkKind, enqueuedAt: TimeInterval) -> ForensicWorkAdmission {
        let admission = ForensicWorkAdmission(id: id, kind: kind,
            policy: .decide(mode: mode, context: context),
            queuedSeconds: max(0, ProcessInfo.processInfo.systemUptime - enqueuedAt))
        active = admission
        return admission
    }

    private struct Waiter {
        let id: UUID
        let kind: ForensicWorkKind
        let enqueuedAt: TimeInterval
        let continuation: CheckedContinuation<ForensicWorkAdmission, Error>
    }
}
