import Foundation
import Testing
@testable import ForensicsCore

@Suite("ForensicWorkSchedulerTests")
struct ForensicWorkSchedulerTests {
    @Test("FIFO across independent windows admits exactly one complete owner")
    func independentWindows() async throws {
        let scheduler = ForensicWorkScheduler(), log = SchedulerTestLog(), drain = SchedulerTestBarrier()
        let seed = try await scheduler.acquire(.imageInspection)
        let first = Task {
            try await scheduler.run(.contentIndex) { _ in
                await log.append("first-start")
                await drain.wait()
                await log.append("first-commit")
                return "committed"
            }
        }
        try await schedulerWait(scheduler, queued: 1)
        let second = Task {
            try await scheduler.run(.documentPreview) { _ in
                await log.append("second-start"); await log.append("second-commit")
            }
        }
        try await schedulerWait(scheduler, queued: 2)
        #expect(await seed.release())
        try await schedulerWait(scheduler, queued: 1)
        try await schedulerLogWait(log, count: 1)
        let firstID = try #require(await scheduler.state().active?.id)
        first.cancel()
        // Cancellation cannot release an active worker while owned cleanup or
        // an already-started atomic publication is still being drained.
        #expect(await scheduler.state().active?.id == firstID)
        #expect(await log.values == ["first-start"])
        await drain.open()
        #expect(try await first.value == "committed")
        try await second.value
        #expect(await log.values == ["first-start", "first-commit", "second-start", "second-commit"])
        #expect(await scheduler.state().active == nil)
    }

    @Test("Canceling a queued task removes it without starting its operation")
    func queuedCancellation() async throws {
        let scheduler = ForensicWorkScheduler(), log = SchedulerTestLog()
        let active = try await scheduler.acquire(.filesystemAnalysis)
        let canceled = Task { try await scheduler.run(.recovery) { _ in await log.append("must-not-start") } }
        try await schedulerWait(scheduler, queued: 1)
        canceled.cancel()
        await #expect(throws: CancellationError.self) { try await canceled.value }
        #expect(await log.values.isEmpty)
        #expect(await scheduler.state().queuedKinds.isEmpty)
        #expect(await scheduler.state().active?.id == active.admission.id)
        #expect(await active.release())
    }

    @Test("Canceling the FIFO head preserves the next waiter's order")
    func canceledHead() async throws {
        let scheduler = ForensicWorkScheduler()
        let active = try await scheduler.acquire(.imageInspection)
        let first = Task { try await scheduler.acquire(.recovery) }
        try await schedulerWait(scheduler, queued: 1)
        let second = Task { try await scheduler.acquire(.timeline) }
        try await schedulerWait(scheduler, queued: 2)
        first.cancel()
        await #expect(throws: CancellationError.self) { try await first.value }
        #expect(await scheduler.state().queuedKinds == [.timeline])
        _ = await active.release()
        let next = try await second.value
        #expect(next.admission.kind == .timeline)
        #expect(await next.release())
        #expect(!(await next.release()))
    }

    @Test("Close rejects queued work but preserves active ownership until drain")
    func closeDuringWork() async throws {
        let scheduler = ForensicWorkScheduler()
        let active = try await scheduler.acquire(.batchExport)
        let waiting = Task { try await scheduler.acquire(.integrityAudit) }
        try await schedulerWait(scheduler, queued: 1)
        await scheduler.close()
        await #expect(throws: ForensicSchedulingError.closed) { try await waiting.value }
        #expect(await scheduler.state().active?.id == active.admission.id)
        #expect(await scheduler.state().queuedKinds.isEmpty)
        await #expect(throws: ForensicSchedulingError.closed) { try await scheduler.acquire(.timeline) }
        #expect(await active.release())
        #expect(await scheduler.state().active == nil)
        #expect(await scheduler.state().isClosed)
    }

    @Test("A thrown workflow releases once and admits the next independent task")
    func throwingDrain() async throws {
        let scheduler = ForensicWorkScheduler()
        await #expect(throws: SchedulerTestError.expected) {
            try await scheduler.run(.extraction) { _ -> Int in throw SchedulerTestError.expected }
        }
        let next = try await scheduler.acquireImmediately(.filesystemAnalysis)
        #expect(next.admission.kind == .filesystemAnalysis)
        #expect(await next.release())
    }

    @Test("Queue capacity fails explicitly without changing the active or queued work")
    func boundedQueue() async throws {
        let scheduler = ForensicWorkScheduler(maximumQueuedWorkflows: 1)
        let active = try await scheduler.acquire(.imageInspection)
        let first = Task { try await scheduler.acquire(.contentIndex) }
        try await schedulerWait(scheduler, queued: 1)
        await #expect(throws: ForensicSchedulingError.queueFull) { try await scheduler.acquire(.recovery) }
        #expect(await scheduler.state().queuedKinds == [.contentIndex])
        #expect(await scheduler.state().active?.id == active.admission.id)
        first.cancel()
        await #expect(throws: CancellationError.self) { try await first.value }
        _ = await active.release()
    }

    @Test("Nested admission fails rather than deadlocking the current workflow")
    func nestedAdmission() async throws {
        let scheduler = ForensicWorkScheduler()
        try await scheduler.run(.contentIndex) { _ in
            await #expect(throws: ForensicSchedulingError.nestedAdmission) {
                try await scheduler.acquire(.documentPreview)
            }
        }
        #expect(await scheduler.state().active == nil)
    }

    @Test("An immediate password workflow neither queues nor bypasses a queued owner")
    func immediateCredentialBoundary() async throws {
        let scheduler = ForensicWorkScheduler(), log = SchedulerTestLog()
        let active = try await scheduler.acquire(.filesystemAnalysis)
        await #expect(throws: ForensicSchedulingError.busy) {
            let permit = try await scheduler.acquireImmediately(.apfsRead)
            await log.append("credentials-created")
            _ = await permit.release()
        }
        #expect(await log.values.isEmpty)
        #expect(await scheduler.state().queuedKinds.isEmpty)
        _ = await active.release()
        let permit = try await scheduler.acquireImmediately(.apfsRead)
        await log.append("credentials-created")
        #expect(await log.values == ["credentials-created"])
        #expect(await permit.release())
    }

    @Test("Power changes affect the next admission; active policy and coverage stay stable")
    func nextAdmissionPolicy() async throws {
        let scheduler = ForensicWorkScheduler()
        let ac = ForensicEnergyContext(powerSource: .externalPower, thermalState: .nominal)
        await scheduler.updatePolicy(mode: .automatic, context: ac)
        let active = try await scheduler.acquire(.filesystemAnalysis)
        #expect(active.admission.policy.priority == .userInitiated)
        let queued = Task { try await scheduler.acquire(.contentIndex) }
        try await schedulerWait(scheduler, queued: 1)
        let hotBattery = ForensicEnergyContext(powerSource: .battery, lowPowerMode: true, thermalState: .critical)
        await scheduler.updatePolicy(mode: .automatic, context: hotBattery)
        #expect(await scheduler.state().active?.policy == active.admission.policy)
        #expect(await scheduler.state().nextPolicy.priority == .utility)
        _ = await active.release()
        let next = try await queued.value
        #expect(next.admission.policy.context == hotBattery)
        #expect(next.admission.policy.reasons == [.batteryPower, .lowPowerMode, .elevatedThermal])
        #expect(next.admission.policy.maximumActiveHeavyWorkflows == 1)
        #expect(ContentIndexLimits().maximumFileBytes == 32 * 1_024 * 1_024)
        #expect(DocumentLimits.maximumInputBytes == 128 * 1_024 * 1_024)
        _ = await next.release()
    }

    @Test("Requested policy propagates through admitted detached workers and the POSIX dispatch queue")
    func requestedPriorityBinding() async throws {
        let scheduler = ForensicWorkScheduler()
        await scheduler.updatePolicy(mode: .conserveEnergy,
            context: .init(powerSource: .externalPower, thermalState: .nominal))
        let requested = try await scheduler.run(.integrityAudit) { admission in
            #expect(admission.policy.priority == .utility)
            #expect(ForensicWorkExecutionContext.requestedPriority == .utility)
            #expect(ForensicWorkExecutionContext.requestedTaskPriority == .utility)
            return try await BlockingWork.run { BlockingWork.queuePriorityForTesting }
        }
        // The queue selection oracle is an independent queue label marker,
        // rather than Task.currentPriority, which Swift may escalate on await.
        #expect(requested == .utility)
        #expect(ForensicWorkExecutionContext.requestedPriority == nil)
    }

    @Test("AC, battery, low-power and every thermal state have explicit independent decisions")
    func decisionMatrix() {
        let cases: [(ForensicEnergyMode, ForensicPowerSource, Bool, ForensicThermalState, ForensicWorkPriority)] = [
            (.automatic, .externalPower, false, .nominal, .userInitiated),
            (.automatic, .battery, false, .nominal, .utility),
            (.automatic, .unknown, false, .nominal, .utility),
            (.automatic, .externalPower, true, .nominal, .utility),
            (.automatic, .externalPower, false, .fair, .utility),
            (.automatic, .externalPower, false, .serious, .utility),
            (.automatic, .externalPower, false, .critical, .utility),
            (.automatic, .externalPower, false, .unknown, .utility),
            (.conserveEnergy, .externalPower, false, .nominal, .utility)
        ]
        for (mode, power, lowPower, thermal, priority) in cases {
            let policy = ForensicWorkPolicy.decide(mode: mode,
                context: .init(powerSource: power, lowPowerMode: lowPower, thermalState: thermal))
            #expect(policy.priority == priority)
            #expect(policy.maximumActiveHeavyWorkflows == 1)
        }
    }
}

private enum SchedulerTestError: Error, Equatable { case expected, queueWaitExpired }
private actor SchedulerTestLog {
    private(set) var values: [String] = []
    func append(_ value: String) { values.append(value) }
}
private actor SchedulerTestBarrier {
    private var isOpen = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { waiting.append($0) }
    }
    func open() {
        isOpen = true
        let pending = waiting; waiting.removeAll()
        for waiter in pending { waiter.resume() }
    }
}
private func schedulerWait(_ scheduler: ForensicWorkScheduler, queued count: Int) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while await scheduler.state().queuedKinds.count != count {
        if ContinuousClock.now >= deadline { throw SchedulerTestError.queueWaitExpired }
        try await Task.sleep(for: .milliseconds(1))
    }
}
private func schedulerLogWait(_ log: SchedulerTestLog, count: Int) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while await log.values.count != count {
        if ContinuousClock.now >= deadline { throw SchedulerTestError.queueWaitExpired }
        try await Task.sleep(for: .milliseconds(1))
    }
}
