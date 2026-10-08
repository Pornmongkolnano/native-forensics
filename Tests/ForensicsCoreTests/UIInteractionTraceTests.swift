import Foundation
import Testing
@testable import ForensicsCore

@Suite("UIInteractionTraceTests")
struct UIInteractionTraceTests {
    @Test("Asynchronous publication measures binding receipt to publication, not completion")
    func asynchronousPublication() throws {
        let trace = UIInteractionTrace()
        let id = try #require(trace.begin(at: 10, inputEventUptimeSeconds: 9.9))
        let initial = try #require(trace.snapshot().trials.first)
        #expect(initial.id == id)
        #expect(initial.inputEventUptimeSeconds == 9.9)
        #expect(initial.stages.map(\.stage) == [.bindingReceived])
        #expect(initial.stages.map(\.uptimeSeconds) == [10])
        #expect(initial.bindingToPublicationSeconds == nil)

        #expect(trace.record(.scheduled, trialID: id, at: 10.01))
        #expect(trace.record(.workerStarted, trialID: id, at: 10.02))
        #expect(trace.record(.workerFinished, trialID: id, at: 10.2))
        #expect(trace.record(.rowsPublished, trialID: id, at: 10.3))
        #expect(trace.finish(.published, trialID: id, at: 10.5))

        let report = trace.snapshot()
        let trial = try #require(report.trials.first)
        #expect(trial.stages.map(\.stage) == [
            .bindingReceived, .scheduled, .workerStarted, .workerFinished, .rowsPublished
        ])
        #expect(trial.outcome == .published)
        #expect(trial.completedUptimeSeconds == 10.5)
        let duration = try #require(trial.bindingToPublicationSeconds)
        #expect(abs(duration - 0.3) < 0.000_000_001)
        #expect(report.evictedTrialCount == 0)
        #expect(report.rejectedMutationCount == 0)
    }

    @Test("Synchronous publication accepts equal timestamps and a zero input timestamp")
    func synchronousPublication() throws {
        let trace = UIInteractionTrace()
        let id = try #require(trace.begin(at: 0, inputEventUptimeSeconds: 0))
        #expect(trace.record(.rowsPublished, trialID: id, at: 0))
        #expect(trace.finish(.published, trialID: id, at: 0))

        let trial = try #require(trace.snapshot().trials.first)
        #expect(trial.stages.map(\.stage) == [.bindingReceived, .rowsPublished])
        #expect(trial.inputEventUptimeSeconds == 0)
        #expect(trial.bindingToPublicationSeconds == 0)
        #expect(trial.completedUptimeSeconds == 0)
    }

    @Test("Eviction removes the oldest trial and stale IDs cannot mutate newer trials")
    func oldestEvictionAndStaleIDs() throws {
        let trace = UIInteractionTrace(capacity: 2)
        let oldestID = try #require(trace.begin(at: 1))
        let secondID = try #require(trace.begin(at: 2))
        let thirdID = try #require(trace.begin(at: 3))
        #expect(oldestID < secondID)
        #expect(secondID < thirdID)

        let before = trace.snapshot()
        #expect(before.trials.map(\.id) == [secondID, thirdID])
        #expect(before.evictedTrialCount == 1)
        #expect(!trace.record(.rowsPublished, trialID: oldestID, at: 4))
        #expect(!trace.finish(.cancelled, trialID: oldestID, at: 4))

        let after = trace.snapshot()
        expectTraceTrialsUnchanged(before.trials, after.trials)
        #expect(after.evictedTrialCount == 1)
        #expect(after.rejectedMutationCount == 2)
        let fourthID = try #require(trace.begin(at: 4))
        #expect(fourthID > thirdID)
        #expect(trace.snapshot().trials.map(\.id) == [thirdID, fourthID])
        #expect(trace.snapshot().evictedTrialCount == 2)
    }

    @Test("Capacity clamps extreme inputs to the documented storage bounds")
    func capacityBounds() throws {
        let minimum = UIInteractionTrace(capacity: .min)
        _ = try #require(minimum.begin(at: 1))
        let retainedID = try #require(minimum.begin(at: 2))
        #expect(minimum.snapshot().trials.map(\.id) == [retainedID])
        #expect(minimum.snapshot().evictedTrialCount == 1)

        for trace in [UIInteractionTrace(), UIInteractionTrace(capacity: .max)] {
            for index in 0...UIInteractionTrace.maximumTrials {
                _ = try #require(trace.begin(at: Double(index)))
            }
            let report = trace.snapshot()
            #expect(report.trials.count == 256)
            #expect(report.evictedTrialCount == 1)
            #expect(report.trials.first?.stages.first?.uptimeSeconds == 1)
            #expect(report.trials.last?.stages.first?.uptimeSeconds == 256)
            #expect(report.trials.allSatisfy { $0.stages.count <= UIInteractionTrace.maxStagesPerTrial })
        }
    }

    @Test("Invalid begin clocks reject without evicting an existing trial")
    func invalidBeginClocks() throws {
        let trace = UIInteractionTrace(capacity: 1)
        _ = try #require(trace.begin(at: 10))
        let before = trace.snapshot()
        let invalidTimes: [Double] = [-1, .nan, .infinity, -.infinity]
        for time in invalidTimes {
            #expect(trace.begin(at: time) == nil)
        }
        let invalidEventTimes: [Double] = [-1, .nan, .infinity, -.infinity, 10.1]
        for time in invalidEventTimes {
            #expect(trace.begin(at: 10, inputEventUptimeSeconds: time) == nil)
        }

        let after = trace.snapshot()
        expectTraceTrialsUnchanged(before.trials, after.trials)
        #expect(after.evictedTrialCount == 0)
        #expect(after.rejectedMutationCount == 9)
    }

    @Test("Invalid or decreasing stage clocks preserve the last accepted stage")
    func invalidStageClocks() throws {
        let trace = UIInteractionTrace()
        let id = try #require(trace.begin(at: 10))
        let before = trace.snapshot()
        for time in [-1, Double.nan, .infinity, -.infinity, 9.9] {
            #expect(!trace.record(.scheduled, trialID: id, at: time))
        }
        expectTraceTrialsUnchanged(before.trials, trace.snapshot().trials)
        #expect(trace.record(.scheduled, trialID: id, at: 10))
        let scheduled = trace.snapshot()
        #expect(!trace.record(.workerStarted, trialID: id, at: 9.9))
        expectTraceTrialsUnchanged(scheduled.trials, trace.snapshot().trials)
        #expect(trace.record(.workerStarted, trialID: id, at: 10))
        #expect(trace.record(.workerFinished, trialID: id, at: 10))
        #expect(trace.record(.rowsPublished, trialID: id, at: 10))
        #expect(trace.finish(.published, trialID: id, at: 10))
        #expect(trace.snapshot().rejectedMutationCount == 6)
    }

    @Test("Duplicate, skipped, and backward stages cannot shorten the asynchronous path")
    func invalidStageOrder() throws {
        let trace = UIInteractionTrace()
        let id = try #require(trace.begin(at: 1))
        var rejected: UInt64 = 0
        func reject(_ stages: [UIInteractionStage], at time: Double) {
            let before = trace.snapshot()
            for stage in stages {
                #expect(!trace.record(stage, trialID: id, at: time))
                rejected += 1
            }
            expectTraceTrialsUnchanged(before.trials, trace.snapshot().trials)
        }

        reject([.bindingReceived, .workerStarted, .workerFinished], at: 1)
        #expect(trace.record(.scheduled, trialID: id, at: 2))
        reject([.bindingReceived, .scheduled, .workerFinished, .rowsPublished], at: 2)
        #expect(trace.record(.workerStarted, trialID: id, at: 3))
        reject([.scheduled, .workerStarted, .rowsPublished], at: 3)
        #expect(trace.record(.workerFinished, trialID: id, at: 4))
        reject([.scheduled, .workerStarted, .workerFinished], at: 4)
        #expect(trace.record(.rowsPublished, trialID: id, at: 5))
        reject([.bindingReceived, .scheduled, .workerStarted, .workerFinished, .rowsPublished], at: 5)
        #expect(trace.finish(.published, trialID: id, at: 5))
        #expect(trace.snapshot().rejectedMutationCount == rejected)
    }

    @Test("Publication requires rows, and published rows cannot finish with a failure outcome")
    func outcomeMustMatchPublication() throws {
        let trace = UIInteractionTrace()
        let id = try #require(trace.begin(at: 1))
        let before = trace.snapshot()
        #expect(!trace.finish(.published, trialID: id, at: 2))
        expectTraceTrialsUnchanged(before.trials, trace.snapshot().trials)
        #expect(trace.record(.rowsPublished, trialID: id, at: 2))
        let published = trace.snapshot()
        for outcome in [UIInteractionOutcome.cancelled, .superseded, .failed] {
            #expect(!trace.finish(outcome, trialID: id, at: 3))
        }
        expectTraceTrialsUnchanged(published.trials, trace.snapshot().trials)
        #expect(trace.finish(.published, trialID: id, at: 3))
        #expect(trace.snapshot().rejectedMutationCount == 4)
    }

    @Test("Invalid completion clocks leave a published trial unfinished")
    func invalidCompletionClocks() throws {
        let trace = UIInteractionTrace()
        let id = try #require(trace.begin(at: 10))
        #expect(trace.record(.rowsPublished, trialID: id, at: 11))
        let before = trace.snapshot()
        for time in [-1, Double.nan, .infinity, -.infinity, 10.9] {
            #expect(!trace.finish(.published, trialID: id, at: time))
        }
        expectTraceTrialsUnchanged(before.trials, trace.snapshot().trials)
        #expect(trace.finish(.published, trialID: id, at: 11))
        #expect(trace.snapshot().rejectedMutationCount == 5)
    }

    @Test("Every terminal outcome is immutable and a later begin uses a fresh ID")
    func terminalTrialsCannotBeReused() throws {
        for outcome in [UIInteractionOutcome.published, .cancelled, .superseded, .failed] {
            let trace = UIInteractionTrace()
            let id = try #require(trace.begin(at: 1))
            if outcome == .published {
                #expect(trace.record(.rowsPublished, trialID: id, at: 2))
            }
            #expect(trace.finish(outcome, trialID: id, at: 2))
            let terminal = trace.snapshot()
            for stage in [UIInteractionStage.bindingReceived, .scheduled, .workerStarted, .workerFinished, .rowsPublished] {
                #expect(!trace.record(stage, trialID: id, at: 3))
            }
            for nextOutcome in [UIInteractionOutcome.published, .cancelled, .superseded, .failed] {
                #expect(!trace.finish(nextOutcome, trialID: id, at: 3))
            }
            expectTraceTrialsUnchanged(terminal.trials, trace.snapshot().trials)
            #expect(trace.snapshot().rejectedMutationCount == 9)
            let nextID = try #require(trace.begin(at: 3))
            #expect(nextID > id)
            #expect(trace.snapshot().trials.count == 2)
            let nextTrial = try #require(trace.snapshot().trials.last)
            #expect(nextTrial.outcome == nil)
            #expect(nextTrial.completedUptimeSeconds == nil)
        }
    }

    @Test("Failure outcomes can terminate any unfinished asynchronous phase")
    func earlyTermination() throws {
        let paths: [(UIInteractionOutcome, [UIInteractionStage])] = [
            (.cancelled, [.scheduled]),
            (.superseded, [.scheduled, .workerStarted]),
            (.failed, [.scheduled, .workerStarted, .workerFinished])
        ]
        for (outcome, stages) in paths {
            let trace = UIInteractionTrace()
            let id = try #require(trace.begin(at: 1))
            for (index, stage) in stages.enumerated() {
                #expect(trace.record(stage, trialID: id, at: Double(index + 2)))
            }
            #expect(trace.finish(outcome, trialID: id, at: 5))
            let trial = try #require(trace.snapshot().trials.first)
            #expect(trial.outcome == outcome)
            #expect(trial.completedUptimeSeconds == 5)
            #expect(trial.bindingToPublicationSeconds == nil)
            #expect(trace.snapshot().rejectedMutationCount == 0)
        }
    }

    @Test("Unknown trial IDs reject without mutating the retained trial")
    func unknownTrialIDs() throws {
        let trace = UIInteractionTrace()
        let id = try #require(trace.begin(at: 1))
        let before = trace.snapshot()
        #expect(!trace.record(.rowsPublished, trialID: id + 1, at: 2))
        #expect(!trace.finish(.failed, trialID: id + 1, at: 2))
        expectTraceTrialsUnchanged(before.trials, trace.snapshot().trials)
        #expect(trace.snapshot().rejectedMutationCount == 2)
    }

    @Test("Concurrent begin and finish preserve unique IDs and complete every retained trial")
    func concurrentTrials() async {
        let trace = UIInteractionTrace()
        let ids = await withTaskGroup(of: UInt64?.self, returning: [UInt64].self) { group in
            for index in 0..<256 {
                group.addTask {
                    let time = Double(index)
                    guard let id = trace.begin(at: time),
                          trace.finish(.cancelled, trialID: id, at: time) else { return nil }
                    return id
                }
            }
            var completedIDs: [UInt64] = []
            for await id in group {
                if let id { completedIDs.append(id) }
            }
            return completedIDs
        }

        let report = trace.snapshot()
        #expect(ids.count == 256)
        #expect(Set(ids).count == 256)
        #expect(report.trials.count == 256)
        #expect(Set(report.trials.map(\.id)) == Set(ids))
        #expect(report.trials.map(\.id) == report.trials.map(\.id).sorted())
        #expect(report.trials.allSatisfy { trial in
            trial.outcome == .cancelled && trial.stages.count == 1
                && trial.completedUptimeSeconds == trial.stages.first?.uptimeSeconds
        })
        #expect(report.evictedTrialCount == 0)
        #expect(report.rejectedMutationCount == 0)
    }
}

private func expectTraceTrialsUnchanged(_ before: [UIInteractionTrial], _ after: [UIInteractionTrial]) {
    #expect(before.count == after.count)
    for (original, current) in zip(before, after) {
        #expect(original.id == current.id)
        #expect(original.inputEventUptimeSeconds == current.inputEventUptimeSeconds)
        #expect(original.stages.map(\.stage) == current.stages.map(\.stage))
        #expect(original.stages.map(\.uptimeSeconds) == current.stages.map(\.uptimeSeconds))
        #expect(original.outcome == current.outcome)
        #expect(original.completedUptimeSeconds == current.completedUptimeSeconds)
        #expect(original.bindingToPublicationSeconds == current.bindingToPublicationSeconds)
    }
}
