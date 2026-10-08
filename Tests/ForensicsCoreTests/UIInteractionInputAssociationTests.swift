import Foundation
import Testing
@testable import ForensicsCore

@Suite("UIInteractionInputAssociationTests")
struct UIInteractionInputAssociationTests {
    @Test("Associating a completed trial preserves publication stages and outcome")
    func completedTrialAssociation() throws {
        let trace = UIInteractionTrace()
        let sequence = try #require(trace.reserveInputEventSequence())
        let id = try #require(trace.begin(at: 10.2))
        #expect(trace.record(.scheduled, trialID: id, at: 10.21))
        #expect(trace.record(.workerStarted, trialID: id, at: 10.22))
        #expect(trace.record(.workerFinished, trialID: id, at: 10.23))
        #expect(trace.record(.rowsPublished, trialID: id, at: 10.24))
        #expect(trace.finish(.published, trialID: id, at: 10.25))
        let before = trace.snapshot()
        let original = try #require(before.trials.first)
        let receipt = makeInputReceipt(sequence: sequence)

        #expect(trace.associateInputEvent(receipt, trialID: id))

        let after = trace.snapshot()
        let associated = try #require(after.trials.first)
        #expect(associated.id == original.id)
        #expect(associated.inputEventUptimeSeconds == receipt.eventUptimeSeconds)
        #expect(associated.inputReceipt == receipt)
        #expect(associated.stages == original.stages)
        #expect(associated.outcome == original.outcome)
        #expect(associated.completedUptimeSeconds == original.completedUptimeSeconds)
        #expect(associated.bindingToPublicationSeconds == original.bindingToPublicationSeconds)
        #expect(after.evictedTrialCount == before.evictedTrialCount)
        #expect(after.rejectedMutationCount == before.rejectedMutationCount)
        let diagnostics = try #require(after.inputDiagnostics)
        #expect(diagnostics.associatedInputCount == 1)
        #expect(diagnostics.reservedInputSequenceCount == 1)
        #expect(diagnostics.rejectionCounts.isEmpty)
    }

    @Test("Missing and temporally unrelated trials require a fresh input reservation")
    func missingAndWrongTrial() throws {
        for (wrongBinding, reason) in [
            (10.05, UIInteractionInputRejection.futureEvent),
            (10.4, UIInteractionInputRejection.ambiguous)
        ] {
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            let wrongID = try #require(trace.begin(at: wrongBinding))
            let correctID = try #require(trace.begin(at: 10.2))
            let receipt = makeInputReceipt(sequence: sequence)
            let before = trace.snapshot()

            #expect(!trace.associateInputEvent(receipt, trialID: correctID + 1))
            expectRejectedInput(before, trace.snapshot(), reason: .missingTrial)
            let wrongSequence = try #require(trace.reserveInputEventSequence())
            let afterMissing = trace.snapshot()
            #expect(!trace.associateInputEvent(makeInputReceipt(sequence: wrongSequence), trialID: wrongID))
            expectRejectedInput(afterMissing, trace.snapshot(), reason: reason)
            let correctSequence = try #require(trace.reserveInputEventSequence())
            let correctReceipt = makeInputReceipt(sequence: correctSequence)
            #expect(trace.associateInputEvent(correctReceipt, trialID: correctID))
            let report = trace.snapshot()
            #expect(report.trials.first?.inputReceipt == nil)
            #expect(report.trials.last?.inputReceipt == correctReceipt)
            #expect(report.inputDiagnostics?.associatedInputCount == 1)
            #expect(report.inputDiagnostics?.reservedInputSequenceCount == 3)
        }
    }

    @Test("Legacy input metadata and an existing receipt cannot be overwritten")
    func alreadyAssociatedInputs() throws {
        let legacyTrace = UIInteractionTrace()
        let legacySequence = try #require(legacyTrace.reserveInputEventSequence())
        let legacyID = try #require(legacyTrace.begin(at: 10.2, inputEventUptimeSeconds: 10))
        let legacyBefore = legacyTrace.snapshot()
        #expect(!legacyTrace.associateInputEvent(makeInputReceipt(sequence: legacySequence), trialID: legacyID))
        expectRejectedInput(legacyBefore, legacyTrace.snapshot(), reason: .alreadyAssociated)

        let trace = UIInteractionTrace()
        let firstSequence = try #require(trace.reserveInputEventSequence())
        let id = try #require(trace.begin(at: 10.2))
        #expect(trace.associateInputEvent(makeInputReceipt(sequence: firstSequence), trialID: id))
        let secondSequence = try #require(trace.reserveInputEventSequence())
        let before = trace.snapshot()
        #expect(!trace.associateInputEvent(
            makeInputReceipt(sequence: secondSequence, event: 10.01), trialID: id))
        expectRejectedInput(before, trace.snapshot(), reason: .alreadyAssociated)
        #expect(trace.snapshot().inputDiagnostics?.associatedInputCount == 1)
    }

    @Test("Zero, unreserved, and consumed input sequences reject as replay")
    func invalidAndConsumedSequences() throws {
        let cases: [(Int, UInt64)] = [(0, 0), (0, 1), (1, 2)]
        for (reservationCount, sequence) in cases {
            let trace = UIInteractionTrace()
            for _ in 0..<reservationCount {
                _ = try #require(trace.reserveInputEventSequence())
            }
            let id = try #require(trace.begin(at: 10.2))
            let before = trace.snapshot()
            #expect(!trace.associateInputEvent(makeInputReceipt(sequence: sequence), trialID: id))
            expectRejectedInput(before, trace.snapshot(), reason: .replay)
        }

        let trace = UIInteractionTrace()
        let olderSequence = try #require(trace.reserveInputEventSequence())
        let acceptedSequence = try #require(trace.reserveInputEventSequence())
        let firstID = try #require(trace.begin(at: 10.2))
        #expect(trace.associateInputEvent(makeInputReceipt(sequence: acceptedSequence), trialID: firstID))
        let secondID = try #require(trace.begin(at: 10.25))
        for sequence in [olderSequence, acceptedSequence] {
            let before = trace.snapshot()
            #expect(!trace.associateInputEvent(
                makeInputReceipt(sequence: sequence, event: 10.01), trialID: secondID))
            expectRejectedInput(before, trace.snapshot(), reason: .replay)
        }
    }

    @Test("A newer reservation also requires a strictly newer event timestamp")
    func nonmonotonicEventTimestamps() throws {
        let trace = UIInteractionTrace()
        let firstSequence = try #require(trace.reserveInputEventSequence())
        let firstID = try #require(trace.begin(at: 10.2))
        #expect(trace.associateInputEvent(makeInputReceipt(sequence: firstSequence), trialID: firstID))
        let secondID = try #require(trace.begin(at: 10.25))
        for event in [10.0, 9.99] {
            let sequence = try #require(trace.reserveInputEventSequence())
            let before = trace.snapshot()
            #expect(!trace.associateInputEvent(
                makeInputReceipt(sequence: sequence, event: event), trialID: secondID))
            expectRejectedInput(before, trace.snapshot(), reason: .replay)
        }
        let validSequence = try #require(trace.reserveInputEventSequence())
        #expect(trace.associateInputEvent(
            makeInputReceipt(sequence: validSequence, event: 10.01), trialID: secondID))
        #expect(trace.snapshot().inputDiagnostics?.associatedInputCount == 2)
    }

    @Test("An event after dispatch receipt or a dispatch after binding rejects as future")
    func futureEventOrDispatch() throws {
        for receipt in [
            makeInputReceipt(sequence: 1, event: 10.11),
            makeInputReceipt(sequence: 1, dispatchStart: 10.21, machStart: 10.21, machEnd: 10.21)
        ] {
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            #expect(sequence == receipt.sequence)
            let id = try #require(trace.begin(at: 10.2))
            let before = trace.snapshot()
            #expect(!trace.associateInputEvent(receipt, trialID: id))
            expectRejectedInput(before, trace.snapshot(), reason: .futureEvent)
        }
    }

    @Test("A rejected reserved sequence cannot be retried against an otherwise valid trial")
    func rejectedSequencesAreConsumed() throws {
        for reason in [UIInteractionInputRejection.missingTrial, .futureEvent, .invalidClock] {
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            let id = try #require(trace.begin(at: 10.2))
            let invalid: UIInteractionInputReceipt
            switch reason {
            case .futureEvent:
                invalid = makeInputReceipt(sequence: sequence, event: 10.11)
            case .invalidClock:
                invalid = makeInputReceipt(sequence: sequence, coreAnimationSample: 10.1005)
            default:
                invalid = makeInputReceipt(sequence: sequence)
            }
            let before = trace.snapshot()
            #expect(!trace.associateInputEvent(invalid, trialID: reason == .missingTrial ? id + 1 : id))
            expectRejectedInput(before, trace.snapshot(), reason: reason)
            let afterRejection = trace.snapshot()
            #expect(!trace.associateInputEvent(makeInputReceipt(sequence: sequence), trialID: id))
            expectRejectedInput(afterRejection, trace.snapshot(), reason: .replay)

            let freshSequence = try #require(trace.reserveInputEventSequence())
            #expect(trace.associateInputEvent(makeInputReceipt(sequence: freshSequence), trialID: id))
            #expect(trace.snapshot().inputDiagnostics?.associatedInputCount == 1)
            #expect(trace.snapshot().inputDiagnostics?.reservedInputSequenceCount == 2)
        }
    }

    @Test("Zero and large unreserved IDs cannot consume a valid lower reservation")
    func unreservedSequenceDoesNotAdvanceHighWater() throws {
        let trace = UIInteractionTrace()
        let sequence = try #require(trace.reserveInputEventSequence())
        let id = try #require(trace.begin(at: 10.2))
        for unreserved in [UInt64(0), .max] {
            let before = trace.snapshot()
            #expect(!trace.associateInputEvent(makeInputReceipt(sequence: unreserved), trialID: id))
            expectRejectedInput(before, trace.snapshot(), reason: .replay)
        }
        #expect(trace.associateInputEvent(makeInputReceipt(sequence: sequence), trialID: id))
        #expect(trace.snapshot().inputDiagnostics?.associatedInputCount == 1)
        #expect(trace.snapshot().inputDiagnostics?.reservedInputSequenceCount == 1)
    }

    @Test("Both input age limits accept equality and reject the next older value")
    func ageBoundaries() throws {
        #expect(UIInteractionTrace.maximumInputEventAgeSeconds == 1)
        #expect(UIInteractionTrace.maximumInputBindingAgeSeconds == 1)
        let trace = UIInteractionTrace()
        let sequence = try #require(trace.reserveInputEventSequence())
        let id = try #require(trace.begin(at: 10))
        let boundaryReceipt = makeInputReceipt(
            sequence: sequence, event: 8, dispatchStart: 9, dispatchEnd: 10,
            machStart: 9, coreAnimationSample: 9, machEnd: 9)
        #expect(trace.associateInputEvent(boundaryReceipt, trialID: id))

        for (event, binding) in [(8.0.nextDown, 10.0), (8.0, 10.0.nextUp)] {
            let staleTrace = UIInteractionTrace()
            let staleSequence = try #require(staleTrace.reserveInputEventSequence())
            let staleID = try #require(staleTrace.begin(at: binding))
            let before = staleTrace.snapshot()
            let staleReceipt = makeInputReceipt(
                sequence: staleSequence, event: event, dispatchStart: 9, dispatchEnd: 11,
                machStart: 9, coreAnimationSample: 9, machEnd: 9)
            #expect(!staleTrace.associateInputEvent(staleReceipt, trialID: staleID))
            expectRejectedInput(before, staleTrace.snapshot(), reason: .staleEvent)
        }
    }

    @Test("Binding at either dispatch endpoint is accepted, outside the end is ambiguous")
    func dispatchBoundaries() throws {
        for binding in [10.1, 10.3] {
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            let id = try #require(trace.begin(at: binding))
            #expect(trace.associateInputEvent(makeInputReceipt(sequence: sequence), trialID: id))
        }
        let trace = UIInteractionTrace()
        let sequence = try #require(trace.reserveInputEventSequence())
        let id = try #require(trace.begin(at: 10.3.nextUp))
        let before = trace.snapshot()
        #expect(!trace.associateInputEvent(makeInputReceipt(sequence: sequence), trialID: id))
        expectRejectedInput(before, trace.snapshot(), reason: .ambiguous)
    }

    @Test("Every receipt clock must be finite and strictly positive")
    func invalidClockValues() throws {
        let validTimes: [TimeInterval] = [10, 10, 10.1, 10.3, 10.1, 10.1, 10.101]
        for index in validTimes.indices {
            for invalid in [-1, 0, Double.nan, .infinity, -.infinity] {
                let trace = UIInteractionTrace()
                let sequence = try #require(trace.reserveInputEventSequence())
                let id = try #require(trace.begin(at: 10.2))
                var times = validTimes
                times[index] = invalid
                let receipt = UIInteractionInputReceipt(
                    sequence: sequence, eventUptimeSeconds: times[0],
                    quartzEventUptimeSeconds: times[1], dispatchReceiptUptimeSeconds: times[2],
                    dispatchEndUptimeSeconds: times[3], machBracketStartSeconds: times[4],
                    coreAnimationSampleSeconds: times[5], machBracketEndSeconds: times[6])
                let before = trace.snapshot()
                #expect(!trace.associateInputEvent(receipt, trialID: id))
                expectRejectedInput(before, trace.snapshot(), reason: .invalidClock)
            }
        }
    }

    @Test("Reversed brackets and mismatched clocks reject without changing a trial")
    func invalidClockRelationships() throws {
        for receipt in [
            makeInputReceipt(sequence: 1, dispatchEnd: 10.05),
            makeInputReceipt(sequence: 1, machEnd: 10.09),
            makeInputReceipt(sequence: 1, quartzEvent: 10.000_002),
            makeInputReceipt(sequence: 1, coreAnimationSample: 10.1005),
            makeInputReceipt(sequence: 1, coreAnimationSample: 10.102)
        ] {
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            #expect(sequence == receipt.sequence)
            let id = try #require(trace.begin(at: 10.2))
            let before = trace.snapshot()
            #expect(!trace.associateInputEvent(receipt, trialID: id))
            expectRejectedInput(before, trace.snapshot(), reason: .invalidClock)
        }
    }

    @Test("Quartz tolerance accepts its exact boundary and rejects the next value outside")
    func quartzClockTolerance() throws {
        let tolerance = UIInteractionTrace.maximumInputQuartzClockDifferenceSeconds
        #expect(tolerance == 0.000_001)
        for (event, boundary, outside) in [
            (tolerance, 2 * tolerance, (2 * tolerance).nextUp),
            (2 * tolerance, tolerance, tolerance.nextDown)
        ] {
            #expect(abs(event - boundary) == tolerance)
            #expect(abs(event - outside) > tolerance)
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            let id = try #require(trace.begin(at: event))
            let before = trace.snapshot()
            let invalid = makeInputReceipt(
                sequence: sequence, event: event, quartzEvent: outside,
                dispatchStart: event, dispatchEnd: event,
                machStart: event, coreAnimationSample: event, machEnd: event)
            #expect(!trace.associateInputEvent(invalid, trialID: id))
            expectRejectedInput(before, trace.snapshot(), reason: .invalidClock)
            let validSequence = try #require(trace.reserveInputEventSequence())
            let valid = makeInputReceipt(
                sequence: validSequence, event: event, quartzEvent: boundary,
                dispatchStart: event, dispatchEnd: event,
                machStart: event, coreAnimationSample: event, machEnd: event)
            #expect(trace.associateInputEvent(valid, trialID: id))
        }
    }

    @Test("Core Animation bracket tolerance uses inclusive lower and upper bounds")
    func coreAnimationBracketTolerance() throws {
        let tolerance = UIInteractionTrace.maximumInputMachBracketToleranceSeconds
        #expect(tolerance == 0.000_000_001)
        let upperBracket = 2 + tolerance
        let lowerBracket = 2 - tolerance
        for (boundary, outside) in [
            (upperBracket, upperBracket.nextUp),
            (lowerBracket, lowerBracket.nextDown)
        ] {
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            let id = try #require(trace.begin(at: 2.1))
            let before = trace.snapshot()
            let invalid = makeInputReceipt(
                sequence: sequence, event: 1.9, dispatchStart: 2, dispatchEnd: 2.2,
                machStart: outside, coreAnimationSample: 2, machEnd: outside)
            #expect(!trace.associateInputEvent(invalid, trialID: id))
            expectRejectedInput(before, trace.snapshot(), reason: .invalidClock)
            let validSequence = try #require(trace.reserveInputEventSequence())
            let valid = makeInputReceipt(
                sequence: validSequence, event: 1.9, dispatchStart: 2, dispatchEnd: 2.2,
                machStart: boundary, coreAnimationSample: 2, machEnd: boundary)
            #expect(trace.associateInputEvent(valid, trialID: id))
        }
    }

    @Test("Dispatch receipt and Core Animation sample agree within an inclusive 1 ns tolerance")
    func dispatchCoreAnimationSampleTolerance() throws {
        let tolerance = UIInteractionTrace.maximumInputMachBracketToleranceSeconds
        for (dispatch, boundary, outside) in [
            (tolerance, 2 * tolerance, (2 * tolerance).nextUp),
            (2 * tolerance, tolerance, tolerance.nextDown)
        ] {
            #expect(abs(dispatch - boundary) == tolerance)
            #expect(abs(dispatch - outside) > tolerance)
            let trace = UIInteractionTrace()
            let sequence = try #require(trace.reserveInputEventSequence())
            let id = try #require(trace.begin(at: dispatch))
            let before = trace.snapshot()
            let invalid = makeInputReceipt(
                sequence: sequence, event: dispatch, dispatchStart: dispatch, dispatchEnd: dispatch,
                machStart: outside, coreAnimationSample: outside, machEnd: outside)
            #expect(!trace.associateInputEvent(invalid, trialID: id))
            expectRejectedInput(before, trace.snapshot(), reason: .invalidClock)
            let freshSequence = try #require(trace.reserveInputEventSequence())
            let valid = makeInputReceipt(
                sequence: freshSequence, event: dispatch, dispatchStart: dispatch, dispatchEnd: dispatch,
                machStart: boundary, coreAnimationSample: boundary, machEnd: boundary)
            #expect(trace.associateInputEvent(valid, trialID: id))
        }
    }

    @Test("Reports without input actions preserve the legacy JSON bytes")
    func legacyJSONCompatibility() throws {
        let legacyReports = [
            #"{"evictedTrialCount":0,"rejectedMutationCount":0,"trials":[]}"#,
            #"{"evictedTrialCount":2,"rejectedMutationCount":3,"trials":[{"completedUptimeSeconds":10.5,"id":7,"outcome":"published","stages":[{"stage":"bindingReceived","uptimeSeconds":10},{"stage":"rowsPublished","uptimeSeconds":10.3}]}]}"#,
            #"{"evictedTrialCount":2,"rejectedMutationCount":3,"trials":[{"completedUptimeSeconds":10.5,"id":7,"inputEventUptimeSeconds":9.9,"outcome":"published","stages":[{"stage":"bindingReceived","uptimeSeconds":10},{"stage":"rowsPublished","uptimeSeconds":10.3}]}]}"#
        ]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        for legacyJSON in legacyReports {
            let bytes = Data(legacyJSON.utf8)
            let report = try JSONDecoder().decode(UIInteractionTraceReport.self, from: bytes)
            #expect(report.inputDiagnostics == nil)
            #expect(report.trials.allSatisfy { $0.inputReceipt == nil })
            #expect(try encoder.encode(report) == bytes)
        }
        let trace = UIInteractionTrace()
        #expect(trace.snapshot().inputDiagnostics == nil)
        _ = try #require(trace.begin(at: 10))
        #expect(trace.snapshot().inputDiagnostics == nil)
        let encoded = try encoder.encode(trace.snapshot())
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object["inputDiagnostics"] == nil)
        let trials = try #require(object["trials"] as? [[String: Any]])
        #expect(trials.first?["inputReceipt"] == nil)
        #expect(trials.first?["inputEventUptimeSeconds"] == nil)
    }

    @Test("Associated input receipts and diagnostics round-trip through report JSON")
    func inputJSONRoundTrip() throws {
        let trace = UIInteractionTrace()
        let sequence = try #require(trace.reserveInputEventSequence())
        let id = try #require(trace.begin(at: 10.2))
        let receipt = makeInputReceipt(sequence: sequence)
        #expect(trace.associateInputEvent(receipt, trialID: id))
        trace.recordInputRejection(.notFocused)
        let report = trace.snapshot()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(report)
        let decoded = try JSONDecoder().decode(UIInteractionTraceReport.self, from: encoded)
        #expect(decoded == report)
        #expect(decoded.trials.first?.inputReceipt == receipt)
        #expect(decoded.trials.first?.inputEventUptimeSeconds == receipt.eventUptimeSeconds)
        #expect(decoded.inputDiagnostics?.rejectionCounts[UIInteractionInputRejection.notFocused.rawValue] == 1)
        #expect(try encoder.encode(decoded) == encoded)
        #expect(decoded.rejectedMutationCount == 0)
    }

    @Test("Every input rejection has a stable numeric code and a separate diagnostic counter")
    func rejectionCodesAndCounters() throws {
        let expected: [UIInteractionInputRejection] = [
            .notFocused, .noChange, .ambiguous, .unsupported, .invalidClock, .staleEvent,
            .futureEvent, .replay, .missingTrial, .alreadyAssociated, .suspended, .sequenceExhausted
        ]
        #expect(UIInteractionInputRejection.allCases == expected)
        #expect(expected.map(\.rawValue) == Array(UInt8(1)...UInt8(12)))
        let trace = UIInteractionTrace()
        for reason in expected { trace.recordInputRejection(reason) }
        let report = trace.snapshot()
        let diagnostics = try #require(report.inputDiagnostics)
        #expect(diagnostics.associatedInputCount == 0)
        #expect(diagnostics.reservedInputSequenceCount == 0)
        #expect(diagnostics.rejectionCounts.count == expected.count)
        for reason in expected { #expect(diagnostics.rejectionCounts[reason.rawValue] == 1) }
        #expect(report.trials.isEmpty)
        #expect(report.rejectedMutationCount == 0)
        #expect(report.evictedTrialCount == 0)
    }

    @Test("Diagnostics discard unknown codes and saturate instead of overflowing")
    func diagnosticFilteringAndSaturation() throws {
        let filtered = UIInteractionInputDiagnostics(rejectionCounts: [0: 1, 1: 2, 12: 3, 13: 4, 255: .max])
        #expect(filtered.rejectionCounts == [1: 2, 12: 3])
        let unfilteredJSON = #"{"associatedInputCount":7,"reservedInputSequenceCount":8,"rejectionCounts":[0,1,1,2,12,3,13,4,255,5]}"#
        let decoded = try JSONDecoder().decode(
            UIInteractionInputDiagnostics.self, from: Data(unfilteredJSON.utf8))
        #expect(decoded.associatedInputCount == 7)
        #expect(decoded.reservedInputSequenceCount == 8)
        #expect(decoded.rejectionCounts == filtered.rejectionCounts)
        let seededCounts = Dictionary(uniqueKeysWithValues:
            UIInteractionInputRejection.allCases.map { ($0.rawValue, UInt64.max - 1) })
        var diagnostics = UIInteractionInputDiagnostics(
            associatedInputCount: UInt64.max - 1,
            reservedInputSequenceCount: UInt64.max - 1,
            rejectionCounts: seededCounts)
        for _ in 0..<2 {
            diagnostics.recordAssociation()
            diagnostics.recordReservation()
            for reason in UIInteractionInputRejection.allCases { diagnostics.recordRejection(reason) }
        }
        #expect(diagnostics.associatedInputCount == .max)
        #expect(diagnostics.reservedInputSequenceCount == .max)
        #expect(diagnostics.rejectionCounts.count == UIInteractionInputRejection.allCases.count)
        #expect(diagnostics.rejectionCounts.values.allSatisfy { $0 == .max })
    }

    @Test("Concurrent reservations issue each input sequence once")
    func concurrentReservations() async {
        let trace = UIInteractionTrace()
        let sequences = await withTaskGroup(of: UInt64?.self, returning: [UInt64].self) { group in
            for _ in 0..<128 {
                group.addTask { trace.reserveInputEventSequence() }
            }
            var reserved: [UInt64] = []
            for await sequence in group {
                if let sequence { reserved.append(sequence) }
            }
            return reserved
        }
        #expect(sequences.sorted() == Array(UInt64(1)...UInt64(128)))
        let report = trace.snapshot()
        #expect(report.inputDiagnostics?.reservedInputSequenceCount == 128)
        #expect(report.inputDiagnostics?.associatedInputCount == 0)
        #expect(report.inputDiagnostics?.rejectionCounts.isEmpty == true)
        #expect(report.trials.isEmpty)
        #expect(report.rejectedMutationCount == 0)
    }

    @Test("Input reservations and trial IDs remain unique beyond eviction capacity")
    func reservationsAcrossEviction() throws {
        let trace = UIInteractionTrace(capacity: 2)
        let count = UIInteractionTrace.maximumTrials + 3
        var sequences: [UInt64] = []
        var trialIDs: [UInt64] = []
        for index in 0..<count {
            let binding = Double(index) + 2
            let sequence = try #require(trace.reserveInputEventSequence())
            let id = try #require(trace.begin(at: binding))
            #expect(trace.finish(.cancelled, trialID: id, at: binding))
            #expect(trace.associateInputEvent(makeInputReceipt(
                sequence: sequence, event: binding - 0.2,
                dispatchStart: binding - 0.1, dispatchEnd: binding + 0.1,
                machStart: binding - 0.1, machEnd: binding - 0.1), trialID: id))
            sequences.append(sequence)
            trialIDs.append(id)
        }
        #expect(sequences == Array(UInt64(1)...UInt64(count)))
        #expect(trialIDs == Array(UInt64(1)...UInt64(count)))
        let before = trace.snapshot()
        #expect(before.trials.map(\.id) == Array(trialIDs.suffix(2)))
        #expect(before.evictedTrialCount == UInt64(count - 2))
        #expect(before.inputDiagnostics?.reservedInputSequenceCount == UInt64(count))
        #expect(before.inputDiagnostics?.associatedInputCount == UInt64(count))

        let nextSequence = try #require(trace.reserveInputEventSequence())
        let binding = Double(count) + 2
        let nextID = try #require(trace.begin(at: binding))
        #expect(nextSequence == UInt64(count + 1))
        #expect(nextID == UInt64(count + 1))
        let receipt = makeInputReceipt(
            sequence: nextSequence, event: binding - 0.2,
            dispatchStart: binding - 0.1, dispatchEnd: binding + 0.1,
            machStart: binding - 0.1, machEnd: binding - 0.1)
        let beforeMissing = trace.snapshot()
        let evictedID = try #require(trialIDs.first)
        #expect(!trace.associateInputEvent(receipt, trialID: evictedID))
        expectRejectedInput(beforeMissing, trace.snapshot(), reason: .missingTrial)
        let validSequence = try #require(trace.reserveInputEventSequence())
        #expect(trace.associateInputEvent(makeInputReceipt(
            sequence: validSequence, event: binding - 0.2,
            dispatchStart: binding - 0.1, dispatchEnd: binding + 0.1,
            machStart: binding - 0.1, machEnd: binding - 0.1), trialID: nextID))
        let after = trace.snapshot()
        #expect(after.trials.count == 2)
        #expect(after.evictedTrialCount == UInt64(count - 1))
        #expect(after.inputDiagnostics?.reservedInputSequenceCount == UInt64(count + 2))
        #expect(after.inputDiagnostics?.associatedInputCount == UInt64(count + 1))
        #expect(after.rejectedMutationCount == 0)
    }
}

private func makeInputReceipt(
    sequence: UInt64, event: TimeInterval = 10, quartzEvent: TimeInterval? = nil,
    dispatchStart: TimeInterval = 10.1, dispatchEnd: TimeInterval = 10.3,
    machStart: TimeInterval = 10.1, coreAnimationSample: TimeInterval? = nil,
    machEnd: TimeInterval = 10.101
) -> UIInteractionInputReceipt {
    UIInteractionInputReceipt(
        sequence: sequence, eventUptimeSeconds: event, quartzEventUptimeSeconds: quartzEvent ?? event,
        dispatchReceiptUptimeSeconds: dispatchStart, dispatchEndUptimeSeconds: dispatchEnd,
        machBracketStartSeconds: machStart, coreAnimationSampleSeconds: coreAnimationSample ?? dispatchStart,
        machBracketEndSeconds: machEnd)
}

private func expectRejectedInput(
    _ before: UIInteractionTraceReport, _ after: UIInteractionTraceReport,
    reason: UIInteractionInputRejection
) {
    #expect(after.trials == before.trials)
    #expect(after.evictedTrialCount == before.evictedTrialCount)
    #expect(after.rejectedMutationCount == before.rejectedMutationCount)
    #expect(after.inputDiagnostics?.associatedInputCount == (before.inputDiagnostics?.associatedInputCount ?? 0))
    #expect(after.inputDiagnostics?.reservedInputSequenceCount == (before.inputDiagnostics?.reservedInputSequenceCount ?? 0))
    let priorCount = before.inputDiagnostics?.rejectionCounts[reason.rawValue] ?? 0
    #expect(after.inputDiagnostics?.rejectionCounts[reason.rawValue] == priorCount + 1)
}
