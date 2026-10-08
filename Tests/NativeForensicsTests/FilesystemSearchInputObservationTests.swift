import AppKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

/// These are deterministic causality tests, not native-key or presentation gates.
@Suite("FilesystemSearchInputObservationTests")
@MainActor
struct FilesystemSearchInputObservationTests {
    @Test("A single owned edit is associated only after dispatch without changing completed milestones")
    func completedDispatch() throws {
        let fixture = InputFixture()
        let sequence = try #require(fixture.begin())
        let trial = try fixture.publishedTrial()
        let original = try #require(fixture.timing.snapshot().trials.first)
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        fixture.end(sequence)
        let actual = try #require(fixture.timing.snapshot().trials.first)
        #expect(actual.inputEventUptimeSeconds == 9.9)
        #expect(actual.inputReceipt?.sequence == sequence)
        #expect(actual.stages == original.stages)
        #expect(actual.outcome == original.outcome && actual.completedUptimeSeconds == original.completedUptimeSeconds)
    }

    @Test("Every concrete focus-owner mismatch leaves the ordinary trial unstamped")
    func ownerMismatch() throws {
        for defect in FocusDefect.allCases {
            let fixture = InputFixture()
            let sequence = try #require(fixture.begin(focus: fixture.focus(defect)))
            let trial = try fixture.publishedTrial()
            fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                            notificationMatchesOwner: true, focus: fixture.focus(defect))
            fixture.end(sequence, focus: fixture.focus(defect))
            #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
            #expect(fixture.rejections(.notFocused) == 1)
        }
    }

    @Test("A different notification editor cannot stamp an otherwise focused control")
    func wrongNotificationOwner() throws {
        let fixture = InputFixture(), sequence = try #require(fixture.begin())
        let trial = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: false, focus: fixture.focus())
        fixture.end(sequence)
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        #expect(fixture.rejections(.notFocused) == 1)
    }

    @Test("Multiple notifications reject the whole dispatch, including an already completed first trial")
    func multipleNotifications() throws {
        let fixture = InputFixture(), sequence = try #require(fixture.begin())
        let first = try fixture.publishedTrial(), second = try fixture.publishedTrial()
        for trial in [first, second] {
            fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                            notificationMatchesOwner: true, focus: fixture.focus())
        }
        fixture.end(sequence)
        #expect(fixture.timing.snapshot().trials.allSatisfy { $0.inputEventUptimeSeconds == nil })
        #expect(fixture.rejections(.ambiguous) == 1)
    }

    @Test("Nested dispatch cannot borrow or stamp its outer event, and later fresh dispatch still works")
    func nestedDispatch() throws {
        let fixture = InputFixture(), outer = try #require(fixture.begin())
        #expect(fixture.begin() == nil)
        let first = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: first),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.end(outer)
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        let next = try #require(fixture.begin()), second = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: second),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.end(next)
        #expect(fixture.timing.snapshot().trials.last?.inputEventUptimeSeconds == 9.9)
    }

    @Test("AX, paste and programmatic changes outside dispatch are binding-only")
    func unscopedMutation() throws {
        let fixture = InputFixture(), trial = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        #expect(fixture.rejections(.unsupported) == 1)
    }

    @Test("A programmatic model update inside a native dispatch still cannot acquire that event")
    func scopedProgrammaticMutation() throws {
        let fixture = InputFixture(), sequence = try #require(fixture.begin())
        let trial = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus(),
                                        isProgrammaticUpdate: true)
        fixture.end(sequence)
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        #expect(fixture.rejections(.unsupported) == 1)
    }

    @Test("Unsupported key and marked-text paths preserve the original binding-only trial")
    func unsupportedPaths() throws {
        for marked in [false, true] {
            let fixture = InputFixture()
            let focus = fixture.focus(markedText: marked)
            let sequence = try #require(fixture.begin(focus: focus, supported: marked))
            let trial = try fixture.publishedTrial()
            fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                            notificationMatchesOwner: true, focus: focus)
            fixture.end(sequence, focus: focus)
            #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
            #expect(fixture.rejections(.unsupported) == 1)
        }
    }

    @Test("Transient paste or composition latches rejection even when the final focus has no marked text")
    func unsupportedOperationLatch() throws {
        let fixture = InputFixture(), sequence = try #require(fixture.begin())
        fixture.observation.rejectCurrentDispatch()
        let trial = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.end(sequence)
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        #expect(fixture.rejections(.unsupported) == 1)
    }

    @Test("The actual editor forwards a programmatic string update while latching its dispatch as unsupported")
    func editorProgrammaticSetter() throws {
        let fixture = InputFixture(), sequence = try #require(fixture.begin())
        let editor = FilesystemSearchField.SearchEditor(frame: .zero)
        editor.observation = fixture.observation
        editor.string = "SYNTHETIC-PROGRAMMATIC"
        #expect(editor.string == "SYNTHETIC-PROGRAMMATIC")
        let trial = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.end(sequence)
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        #expect(fixture.rejections(.unsupported) == 1)
    }

    @Test("The actual editor's transient marked-text path stays unsupported after unmarking")
    func editorTransientMarkedText() throws {
        let fixture = InputFixture(), sequence = try #require(fixture.begin())
        let editor = FilesystemSearchField.SearchEditor(frame: .zero)
        editor.observation = fixture.observation
        editor.setMarkedText("SYNTHETIC-COMPOSITION", selectedRange: NSRange(location: 0, length: 0),
                             replacementRange: NSRange(location: NSNotFound, length: 0))
        editor.unmarkText()
        #expect(!editor.hasMarkedText())
        let trial = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.end(sequence)
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
        #expect(fixture.rejections(.unsupported) == 1)
    }

    @Test("A no-op unmark does not disqualify an otherwise single owned ordinary edit")
    func editorNoOpUnmark() throws {
        let fixture = InputFixture(), sequence = try #require(fixture.begin())
        let editor = FilesystemSearchField.SearchEditor(frame: .zero)
        editor.observation = fixture.observation
        #expect(!editor.hasMarkedText())
        editor.unmarkText()
        let trial = try fixture.publishedTrial()
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.end(sequence)
        #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == 9.9)
    }

    @Test("The custom cell returns its editor only to its own control, preserving all other field editors")
    func customEditorOwnership() throws {
        let field = FilesystemSearchField.SearchField(frame: .zero)
        let other = FilesystemSearchField.SearchField(frame: .zero)
        let cell = FilesystemSearchField.SearchCell(textCell: "")
        field.cell = cell
        let editor = try #require(cell.fieldEditor(for: field))
        #expect(editor === cell.editor && editor.isFieldEditor)
        #expect(cell.fieldEditor(for: other) == nil)
        #expect(cell.editor.owner === field)
    }

    @Test("Missing Quartz clock, mismatched clock and slow queued input are reported instead of disappearing")
    func clockQualification() throws {
        let variants: [(FilesystemSearchInputObservation.ClockSample?, UIInteractionInputRejection)] = [
            (nil, .invalidClock),
            (InputFixture.clock(event: 9.9, quartz: 9.8), .invalidClock),
            (InputFixture.clock(event: 8, quartz: 8), .staleEvent)
        ]
        for (clock, reason) in variants {
            let fixture = InputFixture()
            let sequence = try #require(fixture.observation.beginDispatch(clock: clock, focus: fixture.focus(),
                                                                          isSupportedKeyEvent: true))
            let trial = try fixture.publishedTrial()
            fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                            notificationMatchesOwner: true, focus: fixture.focus())
            fixture.end(sequence)
            #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
            #expect(fixture.rejections(reason) == 1)
        }
    }

    @Test("No-change and missing-trial callbacks do not reuse a prior binding ID")
    func invalidBinding() throws {
        for changed in [false, true] {
            let fixture = InputFixture(), sequence = try #require(fixture.begin())
            _ = try fixture.publishedTrial()
            fixture.observation.noteBinding(.init(changed: changed, trialID: nil),
                                            notificationMatchesOwner: true, focus: fixture.focus())
            fixture.end(sequence)
            #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
            #expect(fixture.rejections(changed ? .missingTrial : .noChange) == 1)
        }
    }

    @Test("Focus loss and lifecycle invalidation clear pending qualification and report it")
    func lifecycleInvalidation() throws {
        for reason in [UIInteractionInputRejection.notFocused, .suspended] {
            let fixture = InputFixture(), sequence = try #require(fixture.begin())
            let trial = try fixture.publishedTrial()
            fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                            notificationMatchesOwner: true, focus: fixture.focus())
            fixture.observation.invalidate(reason)
            fixture.end(sequence)
            #expect(fixture.timing.snapshot().trials.first?.inputEventUptimeSeconds == nil)
            #expect(fixture.rejections(reason) == 1)
        }
    }

    @Test("An old finalizer cannot clear a new dispatch opened after lifecycle invalidation")
    func oldFinalizer() throws {
        let fixture = InputFixture(), old = try #require(fixture.begin())
        fixture.observation.invalidate(.suspended)
        let current = try #require(fixture.begin()), trial = try fixture.publishedTrial()
        fixture.end(old)
        fixture.observation.noteBinding(.init(changed: true, trialID: trial),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.end(current)
        #expect(fixture.timing.snapshot().trials.first?.inputReceipt?.sequence == current)
        #expect(fixture.rejections(.suspended) == 1)
    }

    @Test("Normal launches retain no input observation, diagnostic counters or timing trials")
    func disabledObservation() {
        let fixture = InputFixture(enabled: false)
        #expect(fixture.begin() == nil)
        fixture.observation.noteBinding(.init(changed: true, trialID: 1),
                                        notificationMatchesOwner: true, focus: fixture.focus())
        fixture.observation.invalidate(.suspended)
        #expect(fixture.timing.snapshot() == UIInteractionTraceReport())
    }

    @Test("The real workspace setter returns its own mutation ID, while no-op and generic refresh stay unstamped")
    func workspaceBindingBoundary() async throws {
        let timing = UIInteractionTiming(enabled: true, uptime: { 10.05 })
        let workspace = WorkspaceStore(uiTiming: timing)
        defer { workspace.cancelFilesystemSearch() }
        let first = workspace.setFilesystemSearchTextFromEditor("SYNTHETIC-SECRET-DO-NOT-LOG")
        #expect(first.changed && first.trialID != nil)
        let noOp = workspace.setFilesystemSearchTextFromEditor("SYNTHETIC-SECRET-DO-NOT-LOG")
        #expect(!noOp.changed && noOp.trialID == nil)
        let second = workspace.setFilesystemSearchTextFromEditor("")
        #expect(second.changed && second.trialID != nil && second.trialID != first.trialID)
        _ = workspace.refreshFilesystemRows()
        #expect(timing.snapshot().trials.allSatisfy { $0.inputEventUptimeSeconds == nil })
        let encoder = JSONEncoder(), json = String(decoding: try encoder.encode(timing.snapshot()), as: UTF8.self)
        #expect(!json.contains("SYNTHETIC-SECRET"))
        workspace.cancelFilesystemSearch()
        let owners = Array(workspace.filesystemSearchJobs.values)
        for owner in owners { await owner.value }
    }
}

private enum FocusDefect: CaseIterable {
    case foreignField, foreignEditor, missingWindow, foreignWindow, foreignCurrentEditor
    case foreignResponder, foreignDelegate, notKeyWindow, inactiveApplication, disabled, notEditable, notFieldEditor
}

@MainActor
private final class InputFixture {
    let timing: UIInteractionTiming
    let observation: FilesystemSearchInputObservation
    private let field = NSObject(), editor = NSObject(), window = NSObject(), other = NSObject()

    init(enabled: Bool = true) {
        timing = UIInteractionTiming(enabled: enabled, uptime: { 10.05 })
        observation = FilesystemSearchInputObservation(timing: timing, field: field, editor: editor,
                                                      observeLifecycle: false)
    }

    func focus(_ defect: FocusDefect? = nil, markedText: Bool = false) -> FilesystemSearchInputObservation.Focus {
        let fieldID = ObjectIdentifier(field), editorID = ObjectIdentifier(editor)
        let windowID = ObjectIdentifier(window), otherID = ObjectIdentifier(other)
        return .init(field: defect == .foreignField ? otherID : fieldID,
                     editor: defect == .foreignEditor ? otherID : editorID,
                     fieldWindow: defect == .missingWindow ? nil : windowID,
                     eventWindow: defect == .foreignWindow ? otherID : windowID,
                     currentEditor: defect == .foreignCurrentEditor ? otherID : editorID,
                     firstResponder: defect == .foreignResponder ? otherID : editorID,
                     editorDelegate: defect == .foreignDelegate ? otherID : fieldID,
                     isKeyWindow: defect != .notKeyWindow, isApplicationActive: defect != .inactiveApplication,
                     isEnabled: defect != .disabled, isEditable: defect != .notEditable,
                     isFieldEditor: defect != .notFieldEditor, hasMarkedText: markedText)
    }

    static func clock(event: TimeInterval = 9.9, quartz: TimeInterval = 9.9) -> FilesystemSearchInputObservation.ClockSample {
        .init(eventUptimeSeconds: event, quartzEventUptimeSeconds: quartz,
              dispatchReceiptUptimeSeconds: 10, machBracketStartSeconds: 9.999,
              coreAnimationSampleSeconds: 10, machBracketEndSeconds: 10.001)
    }

    func begin(focus: FilesystemSearchInputObservation.Focus? = nil, supported: Bool = true) -> UInt64? {
        observation.beginDispatch(clock: Self.clock(), focus: focus ?? self.focus(), isSupportedKeyEvent: supported)
    }

    func end(_ sequence: UInt64, focus: FilesystemSearchInputObservation.Focus? = nil) {
        observation.endDispatch(sequence, focus: focus ?? self.focus(), at: 10.1)
    }

    func publishedTrial() throws -> UInt64 {
        let trial = try #require(timing.begin())
        #expect(timing.record(.rowsPublished, trialID: trial))
        #expect(timing.finish(.published, trialID: trial))
        return trial
    }

    func rejections(_ code: UIInteractionInputRejection) -> UInt64 {
        timing.snapshot().inputDiagnostics?.rejectionCounts[code.rawValue] ?? 0
    }
}
