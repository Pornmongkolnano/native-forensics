import AppKit
import Darwin
import ForensicsCore
import QuartzCore

/// The workspace owns the search value. Its receipt contains only mutation state
/// and the trial produced synchronously by that particular binding assignment.
struct FilesystemSearchBindingReceipt {
    let changed: Bool
    let trialID: UInt64?
}

/// One concrete control/editor and one synchronous key dispatch. Native object
/// identities stay in memory; the trace receives only numeric clocks/counters.
@MainActor
final class FilesystemSearchInputObservation {
    struct Focus {
        let field: ObjectIdentifier
        let editor: ObjectIdentifier
        let fieldWindow: ObjectIdentifier?
        let eventWindow: ObjectIdentifier?
        let currentEditor: ObjectIdentifier?
        let firstResponder: ObjectIdentifier?
        let editorDelegate: ObjectIdentifier?
        let isKeyWindow: Bool
        let isApplicationActive: Bool
        let isEnabled: Bool
        let isEditable: Bool
        let isFieldEditor: Bool
        let hasMarkedText: Bool
    }

    struct ClockSample {
        let eventUptimeSeconds: TimeInterval
        let quartzEventUptimeSeconds: TimeInterval
        let dispatchReceiptUptimeSeconds: TimeInterval
        let machBracketStartSeconds: TimeInterval
        let coreAnimationSampleSeconds: TimeInterval
        let machBracketEndSeconds: TimeInterval

        /// Event contents and native event objects never leave this call.
        static func capture(_ event: NSEvent) -> ClockSample? {
            guard let quartzEvent = event.cgEvent else { return nil }
            var timebase = mach_timebase_info_data_t()
            guard mach_timebase_info(&timebase) == KERN_SUCCESS,
                  timebase.numer > 0, timebase.denom > 0 else { return nil }
            let before = mach_absolute_time()
            let sample = CACurrentMediaTime()
            let after = mach_absolute_time()
            func seconds(_ ticks: UInt64) -> Double {
                Double(ticks) * Double(timebase.numer) / Double(timebase.denom) / 1_000_000_000
            }
            return ClockSample(eventUptimeSeconds: event.timestamp,
                quartzEventUptimeSeconds: Double(quartzEvent.timestamp) / 1_000_000_000,
                dispatchReceiptUptimeSeconds: sample, machBracketStartSeconds: seconds(before),
                coreAnimationSampleSeconds: sample, machBracketEndSeconds: seconds(after))
        }
    }

    private struct Dispatch {
        let sequence: UInt64
        let window: ObjectIdentifier?
        let lifecycleGeneration: UInt64
        let clock: ClockSample?
        var rejection: UIInteractionInputRejection?
        var notificationCount = 0
        var trialID: UInt64?
    }

    private let timing: UIInteractionTiming
    private let field: ObjectIdentifier
    private let editor: ObjectIdentifier
    private var active: Dispatch?
    private var lifecycleGeneration: UInt64 = 0
    private var lifecycleRegistration: LifecycleRegistration?

    init(timing: UIInteractionTiming, field: AnyObject, editor: AnyObject,
         observeLifecycle: Bool = true) {
        self.timing = timing
        self.field = ObjectIdentifier(field)
        self.editor = ObjectIdentifier(editor)
        guard timing.isEnabled, observeLifecycle else { return }
        let center = NSWorkspace.shared.notificationCenter
        let tokens = [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification].map { name in
            center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.invalidate(.suspended) }
            }
        }
        lifecycleRegistration = LifecycleRegistration(center: center, tokens: tokens)
    }

    func beginDispatch(clock: ClockSample?, focus: Focus, isSupportedKeyEvent: Bool) -> UInt64? {
        guard timing.isEnabled, let sequence = timing.reserveInputEventSequence() else { return nil }
        guard active == nil else {
            active?.rejection = .ambiguous
            timing.recordInputRejection(.ambiguous)
            return nil
        }
        let rejection: UIInteractionInputRejection?
        if !matches(focus) { rejection = .notFocused }
        else if !isSupportedKeyEvent || focus.hasMarkedText { rejection = .unsupported }
        else if clock == nil { rejection = .invalidClock }
        else { rejection = nil }
        active = Dispatch(sequence: sequence, window: focus.fieldWindow,
                          lifecycleGeneration: lifecycleGeneration, clock: clock, rejection: rejection)
        return sequence
    }

    /// Runs after the normal synchronous setter. A notification outside this
    /// dispatch is binding-only, including AX, paste and programmatic mutations.
    func noteBinding(_ binding: FilesystemSearchBindingReceipt,
                     notificationMatchesOwner: Bool, focus: Focus, isProgrammaticUpdate: Bool = false) {
        guard timing.isEnabled else { return }
        guard var dispatch = active else {
            timing.recordInputRejection(.unsupported)
            return
        }
        dispatch.notificationCount = min(2, dispatch.notificationCount + 1)
        if dispatch.notificationCount > 1 { dispatch.rejection = .ambiguous }
        else if dispatch.rejection == nil {
            if !notificationMatchesOwner || !matches(focus)
                || focus.fieldWindow != dispatch.window { dispatch.rejection = .notFocused }
            else if isProgrammaticUpdate || focus.hasMarkedText { dispatch.rejection = .unsupported }
            else if !binding.changed { dispatch.rejection = .noChange }
            else if binding.trialID == nil { dispatch.rejection = .missingTrial }
        }
        if dispatch.notificationCount == 1 { dispatch.trialID = binding.trialID }
        active = dispatch
    }

    /// Attach after super.keyDown returns. Multiple notifications therefore
    /// cannot leave an incorrectly stamped first trial behind. Stage clocks and
    /// all ordinary workspace updates have already happened and stay unchanged.
    func endDispatch(_ sequence: UInt64?, focus: Focus, at end: TimeInterval) {
        guard let sequence, let dispatch = active, dispatch.sequence == sequence else { return }
        active = nil
        let rejection: UIInteractionInputRejection?
        if let pending = dispatch.rejection {
            rejection = pending
        } else if dispatch.lifecycleGeneration != lifecycleGeneration {
            rejection = .suspended
        } else if !matches(focus) || focus.fieldWindow != dispatch.window {
            rejection = .notFocused
        } else if focus.hasMarkedText {
            rejection = .unsupported
        } else if dispatch.notificationCount == 0 {
            rejection = .noChange
        } else {
            rejection = nil
        }
        if let rejection { timing.recordInputRejection(rejection); return }
        guard dispatch.notificationCount == 1, let trialID = dispatch.trialID,
              let sample = dispatch.clock else {
            timing.recordInputRejection(.ambiguous)
            return
        }
        let receipt = UIInteractionInputReceipt(sequence: sequence,
            eventUptimeSeconds: sample.eventUptimeSeconds,
            quartzEventUptimeSeconds: sample.quartzEventUptimeSeconds,
            dispatchReceiptUptimeSeconds: sample.dispatchReceiptUptimeSeconds,
            dispatchEndUptimeSeconds: end, machBracketStartSeconds: sample.machBracketStartSeconds,
            coreAnimationSampleSeconds: sample.coreAnimationSampleSeconds,
            machBracketEndSeconds: sample.machBracketEndSeconds)
        timing.associateFilesystemInputEvent(receipt, trialID: trialID)
    }

    /// Sleep/wake is reported even without a pending dispatch. Every subsequent
    /// dispatch must provide a fresh NSEvent/Quartz/Mach/CA clock sample.
    func invalidate(_ reason: UIInteractionInputRejection = .notFocused) {
        guard timing.isEnabled else { return }
        if lifecycleGeneration != UInt64.max { lifecycleGeneration += 1 }
        active = nil
        timing.recordInputRejection(reason)
    }

    /// Latches an unsupported/native-ambiguous operation without suppressing its
    /// normal text behavior. A transient composition or custom paste command
    /// cannot become eligible again when marked text disappears before callback.
    func rejectCurrentDispatch(_ reason: UIInteractionInputRejection = .unsupported) {
        guard active != nil else { return }
        if reason == .ambiguous || active?.rejection == nil { active?.rejection = reason }
    }

    private func matches(_ focus: Focus) -> Bool {
        focus.field == field && focus.editor == editor && focus.fieldWindow != nil
            && focus.eventWindow == focus.fieldWindow && focus.currentEditor == editor
            && focus.firstResponder == editor && focus.editorDelegate == field
            && focus.isKeyWindow && focus.isApplicationActive && focus.isEnabled
            && focus.isEditable && focus.isFieldEditor
    }
}

/// Immutable owned registrations can be removed on their release thread;
/// NotificationCenter removal does not reach into AppKit window state.
private final class LifecycleRegistration: @unchecked Sendable {
    private let center: NotificationCenter
    private let tokens: [NSObjectProtocol]

    init(center: NotificationCenter, tokens: [NSObjectProtocol]) {
        self.center = center
        self.tokens = tokens
    }

    deinit { for token in tokens { center.removeObserver(token) } }
}
