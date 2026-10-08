import AppKit
import ForensicsCore
import QuartzCore
import SwiftUI

/// SwiftUI owns the search value; AppKit supplies an exact native edit boundary.
/// Normal and diagnostic launches use the same control, but only opt-in launches
/// allocate the observer. The observer/trace never receives the search value.
struct FilesystemSearchField: NSViewRepresentable {
    var value: String
    let timing: UIInteractionTiming
    var changed: @MainActor (String) -> FilesystemSearchBindingReceipt
    var exited: @MainActor () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(timing: timing, changed: changed, exited: exited)
    }

    func makeNSView(context: Context) -> SearchField {
        let field = SearchField(frame: .zero)
        field.cell = SearchCell(textCell: "")
        field.isEditable = true
        field.isSelectable = true
        field.isBezeled = true
        field.isBordered = true
        field.bezelStyle = .roundedBezel
        field.usesSingleLineMode = true
        field.font = .systemFont(ofSize: NSFont.systemFontSize)
        field.placeholderString = "Find file path"
        field.setAccessibilityLabel("Find file path")
        field.setAccessibilityIdentifier("filesystem-path-search")
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.delegate = context.coordinator
        context.coordinator.attach(field)
        context.coordinator.setModelValue(value, on: field)
        return field
    }

    func updateNSView(_ field: SearchField, context: Context) {
        context.coordinator.changed = changed
        context.coordinator.exited = exited
        context.coordinator.updateTiming(timing, field: field)
        context.coordinator.setModelValue(value, on: field)
    }

    static func dismantleNSView(_ field: SearchField, coordinator: Coordinator) {
        coordinator.detach(field)
    }

    @MainActor
    final class Coordinator: NSObject, NSTextFieldDelegate {
        var changed: @MainActor (String) -> FilesystemSearchBindingReceipt
        var exited: @MainActor () -> Void
        private var timing: UIInteractionTiming
        private weak var field: SearchField?
        private var observation: FilesystemSearchInputObservation?
        private var modelUpdateDepth = 0

        init(timing: UIInteractionTiming,
             changed: @escaping @MainActor (String) -> FilesystemSearchBindingReceipt,
             exited: @escaping @MainActor () -> Void) {
            self.timing = timing
            self.changed = changed
            self.exited = exited
        }

        func attach(_ field: SearchField) {
            self.field = field
            guard let cell = field.cell as? SearchCell else { return }
            cell.editor.owner = field
            if timing.isEnabled {
                observation = FilesystemSearchInputObservation(timing: timing, field: field, editor: cell.editor)
            }
            cell.editor.observation = observation
        }

        func updateTiming(_ timing: UIInteractionTiming, field: SearchField) {
            guard timing !== self.timing else { return }
            observation?.invalidate()
            self.timing = timing
            observation = nil
            attach(field)
        }

        func setModelValue(_ value: String, on field: SearchField) {
            guard field.stringValue != value else { return }
            modelUpdateDepth += 1
            defer { modelUpdateDepth -= 1 }
            // Equality avoids changing the selection/marked text on ordinary
            // SwiftUI updates. Programmatic clears update the active editor too.
            field.stringValue = value
            if let editor = field.currentEditor(), editor.string != value { editor.string = value }
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field, notification.object as AnyObject? === field,
                  let editor = field.currentEditor() as? SearchEditor else { return }
            let notificationEditor = notification.userInfo?["NSFieldEditor"] as AnyObject?
            let binding = changed(field.stringValue)
            observation?.noteBinding(binding, notificationMatchesOwner: notificationEditor === editor,
                                     focus: editor.focus(eventWindow: field.window),
                                     isProgrammaticUpdate: modelUpdateDepth > 0 || !editor.isNativeMutationInDispatch)
        }

        func controlTextDidEndEditing(_ notification: Notification) {
            guard notification.object as AnyObject? === field else { return }
            observation?.invalidate()
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
            guard control === field else { return false }
            if commandSelector == #selector(NSResponder.cancelOperation(_:)) {
                observation?.invalidate(.unsupported)
                exited()
                return true
            }
            // AppKit retains ordinary Tab, Shift-Tab and editing commands.
            return false
        }

        func detach(_ field: SearchField) {
            observation?.invalidate()
            observation = nil
            (field.cell as? SearchCell)?.editor.observation = nil
            (field.cell as? SearchCell)?.editor.owner = nil
            field.delegate = nil
            self.field = nil
        }
    }

    @MainActor
    final class SearchField: NSTextField {}

    @MainActor
    final class SearchCell: NSTextFieldCell {
        let editor = SearchEditor(frame: .zero)

        override func fieldEditor(for controlView: NSView) -> NSTextView? {
            guard let field = controlView as? SearchField, field.cell === self else { return nil }
            editor.isFieldEditor = true
            editor.owner = field
            return editor
        }
    }

    @MainActor
    final class SearchEditor: NSTextView {
        weak var owner: SearchField?
        weak var observation: FilesystemSearchInputObservation?
        private var dispatchDepth = 0
        private var nativeMutationDepth = 0

        var isNativeMutationInDispatch: Bool { dispatchDepth == 1 && nativeMutationDepth == 1 }

        override func keyDown(with event: NSEvent) {
            guard let observation else { super.keyDown(with: event); return }
            let priorDepth = dispatchDepth
            dispatchDepth = min(2, dispatchDepth + 1)
            let sequence = observation.beginDispatch(
                clock: FilesystemSearchInputObservation.ClockSample.capture(event),
                focus: focus(eventWindow: event.window),
                isSupportedKeyEvent: event.type == .keyDown && !event.isARepeat
                    && event.modifierFlags.intersection([.command, .control, .option]).isEmpty)
            defer {
                observation.endDispatch(sequence, focus: focus(eventWindow: event.window), at: CACurrentMediaTime())
                dispatchDepth = priorDepth
            }
            super.keyDown(with: event)
        }

        /// These are the documented return paths from the native input context.
        /// A bare AX/string/text-storage notification has no eligible mutation
        /// scope. Payloads and selectors are forwarded, never recorded.
        override func insertText(_ insertString: Any, replacementRange: NSRange) {
            let priorDepth = nativeMutationDepth
            nativeMutationDepth = min(2, nativeMutationDepth + 1)
            if nativeMutationDepth > 1 { observation?.rejectCurrentDispatch(.ambiguous) }
            defer { nativeMutationDepth = priorDepth }
            super.insertText(insertString, replacementRange: replacementRange)
        }

        override func doCommand(by selector: Selector) {
            let isSimpleDelete = selector == #selector(NSResponder.deleteBackward(_:))
                || selector == #selector(NSResponder.deleteForward(_:))
            if !isSimpleDelete { observation?.rejectCurrentDispatch() }
            let priorDepth = nativeMutationDepth
            nativeMutationDepth = min(2, nativeMutationDepth + 1)
            if nativeMutationDepth > 1 { observation?.rejectCurrentDispatch(.ambiguous) }
            defer { nativeMutationDepth = priorDepth }
            super.doCommand(by: selector)
        }

        override var string: String {
            get { super.string }
            set {
                observation?.rejectCurrentDispatch()
                super.string = newValue
            }
        }

        override func paste(_ sender: Any?) {
            observation?.rejectCurrentDispatch()
            super.paste(sender)
        }

        override func pasteAsPlainText(_ sender: Any?) {
            observation?.rejectCurrentDispatch()
            super.pasteAsPlainText(sender)
        }

        override func pasteAsRichText(_ sender: Any?) {
            observation?.rejectCurrentDispatch()
            super.pasteAsRichText(sender)
        }

        override func setMarkedText(_ string: Any, selectedRange: NSRange, replacementRange: NSRange) {
            observation?.rejectCurrentDispatch()
            super.setMarkedText(string, selectedRange: selectedRange, replacementRange: replacementRange)
        }

        override func unmarkText() {
            if hasMarkedText() { observation?.rejectCurrentDispatch() }
            super.unmarkText()
        }

        func focus(eventWindow: NSWindow?) -> FilesystemSearchInputObservation.Focus {
            let fieldWindow = owner?.window
            let currentEditor = owner?.currentEditor()
            let firstResponder = fieldWindow?.firstResponder
            return FilesystemSearchInputObservation.Focus(
                field: owner.map { ObjectIdentifier($0) } ?? ObjectIdentifier(self), editor: ObjectIdentifier(self),
                fieldWindow: fieldWindow.map { ObjectIdentifier($0) }, eventWindow: eventWindow.map { ObjectIdentifier($0) },
                currentEditor: currentEditor.map { ObjectIdentifier($0) },
                firstResponder: firstResponder.map { ObjectIdentifier($0) },
                editorDelegate: delegate.map { ObjectIdentifier($0 as AnyObject) },
                isKeyWindow: fieldWindow?.isKeyWindow ?? false, isApplicationActive: NSApp.isActive,
                isEnabled: owner?.isEnabled ?? false, isEditable: owner?.isEditable ?? false,
                isFieldEditor: isFieldEditor, hasMarkedText: hasMarkedText())
        }
    }
}
