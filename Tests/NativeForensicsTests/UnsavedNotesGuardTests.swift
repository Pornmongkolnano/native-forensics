import AppKit
import Testing
@testable import NativeForensics

@Suite("UnsavedNotesGuardTests", .serialized)
@MainActor
struct UnsavedNotesGuardTests {
    @Test("No drafts skips confirmation, and only explicit discard permits close or Quit")
    func confirmationPolicy() {
        var prompts = 0
        let cancel: (NSAlert) -> NSApplication.ModalResponse = { _ in
            prompts += 1
            return .alertFirstButtonReturn
        }
        #expect(UnsavedNotesGuard.confirmDiscardForClose(count: 0, present: cancel))
        #expect(UnsavedNotesGuard.confirmDiscardForQuit(count: 0, present: cancel))
        #expect(prompts == 0)
        #expect(!UnsavedNotesGuard.confirmDiscardForClose(count: 2, present: cancel))
        #expect(!UnsavedNotesGuard.confirmDiscardForQuit(count: 3, present: cancel))
        #expect(prompts == 2)
        #expect(UnsavedNotesGuard.confirmDiscardForClose(count: 2, present: { _ in .alertSecondButtonReturn }))
        #expect(UnsavedNotesGuard.confirmDiscardForQuit(count: 2, present: { _ in .alertSecondButtonReturn }))
        #expect(!UnsavedNotesGuard.confirmDiscardForQuit(count: 2, present: { _ in .cancel }))
    }

    @Test("Native confirmation defaults to Cancel and describes every retained draft")
    func safeAlertDefaults() {
        let close = UnsavedNotesGuard.confirmDiscardForClose(count: 3) { alert in
            #expect(alert.alertStyle == .warning)
            #expect(alert.messageText == "Discard Unsaved Notes and Close?")
            #expect(alert.informativeText.contains("3 file drafts"))
            #expect(alert.informativeText.contains("Save Notes"))
            #expect(alert.informativeText.contains("Previously saved notes remain"))
            #expect(alert.buttons.map(\.title) == ["Cancel", "Discard Unsaved Notes and Close"])
            #expect(alert.buttons.first?.keyEquivalent == "\r")
            #expect(alert.buttons.last?.keyEquivalent.isEmpty == true)
            return .alertFirstButtonReturn
        }
        #expect(!close)
        let quit = UnsavedNotesGuard.confirmDiscardForQuit(count: 1) { alert in
            #expect(alert.messageText == "Discard Unsaved Notes and Quit?")
            #expect(alert.informativeText.contains("1 file draft has"))
            #expect(alert.buttons.last?.title == "Discard Unsaved Notes and Quit")
            return .alertFirstButtonReturn
        }
        #expect(!quit)
    }

    @Test("A Quit or close request during a confirmation fails closed without a second modal")
    func reentrantConfirmation() {
        var nestedPrompts = 0
        let allowed = UnsavedNotesGuard.confirmDiscardForClose(count: 1) { _ in
            let nested = UnsavedNotesGuard.confirmDiscardForQuit(count: 2) { _ in
                nestedPrompts += 1
                return .alertSecondButtonReturn
            }
            #expect(!nested)
            return .alertFirstButtonReturn
        }
        #expect(!allowed)
        #expect(nestedPrompts == 0)
        #expect(UnsavedNotesGuard.confirmDiscardForQuit(count: 1, present: { _ in .alertSecondButtonReturn }))
    }

    @Test("Window attachment preserves native delegate vetoes and forwards unrelated callbacks")
    func originalDelegateForwarding() throws {
        let window = makeWindow()
        defer { window.delegate = nil; window.close() }
        let original = OriginalWindowDelegate()
        window.delegate = original
        var decisions = 0
        let attachment = UnsavedNotesWindowAttachment {
            decisions += 1
            return false
        }
        attachment.attach(to: window)
        let proxy = try #require(window.delegate as? UnsavedNotesWindowDelegate)
        original.closeAllowed = false
        #expect(!proxy.windowShouldClose(window))
        #expect(original.closeRequests == 1)
        #expect(decisions == 0)
        original.closeAllowed = true
        #expect(!proxy.windowShouldClose(window))
        #expect(original.closeRequests == 2)
        #expect(decisions == 1)

        let resize = #selector(NSWindowDelegate.windowDidResize(_:))
        #expect(proxy.responds(to: resize))
        let notification = Notification(name: NSWindow.didResizeNotification, object: window)
        proxy.perform(resize, with: notification)
        #expect(original.resizeCallbacks == 1)
        #expect(!proxy.responds(to: #selector(NSWindowDelegate.windowShouldZoom(_:toFrame:))))
        attachment.attach(to: nil)
        #expect(window.delegate === original)
    }

    @Test("Native performClose preserves the window on veto and forwards the final close notification")
    func nativeCloseRequests() {
        let window = makeWindow()
        defer { window.delegate = nil; window.close() }
        let original = OriginalWindowDelegate()
        window.delegate = original
        var decisions = 0
        let attachment = UnsavedNotesWindowAttachment {
            decisions += 1
            return false
        }
        attachment.attach(to: window)
        window.performClose(nil)
        #expect(decisions == 1)
        #expect(original.closeRequests == 1)
        #expect(original.closeNotifications == 0)
        attachment.shouldClose = { decisions += 1; return true }
        attachment.attach(to: window)
        window.performClose(nil)
        #expect(decisions == 2)
        #expect(original.closeRequests == 2)
        #expect(original.closeNotifications == 1)
        attachment.attach(to: nil)
    }

    @Test("A passive attachment follows native view/window lifecycle without taking pointer input")
    func attachmentViewLifecycle() throws {
        let window = makeWindow()
        defer { window.delegate = nil; window.close() }
        let original = OriginalWindowDelegate()
        window.delegate = original
        let attachment = UnsavedNotesWindowAttachment { false }
        let view = UnsavedNotesAttachmentView(frame: .zero)
        view.windowChanged = { [weak attachment] in attachment?.attach(to: $0) }
        let contentView = try #require(window.contentView)
        contentView.addSubview(view)
        #expect(window.delegate is UnsavedNotesWindowDelegate)
        #expect(view.hitTest(.zero) == nil)
        view.removeFromSuperview()
        #expect(window.delegate === original)
    }

    @Test("Recreated attachments share one proxy, refresh policy and restore only on final detach")
    func recreationAndUpdates() throws {
        let window = makeWindow()
        defer { window.delegate = nil; window.close() }
        let original = OriginalWindowDelegate()
        window.delegate = original
        let first = UnsavedNotesWindowAttachment { false }
        let second = UnsavedNotesWindowAttachment { true }
        first.attach(to: window)
        let proxy = try #require(window.delegate as? UnsavedNotesWindowDelegate)
        for _ in 0..<5 { first.attach(to: window) }
        second.attach(to: window)
        #expect(window.delegate === proxy)
        #expect(!proxy.windowShouldClose(window))
        first.shouldClose = { true }
        first.attach(to: window)
        #expect(proxy.windowShouldClose(window))
        first.attach(to: nil)
        #expect(window.delegate === proxy)
        #expect(proxy.windowShouldClose(window))
        second.attach(to: nil)
        #expect(window.delegate === original)
    }

    @Test("Detach never overwrites a newer delegate, and an update protects a replacement")
    func laterDelegateReplacement() throws {
        let window = makeWindow()
        defer { window.delegate = nil; window.close() }
        let original = OriginalWindowDelegate()
        let replacement = OriginalWindowDelegate()
        window.delegate = original
        let attachment = UnsavedNotesWindowAttachment { false }
        attachment.attach(to: window)
        window.delegate = replacement
        attachment.attach(to: nil)
        #expect(window.delegate === replacement)
        attachment.attach(to: window)
        let oldProxy = try #require(window.delegate as? UnsavedNotesWindowDelegate)
        window.delegate = original
        attachment.attach(to: window)
        let newProxy = try #require(window.delegate as? UnsavedNotesWindowDelegate)
        #expect(newProxy !== oldProxy)
        #expect(!newProxy.windowShouldClose(window))
        attachment.attach(to: nil)
        #expect(window.delegate === original)
    }

    @Test("Moving the attachment releases the prior window and delegate without cycles")
    func weakOwnershipAndWindowMove() throws {
        let next = makeWindow()
        defer { next.delegate = nil; next.close() }
        let nextOriginal = OriginalWindowDelegate()
        next.delegate = nextOriginal
        let attachment = UnsavedNotesWindowAttachment { true }
        weak var priorWindow: NSWindow?
        weak var priorDelegate: OriginalWindowDelegate?
        weak var priorProxy: UnsavedNotesWindowDelegate?
        try autoreleasepool {
            let window = makeWindow()
            let original = OriginalWindowDelegate()
            priorWindow = window
            priorDelegate = original
            window.delegate = original
            attachment.attach(to: window)
            priorProxy = try #require(window.delegate as? UnsavedNotesWindowDelegate)
            attachment.attach(to: next)
            #expect(window.delegate === original)
            window.delegate = nil
            window.close()
        }
        #expect(priorWindow == nil)
        #expect(priorDelegate == nil)
        #expect(priorProxy == nil)
        attachment.attach(to: nil)
        #expect(next.delegate === nextOriginal)
    }

    private func makeWindow() -> NSWindow {
        _ = NSApplication.shared
        let window = NSWindow(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: true)
        window.isReleasedWhenClosed = false
        return window
    }
}

@MainActor
private final class OriginalWindowDelegate: NSObject, NSWindowDelegate {
    var closeAllowed = true
    var closeRequests = 0
    var resizeCallbacks = 0
    var closeNotifications = 0

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        closeRequests += 1
        return closeAllowed
    }

    func windowDidResize(_ notification: Notification) {
        resizeCallbacks += 1
    }

    func windowWillClose(_ notification: Notification) {
        closeNotifications += 1
    }
}
