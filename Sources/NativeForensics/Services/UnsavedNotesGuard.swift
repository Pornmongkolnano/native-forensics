import AppKit
import SwiftUI

/// A close decision only. The workspace remains the owner of all note drafts;
/// this guard neither saves them nor changes a previously saved revision.
@MainActor
enum UnsavedNotesGuard {
    private static var isPresentingConfirmation = false
    static func confirmDiscardForClose(
        count: Int,
        present: (NSAlert) -> NSApplication.ModalResponse = { $0.runModal() }
    ) -> Bool {
        confirmDiscard(count: count, action: .close, present: present)
    }

    static func confirmDiscardForQuit(
        count: Int,
        present: (NSAlert) -> NSApplication.ModalResponse = { $0.runModal() }
    ) -> Bool {
        confirmDiscard(count: count, action: .quit, present: present)
    }

    private enum Action {
        case close, quit

        var verb: String { self == .close ? "Close" : "Quit" }
    }

    private static func confirmDiscard(
        count: Int,
        action: Action,
        present: (NSAlert) -> NSApplication.ModalResponse
    ) -> Bool {
        guard count > 0 else { return true }
        guard !isPresentingConfirmation else { return false }
        isPresentingConfirmation = true
        defer { isPresentingConfirmation = false }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Discard Unsaved Notes and \(action.verb)?"
        let drafts = count == 1 ? "1 file draft has" : "\(count) file drafts have"
        alert.informativeText = "\(drafts) unsaved note, bookmark, tag or review changes. Choose Cancel and Save Notes to keep these changes. Previously saved notes remain in the case."
        let cancel = alert.addButton(withTitle: "Cancel")
        cancel.keyEquivalent = "\r"
        let discard = alert.addButton(withTitle: "Discard Unsaved Notes and \(action.verb)")
        discard.keyEquivalent = ""
        // Any unexpected response also preserves the drafts.
        return present(alert) == .alertSecondButtonReturn
    }
}

/// SwiftUI does not expose a synchronous veto for the workbench's native close
/// button or Command-W. A zero-sized attachment installs one forwarding delegate
/// for its own window while SwiftUI still owns the close policy and draft state.
struct UnsavedNotesWindowGuard: NSViewRepresentable {
    var shouldClose: @MainActor () -> Bool

    func makeCoordinator() -> UnsavedNotesWindowAttachment {
        UnsavedNotesWindowAttachment(shouldClose: shouldClose)
    }

    func makeNSView(context: Context) -> UnsavedNotesAttachmentView {
        let view = UnsavedNotesAttachmentView(frame: .zero)
        view.windowChanged = { [weak coordinator = context.coordinator] window in
            coordinator?.attach(to: window)
        }
        return view
    }

    func updateNSView(_ view: UnsavedNotesAttachmentView, context: Context) {
        context.coordinator.shouldClose = shouldClose
        context.coordinator.attach(to: view.window)
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: UnsavedNotesAttachmentView, context: Context) -> CGSize? {
        .zero
    }

    static func dismantleNSView(_ view: UnsavedNotesAttachmentView, coordinator: UnsavedNotesWindowAttachment) {
        view.windowChanged = nil
        coordinator.attach(to: nil)
    }
}

@MainActor
final class UnsavedNotesAttachmentView: NSView {
    var windowChanged: ((NSWindow?) -> Void)?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        windowChanged?(window)
    }

    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}

/// Coordinators own the proxy because NSWindow.delegate is weak. The proxy
/// references both the window and its original delegate weakly, so detaching or
/// releasing a window does not create a retain cycle through SwiftUI's delegate.
@MainActor
final class UnsavedNotesWindowAttachment {
    var shouldClose: @MainActor () -> Bool
    private let ownerID = UUID()
    private weak var window: NSWindow?
    private var proxy: UnsavedNotesWindowDelegate?

    init(shouldClose: @escaping @MainActor () -> Bool) {
        self.shouldClose = shouldClose
    }

    deinit {
        let releasedProxy = proxy
        let releasedOwner = ownerID
        // The normal representable teardown is synchronous. This fallback also
        // releases a registration if its coordinator is destroyed directly.
        Task { @MainActor in releasedProxy?.unregister(releasedOwner) }
    }

    func attach(to nextWindow: NSWindow?) {
        if let nextWindow, window === nextWindow, let proxy,
           nextWindow.delegate === proxy {
            proxy.register(ownerID, shouldClose: shouldClose)
            return
        }
        proxy?.unregister(ownerID)
        proxy = nil
        window = nil
        guard let nextWindow else { return }

        // Recreated or overlapping representables share the installed proxy;
        // they never wrap it as the original delegate or restore a stale proxy.
        let nextProxy: UnsavedNotesWindowDelegate
        if let installed = nextWindow.delegate as? UnsavedNotesWindowDelegate {
            nextProxy = installed
        } else {
            nextProxy = UnsavedNotesWindowDelegate(window: nextWindow, originalDelegate: nextWindow.delegate)
        }
        nextProxy.register(ownerID, shouldClose: shouldClose)
        proxy = nextProxy
        window = nextWindow
        if nextWindow.delegate !== nextProxy { nextWindow.delegate = nextProxy }
    }
}

@MainActor
final class UnsavedNotesWindowDelegate: NSObject, NSWindowDelegate {
    private weak var window: NSWindow?
    // NSObject's forwarding hooks are nonisolated. This weak Objective-C
    // identity is initialized on MainActor and only read after an explicit
    // MainActor assertion in those hooks; the delegate is never sent to a task.
    nonisolated(unsafe) private weak var originalDelegate: (any NSWindowDelegate)?
    private var owners: [(id: UUID, shouldClose: @MainActor () -> Bool)] = []

    init(window: NSWindow, originalDelegate: (any NSWindowDelegate)?) {
        self.window = window
        self.originalDelegate = originalDelegate
        super.init()
    }

    func register(_ id: UUID, shouldClose: @escaping @MainActor () -> Bool) {
        if let index = owners.firstIndex(where: { $0.id == id }) {
            owners[index].shouldClose = shouldClose
        } else {
            owners.append((id, shouldClose))
        }
    }

    func unregister(_ id: UUID) {
        owners.removeAll(where: { $0.id == id })
        if owners.isEmpty, let window, window.delegate === self {
            window.delegate = originalDelegate
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        // Preserve an existing delegate veto before requesting explicit discard.
        guard originalDelegate?.windowShouldClose?(sender) ?? true else { return false }
        return owners.allSatisfy { $0.shouldClose() }
    }

    nonisolated override func responds(to selector: Selector!) -> Bool {
        if super.responds(to: selector) { return true }
        // AppKit queries window delegates on its main thread. Selector forwarding
        // preserves all optional callbacks implemented by SwiftUI's delegate.
        return MainActor.assumeIsolated { originalDelegate?.responds(to: selector) ?? false }
    }

    nonisolated override func forwardingTarget(for selector: Selector!) -> Any? {
        MainActor.preconditionIsolated()
        if let originalDelegate, originalDelegate.responds(to: selector) { return originalDelegate }
        return super.forwardingTarget(for: selector)
    }
}
