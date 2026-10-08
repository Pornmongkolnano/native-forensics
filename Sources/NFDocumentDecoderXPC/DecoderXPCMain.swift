import Darwin
import Foundation
import ForensicsCore
import NFDecoderIPC
import Security

@main
enum DecoderXPCMain {
    static func main() {
        guard let task = SecTaskCreateFromSelf(nil),
              let sandbox = SecTaskCopyValueForEntitlement(task, "com.apple.security.app-sandbox" as CFString, nil),
              CFGetTypeID(sandbox) == CFBooleanGetTypeID(), (sandbox as? Bool) == true else { Darwin._exit(78) }
        var core = rlimit(rlim_cur: 0, rlim_max: 0)
        guard Darwin.setrlimit(RLIMIT_CORE, &core) == 0 else { Darwin._exit(78) }
        // CPU deadlines apply to each fresh worker, never cumulatively to this
        // persistent broker. The broker parses only bounded control metadata.
        let delegate = DecoderXPCListenerDelegate()
        let listener = NSXPCListener.service()
        listener.delegate = delegate
        withExtendedLifetime(delegate) {
            listener.resume()
            dispatchMain()
        }
    }
}

private final class DecoderXPCListenerDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == Darwin.geteuid(),
              let session = try? DocumentXPCBrokerSession(verifiedEmbeddedBroker: true) else { return false }
        connection.setCodeSigningRequirement("identifier \"io.github.pornmongkolnano.nativeforensics\"")
        connection.exportedInterface = NSXPCInterface(with: NFDocumentDecoderXPC.self)
        connection.exportedObject = session
        connection.invalidationHandler = { session.invalidate() }
        connection.interruptionHandler = { session.invalidate() }
        connection.resume()
        return true
    }
}
