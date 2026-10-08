import ForensicsCore
import SwiftUI

struct EFSKeyInputSheet: View {
    let store: EFSKeyInputStore
    let onClose: @MainActor () -> Void
    @State private var closing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Decrypt EFS File", systemImage: "lock.open")
                .font(.title2.weight(.semibold))
            if let context = store.context {
                Text(verbatim: context.file.path).font(.callout.weight(.semibold)).lineLimit(2).truncationMode(.middle)
                Text("EFS-marked NTFS file · allocated unnamed DATA stream")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("Select the private RSA key and matching certificate for this one extraction. Credentials are read only when the application workflow slot is available. They are not saved in the case.")
                .fixedSize(horizontal: false, vertical: true)
            credentialRow("RSA Private DER", filename: store.privateKeyFilename, limit: "PKCS#1 DER · 64 KiB maximum", role: .privateKey)
            credentialRow("Certificate DER", filename: store.certificateFilename, limit: "Matching EFS certificate · 128 KiB maximum", role: .certificate)
            Text("PFX/P12, passwords, keychain imports and network trust checks are unavailable in this operation.")
                .font(.caption).foregroundStyle(.secondary)
            Label("EFS AES-CBC has no authentication tag. The output receipt describes the bytes actually decrypted; it cannot authenticate historical plaintext.", systemImage: "info.circle")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if !store.selectionIsCurrent && store.context != nil {
                Text("The case, source or file selection changed. Close this sheet and select the encrypted file again.")
                    .font(.caption).foregroundStyle(.orange)
            }
            if let error = store.errorMessage { Text(verbatim: error).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            Text(verbatim: store.statusMessage).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let publication = store.lastPublication {
                Label(store.publicationIsCurrent ? "Output receipt retained" : "Earlier selection output receipt retained", systemImage: "checkmark.circle")
                    .font(.callout)
                Text("\(publication.receipt.byteCount.formatted()) bytes · SHA-256 \(publication.receipt.sha256)")
                    .font(.caption.monospaced()).textSelection(.enabled)
                if let history = store.historyOutcome {
                    Text(history.message).font(.caption)
                        .foregroundStyle(history.historyIsConfirmed ? Color.secondary : Color.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Divider()
            HStack {
                if store.hasActiveWork { ProgressView().controlSize(.small); Button("Cancel Operation", action: store.cancel).disabled(closing) }
                Spacer()
                Button(closing ? "Closing…" : "Close", action: close).keyboardShortcut(.cancelAction).disabled(closing)
                Button("Decrypt to New File…", action: store.beginChoosingDestination)
                    .keyboardShortcut(.defaultAction).disabled(!store.canBegin || closing)
            }
        }
        .padding(20).frame(width: 610)
        .interactiveDismissDisabled(store.hasActiveWork || closing)
        .onDisappear { Task { await store.close() } }
    }

    private func credentialRow(_ title: String, filename: String?, limit: String, role: EFSKeyFileRole) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.callout.weight(.semibold))
                Text(verbatim: filename ?? "No file selected").font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                Text(limit).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Choose…") { store.choose(role) }.disabled(!store.canSelectCredentials || closing)
                .accessibilityLabel("Choose \(title)")
        }
    }
    private func close() {
        guard !closing else { return }; closing = true
        Task { await store.close(); onClose() }
    }
}
