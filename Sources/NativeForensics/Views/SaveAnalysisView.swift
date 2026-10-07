import ForensicsCore
import SwiftUI

/// This consent concerns local retention. Sending to the provider has already
/// been independently reviewed; saving never starts another provider request.
struct SaveAnalysisView: View {
    let save: (AnalysisRetention) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var keepExactRequest = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Save Analysis to Case", systemImage: "tray.and.arrow.down")
                .font(.title2.weight(.semibold))
            Text("Save the question, AI answer, file metadata and provenance locally in this case. They may contain private information. The record describes this completed request; it does not verify the AI conclusions or current source bytes.")
                .font(.callout)
            Toggle("Keep the exact reviewed request and attached excerpt", isOn: $keepExactRequest)
                .toggleStyle(.checkbox)
            Text(keepExactRequest
                ? "Full retention stores the exact request bytes, including any evidence text you sent."
                : "Digest only stores the request hash without its prompt or excerpt. The saved question and answer can still quote evidence. The original request cannot be reconstructed from its hash.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save Locally") {
                    save(keepExactRequest ? .full : .digestOnly)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 510)
    }
}
