import ForensicsCore
import SwiftUI

struct RecoveryRawHexView: View {
    @Bindable var store: RecoveryExaminationStore

    var body: some View {
        DisclosureGroup("RAW Source Hex · verified byte offsets") {
            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 10) {
                    TextField("Decimal or 0x byte offset", text: $store.rawOffsetText)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 250)
                        .accessibilityLabel("RAW image byte offset in decimal or hexadecimal")
                    Button("Read 4 KiB", action: store.readRawRange)
                        .disabled(!store.canReadRaw)
                    if store.isReadingRaw {
                        ProgressView().controlSize(.small)
                        Button("Cancel", action: store.cancel)
                    }
                    Spacer(minLength: 0)
                }
                Text("Offset is in the selected RAW file. Each read verifies its complete recorded SHA-256 before and after the bounded range; large images can take time.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let snapshot = store.rawSnapshot {
                    Text("Offset \(snapshot.offset.formatted()) · \(snapshot.bytes.count.formatted()) shown bytes · \(snapshot.byteCount.formatted()) total source bytes")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                    ScrollView([.horizontal, .vertical]) {
                        Text(verbatim: snapshot.hexText)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(minHeight: 100, maxHeight: 220)
                    .padding(9)
                    .background(.background, in: RoundedRectangle(cornerRadius: 6))
                }
                if store.isReadingRaw {
                    Text(store.statusMessage).font(.caption).foregroundStyle(.secondary)
                }
                if let error = store.errorMessage {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.top, 9)
        }
        .font(.caption)
        .controlSize(.small)
    }
}
