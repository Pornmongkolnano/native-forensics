import ForensicsCore
import SwiftUI

struct OpticalInspectorView: View {
    let workspace: WorkspaceStore
    @State private var pane: OpticalInspectorPane = .properties

    private enum OpticalInspectorPane: String, CaseIterable {
        case properties = "Properties"
        case preview = "Preview"
        case provenance = "Provenance"
    }

    private var store: OpticalWorkspaceStore { workspace.optical }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "opticaldisc")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(store.selectedEntry?.name ?? "Optical Inspector")
                            .font(.headline)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        Text(store.selectedEntry.map { OpticalViewFormatting.state($0.state) } ?? "Recorded UDF files and linked snapshots")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Picker("Optical inspector information", selection: $pane) {
                    ForEach(OpticalInspectorPane.allCases, id: \.self) { pane in
                        Text(pane.rawValue).tag(pane)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityLabel("Optical inspector information")
            }
            .padding(16)
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    if pane == .provenance {
                        if let result = store.result {
                            OpticalProvenanceView(result: result)
                        } else {
                            Text("Inspect a supported RAW optical image to record UDF provenance and linked snapshots.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    } else if let entry = store.selectedEntry {
                        if pane == .properties {
                            OpticalEntryPropertiesView(entry: entry, result: store.result, store: store)
                        } else {
                            OpticalDocumentPreviewView(entry: entry, store: store)
                        }
                    } else {
                        Text("Select a recorded UDF file to inspect its original path, metadata, raw timestamps and supported content.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onChange(of: store.result?.sourceEvidenceID) { _, _ in pane = .properties }
        .onChange(of: store.analysis?.sourceSHA256) { _, hash in
            if hash != nil { pane = .preview }
        }
    }
}

private struct OpticalEntryPropertiesView: View {
    let entry: UDFFileEntry
    let result: UDFInspectionResult?
    let store: OpticalWorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            OpticalInspectorField(label: "Recorded Original Path", value: entry.originalPath)
            OpticalInspectorField(label: "State", value: OpticalViewFormatting.state(entry.state))
            Text(stateExplanation)
                .font(.caption)
                .foregroundStyle(entry.state == .current ? Color.secondary : Color.orange)
            OpticalInspectorField(label: "Exact Size", value: "\(entry.byteCount.formatted()) bytes")
            OpticalInspectorField(label: "Filename Extension Hint", value: OpticalViewFormatting.extensionHint(entry))
            Text("The extension is a filename hint. MIME and readable content are checked separately by Preview.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Text("File SHA-256").font(.headline)
                Spacer(minLength: 8)
                Button(action: store.copySelectedHash) { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .help("Copy optical file SHA-256")
                    .accessibilityLabel("Copy optical file SHA-256")
            }
            OpticalInspectorField(label: "Scope · file payload bytes", value: entry.sha256, monospaced: true)
            Button(action: store.previewSelected) {
                Label("Verify and Preview", systemImage: "doc.text.viewfinder")
                    .frame(maxWidth: .infinity)
            }
            .disabled(!store.canPreview)
            Button(action: store.exportSelected) {
                Label("Export to New File…", systemImage: "square.and.arrow.up")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!store.canExport)
            if let receipt = store.lastExport,
               receipt.entryID == entry.id, receipt.jobID == result?.jobID {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Verified Export Receipt", systemImage: "doc.badge.checkmark")
                            .font(.headline)
                        OpticalInspectorField(label: "Output Path", value: receipt.destinationPath)
                        OpticalInspectorField(label: "Exported Bytes", value: "\(receipt.byteCount.formatted()) bytes")
                        OpticalInspectorField(label: "SHA-256 · exported file bytes", value: receipt.sha256, monospaced: true)
                        OpticalInspectorField(label: "Exported At", value: OpticalViewFormatting.utc(receipt.exportedAt))
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            OpticalFileMetadataView(entry: entry)
            OpticalEntryTimestampsView(timestamps: entry.timestamps)
            OpticalDeletedAncestorView(proofs: entry.deletedAncestorProof, childFlags: entry.fidCharacteristics)
            OpticalSourceExtentsView(extents: entry.sourceExtents)
            DisclosureGroup("Recorded Snapshot Membership · \(entry.snapshotIDs.count.formatted())") {
                VStack(alignment: .leading, spacing: 7) {
                    ForEach(Array(entry.snapshotIDs.enumerated()), id: \.offset) { _, id in
                        Text(verbatim: id + (id == result?.latestSnapshotID ? " · latest" : ""))
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                .padding(.top, 8)
            }
            .font(.caption)
            if !entry.historicalPaths.isEmpty {
                DisclosureGroup("Other Recorded Namespace Paths · \(entry.historicalPaths.count.formatted())") {
                    VStack(alignment: .leading, spacing: 7) {
                        ForEach(Array(entry.historicalPaths.enumerated()), id: \.offset) { _, path in
                            Text(verbatim: path)
                                .font(.caption)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.top, 8)
                }
                .font(.caption)
            }
        }
    }

    private var stateExplanation: String {
        switch entry.state {
        case .current:
            "This file is recorded in the latest inspected namespace. Snapshot membership can include earlier states."
        case .historical:
            "This file is retained from a linked historical snapshot. Historical presence alone is not a deleted-child FID flag."
        case .historicalDeletedAncestor:
            "This historical file is beneath a directory marked deleted in the latest namespace. The child's own FID may remain undeleted; inspect the ancestor proof below."
        case .fidDeleted:
            "This file's recorded FID has its deleted bit set. Readable exported bytes are checked separately."
        }
    }
}

private struct OpticalFileMetadataView: View {
    let entry: UDFFileEntry

    var body: some View {
        DisclosureGroup("Recorded FID and ICB Metadata") {
            VStack(alignment: .leading, spacing: 10) {
                OpticalInspectorField(label: "Child FID Characteristics", value: String(format: "0x%02X", entry.fidCharacteristics), monospaced: true)
                OpticalInspectorField(label: "Child FID Deleted Bit (0x04)", value: entry.fidCharacteristics & 0x04 != 0 ? "Set" : "Not set")
                OpticalInspectorField(label: "FID RAW Source Offset", value: "\(entry.fidSourceOffset.formatted()) bytes")
                OpticalInspectorField(label: "ICB Logical Block", value: entry.icb.logicalBlock.formatted())
                OpticalInspectorField(label: "Partition Reference", value: entry.icb.partitionReference.formatted())
                OpticalInspectorField(label: "ICB RAW Source Offset", value: "\(entry.icb.sourceOffset.formatted()) bytes")
                OpticalInspectorField(label: "Descriptor Tag Identifier", value: entry.icb.tagIdentifier.formatted())
                Text("Logical block identifiers and absolute source byte offsets are separate address scopes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 8)
        }
        .font(.caption)
    }
}

private struct OpticalEntryTimestampsView: View {
    let timestamps: UDFEntryTimestamps

    var body: some View {
        DisclosureGroup("Recorded UDF Timestamps") {
            VStack(alignment: .leading, spacing: 12) {
                if let creation = timestamps.creation {
                    OpticalTimestampView(label: "Created", timestamp: creation)
                } else {
                    OpticalInspectorField(label: "Created", value: "Not recorded in this file entry")
                }
                OpticalTimestampView(label: "Modified", timestamp: timestamps.modification)
                OpticalTimestampView(label: "Accessed", timestamp: timestamps.access)
                OpticalTimestampView(label: "Attributes Changed", timestamp: timestamps.attribute)
                Text("UTC presentation uses the recorded UDF timezone. Unspecified timestamps stay unzoned. Exact raw bytes and microsecond fields remain below each value.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 8)
        }
        .font(.caption)
    }
}

private struct OpticalTimestampView: View {
    let label: String
    let timestamp: UDFTimestamp

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(timestamp.utcDate.map(OpticalViewFormatting.utc) ?? "Unspecified / unzoned · no UTC instant established")
                .font(.callout)
                .textSelection(.enabled)
            Text("Type \(timestamp.type) · zone \(timestamp.timezoneMinutes.map { "\($0) minutes" } ?? "unspecified") · microseconds \(timestamp.microsecond)")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            Text("RAW offset \(timestamp.sourceOffset.formatted()) · \(timestamp.rawHex)")
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct OpticalDeletedAncestorView: View {
    let proofs: [UDFDeletedAncestorProof]
    let childFlags: UInt8

    var body: some View {
        if !proofs.isEmpty {
            DisclosureGroup("Deleted Ancestor Metadata Proof · \(proofs.count.formatted())") {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Ancestor deletion is recorded separately from the child's FID. Child flags: \(String(format: "0x%02X", childFlags)).")
                        .font(.caption)
                        .foregroundStyle(.orange)
                    ForEach(Array(proofs.enumerated()), id: \.offset) { _, proof in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 9) {
                                OpticalInspectorField(label: "Deleted Directory Path", value: proof.originalPath)
                                OpticalInspectorField(label: "Latest Snapshot", value: proof.latestSnapshotID, monospaced: true)
                                OpticalInspectorField(label: "Ancestor FID Characteristics", value: String(format: "0x%02X", proof.fidCharacteristics), monospaced: true)
                                Text("Directory bit (0x02): \(proof.fidCharacteristics & 0x02 != 0 ? "set" : "not set") · Deleted bit (0x04): \(proof.fidCharacteristics & 0x04 != 0 ? "set" : "not set")")
                                    .font(.caption)
                                OpticalInspectorField(label: "Null ICB", value: proof.nullICB ? "Yes" : "No")
                                OpticalInspectorField(label: "Ancestor FID RAW Offset", value: "\(proof.fidSourceOffset.formatted()) bytes")
                                OpticalInspectorField(label: "Raw Encoded Name", value: proof.rawNameHex, monospaced: true)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .padding(.top, 8)
            }
            .font(.caption)
        }
    }
}

private struct OpticalSourceExtentsView: View {
    let extents: [UDFSourceExtent]
    @State private var page = 0
    private let pageSize = 32

    private var lastPage: Int { max(0, (extents.count - 1) / pageSize) }
    private var displayedPage: Int { min(max(0, page), lastPage) }
    private var visibleRange: Range<Int> {
        let start = displayedPage * pageSize
        return start..<min(start + pageSize, extents.count)
    }

    var body: some View {
        DisclosureGroup("Recorded RAW Source Extents · \(extents.count.formatted())") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Absolute byte ranges refer to the original selected RAW image, including inline file allocations. Export verifies the source and assembled file bytes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ForEach(visibleRange, id: \.self) { index in
                    let extent = extents[index]
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Extent \(index + 1) · \(extent.allocation)").foregroundStyle(.secondary)
                        Text("RAW offset: \(extent.offset.formatted())")
                        Text("Length: \(extent.byteCount.formatted()) bytes")
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                }
                if extents.count > pageSize {
                    HStack {
                        Button { page = max(0, displayedPage - 1) } label: { Image(systemName: "chevron.left") }
                            .disabled(displayedPage == 0)
                            .accessibilityLabel("Previous UDF source extents")
                        Text("\(displayedPage + 1) / \(lastPage + 1)").monospacedDigit()
                        Button { page = min(lastPage, displayedPage + 1) } label: { Image(systemName: "chevron.right") }
                            .disabled(displayedPage == lastPage)
                            .accessibilityLabel("Next UDF source extents")
                    }
                    .controlSize(.small)
                }
            }
            .padding(.top, 8)
        }
        .font(.caption)
        .onChange(of: extents) { _, _ in page = 0 }
    }
}

private struct OpticalDocumentPreviewView: View {
    let entry: UDFFileEntry
    @Bindable var store: OpticalWorkspaceStore

    private var matchingAnalysis: DocumentAnalysis? {
        guard let analysis = store.analysis, analysis.sourceSHA256 == entry.sha256,
              analysis.sourceByteCount == entry.byteCount else { return nil }
        return analysis
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Verified Local Preview", systemImage: "doc.text.viewfinder")
                .font(.headline)
            Text("UDF file bytes are exported to an owned temporary file and checked before the isolated decoder runs. Preview limits are separate from UDF inspection limits.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button(matchingAnalysis == nil ? "Verify and Preview" : "Verify and Reload", action: store.previewSelected)
                    .disabled(!store.canPreview)
                if store.isPreviewing {
                    ProgressView().controlSize(.small)
                    Button("Cancel", action: store.cancel)
                }
            }
            if let reason = store.documentUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let analysis = matchingAnalysis {
                DecodedDocumentContentView(analysis: analysis, contentQuery: $store.contentQuery, searchOutcome: store.searchOutcome)
            } else if !store.isPreviewing {
                Text("Preview validates supported content separately from UDF metadata and file-byte hashes.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if let error = store.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct OpticalProvenanceView: View {
    let result: UDFInspectionResult

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            OpticalInspectorField(label: "Volume Identifier", value: result.volumeIdentifier)
            OpticalInspectorField(label: "UDF Revision", value: result.udfRevision)
            OpticalInspectorField(label: "Reader Profile", value: result.profile)
            OpticalInspectorField(label: "Parser Version", value: result.parserVersion)
            OpticalInspectorField(label: "Block Size", value: "\(result.blockSize.formatted()) bytes")
            OpticalInspectorField(label: "Source Size", value: "\(result.sourceByteCount.formatted()) bytes")
            OpticalInspectorField(label: "Source SHA-256 · selected RAW file bytes", value: result.sourceSHA256, monospaced: true)
            OpticalInspectorField(label: "Inspection Job ID", value: result.jobID.uuidString.lowercased(), monospaced: true)
            OpticalInspectorField(label: "Receipt Saved At", value: OpticalViewFormatting.utc(result.savedAt))
            Text("Receipt Saved At is an application event. Recorded UDF file and VAT timestamps are shown separately.")
                .font(.caption)
                .foregroundStyle(.secondary)
            DisclosureGroup("Linked VAT Snapshots · \(result.snapshots.count.formatted())") {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(result.snapshots) { snapshot in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 9) {
                                OpticalInspectorField(label: snapshot.id == result.latestSnapshotID ? "Latest Snapshot" : "Historical Snapshot", value: snapshot.id, monospaced: true)
                                OpticalInspectorField(label: "VAT ICB RAW Offset", value: "\(snapshot.vatICBSourceOffset.formatted()) bytes")
                                OpticalInspectorField(label: "Previous VAT Logical Block", value: snapshot.previousVATLogicalBlock.map { $0.formatted() } ?? "No previous VAT recorded")
                                OpticalInspectorField(label: "Mapped Blocks / Namespace Files", value: "\(snapshot.mappedBlockCount.formatted()) / \(snapshot.namespaceFileCount.formatted())")
                                OpticalTimestampView(label: "Recorded VAT Modification", timestamp: snapshot.modification)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .padding(.top, 8)
            }
            .font(.caption)
            if !result.limitations.isEmpty {
                DisclosureGroup("Inspection Limitations · \(result.limitations.count.formatted())") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(result.limitations.enumerated()), id: \.offset) { _, limitation in
                            Label(limitation, systemImage: "exclamationmark.triangle")
                                .foregroundStyle(.orange)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.top, 8)
                }
                .font(.caption)
            }
        }
    }
}

private struct OpticalInspectorField: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(verbatim: value)
                .font(monospaced ? .system(.caption2, design: .monospaced) : .callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
