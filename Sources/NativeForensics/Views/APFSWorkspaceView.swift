import AppKit
import ForensicsCore
import SwiftUI

struct APFSWorkspaceView: View {
    let store: APFSWorkspaceStore
    @State private var usesContainerCredential = false
    @State private var usesVolumeCredential = false
    @State private var containerCredential = ""
    @State private var volumeCredential = ""
    @State private var admissionTask: Task<Void, Never>?
    @State private var admissionID: UUID?
    @State private var admissionMessage: String?

    private enum AdmittedAction {
        case discoverVolumes
        case inspect
    }

    var body: some View {
        VStack(spacing: 0) {
            controls
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            Divider()
            if let result = store.result {
                APFSResultSummaryView(result: result, isHistorical: store.isHistorical)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                Divider()
                APFSFilesTableView(store: store)
                    .disabled(admissionID != nil)
            } else {
                ContentUnavailableView {
                    Label(store.state == .loading ? "Loading APFS Result" : "Inspect APFS Files", systemImage: "externaldrive")
                } description: {
                    Text("Inspect one supported APFS disk-image volume through a read-only system view. Select a recorded source to inspect allocated files and their verified hashes.")
                        .frame(maxWidth: 450)
                } actions: {
                    if store.hasActiveWork || admissionID != nil {
                        ProgressView().controlSize(.small)
                    } else {
                        Button("Inspect APFS", action: inspect)
                            .disabled(!store.canInspect || admissionID != nil)
                    }
                }
            }
        }
        .onDisappear(perform: invalidatePendingActions)
        .onChange(of: store.selectedEntryPath) { _, _ in invalidatePendingActions() }
        .onChange(of: store.selectedSourceFilename) { _, _ in invalidatePendingActions() }
        .onChange(of: store.selectedEvidenceID) { _, _ in invalidatePendingActions() }
        .onChange(of: store.selectedCaseID) { _, _ in invalidatePendingActions() }
        .onChange(of: store.result?.evidenceID) { _, _ in invalidatePendingActions() }
        .onChange(of: store.jobBindingID) { _, _ in invalidatePendingActions() }
        .onChange(of: store.state) { _, state in
            if state != .idle { invalidatePendingActions() }
        }
        .onChange(of: store.errorMessage) { _, error in
            if error != nil { clearCredentials() }
        }
        .onChange(of: store.cleanupWarning) { _, warning in
            if warning != nil { invalidatePendingActions() }
        }
    }

    private var controls: some View {
        @Bindable var apfs = store
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Label("APFS Allocated Files", systemImage: "externaldrive")
                        .font(.headline)
                    Text(store.selectedSourceFilename)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(store.selectedSourceFilename)
                }
                Spacer(minLength: 8)
                Button(action: store.refresh) {
                    Label("Reload Saved Result", systemImage: "arrow.clockwise")
                }
                .disabled(!store.hasSource || store.hasActiveWork || admissionID != nil)
                Button(action: discoverVolumes) {
                    Label("Find Volumes", systemImage: "externaldrive.badge.magnifyingglass")
                }
                .disabled(!store.canDiscoverVolumes || admissionID != nil)
                Button(action: inspect) {
                    Label(store.result == nil ? "Inspect APFS" : "Inspect Again", systemImage: "play.circle")
                }
                .disabled(!store.canInspect || admissionID != nil)
            }
            Text("Experimental read-only system view · one selected current volume or snapshot · allocated files")
                .font(.caption)
                .foregroundStyle(.secondary)
            DisclosureGroup("Image Profile and Limits") {
                VStack(alignment: .leading, spacing: 7) {
                    Text("Supported images include APFS in UDIF and verified raw GPT layouts. UDIF may use container encryption, Disk-user APFS volume encryption, or both. Find Volumes records source-bound metadata; each inspection reads one selected UUID. Container and volume credentials are separate.")
                    Text("Up to \(store.maximumEntries.formatted()) entries are recorded for the chosen view. File content and file SHA-256 cover regular-file main data forks; extended attributes and resource forks are outside this view. Snapshot content uses an exact UUID from an unencrypted APFS volume. Plain images and the tested AES-256 UDIF wrapper profile are supported. Snapshots from encrypted APFS volumes, deleted-file recovery, boot FileVault and hardware-bound FileVault remain unsupported.")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 6)
            }
            .font(.caption)
            if let catalog = store.volumeCatalog, catalog.evidenceID == store.selectedEvidenceID {
                Picker("APFS Volume", selection: $apfs.selectedVolumeUUID) {
                    Text("Choose a volume UUID").tag(Optional<UUID>.none)
                    ForEach(catalog.volumes) { volume in
                        Text("\(volume.name) · \(volume.volumeUUID.uuidString.lowercased())")
                            .tag(Optional(volume.volumeUUID))
                    }
                }
                .pickerStyle(.menu)
                .disabled(store.hasActiveWork || admissionID != nil)
                .help("Each inspection reads the selected source-bound volume UUID.")
                DisclosureGroup("Volume Inventory · \(catalog.volumes.count.formatted())") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Encryption and lock flags describe inventory metadata. They do not establish that a credential or encryption profile can produce verified plaintext.")
                            .foregroundStyle(.secondary)
                        Text(catalog.volumeGroupInventoryAvailable
                            ? "Volume group identities were included in the available inventory."
                            : "Volume group inventory was unavailable; an absent group UUID does not establish that a volume is ungrouped.")
                            .foregroundStyle(.secondary)
                        ForEach(catalog.volumes) { volume in
                            VStack(alignment: .leading, spacing: 3) {
                                Text(verbatim: volume.name).fontWeight(.medium)
                                Text(verbatim: volume.volumeUUID.uuidString.lowercased())
                                    .font(.system(.caption2, design: .monospaced))
                                    .textSelection(.enabled)
                                Text("\(volume.encrypted ? "Encrypted" : "Unencrypted") · \(volume.locked ? "Locked" : "Unlocked") · Roles: \(volume.roles.isEmpty ? "None declared" : volume.roles.joined(separator: ", "))")
                                    .foregroundStyle(.secondary)
                                if let group = volume.volumeGroupUUID {
                                    Text("Volume group · \(group.uuidString.lowercased())")
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                }
                            }
                            .fixedSize(horizontal: false, vertical: true)
                        }
                        ForEach(Array(catalog.warnings.enumerated()), id: \.offset) { _, warning in
                            Label(warning, systemImage: "exclamationmark.triangle")
                                .foregroundStyle(.orange)
                        }
                    }
                    .padding(.top, 6)
                }
                .font(.caption)
            }
            if let inventory = store.snapshotInventory,
               inventory.evidenceID == store.selectedEvidenceID,
               store.selectedVolumeUUID == nil || store.selectedVolumeUUID == inventory.volumeUUID {
                let supportsSnapshotSelection = inventory.volumeEncryption == APFSVolumeEncryption.none
                Picker("APFS View", selection: $apfs.selectedSnapshotUUID) {
                    Text("Current Volume").tag(Optional<UUID>.none)
                    if inventory.isAvailable && supportsSnapshotSelection {
                        ForEach(inventory.entries, id: \.uuid) { snapshot in
                            Text("\(snapshot.name) · \(snapshot.uuid.uuidString.lowercased()) · XID \(snapshot.transactionID)")
                                .tag(Optional(snapshot.uuid))
                        }
                    }
                }
                .pickerStyle(.menu)
                .disabled(store.hasActiveWork || admissionID != nil)
                .help("Inspect the current volume or the exact selected snapshot UUID from this source-bound inventory.")
                if !supportsSnapshotSelection {
                    Text("Snapshot content requires a recorded unencrypted APFS volume. Current Volume remains selectable; encryption metadata and snapshot names do not establish support for snapshots from encrypted APFS volumes.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(!inventory.isAvailable
                    ? "Snapshot inventory was unavailable for this recorded volume. This does not establish that the volume has no snapshots."
                    : inventory.entries.isEmpty
                        ? "No snapshots were recorded in this \(inventory.isHistorical ? "saved" : "inspection") inventory. The current volume remains selectable."
                        : "\(inventory.entries.count.formatted()) snapshot metadata records from the \(inventory.isHistorical ? "saved" : "completed") inspection. Snapshot content is verified only when that exact snapshot is inspected.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let reason = store.snapshotSelectionUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            APFSJobCredentialsView(usesContainerCredential: $usesContainerCredential,
                usesVolumeCredential: $usesVolumeCredential, containerCredential: $containerCredential,
                volumeCredential: $volumeCredential)
                .disabled(store.hasActiveWork || store.cleanupUncertain || admissionID != nil)
            if let message = admissionMessage {
                Label(message, systemImage: "clock")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let warning = store.cleanupWarning {
                Label(warning, systemImage: "externaldrive.badge.exclamationmark")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let reason = store.inspectionUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 10) {
                if store.hasActiveWork || admissionID != nil { ProgressView().controlSize(.small) }
                Text(admissionID == nil ? store.statusMessage : "Checking the available forensic workflow slot…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                if store.hasActiveWork || admissionID != nil {
                    Button("Cancel") {
                        cancelAdmission()
                        clearCredentials()
                        store.cancel()
                    }
                    .disabled(store.state == .cancelling)
                }
            }
            if let error = store.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .controlSize(.small)
    }

    private func inspect() {
        beginAdmission(.inspect)
    }

    private func discoverVolumes() {
        beginAdmission(.discoverVolumes)
    }

    private func beginAdmission(_ action: AdmittedAction) {
        guard canStart(action), admissionID == nil else {
            clearCredentials()
            return
        }
        let id = UUID(), bindingID = store.jobBindingID, maximumEntries = store.maximumEntries
        let selectedResult = store.result, catalog = store.volumeCatalog, volumeUUID = store.selectedVolumeUUID
        let snapshotUUID = store.selectedSnapshotUUID
        admissionID = id; admissionMessage = nil
        admissionTask = Task { @MainActor in
            defer {
                if admissionID == id { admissionID = nil; admissionTask = nil }
            }
            var permit: ForensicWorkPermit?
            do {
                let admitted = try await store.acquireImmediateAdmission()
                permit = admitted
                try Task.checkCancellation()
                guard admissionID == id, store.jobBindingID == bindingID,
                      store.maximumEntries == maximumEntries, store.result == selectedResult,
                      store.volumeCatalog == catalog, store.selectedVolumeUUID == volumeUUID,
                      store.selectedSnapshotUUID == snapshotUUID,
                      canStart(action) else { throw CancellationError() }
                do {
                    let started: Bool
                    switch action {
                    case .discoverVolumes:
                        let container = try APFSViewCredentialCapture.captureContainer(container: &containerCredential,
                            volume: &volumeCredential, containerEnabled: usesContainerCredential)
                        started = store.discoverVolumes(passphrase: container, permit: admitted)
                    case .inspect:
                        let credentials = try APFSViewCredentialCapture.capture(container: &containerCredential, volume: &volumeCredential,
                            containerEnabled: usesContainerCredential, volumeEnabled: usesVolumeCredential)
                        started = store.inspect(passphrase: credentials.container, volumePassphrase: credentials.volume, permit: admitted)
                    }
                    if started { permit = nil }
                } catch {
                    store.rejectCredentialCapture()
                }
            } catch is CancellationError {
                // A canceled or superseded action does not capture credentials.
            } catch {
                if admissionID == id, store.jobBindingID == bindingID {
                    admissionMessage = APFSViewAdmissionFormatting.message(error)
                }
            }
            if let permit { await permit.release() }
        }
    }

    private func canStart(_ action: AdmittedAction) -> Bool {
        switch action {
        case .discoverVolumes: store.canDiscoverVolumes
        case .inspect: store.canInspect
        }
    }

    private func cancelAdmission() {
        admissionTask?.cancel()
        admissionTask = nil
        admissionID = nil
    }

    private func invalidatePendingActions() {
        cancelAdmission()
        admissionMessage = nil
        clearCredentials()
    }

    private func clearCredentials() {
        containerCredential = ""
        volumeCredential = ""
    }
}

private struct APFSResultSummaryView: View {
    let result: APFSInspectionResult
    let isHistorical: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Label(result.coverage == .completeAllocatedView ? "Complete Allocated View" : "Partial Allocated View",
                    systemImage: result.coverage == .completeAllocatedView ? "checkmark.circle" : "exclamationmark.triangle")
                    .foregroundStyle(result.coverage == .completeAllocatedView ? Color.primary : Color.orange)
                Spacer(minLength: 0)
                Text("\(result.entries.count.formatted()) entries")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            .font(.caption)
            Text(APFSViewFormatting.selectedView(result.selectedSnapshot))
                .font(.caption)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if isHistorical {
                Label("Saved inspection receipt. It describes the allocated view verified when that inspection completed.", systemImage: "clock.arrow.circlepath")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            DisclosureGroup("Source and Inspection Scope") {
                VStack(alignment: .leading, spacing: 7) {
                    Text(APFSViewFormatting.encryption(result))
                    Text("Volume UUID · \(result.volumeUUID.uuidString.lowercased())")
                    Text("Source SHA-256 · selected disk-image container bytes")
                        .foregroundStyle(.secondary)
                    Text(verbatim: result.containerSHA256)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                    Text("Source size: \(EvidenceFormatting.bytes(result.containerByteCount)). File SHA-256 values describe complete plaintext main data forks read from the recorded current or selected snapshot view.")
                    Text("Limits: \(result.options.maximumEntries.formatted()) entries · \(EvidenceFormatting.bytes(result.options.maximumFileBytes)) per file · \(EvidenceFormatting.bytes(result.options.maximumAggregateFileBytes)) file bytes in total")
                    Text(result.snapshotInventoryAvailable
                        ? "\(result.snapshots.count.formatted()) snapshot inventory records. \(result.selectedSnapshot == nil ? "This receipt covers the current volume." : "This receipt covers only the explicitly selected snapshot.")"
                        : "Snapshot inventory was unavailable for this receipt; an empty inventory does not establish the absence of snapshots.")
                    ForEach(Array(result.warnings.enumerated()), id: \.offset) { _, warning in
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 7)
            }
            .font(.caption)
        }
    }
}

private struct APFSFilesTableView: View {
    let store: APFSWorkspaceStore
    @State private var page = 0
    private let pageSize = 100

    private struct Row: Identifiable {
        let entry: APFSFileEntry
        var id: String { entry.relativePath }
    }

    private var lastPage: Int { max(0, (store.rows.count - 1) / pageSize) }
    private var displayedPage: Int { min(max(0, page), lastPage) }
    private var pageRange: Range<Int> {
        let start = displayedPage * pageSize
        return start..<min(start + pageSize, store.rows.count)
    }
    private var pageRows: [Row] { store.rows[pageRange].map { Row(entry: $0) } }

    var body: some View {
        @Bindable var store = store
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Find path or file SHA-256", text: $store.searchText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Find APFS path or file SHA-256")
                    .onExitCommand { store.searchText = "" }
                Text("\(store.rows.count.formatted()) / \((store.result?.entries.count ?? 0).formatted())")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .fixedSize()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            Table(pageRows, selection: $store.selectedEntryPath) {
                TableColumn("Name / Path") { row in
                    VStack(alignment: .leading, spacing: 2) {
                        Label(APFSViewFormatting.filename(row.entry), systemImage: APFSViewFormatting.icon(row.entry.kind))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(verbatim: row.entry.relativePath)
                            .font(.caption2)
                            .foregroundStyle(store.selectedEntryPath == row.id
                                ? Color(nsColor: .alternateSelectedControlTextColor).opacity(0.8) : Color.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .padding(.vertical, 3)
                    .help(row.entry.relativePath)
                }
                .width(min: 170, ideal: 280, max: 500)
                TableColumn("Kind") { row in
                    Text(APFSViewFormatting.kind(row.entry.kind)).font(.caption)
                }
                .width(92)
                TableColumn("Size") { row in
                    Text(EvidenceFormatting.bytes(row.entry.byteCount))
                        .font(.caption)
                        .monospacedDigit()
                        .help("\(row.entry.byteCount.formatted()) recorded bytes")
                }
                .width(76)
                TableColumn("Modified") { row in
                    Text(APFSViewFormatting.modified(row.entry))
                        .font(.caption2)
                        .lineLimit(1)
                        .help("Recorded modification time in UTC")
                }
                .width(min: 145, ideal: 160, max: 185)
                TableColumn("File SHA-256") { row in
                    Text(row.entry.sha256.map { String($0.prefix(12)) + "…" } ?? "Not verified")
                        .font(.system(.caption2, design: .monospaced))
                        .help(row.entry.sha256.map { "Plaintext main data-fork SHA-256 from the recorded current or snapshot view: \($0)" }
                            ?? "This entry has no complete bounded file-byte hash.")
                }
                .width(110)
            }
            .frame(minHeight: 192)
            .disabled(store.hasActiveWork)
            .contextMenu(forSelectionType: String.self) { selection in
                if selection.count == 1, let path = selection.first,
                   let row = pageRows.first(where: { $0.id == path }), row.entry.sha256 != nil {
                    Button {
                        store.selectedEntryPath = path
                        store.copySelectedHash()
                    } label: {
                        Label("Copy File SHA-256", systemImage: "doc.on.doc")
                    }
                }
            }
            .overlay {
                if store.rows.isEmpty && !store.hasActiveWork {
                    ContentUnavailableView {
                        Label(store.searchText.isEmpty ? "No Entries Recorded" : "No Matching Entries", systemImage: "doc.text.magnifyingglass")
                    } description: {
                        Text(store.searchText.isEmpty
                            ? "Review the inspection scope and warnings. This result records the bounded allocated view."
                            : "Try another path or file SHA-256. Search covers all recorded entries.")
                    }
                }
            }
            Divider()
            HStack(spacing: 10) {
                Text(store.rows.isEmpty ? "0 entries"
                    : "Entries \((pageRange.lowerBound + 1).formatted())–\(pageRange.upperBound.formatted()) of \(store.rows.count.formatted())")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                Spacer(minLength: 0)
                Button { changePage(to: displayedPage - 1) } label: { Label("Previous", systemImage: "chevron.left") }
                    .disabled(displayedPage == 0)
                Button { changePage(to: displayedPage + 1) } label: { Label("Next", systemImage: "chevron.right") }
                    .disabled(displayedPage == lastPage)
            }
            .font(.caption)
            .controlSize(.small)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .disabled(store.hasActiveWork)
            .help("Search covers all recorded entries. The table displays up to \(pageSize) rows per page.")
        }
        .onChange(of: store.searchText) { _, _ in changePage(to: 0) }
        .onChange(of: store.result?.containerSHA256) { _, _ in changePage(to: 0) }
        .onChange(of: store.rows.count) { _, _ in
            if page != displayedPage { changePage(to: displayedPage) }
        }
    }

    private func changePage(to newPage: Int) {
        store.selectedEntryPath = nil
        page = min(max(0, newPage), lastPage)
    }
}

struct APFSJobCredentialsView: View {
    @Binding var usesContainerCredential: Bool
    @Binding var usesVolumeCredential: Bool
    @Binding var containerCredential: String
    @Binding var volumeCredential: String

    var body: some View {
        DisclosureGroup("Credentials for This Job") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Encrypted Disk Image", isOn: $usesContainerCredential)
                    .toggleStyle(.button)
                    .accessibilityLabel("Use a disk-image container credential")
                if usesContainerCredential {
                    SecureField("Disk-image passphrase", text: $containerCredential)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Disk-image container passphrase for this job")
                }
                Toggle("Encrypted APFS Volume", isOn: $usesVolumeCredential)
                    .toggleStyle(.button)
                    .accessibilityLabel("Use an APFS volume credential")
                if usesVolumeCredential {
                    SecureField("APFS-volume passphrase", text: $volumeCredential)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("APFS volume passphrase for this job")
                }
                Text("Enter the container and volume credentials separately. Starting a job clears these fields. If the workflow slot is busy, the fields remain available for retry. Find Volumes uses only the container credential.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 6)
        }
        .font(.caption)
        .onChange(of: usesContainerCredential) { _, enabled in
            if !enabled { containerCredential = "" }
        }
        .onChange(of: usesVolumeCredential) { _, enabled in
            if !enabled { volumeCredential = "" }
        }
    }
}

enum APFSViewCredentialCapture {
    static func captureContainer(container: inout String, volume: inout String,
                                 containerEnabled: Bool = true) throws -> APFSPassphrase? {
        defer { container = ""; volume = "" }
        guard containerEnabled, !container.isEmpty else { return nil }
        return try APFSPassphrase(Data(container.utf8))
    }

    static func capture(container: inout String, volume: inout String,
                        containerEnabled: Bool = true, volumeEnabled: Bool = true) throws
        -> (container: APFSPassphrase?, volume: APFSPassphrase?) {
        defer {
            container = ""
            volume = ""
        }
        let containerPassphrase: APFSPassphrase?
        if !containerEnabled || container.isEmpty { containerPassphrase = nil }
        else { containerPassphrase = try APFSPassphrase(Data(container.utf8)) }
        let volumePassphrase: APFSPassphrase?
        if !volumeEnabled || volume.isEmpty { volumePassphrase = nil }
        else { volumePassphrase = try APFSPassphrase(Data(volume.utf8)) }
        return (containerPassphrase, volumePassphrase)
    }
}

enum APFSViewAdmissionFormatting {
    static func message(_ error: Error) -> String {
        if let error = error as? ForensicSchedulingError { return error.localizedDescription }
        return "The forensic workflow slot could not be acquired. No credentials were used. Try again when the current workflow finishes."
    }
}

enum APFSViewFormatting {
    static func selectedView(_ snapshot: APFSSnapshotInventoryEntry?) -> String {
        guard let snapshot else { return "Recorded view · Current Volume" }
        return "Recorded snapshot · \(snapshot.name) · \(snapshot.uuid.uuidString.lowercased()) · XID \(snapshot.transactionID)"
    }

    static func filename(_ entry: APFSFileEntry) -> String {
        let name = (entry.relativePath as NSString).lastPathComponent
        return name.isEmpty ? entry.relativePath : name
    }

    static func kind(_ kind: APFSFileKind) -> String {
        switch kind {
        case .regular: "File"
        case .directory: "Directory"
        case .symbolicLink: "Symbolic Link"
        case .other: "Other"
        }
    }

    static func icon(_ kind: APFSFileKind) -> String {
        switch kind {
        case .regular: "doc"
        case .directory: "folder"
        case .symbolicLink: "link"
        case .other: "questionmark.folder"
        }
    }

    static func modified(_ entry: APFSFileEntry) -> String {
        guard (-62_135_596_800...253_402_300_799).contains(entry.modifiedSeconds) else {
            return "Outside the formatted calendar range; see the exact recorded value."
        }
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        let whole = formatter.string(from: Date(timeIntervalSince1970: Double(entry.modifiedSeconds)))
        guard whole.hasSuffix("Z") else { return "See the exact recorded modification time." }
        return String(whole.dropLast()) + "." + String(format: "%09d", entry.modifiedNanoseconds) + "Z"
    }

    static func utc(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    static func encryption(_ result: APFSInspectionResult) -> String {
        let container = result.containerEncryption == .encryptedDiskImage ? "Encrypted UDIF container" : "Plain disk-image container"
        let volume = result.volumeEncryption == .diskUserAPFS ? "Disk-user encrypted APFS volume" : "Plain APFS volume"
        return "\(container) · \(volume)"
    }
}
