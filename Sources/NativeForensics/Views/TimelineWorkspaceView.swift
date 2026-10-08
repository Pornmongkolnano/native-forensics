import AppKit
import Foundation
import ForensicsCore
import SwiftUI

struct TimelineWorkspaceView: View {
    let store: TimelineWorkspaceStore
    /// Resolver must compare this immutable binding with the current workspace
    /// before selecting/opening a file. A fileID alone is not a safe reference.
    let openFile: @MainActor (TimelineSourceBinding, String) -> Void
    @State private var page = 0
    private let pageSize = 100
    private var lastPage: Int { max(0, (store.rows.count - 1) / pageSize) }
    private var currentPage: Int { min(max(page, 0), lastPage) }
    private var range: Range<Int> {
        let start = currentPage * pageSize
        return start..<min(start + pageSize, store.rows.count)
    }

    var body: some View {
        @Bindable var timeline = store
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    Label("Evidence Timeline", systemImage: "clock.arrow.circlepath").font(.headline)
                    Spacer()
                    Button("Build Filesystem", action: store.loadFilesystem).disabled(!store.canLoad)
                    Button("Export Reports…", action: store.chooseExport).disabled(!store.canExport)
                }
                Text("Selected evidence only · recorded filesystem timestamps, including unresolved civil values · optional verified Chromium History and bounded UTF-8 log imports · observations remain separate from examiner notes")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if !store.browserCandidates.isEmpty {
                    HStack(spacing: 10) {
                        Picker("Chromium History", selection: $timeline.selectedBrowserID) {
                            Text("Select History").tag(String?.none)
                            ForEach(store.browserCandidates) { file in Text(file.path).tag(Optional(file.id)) }
                        }.frame(maxWidth: 480)
                        Button("Verify & Import", action: store.loadSelectedBrowserHistory).disabled(!store.canLoadBrowser)
                        Text("Complete listing required · allocated History ≤64 MiB; WAL/SHM ≤16 MiB each")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                DisclosureGroup("Verify and import a selected syslog file") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 10) {
                            Picker("Allocated log candidate", selection: $timeline.selectedSyslogID) {
                                Text("Choose a recorded file").tag(String?.none)
                                ForEach(store.syslogCandidates) { file in Text(file.path).tag(Optional(file.id)) }
                            }.frame(maxWidth: 540)
                            Button("Verify & Import Syslog", action: store.loadSelectedSyslog).disabled(!store.canLoadSyslog)
                        }
                        HStack(spacing: 10) {
                            TextField("Explicit year", text: $timeline.syslogYear).frame(width: 108).textFieldStyle(.roundedBorder)
                                .accessibilityLabel("Explicit classic syslog year")
                            TextField("IANA timezone, e.g. Asia/Bangkok", text: $timeline.syslogTimezone).frame(maxWidth: 270).textFieldStyle(.roundedBorder)
                                .accessibilityLabel("Explicit classic syslog IANA timezone")
                            Picker("DST gap / overlap", selection: $timeline.syslogLocalTimePolicy) {
                                Text("Preserve unresolved candidates").tag(SyslogLocalTimePolicy.preserveUnresolved)
                                Text("Reject ambiguous or nonexistent times").tag(SyslogLocalTimePolicy.rejectAmbiguousOrNonexistent)
                            }.frame(maxWidth: 320)
                        }
                        Text("Strict UTF-8 ≤1 MiB; each line ≤16 KiB; ≤20,000 events. Classic timestamps require the selected year and IANA zone; explicit RFC3339 offsets need neither. Picker shows \(store.syslogCandidates.count) / \(store.syslogCandidateCount) eligible recorded files, with conventional log names first. Imports replace the prior syslog selection.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }.padding(.vertical, 6)
                }.font(.caption)
                HStack(spacing: 10) {
                    TextField("Search path, event or observation", text: $timeline.query).textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Search recorded timeline observations")
                    Toggle("Date range", isOn: $timeline.useDateRange).toggleStyle(.checkbox)
                    Toggle("Unresolved times", isOn: $timeline.includeUnresolved).toggleStyle(.checkbox)
                    Text("\(store.rows.count.formatted()) / \((store.report?.events.count ?? 0).formatted())").font(.caption).monospacedDigit()
                }
                if store.useDateRange {
                    HStack {
                        DatePicker("From (display timezone)", selection: $timeline.from)
                        DatePicker("Through", selection: $timeline.through)
                        Text("Bounds compare normalized instants; unresolved timestamps are controlled separately.").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if store.isLoading || store.isExporting || store.isFiltering {
                    HStack { ProgressView().controlSize(.small); Text(store.phase).font(.caption); Spacer(); Button("Cancel", action: store.cancel) }
                } else { Text(store.phase).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                if let error = store.errorMessage { Label(error, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
                if let receipt = store.exportReceipt {
                    HStack { Label("Reports saved · \(receipt.eventCount.formatted()) recorded events", systemImage: "checkmark.seal").font(.caption)
                        Spacer(); Button("Show Reports") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: receipt.destinationPath)]) }
                    }
                }
            }.padding(16).controlSize(.small)
            Divider()
            Table(store.rows[range], selection: $timeline.selectedEventID) {
                TableColumn("Time (UTC)") { event in
                    Text(Self.utc(event.timestamp)).font(.system(.caption, design: .monospaced)).lineLimit(1)
                        .help("Raw: \(event.timestamp.rawValue)\nPrecision: \(event.timestamp.precision)\n\(event.timestamp.timezoneAssumption ?? "No assumed timezone")\nInterpretation: \(event.timestamp.interpretation)")
                }.width(min: 180, ideal: 208, max: 260)
                TableColumn("Event") { event in Text(Self.kind(event.kind)).font(.caption) }.width(116)
                TableColumn("Evidence path / observation") { event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.evidencePath).lineLimit(1).truncationMode(.middle)
                        Text(event.title).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }.padding(.vertical, 3).help(event.detail + Self.sourcePointer(event))
                }.width(min: 180, ideal: 340, max: 700)
                TableColumn("Source state") { event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.artifactSHA256 == nil ? (store.binding?.historical == true ? "Historical metadata" : "Recorded metadata") : "Verified artifact bytes")
                            .font(.caption2).foregroundStyle(event.artifactSHA256 == nil ? Color.secondary : Color.green)
                        if event.isDeleted { Label("Deleted entry", systemImage: "trash").font(.caption2).foregroundStyle(.orange).help("The recorded entry is deleted; no deletion time is inferred.") }
                    }
                }.width(144)
            }
            .frame(minHeight: 192)
            .disabled(store.isLoading || store.isExporting || store.isFiltering)
            .contextMenu(forSelectionType: String.self) { selected in
                if let id = selected.first, let event = store.rows.first(where: { $0.id == id }), let binding = store.binding {
                    Button("Open Recorded Source") { openFile(binding, event.fileID) }
                }
            }
            .overlay {
                if store.rows.isEmpty && !store.isLoading && !store.isFiltering {
                    ContentUnavailableView("No Timeline Events", systemImage: "clock", description: Text(store.report == nil ? "Build the recorded filesystem timeline or explicitly import Chromium History or a bounded UTF-8 log." : "No events match this filter. Missing timestamps and uncovered artifacts do not establish that no activity occurred."))
                }
            }
            Divider()
            HStack {
                Text(store.rows.isEmpty ? "0 events" : "Events \(range.lowerBound + 1)–\(range.upperBound) of \(store.rows.count.formatted())").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Previous") { page = currentPage - 1; timeline.selectedEventID = nil }.disabled(currentPage == 0)
                Button("Next") { page = currentPage + 1; timeline.selectedEventID = nil }.disabled(currentPage == lastPage)
                if let event = store.selectedEvent, let binding = store.binding {
                    if let reference = event.sourceReference {
                        Text("Source line \(reference.line); UTF-8 \(reference.utf8Offset)..<\(reference.utf8Offset + reference.utf8Length)")
                            .font(.caption2).textSelection(.enabled).help(Self.sourcePointer(event))
                    }
                    Button("Open Source") { openFile(binding, event.fileID) }
                }
            }.padding(.horizontal, 16).padding(.vertical, 8).controlSize(.small)
            DisclosureGroup("Report provenance, limits and examiner notes") {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        if let report = store.report {
                            Text(report.coverage).font(.caption).textSelection(.enabled)
                            Text("Snapshot SHA-256: \(report.binding.snapshotSHA256)").font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                            ForEach(Array(report.warnings.enumerated()), id: \.offset) { _, warning in Label(warning, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.secondary) }
                        }
                        Text("Examiner notes are separate from deterministic observations. No AI interpretation is automatically added.").font(.caption).foregroundStyle(.secondary)
                        TextEditor(text: $timeline.examinerNotes).font(.body).frame(minHeight: 72, maxHeight: 96).accessibilityLabel("Examiner notes for timeline report")
                        Text("Export includes every event in the current bounded report, regardless of presentation filters, with JSON/Markdown/PDF and an independently verified hash receipt in a new folder.").font(.caption).foregroundStyle(.secondary)
                    }.padding(.vertical, 8)
                }.frame(maxHeight: 180)
            }.font(.caption).padding(.horizontal, 16).padding(.vertical, 10)
        }
        .onChange(of: store.rows.count) { _, _ in if page > lastPage { page = lastPage } }
        .onChange(of: store.query) { _, _ in page = 0 }
        .onChange(of: store.useDateRange) { _, _ in page = 0 }
        .onChange(of: store.binding?.snapshotSHA256) { _, _ in page = 0 }
    }

    private static func kind(_ value: TimelineEventKind) -> String {
        switch value {
        case .filesystemCreated: "Created"
        case .filesystemModified: "Modified"
        case .filesystemAccessed: "Accessed"
        case .filesystemChanged: "Metadata changed"
        case .browserVisit: "Browser visit"
        case .downloadStarted: "Download started"
        case .downloadEnded: "Download ended"
        case .syslogRecord: "Syslog record"
        }
    }
    private static func sourcePointer(_ event: TimelineEvent) -> String {
        guard let pointer = event.sourceReference else { return "" }
        return "\nSource: \(pointer.unitKind), unit \(pointer.unit), line \(pointer.line), UTF-8 offset \(pointer.utf8Offset), length \(pointer.utf8Length).\nDerived-text SHA-256: \(pointer.derivedTextSHA256)"
    }
    private static func utc(_ stamp: TimelineTimestamp) -> String {
        guard let seconds = stamp.epochSeconds else { return "Unresolved · \(stamp.interpretation)" }
        let formatter = ISO8601DateFormatter(); formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: Date(timeIntervalSince1970: Double(seconds))).replacingOccurrences(of: "Z", with: String(format: ".%09dZ", stamp.nanoseconds))
    }
}
