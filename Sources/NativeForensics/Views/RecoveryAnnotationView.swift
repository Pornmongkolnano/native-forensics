import ForensicsCore
import SwiftUI

struct RecoveryAnnotationView: View {
    @Bindable var store: RecoveryExaminationStore

    var body: some View {
        GroupBox("Examiner Assessment") {
            VStack(alignment: .leading, spacing: 9) {
                Picker("Assessment", selection: $store.assessment) {
                    ForEach(RecoveryAssessment.allCases, id: \.self) { value in
                        Text(title(value)).tag(value)
                    }
                }
                .disabled(store.isLoading || store.isSaving)
                TextEditor(text: $store.note)
                    .font(.callout)
                    .frame(minHeight: 80, maxHeight: 120)
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.secondary.opacity(0.25)))
                    .disabled(store.isLoading || store.isSaving)
                    .accessibilityLabel("Examiner note for recovered file")
                HStack {
                    Text("\(store.note.utf8.count.formatted()) / 8,192 UTF-8 bytes")
                        .font(.caption2).foregroundStyle(.secondary).monospacedDigit()
                    Spacer()
                    if store.hasUnsavedChanges { Text("Unsaved").font(.caption2).foregroundStyle(.orange) }
                }
                if let message = store.noteValidationMessage {
                    Text(message).font(.caption).foregroundStyle(.orange)
                }
                HStack {
                    Button("Save Assessment", action: store.saveAnnotation).disabled(!store.canSaveAnnotation)
                    Button("Discard Draft", action: store.discardDraft)
                        .disabled(!store.hasUnsavedChanges || store.isSaving)
                    if store.isLoading || store.isSaving { ProgressView().controlSize(.small) }
                }
                Text("This is your examination judgment. Decoder status, byte integrity and deletion status remain separate. Reports include saved assessments only.")
                    .font(.caption2).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let error = store.errorMessage {
                    Text(error).font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func title(_ value: RecoveryAssessment) -> String {
        switch value {
        case .notReviewed: "Not reviewed"
        case .accessible: "Accessible in examination"
        case .damaged: "Damaged in examination"
        case .unsupported: "Requires another application"
        case .unknown: "Undetermined"
        }
    }
}
